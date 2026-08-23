package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/pascalgross/farrier/internal/canonical"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/notify"
	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/store"
)

// ReadJobValidity is how long an unsigned job stays executable after it is created.
//
// A signed job's window comes from whoever signed it and is never chosen here: it is covered by the
// signature, so a control plane that could widen it would be able to make an old authorisation good
// again. Only a read intent has a window this side may pick, and a day is chosen for the host that was
// offline when the operator asked — coming back to a facts collection somebody wanted this morning is
// useful, and coming back to one from a fortnight ago is noise.
const ReadJobValidity = 24 * time.Hour

// MaxJobRequestBytes bounds a job-creation request body.
//
// The catalogue bounds a parameter object to 8 KiB and a signature is a few hundred bytes, so this is
// generous by two orders of magnitude. It exists so the body is bounded before it is in memory.
const MaxJobRequestBytes = 64 << 10

// jobRequest is the body of POST /api/v1/jobs.
//
// The shape follows from what a signature covers. docs/SECURITY.md §2.3 fixes the signed payload as
// {jobId, hostId, intent, params, notBefore, notAfter, nonce}, so for a signed job every one of those
// arrives from the signer and none of them may be chosen here — including the id, because a
// server-generated one would invalidate every signature the moment it was assigned.
type jobRequest struct {
	// ID is the job identifier. Required for a signed job, refused for an unsigned one.
	ID string `json:"id,omitempty"`

	// HostID is the host to issue to. It is covered by the signature, so it binds a signed job to
	// exactly one machine.
	HostID string `json:"hostId"`

	// Intent is the catalogue member.
	Intent string `json:"intent"`

	// Params is the parameter object, validated here by the same decoder the agent and the helper use.
	Params map[string]any `json:"params"`

	// NotBefore and NotAfter bound the job's validity, and are the signer's to choose.
	NotBefore time.Time `json:"notBefore,omitempty"`
	NotAfter  time.Time `json:"notAfter,omitempty"`

	// Nonce is what the host persists to refuse a replayed signature.
	Nonce string `json:"nonce,omitempty"`

	// Signature is base64 over the canonical signed payload, produced offline by a key this control
	// plane does not hold.
	Signature string `json:"signature,omitempty"`

	// SignerKeyID names the key, and must be one in the host's own trusted-signers.
	SignerKeyID string `json:"signerKeyId,omitempty"`

	// SignerAlgorithm is "ed25519" or "ecdsa-p256".
	SignerAlgorithm string `json:"signerAlgorithm,omitempty"`
}

// jobView is one job as the API renders it.
//
// It is a separate type from store.JobRecord for the same reason hostView is separate from store.Host:
// the stored shape follows the schema and this follows what a client needs, and coupling them makes a
// column rename a breaking API change.
type jobView struct {
	// ID identifies the job.
	ID string `json:"id"`

	// HostID is the host it was issued to.
	HostID string `json:"hostId"`

	// Intent is the catalogue member.
	Intent string `json:"intent"`

	// Params is the parameter object.
	Params map[string]any `json:"params"`

	// Class is the authorisation tier, for display. The agent takes it from its own catalogue.
	Class string `json:"class"`

	// CreatedAt is when the control plane created it.
	CreatedAt time.Time `json:"createdAt"`

	// CreatedBy is the operator who asked for it.
	CreatedBy string `json:"createdBy"`

	// NotBefore is when the job becomes valid, or null when it has no lower bound.
	//
	// Null is the ordinary case for a read job: nothing signed it, so there is no authorisation whose
	// start needs pinning, and a lower bound taken from the control plane's clock would be refused by
	// any host running a second behind it.
	NotBefore *time.Time `json:"notBefore"`

	// NotAfter is when it stops being valid, checked on the host against the host's own clock.
	NotAfter time.Time `json:"notAfter"`

	// Signed reports whether an offline signature is attached.
	//
	// The signature itself is not rendered. It authorises nothing here — the host is what verifies it —
	// and putting it on a fleet dashboard would invite somebody to copy one.
	Signed bool `json:"signed"`

	// SignerKeyID names the key that signed it, empty for an unsigned job.
	SignerKeyID string `json:"signerKeyId,omitempty"`

	// ApprovalRequired reports whether somebody must release it before a host may claim it.
	ApprovalRequired bool `json:"approvalRequired"`

	// ApprovalDistinctOperator reports whether that somebody must be other than its creator.
	//
	// Rendered so that an interface can tell an operator whether they can release this job themselves
	// before they press the button, rather than after.
	ApprovalDistinctOperator bool `json:"approvalDistinctOperator"`

	// ApprovedAt and ApprovedBy record that agreement, null and empty until it happens.
	ApprovedAt *time.Time `json:"approvedAt"`
	ApprovedBy string     `json:"approvedBy,omitempty"`

	// ClaimedAt is when a host took it, null if none has.
	ClaimedAt *time.Time `json:"claimedAt"`

	// State is one word for what is happening, so that every client agrees on the vocabulary.
	State string `json:"state"`

	// Result is what the host reported, null until it does.
	//
	// Null rather than an empty object: "not reported yet" and "reported nothing" are different states,
	// and a host part way through a forty-minute upgrade is in the first one.
	Result *protocol.ResultRequest `json:"result"`
}

// toJobView converts a stored record into its API representation.
func toJobView(rec store.JobRecord) jobView {
	view := jobView{
		ID:                       rec.Job.ID,
		HostID:                   rec.HostID,
		Intent:                   rec.Job.Intent,
		Params:                   rec.Job.Params,
		Class:                    rec.Job.Class,
		CreatedAt:                rec.CreatedAt,
		CreatedBy:                rec.CreatedBy,
		NotAfter:                 rec.Job.NotAfter,
		Signed:                   rec.Job.Signature != "",
		SignerKeyID:              rec.Job.SignerKeyID,
		ApprovalRequired:         rec.ApprovalRequired,
		ApprovalDistinctOperator: rec.ApprovalDistinctOperator,
		ApprovedBy:               rec.ApprovedBy,
		State:                    jobState(rec),
		Result:                   rec.Result,
	}
	if view.Params == nil {
		view.Params = map[string]any{}
	}
	if !rec.Job.NotBefore.IsZero() {
		at := rec.Job.NotBefore
		view.NotBefore = &at
	}
	if !rec.ApprovedAt.IsZero() {
		at := rec.ApprovedAt
		view.ApprovedAt = &at
	}
	if !rec.ClaimedAt.IsZero() {
		at := rec.ClaimedAt
		view.ClaimedAt = &at
	}
	return view
}

// jobState reduces a record to the one word a client shows.
//
// It is computed here rather than by each client, so that the UI, a script and a future CLI agree about
// what a job that has been claimed but not reported is called. Note that "waiting for approval" is a
// state and not an error: it is the system working, and rendering it as a failure would teach operators
// to ignore the one thing docs/SECURITY.md §3 asks a second person to look at.
func jobState(rec store.JobRecord) string {
	switch {
	case rec.Result != nil:
		return rec.Result.Status
	case !rec.ClaimedAt.IsZero():
		return "running"
	case rec.AwaitingApproval():
		return "awaiting_approval"
	default:
		return "queued"
	}
}

// handleCreateJob issues one job to one host.
//
// One host per request, deliberately. A signature covers the host id, so a signed job is bound to
// exactly one machine and a fan-out request could not be signed at all; making the unsigned case behave
// differently would mean two shapes for one endpoint, and the client loop it saves is three lines.
func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request, who operator) {
	var req jobRequest
	if err := decodeJSON(w, r, MaxJobRequestBytes, &req); err != nil {
		switch {
		case isTooLarge(err):
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the request body is too large")
		case errors.Is(err, errTrailingData):
			// Worth its own message here. This endpoint is the one somebody scripts in a loop, and the
			// failure it catches — two concatenated requests, of which only the first was ever going to
			// be read — otherwise looks exactly like success for both.
			writeError(w, http.StatusBadRequest, "malformed",
				"this endpoint issues one job to one host, and the body holds more than one JSON "+
					"value. Nothing was queued; send them as separate requests.")
		default:
			writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		}
		return
	}

	spec, params, err := s.validateJobRequest(w, req)
	if err != nil {
		return // validateJobRequest has already written the response.
	}

	host, err := who.Store.GetHost(r.Context(), req.HostID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_host", "no such host")
		return
	case err != nil:
		slog.Error("could not read a host", "error", err, "host", req.HostID)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the host")
		return
	case host.Revoked:
		// A revoked host cannot authenticate, so the job would sit in the queue for ever. Refusing here
		// says so at the moment somebody would otherwise wonder why nothing happened.
		writeError(w, http.StatusConflict, "revoked",
			"this host is revoked and can no longer authenticate, so it would never collect the job")
		return
	}

	job, err := s.buildJob(req, spec, req.HostID)
	if err != nil {
		slog.Error("could not build a job", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not create the job")
		return
	}

	// How this tenant releases a destructive job, read now and recorded on the row.
	//
	// Recorded rather than re-derived, and that matters more here than it did when the rule was a
	// constant: this setting is one an operator can edit. Deriving it at approval time would mean
	// queueing a job under the two-person rule, relaxing the tenant, and then releasing it yourself —
	// which is the whole rule defeated by two API calls. A job records what it required.
	tenant, err := s.cfg.Store.GetTenant(r.Context(), who.Store.Tenant())
	if err != nil {
		slog.Error("could not read the tenant's approval mode", "error", err, "tenant", who.Store.Tenant())
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tenant")
		return
	}
	destructive := spec.Class == intent.ClassDestructive

	record := store.NewJob{
		Job:                      job,
		HostID:                   req.HostID,
		CreatedBy:                who.Principal(),
		ApprovalRequired:         destructive && tenant.ApprovalMode.RequiresApproval(),
		ApprovalDistinctOperator: destructive && tenant.ApprovalMode.RequiresDistinctOperator(),
	}
	switch err := who.Store.CreateJob(r.Context(), record); {
	case errors.Is(err, store.ErrConflict):
		// Two different uniqueness rules reach here and they are not the same news. The job id is the
		// primary key within this tenant; (host_id, nonce) is per host. Both are this tenant's own —
		// a job id another customer chose is not a collision and is not mentioned, because saying so
		// would tell one customer what another had queued.
		writeError(w, http.StatusConflict, "duplicate",
			"this job was not queued: either its id is already in use in this fleet, or this host has "+
				"already been sent a job with this nonce")
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_host", "no such host")
		return
	case err != nil:
		slog.Error("could not create a job", "error", err, "host", req.HostID)
		writeError(w, http.StatusInternalServerError, "internal", "could not create the job")
		return
	}

	slog.Info("job created",
		"job", job.ID, "tenant", who.Store.Tenant(), "host", req.HostID,
		"intent", job.Intent, "class", job.Class,
		"params", params.Describe(), "operator", who.Principal(),
		"signed", job.Signature != "", "signer", job.SignerKeyID,
		"approval_required", record.ApprovalRequired,
		"approval_distinct_operator", record.ApprovalDistinctOperator)

	s.emit(r.Context(), who.Store.Tenant(), notify.Event{
		Kind: "job.created", HostID: req.HostID, Hostname: host.Hostname, At: job.IssuedAt,
		Summary: params.Describe() + " queued for " + host.Hostname + " by " + who.Principal(),
		Detail: map[string]any{
			"jobId": job.ID, "intent": job.Intent, "class": job.Class,
			"approvalRequired": record.ApprovalRequired, "signerKeyId": job.SignerKeyID,
		},
	})

	stored, err := who.Store.GetJob(r.Context(), job.ID)
	if err != nil {
		slog.Error("could not read back a created job", "error", err, "job", job.ID)
		writeError(w, http.StatusInternalServerError, "internal", "the job was created but not readable")
		return
	}
	writeJSON(w, http.StatusCreated, toJobView(stored))
}

// validateJobRequest checks a request against the catalogue and the class rules, or writes the refusal.
//
// Every refusal here is one the agent would also make on the host. Making them at creation is not a
// second line of defence — the host's checks are the ones the guarantee rests on — it is so that an
// operator learns immediately rather than by reading a failed job result twenty-five seconds later.
func (s *Server) validateJobRequest(w http.ResponseWriter, req jobRequest) (intent.Spec, intent.Params, error) {
	refuse := func(status int, code, message string) (intent.Spec, intent.Params, error) {
		writeError(w, status, code, message)
		return intent.Spec{}, nil, errors.New(code)
	}

	if req.HostID == "" {
		return refuse(http.StatusBadRequest, "malformed", "hostId is required")
	}

	rawParams, err := json.Marshal(req.Params)
	if err != nil {
		return refuse(http.StatusBadRequest, "malformed", "the parameters could not be re-encoded")
	}
	spec, params, err := intent.Decode(intent.Name(req.Intent), rawParams)
	if err != nil {
		// One message for an unknown intent and for bad parameters, both naming the cause. The
		// catalogue is public — it is served from /api/v1/catalogue — so there is nothing to withhold.
		return refuse(http.StatusBadRequest, "unsupported_intent", err.Error())
	}

	switch spec.Class {
	case intent.ClassRoutine:
		// The one class this control plane signs itself. docs/PROTOCOL.md §5.1 requires a signature by
		// the control plane's online key, and this side supplies it — so a caller sends none, exactly
		// as for a read intent, and everything the signature covers is chosen here.
		if s.cfg.OnlineKey == nil {
			return refuse(http.StatusNotImplemented, "no_online_key",
				spec.Name.String()+" is a routine intent, which requires a signature by this control "+
					"plane's online key. This control plane has none, and an agent refuses a routine "+
					"intent until it can verify one. See docs/PROTOCOL.md §5.1.")
		}
		if req.Signature != "" || req.SignerKeyID != "" || req.Nonce != "" || req.ID != "" {
			return refuse(http.StatusBadRequest, "malformed",
				spec.Name.String()+" is signed by this control plane, not by you. It takes no "+
					"signature, no nonce and no caller-chosen id: an agent verifies it against the "+
					"online key it was given, and a signature from anywhere else would not verify.")
		}

	case intent.ClassDestructive:
		if req.Signature == "" || req.SignerKeyID == "" || req.SignerAlgorithm == "" {
			return refuse(http.StatusBadRequest, "unsigned",
				spec.Name.String()+" is destructive and requires a signature from a key in the host's "+
					"own trusted-signers, which this control plane does not hold. Sign the request "+
					"offline and send the signature with it.")
		}
		if req.ID == "" || req.Nonce == "" || req.NotBefore.IsZero() || req.NotAfter.IsZero() {
			return refuse(http.StatusBadRequest, "malformed",
				"a signed job must carry its id, nonce, notBefore and notAfter: all four are covered "+
					"by the signature, so a value chosen here would invalidate it")
		}
		// The id is the signer's, but it is not arbitrary. It becomes a path segment in the result POST
		// and a filename in the agent's spool, so an id carrying a slash produces a job whose result the
		// host can never deliver — and the shape has to be refused here rather than corrected, because
		// the signature covers it and a normalised id would simply stop verifying.
		if !protocol.ValidJobID(req.ID) {
			return refuse(http.StatusBadRequest, "malformed",
				"the job id must be "+protocol.JobIDShape+": it is a path segment in the result "+
					"endpoint and a filename in the agent's spool, and a host refuses any other shape. "+
					"Sign a different id rather than expecting this one to be corrected.")
		}
		if !req.NotAfter.After(req.NotBefore) {
			return refuse(http.StatusBadRequest, "malformed", "notAfter must be after notBefore")
		}

	default:
		if req.Signature != "" || req.SignerKeyID != "" || req.Nonce != "" || req.ID != "" {
			// A read intent's signature is verified by nothing: mTLS is the whole authorisation, and
			// the agent does not look at one. Storing it would put a value on a dashboard that means
			// less than it appears to.
			return refuse(http.StatusBadRequest, "malformed",
				spec.Name.String()+" is read-only and is authorised by mTLS alone. It takes no "+
					"signature, no nonce and no caller-chosen id, and an agent verifies none of them.")
		}
	}

	if !spec.Implemented {
		return refuse(http.StatusNotImplemented, "unsupported_intent",
			spec.Name.String()+" has no executor on any agent in this release, so a host would refuse "+
				"it. See internal/intent for why.")
	}
	return spec, params, nil
}

// buildJob assembles the wire job from a validated request.
//
// A signed job is copied through unchanged, field for field. Everything the signature covers must reach
// the host exactly as the signer wrote it, so this function has no opinion about any of it — the moment
// it adjusted a timestamp or normalised a nonce, every signature would stop verifying and the failure
// would look like a broken key.
func (s *Server) buildJob(req jobRequest, spec intent.Spec, hostID string) (protocol.Job, error) {
	job := protocol.Job{
		ID:              req.ID,
		Intent:          spec.Name.String(),
		Params:          req.Params,
		Class:           string(spec.Class),
		IssuedAt:        time.Now().UTC(),
		NotBefore:       req.NotBefore,
		NotAfter:        req.NotAfter,
		Nonce:           req.Nonce,
		Signature:       req.Signature,
		SignerKeyID:     req.SignerKeyID,
		SignerAlgorithm: req.SignerAlgorithm,
	}
	if job.Params == nil {
		job.Params = map[string]any{}
	}
	if job.Signature != "" {
		return job, nil
	}

	// Unsigned, so every field the signature would have fixed is this side's to choose.
	id, err := NewID()
	if err != nil {
		return protocol.Job{}, err
	}
	nonce, err := NewID()
	if err != nil {
		return protocol.Job{}, err
	}
	job.ID = id
	// A nonce nothing checks, so that the column can stay NOT NULL and a future signed intent cannot
	// find the constraint missing when it needs it.
	job.Nonce = nonce

	// No lower bound at all, and this is the one line here worth arguing about.
	//
	// The obvious value is "now", and it is wrong. An agent checks the window against its *own* clock —
	// it must, or a compromised control plane could extend a signature's validity by lying about the
	// time — so a host whose clock is a second behind the control plane's would find a job whose window
	// had not opened yet and report it expired. Read intents deliberately skip the clock-skew check, so
	// nothing else would catch it, and the result is that every on-demand report fails on exactly the
	// host whose clock is wrong: the one an operator most wants to look at.
	//
	// Nothing signed this job, so there is no authorisation whose start needs pinning. notAfter still
	// bounds it, and a zero notBefore is what the agent's own check reads as "no lower bound".
	job.NotBefore = time.Time{}
	job.NotAfter = job.IssuedAt.Add(ReadJobValidity)

	if spec.Class == intent.ClassRoutine {
		return s.signRoutine(job, hostID)
	}
	return job, nil
}

// RoutineJobValidity is how long a routine job stays executable after the control plane signs it.
//
// Shorter than a read job's day, because this one does something. A security update that an operator
// asked for this morning is worth applying when a host comes back this afternoon; one from last week
// is a surprise, and the host's own timer will have applied it anyway.
const RoutineJobValidity = 6 * time.Hour

// signRoutine signs a routine job with the control plane's own key.
//
// The window is the interesting part. notBefore is covered by the signature and is therefore what the
// agent measures a job's age from, so it cannot be left at zero — an age measured from the year 1 is an
// age past every limit. But it also cannot be exactly now: the agent checks the window against its own
// clock, so a host a second behind would find a job whose window had not opened and report it expired.
//
// So it opens as early as the clock skew the agent would still tolerate for a privileged intent.
// Beyond that the agent refuses on skew rather than on the window, which is the refusal that names the
// real problem — and inside it, a host with an ordinary few seconds of drift simply runs the job.
func (s *Server) signRoutine(job protocol.Job, hostID string) (protocol.Job, error) {
	now := job.IssuedAt
	job.NotBefore = now.Add(-protocol.MaxClockSkewSeconds * time.Second)
	job.NotAfter = now.Add(RoutineJobValidity)

	payload, err := canonical.Marshal(job.SignedPayload(hostID))
	if err != nil {
		return protocol.Job{}, fmt.Errorf("canonicalising a routine job: %w", err)
	}
	signature, err := s.cfg.OnlineKey.Sign(context.Background(), payload)
	if err != nil {
		return protocol.Job{}, fmt.Errorf("signing a routine job: %w", err)
	}

	job.Signature = base64.StdEncoding.EncodeToString(signature)
	job.SignerKeyID = s.cfg.OnlineKey.KeyID()
	job.SignerAlgorithm = string(s.cfg.OnlineKey.Algorithm())
	return job, nil
}

// handleApproveJob records an operator's release of a job.
//
// Whether the releaser may be the creator is a property of the job, stamped from the tenant's approval
// mode when it was created. Which rule applies is therefore fixed at creation and cannot be changed by
// editing the tenant afterwards.
//
// Whichever rule it is, it is enforced in the store, in the statement that does the update, and not
// here. This handler reads the row first only to say *why* an approval was refused; if it decided, two
// requests arriving together would let one operator release their own job by racing it against itself.
func (s *Server) handleApproveJob(w http.ResponseWriter, r *http.Request, who operator) {
	jobID := r.PathValue("id")

	before, err := who.Store.GetJob(r.Context(), jobID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_job", "no such job")
		return
	case err != nil:
		slog.Error("could not read a job", "error", err, "job", jobID)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the job")
		return
	}

	switch {
	case !before.ApprovalRequired:
		writeError(w, http.StatusConflict, "no_approval_required",
			"this job needs no approval; recording one would put a name in the audit log beside a "+
				"decision nobody made")
		return
	case !before.ApprovedAt.IsZero():
		writeError(w, http.StatusConflict, "already_approved",
			"this job was already approved by "+before.ApprovedBy)
		return
	case before.ApprovalDistinctOperator && before.CreatedBy == who.Principal():
		writeError(w, http.StatusConflict, "self_approval",
			"this fleet requires a second person to release a destructive job, and this credential "+
				"created it. An operator working alone can set the fleet's approval mode to \"self\" "+
				"or \"none\" instead; see docs/SECURITY.md §3.")
		return
	}

	if err := who.Store.ApproveJob(r.Context(), jobID, who.Principal(), time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			// The row moved between the read above and the update. The store refused, which is the
			// answer; this is only the message.
			writeError(w, http.StatusConflict, "not_approvable",
				"this job is no longer waiting for approval")
			return
		}
		slog.Error("could not approve a job", "error", err, "job", jobID)
		writeError(w, http.StatusInternalServerError, "internal", "could not approve the job")
		return
	}

	slog.Info("job approved",
		"job", jobID, "tenant", who.Store.Tenant(), "host", before.HostID,
		"intent", before.Job.Intent,
		"created_by", before.CreatedBy, "approved_by", who.Principal())

	s.emit(r.Context(), who.Store.Tenant(), notify.Event{
		Kind: "job.approved", HostID: before.HostID, At: time.Now().UTC(),
		Summary: before.Job.Intent + " on " + before.HostID + " approved by " + who.Principal() +
			", created by " + before.CreatedBy,
		Detail: map[string]any{"jobId": jobID, "intent": before.Job.Intent},
	})

	after, err := who.Store.GetJob(r.Context(), jobID)
	if err != nil {
		slog.Error("could not read back an approved job", "error", err, "job", jobID)
		writeError(w, http.StatusInternalServerError, "internal", "the job was approved but not readable")
		return
	}
	writeJSON(w, http.StatusOK, toJobView(after))
}

// handleListJobs returns recent jobs, newest first, optionally for one host.
//
// The listing is bounded, and the response says so when the bound bit. A page that silently returns the
// newest hundred reads as the whole truth, and the row it is most likely to be hiding is a destructive
// job nobody has approved yet — the one thing docs/SECURITY.md §3 needs a second person to be able to
// find. Hence both the disclosure and the awaiting filter, which is not subject to the same drift.
func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request, who operator) {
	query := r.URL.Query()
	limit, err := jobLimit(query.Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}

	filter := store.JobFilter{
		HostID:           query.Get("host"),
		Limit:            limit,
		AwaitingApproval: query.Get("awaiting") == "true",
	}

	records, err := who.Store.ListJobs(r.Context(), filter)
	if err != nil {
		slog.Error("could not list jobs", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the job list")
		return
	}

	views := make([]jobView, 0, len(records))
	for _, rec := range records {
		views = append(views, toJobView(rec))
	}
	effective := filter.Limit
	if effective <= 0 {
		effective = store.DefaultJobLimit
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"jobs":     views,
		"limit":    effective,
		"maxLimit": store.MaxJobLimit,
		// True when the listing filled its bound, so there may be older jobs it did not return. It is
		// reported rather than inferred from len(jobs) == limit, because a client that has to work that
		// out for itself is a client that will not.
		"truncated": len(views) >= effective,
		// The control plane's clock, for the same reason /api/v1/hosts sends it: ages on this page are
		// decision inputs — "asked 4h ago" is why a second operator releases or investigates — and a
		// browser's clock is nobody's authority on anything.
		"serverTime": time.Now().UTC(),
	})
}

// jobLimit reads the listing bound from the query string.
//
// An unparseable or out-of-range value is refused rather than quietly replaced by the default: a
// caller who asked for a thousand and silently got a hundred draws exactly the wrong conclusion from a
// short list.
func jobLimit(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("limit must be a whole number")
	}
	if n < 1 || n > store.MaxJobLimit {
		return 0, fmt.Errorf("limit must be between 1 and %d", store.MaxJobLimit)
	}
	return n, nil
}

// handleGetJob returns one job and its result.
func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request, who operator) {
	rec, err := who.Store.GetJob(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_job", "no such job")
		return
	case err != nil:
		slog.Error("could not read a job", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the job")
		return
	}
	writeJSON(w, http.StatusOK, toJobView(rec))
}

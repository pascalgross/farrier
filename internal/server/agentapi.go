package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/pegasusnetworks/farrier/internal/canonical"
	"github.com/pegasusnetworks/farrier/internal/notify"
	"github.com/pegasusnetworks/farrier/internal/protocol"
	"github.com/pegasusnetworks/farrier/internal/store"
)

// handleEnroll exchanges a bootstrap token and a CSR for a host-scoped client certificate.
//
// It is the only endpoint that does not require a client certificate, because a host enrolling does not
// have one yet. Everything that makes it safe is therefore in the token: single-use, time-limited,
// consumed atomically, and stored only as a hash.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	// The only endpoint reachable without a client certificate, and therefore the only one worth rate
	// limiting. A token is 256 bits of uniform randomness, so this defends against the load of guessing
	// rather than against its success — and against a misconfigured provisioning loop, which is the
	// case that actually happens.
	if !s.enrolLimiter.allow(requestSource(r), time.Now()) {
		w.Header().Set("Retry-After", strconv.Itoa(int(s.enrolLimiter.retryAfter().Seconds())))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many enrolment attempts")
		return
	}

	var req protocol.EnrollRequest
	if err := decodeJSON(w, r, protocol.MaxEnrollBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		return
	}
	if req.Token == "" || req.CSR == "" {
		writeError(w, http.StatusBadRequest, "malformed", "token and csr are both required")
		return
	}

	// The machine-id check comes before the token is consumed, so that a host retrying an enrolment it
	// has already completed does not burn a second token in the process of being told no.
	if req.MachineIDHash != "" {
		existing, err := s.cfg.Store.GetHostByMachineID(r.Context(), req.MachineIDHash)
		switch {
		case err == nil:
			writeError(w, http.StatusConflict, "already_enrolled",
				"a host with this machine id is already enrolled as "+existing.ID)
			return
		case !errors.Is(err, store.ErrNotFound):
			slog.Error("machine id lookup failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "could not check for an existing host")
			return
		}
	}

	hostID, err := NewID()
	if err != nil {
		slog.Error("could not generate a host id", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not allocate a host id")
		return
	}

	// The certificate request is checked before the token is consumed. A token is single-use, so a
	// malformed CSR would otherwise burn one and leave an operator to work out why their second attempt
	// says the token is unusable — which reads exactly like the token having been stolen.
	if _, _, err := s.cfg.Authority.Issue([]byte(req.CSR), hostID); err != nil {
		slog.Warn("rejected a certificate request before consuming the token", "error", err)
		writeError(w, http.StatusBadRequest, "bad_csr", "the certificate request could not be signed")
		return
	}

	now := time.Now()
	token, err := s.cfg.Store.ConsumeEnrollmentToken(r.Context(), HashToken(req.Token), hostID, now)
	if errors.Is(err, store.ErrTokenUnusable) {
		// Unknown, expired and already used are one response. Telling an attacker which of the three
		// applies is free reconnaissance.
		writeError(w, http.StatusUnauthorized, "token_unusable", "the enrolment token cannot be used")
		return
	}
	if err != nil {
		slog.Error("could not consume an enrolment token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not redeem the token")
		return
	}

	host := store.Host{
		ID:            hostID,
		Hostname:      req.Hostname,
		MachineIDHash: req.MachineIDHash,
		Group:         token.Group,
		AgentVersion:  req.AgentVersion,
		EnrolledAt:    now,
	}
	if err := s.cfg.Store.CreateHost(r.Context(), host); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "already_enrolled", "this host is already enrolled")
			return
		}
		slog.Error("could not create a host", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the host")
		return
	}

	certPEM, cert, err := s.cfg.Authority.Issue([]byte(req.CSR), hostID)
	if err != nil {
		slog.Warn("rejected a certificate request", "error", err, "host", hostID)
		writeError(w, http.StatusBadRequest, "bad_csr", "the certificate request could not be signed")
		return
	}
	if err := s.cfg.Store.AddCertificate(r.Context(), store.Certificate{
		Fingerprint: Fingerprint(cert),
		HostID:      hostID,
		Serial:      cert.SerialNumber.Text(16),
		IssuedAt:    now,
		NotAfter:    cert.NotAfter,
	}); err != nil {
		slog.Error("could not record a certificate", "error", err, "host", hostID)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the certificate")
		return
	}

	slog.Info("host enrolled",
		"host", hostID, "hostname", req.Hostname, "group", token.Group,
		"agent_version", req.AgentVersion, "token_label", token.Label)
	s.emit(r.Context(), notify.Event{
		Kind: "host.enrolled", HostID: hostID, Hostname: req.Hostname, At: now,
		Summary: req.Hostname + " enrolled into group " + token.Group,
	})

	// Phase 0 issues no bootstrap templates: Tier 1 provisioning renders cloud-init for a human or for
	// Terraform and never delivers it to a host, and Tier 2 arrives in phase 3 with every guardrail in
	// docs/SECURITY.md §6. A request for one is refused rather than ignored, because an agent that
	// asked for a template and silently received none would proceed as though it had been applied.
	if req.RequestedBootstrap != "" {
		slog.Warn("a bootstrap template was requested and this build issues none",
			"host", hostID, "template", req.RequestedBootstrap)
	}

	writeJSON(w, http.StatusOK, protocol.EnrollResponse{
		HostID:               hostID,
		Certificate:          string(certPEM),
		CABundle:             string(s.cfg.Authority.CertificatePEM()),
		ServerTime:           now.UTC(),
		NextHeartbeatSeconds: s.cfg.HeartbeatSeconds,
	})
}

// handleHeartbeat records a host's state and decides what to ask for next.
//
// The digest comparison here is the entire digest-first design. Five hundred hosts sending a full
// inventory every sixty seconds is hundreds of kilobytes per host per minute of write amplification;
// comparing a digest instead makes the steady state hundreds of bytes and full reports rare and
// event-driven.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, host store.Host) {
	var req protocol.HeartbeatRequest
	if err := decodeJSON(w, r, protocol.MaxHeartbeatBytes, &req); err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large",
				"the heartbeat body exceeded the limit; truncate a section and set its truncated flag")
			return
		}
		writeError(w, http.StatusBadRequest, "malformed", "the heartbeat body could not be read")
		return
	}

	now := time.Now()
	if err := s.cfg.Store.RecordHeartbeat(r.Context(), host.ID, store.HeartbeatUpdate{
		AgentVersion:       req.AgentVersion,
		BootID:             req.BootID,
		UptimeSeconds:      req.UptimeSeconds,
		ClockOffsetSeconds: req.ClockOffsetSeconds,
		Paused:             req.Paused,
		LastSeen:           now,
	}); err != nil {
		slog.Error("could not record a heartbeat", "error", err, "host", host.ID)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the heartbeat")
		return
	}

	s.storeDocumentIfPresent(r.Context(), host.ID, "facts", req.Facts, req.FactsDigest)
	s.storeDocumentIfPresent(r.Context(), host.ID, "policy", req.Policy, req.PolicyDigest)
	// req.Signers != nil rather than len() > 0: an empty trust anchor is a real answer and the default
	// one, and treating it as "not reported" would make the server ask for it forever.
	if req.Signers != nil {
		s.storeDocumentIfPresent(r.Context(), host.ID, "signers", req.Signers, req.SignersDigest)
	}

	// host carries the digests of the documents the server actually holds, read before this beat was
	// applied; the store never records a digest a host merely claimed. A mismatch therefore means "I do
	// not have this document", and it keeps meaning that until one arrives — which is what makes a lost
	// full report recoverable rather than permanent. Recording the claim instead would make the server
	// ask exactly once, and if that one report were lost to a network failure it would compare the next
	// heartbeat against its own stored claim, conclude it was up to date, and never ask again.
	wantFacts := req.FactsDigest != "" && req.FactsDigest != host.FactsDigest && req.Facts == nil
	wantPolicy := req.PolicyDigest != "" && req.PolicyDigest != host.PolicyDigest && req.Policy == nil
	wantSigners := req.SignersDigest != "" && req.SignersDigest != host.SignersDigest && req.Signers == nil

	if req.ClockOffsetSeconds > protocol.MaxClockSkewSeconds ||
		req.ClockOffsetSeconds < -protocol.MaxClockSkewSeconds {
		// Logged rather than acted on. The host has already decided to refuse privileged intents; the
		// server's job is to make the reason visible before somebody spends an afternoon on it.
		slog.Warn("host clock is far from the control plane's",
			"host", host.ID, "hostname", host.Hostname, "offset_seconds", req.ClockOffsetSeconds)
	}

	writeJSON(w, http.StatusOK, protocol.HeartbeatResponse{
		ServerTime:           now.UTC(),
		NextHeartbeatSeconds: s.cfg.HeartbeatSeconds,
		WantFullReport:       wantFacts && wantPolicy,
		WantFacts:            wantFacts,
		WantPolicy:           wantPolicy,
		WantSigners:          wantSigners,
	})
}

// storeDocumentIfPresent persists one full document from a heartbeat, if it carried one.
//
// The digest is recomputed from the document rather than taken from the request. A host whose reported
// digest did not match what it sent would otherwise poison the comparison for every future beat: the
// server would believe it held something it did not, and would stop asking for the real thing.
func (s *Server) storeDocumentIfPresent(ctx context.Context, hostID, kind string, document any, claimed string) {
	if document == nil {
		return
	}
	encoded, err := canonical.Marshal(document)
	if err != nil {
		slog.Warn("could not canonicalise a reported document", "kind", kind, "host", hostID, "error", err)
		return
	}
	actual := canonical.DigestBytes(encoded)
	if claimed != "" && claimed != actual {
		slog.Warn("a host reported a digest that does not match the document it sent",
			"kind", kind, "host", hostID, "claimed", claimed, "actual", actual)
	}

	var storeFn func(context.Context, string, string, []byte) error
	switch kind {
	case "facts":
		storeFn = s.cfg.Store.StoreFacts
	case "policy":
		storeFn = s.cfg.Store.StorePolicy
	case "signers":
		storeFn = s.cfg.Store.StoreSigners
	default:
		return
	}
	if err := storeFn(ctx, hostID, actual, encoded); err != nil {
		slog.Error("could not store a reported document", "kind", kind, "host", hostID, "error", err)
	}
}

// handleJobs is the long-poll that delivers work.
//
// The hold defaults to twenty-five seconds and is clamped to sixty. It must sit below the smallest idle
// timeout on the path — thirty to sixty seconds is the common default for proxies, load balancers and
// NAT tables — because a hold longer than that produces intermittent failures that look like network
// flakiness and get debugged as such for weeks. wait=0 degrades to plain polling, for environments that
// terminate held connections regardless.
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request, host store.Host) {
	wait := protocol.DefaultJobWaitSeconds
	if raw := r.URL.Query().Get("wait"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "malformed", "wait must be an integer number of seconds")
			return
		}
		wait = min(max(n, 0), protocol.MaxJobWaitSeconds)
	}

	// Subscribed before the queue is read, not after. The other order leaves a gap in which a job
	// inserted between the empty read and the subscription fires its notification with nobody
	// listening — and the agent then holds its long-poll for the full twenty-five seconds over work
	// that was already waiting. The consequence is only latency, which is precisely why nobody would
	// ever diagnose it.
	notified, unsubscribe := s.cfg.Store.Subscribe(host.ID)
	defer unsubscribe()

	jobs, err := s.cfg.Store.ClaimJobs(r.Context(), host.ID, 10)
	if err != nil {
		slog.Error("could not claim jobs", "error", err, "host", host.ID)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the job queue")
		return
	}
	if len(jobs) > 0 || wait == 0 {
		writeJSON(w, http.StatusOK, protocol.JobsResponse{Jobs: nonNil(jobs)})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(wait)*time.Second)
	defer cancel()

	// A wake-up may be spurious — the store says so — so the queue is re-read rather than trusted.
	// Returning an empty list after a spurious wake is correct and costs the agent one round trip.
	select {
	case <-notified:
		jobs, err = s.cfg.Store.ClaimJobs(r.Context(), host.ID, 10)
		if err != nil {
			slog.Error("could not claim jobs after a wake-up", "error", err, "host", host.ID)
			writeError(w, http.StatusInternalServerError, "internal", "could not read the job queue")
			return
		}
	case <-ctx.Done():
	}
	writeJSON(w, http.StatusOK, protocol.JobsResponse{Jobs: nonNil(jobs)})
}

// nonNil returns an empty slice rather than nil, so the JSON is [] and never null.
//
// A client that has to handle both is a client with a branch nobody tests, and docs/PROTOCOL.md shows
// an empty array.
func nonNil(jobs []protocol.Job) []protocol.Job {
	if jobs == nil {
		return []protocol.Job{}
	}
	return jobs
}

// handleResult records a job result idempotently.
//
// The agent retries until it receives a 2xx, and a repeated result for a job that already has one
// returns 200 and changes nothing. Work that succeeded but whose result was lost must never re-execute:
// that is how a retry turns one reboot into a reboot loop.
func (s *Server) handleResult(w http.ResponseWriter, r *http.Request, host store.Host) {
	jobID := r.PathValue("id")
	if jobID == "" {
		writeError(w, http.StatusBadRequest, "malformed", "the job id is missing from the path")
		return
	}

	var req protocol.ResultRequest
	if err := decodeJSON(w, r, protocol.MaxResultBytes, &req); err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large",
				"the result body exceeded the limit; output is truncated to its last 64 KiB")
			return
		}
		writeError(w, http.StatusBadRequest, "malformed", "the result body could not be read")
		return
	}
	if req.JobID != "" && req.JobID != jobID {
		writeError(w, http.StatusBadRequest, "malformed", "the job id in the body does not match the path")
		return
	}
	req.JobID = jobID
	req.Output, req.OutputTruncated = protocol.TruncateOutput(req.Output)

	switch err := s.cfg.Store.RecordResult(r.Context(), host.ID, req); {
	case errors.Is(err, store.ErrNotFound):
		// Either the job never existed or it belongs to a different host. The two are one response, as
		// everywhere else: distinguishing them would let an enrolled host enumerate other hosts' jobs.
		slog.Warn("a host reported a result for a job that is not its own",
			"host", host.ID, "job", jobID)
		writeError(w, http.StatusNotFound, "unknown_job", "no such job for this host")
		return
	case err != nil:
		slog.Error("could not record a job result", "error", err, "host", host.ID, "job", jobID)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the result")
		return
	}

	slog.Info("job result recorded",
		"host", host.ID, "job", jobID, "status", req.Status, "exit_code", req.ExitCode)
	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

// handleRenew issues a fresh certificate for an already-authenticated host.
//
// The identity comes from the presenting certificate and never from the CSR. A CSR is an untrusted
// document: honouring the subject in it would let a host re-key a certificate for a different host
// entirely, which is a full compromise of the fleet's identity from one enrolled machine.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request, host store.Host) {
	var req protocol.RenewRequest
	if err := decodeJSON(w, r, protocol.MaxEnrollBytes, &req); err != nil || req.CSR == "" {
		writeError(w, http.StatusBadRequest, "malformed", "a csr is required")
		return
	}

	certPEM, cert, err := s.cfg.Authority.Issue([]byte(req.CSR), host.ID)
	if err != nil {
		slog.Warn("rejected a renewal request", "error", err, "host", host.ID)
		writeError(w, http.StatusBadRequest, "bad_csr", "the certificate request could not be signed")
		return
	}
	if err := s.cfg.Store.AddCertificate(r.Context(), store.Certificate{
		Fingerprint: Fingerprint(cert),
		HostID:      host.ID,
		Serial:      cert.SerialNumber.Text(16),
		IssuedAt:    time.Now(),
		NotAfter:    cert.NotAfter,
	}); err != nil {
		slog.Error("could not record a renewed certificate", "error", err, "host", host.ID)
		writeError(w, http.StatusInternalServerError, "internal", "could not record the certificate")
		return
	}

	slog.Info("certificate renewed", "host", host.ID, "not_after", cert.NotAfter.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, protocol.RenewResponse{
		Certificate: string(certPEM),
		CABundle:    string(s.cfg.Authority.CertificatePEM()),
		NotAfter:    cert.NotAfter,
	})
}

// emit delivers an event to every configured sink.
//
// Failures are logged and never propagated: a webhook endpoint being down must not fail an enrolment.
// Delivery is synchronous with a short deadline rather than fire-and-forget, so that a request cannot
// outlive the goroutine reporting on it and lose the log line.
func (s *Server) emit(ctx context.Context, ev notify.Event) {
	if len(s.cfg.Sinks) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()

	for _, sink := range s.cfg.Sinks {
		if err := sink.Deliver(ctx, ev); err != nil {
			slog.Warn("event delivery failed", "sink", sink.Name(), "kind", ev.Kind, "error", err)
		}
	}
}

// jsonOrNull returns raw JSON bytes, or the literal null, for embedding a stored document in a response.
//
// Stored documents are already JSON, so re-encoding them would double-escape. A host that has never
// sent one has an empty column, and the API renders that as null rather than as an empty string, so a
// client can tell "not reported yet" from "reported as empty".
func jsonOrNull(raw []byte) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return json.RawMessage(raw)
}

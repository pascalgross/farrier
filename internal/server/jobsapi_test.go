package server_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/agent"
	"github.com/pascalgross/farrier/internal/canonical"
	"github.com/pascalgross/farrier/internal/policy"
	"github.com/pascalgross/farrier/internal/privsep"
	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/server"
	"github.com/pascalgross/farrier/internal/signing"
	"github.com/pascalgross/farrier/internal/signing/backend/file"
)

// adminJSON performs an administrative API call as one of the two operators and returns the response.
//
// The body is returned as bytes rather than decoded, because several of these assertions are about the
// error document and one is about the status alone.
func (h *harness) adminJSON(t *testing.T, token, method, path string, body any) (int, []byte) {
	t.Helper()

	var payload []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding a request body: %v", err)
		}
		payload = encoded
	}

	req, err := http.NewRequest(method, h.server.URL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	res, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()

	decoded, err := readAll(res)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	return res.StatusCode, decoded
}

// readAll reads a response body in full.
func readAll(res *http.Response) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// jobViewOf decodes a job document from an API response.
func jobViewOf(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var view map[string]any
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decoding a job document from %s: %v", raw, err)
	}
	return view
}

// TestAReadJobReachesTheHostAndComesBackWithItsResult is the path that had no producer at all.
//
// The jobs table and the delivery path were built and tested a phase before anything created a job, so
// until now no job of any class reached a host from the server side — not a reboot, and not a facts
// collection either. This is that end to end: an operator asks, an agent claims, an agent reports, and
// the operator reads the answer.
func TestAReadJobReachesTheHostAndComesBackWithItsResult(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
		"hostId": state.HostID,
		"intent": "facts.collect",
		"params": map[string]any{},
	})
	if status != http.StatusCreated {
		t.Fatalf("creating a read job returned %d: %s", status, body)
	}
	created := jobViewOf(t, body)
	jobID, _ := created["id"].(string)
	if jobID == "" {
		t.Fatalf("the created job has no id: %s", body)
	}
	if created["state"] != "queued" {
		t.Errorf("a read job starts in state %v, want queued", created["state"])
	}
	if created["approvalRequired"] != false {
		t.Error("a read job requires approval; only the destructive tier does")
	}
	if created["createdBy"] != "tester" {
		t.Errorf("the job records its creator as %v, want tester", created["createdBy"])
	}

	client := h.agentClient(t, state)
	jobs, err := client.PollJobs(context.Background(), 0)
	if err != nil {
		t.Fatalf("polling for jobs: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != jobID {
		t.Fatalf("the agent claimed %+v", jobs)
	}
	if jobs[0].Intent != "facts.collect" {
		t.Errorf("the agent was asked for %q", jobs[0].Intent)
	}
	if jobs[0].NotAfter.Before(time.Now()) {
		t.Error("a freshly created read job is already outside its validity window")
	}

	if err := client.ReportResult(context.Background(), protocol.ResultRequest{
		JobID: jobID, Status: protocol.StatusSucceeded,
		StartedAt: time.Now(), FinishedAt: time.Now(), Output: "collected",
	}); err != nil {
		t.Fatalf("reporting a result: %v", err)
	}

	status, body = h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/jobs/"+jobID, nil)
	if status != http.StatusOK {
		t.Fatalf("reading the job back returned %d: %s", status, body)
	}
	final := jobViewOf(t, body)
	if final["state"] != protocol.StatusSucceeded {
		t.Errorf("the job ended in state %v, want %q", final["state"], protocol.StatusSucceeded)
	}
	result, ok := final["result"].(map[string]any)
	if !ok || result["output"] != "collected" {
		t.Errorf("the job carries result %v", final["result"])
	}
}

// TestGuaranteeTheRoutineTierCannotBeQueued is the online key, refused at the door.
//
// packages.applySecurity is the one routine intent, and routine is the tier for which no offline
// signature is required — so an agent that ran one without verifying the control plane's online key
// would be acting on mTLS alone. There is no online key, the agent refuses one, and queueing it here
// would produce a job that failed on every host in the fleet with a message about a key nobody has.
func TestGuaranteeTheRoutineTierCannotBeQueued(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
		"hostId": state.HostID,
		"intent": "packages.applySecurity",
		"params": map[string]any{},
	})
	if status != http.StatusNotImplemented {
		t.Fatalf("queueing a routine intent returned %d, want 501: %s", status, body)
	}
	if !bytes.Contains(body, []byte("online key")) {
		t.Errorf("the refusal does not name the online key: %s", body)
	}
}

// TestGuaranteeADestructiveJobWithoutASignatureIsRefused keeps the control plane out of the trust path.
//
// The signature comes from a key this control plane does not hold, which is the whole of the third
// mechanism. Refusing here is not what makes that true — the host is what verifies — but a job queued
// without one would be delivered, refused on the host, and reported as a failure twenty-five seconds
// later, which teaches an operator nothing except to distrust the dashboard.
func TestGuaranteeADestructiveJobWithoutASignatureIsRefused(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	for _, name := range []string{"host.reboot", "service.restart", "packages.applyAll"} {
		params := map[string]any{}
		if name == "service.restart" {
			params["unit"] = "nginx.service"
		}
		status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
			"hostId": state.HostID, "intent": name, "params": params,
		})
		if status != http.StatusBadRequest {
			t.Errorf("queueing an unsigned %s returned %d, want 400: %s", name, status, body)
		}
		if !bytes.Contains(body, []byte("trusted-signers")) {
			t.Errorf("the refusal of %s does not say where the signature must come from: %s", name, body)
		}
	}

	listed := h.jobs(t)
	if len(listed) != 0 {
		t.Errorf("%d unsigned destructive jobs were queued anyway", len(listed))
	}
}

// jobs returns every job the control plane holds, for assertions about what was queued.
func (h *harness) jobs(t *testing.T) []any {
	t.Helper()
	status, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/jobs", nil)
	if status != http.StatusOK {
		t.Fatalf("listing jobs returned %d: %s", status, body)
	}
	var listing struct {
		Jobs []any `json:"jobs"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decoding the job list: %v", err)
	}
	return listing.Jobs
}

// signedRebootRequest builds a host.reboot request signed by a freshly generated key.
//
// The payload is built with protocol.Job.SignedPayload and canonical.Marshal — the same two functions
// the agent uses to verify — because the point of the test below is that what the control plane stores
// is byte-for-byte what the host will check. A test that assembled the payload by hand would prove the
// test author and the agent agreed, which is not the property that matters.
func signedRebootRequest(t *testing.T, hostID string) (map[string]any, *signing.SignerSet) {
	t.Helper()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ops.key")
	signer, err := file.Generate(keyPath, "ops-laptop", signing.Ed25519, []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}
	t.Cleanup(func() { _ = signer.Close() })

	line, err := signing.TrustedSignerLine(signer)
	if err != nil {
		t.Fatalf("rendering a trusted-signers line: %v", err)
	}
	signersPath := filepath.Join(dir, "trusted-signers")
	if err := os.WriteFile(signersPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("writing trusted-signers: %v", err)
	}
	signers, err := signing.LoadSignersFrom(signersPath)
	if err != nil {
		t.Fatalf("loading trusted-signers: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	job := protocol.Job{
		ID:        "01JSIGNEDREBOOT",
		Intent:    "host.reboot",
		Params:    map[string]any{"delaySeconds": 60, "message": "patching"},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(time.Hour),
		Nonce:     "nonce-signed-reboot",
	}
	payload, err := canonical.Marshal(job.SignedPayload(hostID))
	if err != nil {
		t.Fatalf("canonicalising the signed payload: %v", err)
	}
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	return map[string]any{
		"id":              job.ID,
		"hostId":          hostID,
		"intent":          job.Intent,
		"params":          job.Params,
		"notBefore":       job.NotBefore,
		"notAfter":        job.NotAfter,
		"nonce":           job.Nonce,
		"signature":       base64.StdEncoding.EncodeToString(signature),
		"signerKeyId":     signer.KeyID(),
		"signerAlgorithm": string(signer.Algorithm()),
	}, signers
}

// TestASignedDestructiveJobSurvivesTheRoundTripAndVerifiesOnTheHost is the whole chain.
//
// Sign offline, queue, have a second operator approve, let the agent claim it, and let the agent's own
// acceptance sequence verify the signature against a trust anchor the control plane never saw. It is
// worth doing in one test because every link is a place where a field could be normalised, reordered or
// dropped, and the symptom of any of them is identical: a signature that does not verify, on a host, at
// the moment somebody needed a reboot.
func TestASignedDestructiveJobSurvivesTheRoundTripAndVerifiesOnTheHost(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	request, signers := signedRebootRequest(t, state.HostID)

	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", request)
	if status != http.StatusCreated {
		t.Fatalf("queueing a signed job returned %d: %s", status, body)
	}
	created := jobViewOf(t, body)
	if created["state"] != "awaiting_approval" {
		t.Fatalf("a signed destructive job starts in state %v, want awaiting_approval", created["state"])
	}
	if created["signed"] != true || created["signerKeyId"] != "ops-laptop" {
		t.Errorf("the job does not record who signed it: %s", body)
	}
	if _, rendered := created["signature"]; rendered {
		t.Error("the API renders the signature itself; it authorises nothing here and putting one on a " +
			"dashboard invites somebody to copy it")
	}

	// Not claimable until a second person agrees.
	client := h.agentClient(t, state)
	jobs, err := client.PollJobs(context.Background(), 0)
	if err != nil {
		t.Fatalf("polling: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("a host claimed a job no second operator had approved: %+v", jobs)
	}

	status, body = h.adminJSON(t, h.secondToken, http.MethodPost,
		"/api/v1/jobs/"+request["id"].(string)+"/approve", nil)
	if status != http.StatusOK {
		t.Fatalf("approving returned %d: %s", status, body)
	}
	if approved := jobViewOf(t, body); approved["approvedBy"] != "second-operator" {
		t.Errorf("the approval is recorded as %v", approved["approvedBy"])
	}

	jobs, err = client.PollJobs(context.Background(), 0)
	if err != nil {
		t.Fatalf("polling after approval: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("an approved job was not delivered: %+v", jobs)
	}

	// And now the part that matters: the agent's own acceptance sequence, against a trust anchor this
	// control plane has never held a copy of.
	elevator := &recordingElevator{reply: privsep.Response{ExitCode: 0, Output: "reboot scheduled for +1"}}
	nonces, err := agent.LoadNonceStore(t.TempDir())
	if err != nil {
		t.Fatalf("opening a nonce store: %v", err)
	}
	permissive, err := policy.Parse([]byte(`
[updates]
allow = "all"
reboot = "window"
window = "daily 00:00-00:00"
timezone = "UTC"

[services]
restartable = ["nginx.service"]

[limits]
max_job_age_seconds = 900
`))
	if err != nil {
		t.Fatalf("parsing a policy: %v", err)
	}

	spoolDir := t.TempDir()
	runner := agent.Runner{
		HostID:  state.HostID,
		Policy:  permissive,
		Signers: signers,
		Nonces:  nonces,
		Elevate: elevator,
		Spool:   func(r protocol.ResultRequest) error { return agent.SpoolResult(spoolDir, r) },
	}
	result := runner.Run(context.Background(), jobs[0])

	if result.Status != protocol.StatusSucceeded {
		t.Fatalf("the agent refused a correctly signed job with %q: %s", result.Status, result.Error)
	}
	if elevator.calls != 1 {
		t.Fatalf("the job crossed the privilege boundary %d times, want 1", elevator.calls)
	}
	if elevator.seen.Intent != "host.reboot" {
		t.Errorf("the helper was asked for %q", elevator.seen.Intent)
	}
	if string(elevator.seen.Params) != `{"delaySeconds":60,"message":"patching"}` {
		t.Errorf("the parameters reached the helper as %s, which is not what was signed",
			elevator.seen.Params)
	}
}

// recordingElevator stands in for the route to the root helpers.
//
// The agent's job path must be exercisable without a root helper and without systemd, for the same
// reason it is exercised without a real platform: a test that needed either would be a test of the
// machine it ran on.
type recordingElevator struct {
	// seen is the last request that crossed the boundary.
	seen privsep.Request

	// calls counts invocations, so a test can assert that nothing crossed at all.
	calls int

	// reply is what to answer with.
	reply privsep.Response
}

// Invoke records the request and returns the configured reply.
func (e *recordingElevator) Invoke(_ context.Context, req privsep.Request) (privsep.Response, error) {
	e.seen = req
	e.calls++
	return e.reply, nil
}

// TestGuaranteeOneOperatorCannotApproveTheirOwnJob is the second person, made mechanical.
//
// docs/SECURITY.md §3 requires a second person for the destructive tier. This asserts the refusal from
// the outside, through the API, with the credential that created the job — which is exactly the shape a
// single-operator installation has, because the shipped auth.StaticToken holds one token and one
// subject. Such an installation therefore cannot approve a destructive job at all, and that is the
// correct outcome rather than a gap: the requirement is a second *person*, and there is only one.
func TestGuaranteeOneOperatorCannotApproveTheirOwnJob(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	request, _ := signedRebootRequest(t, state.HostID)

	if status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", request); status != http.StatusCreated {
		t.Fatalf("queueing returned %d: %s", status, body)
	}
	jobID := request["id"].(string)

	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs/"+jobID+"/approve", nil)
	if status != http.StatusConflict {
		t.Fatalf("self-approval returned %d, want 409: %s", status, body)
	}
	if !bytes.Contains(body, []byte("second person")) {
		t.Errorf("the refusal does not say why: %s", body)
	}

	// And the host still cannot have it.
	client := h.agentClient(t, state)
	jobs, err := client.PollJobs(context.Background(), 0)
	if err != nil {
		t.Fatalf("polling: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("a self-approval refused by the API still delivered the job: %+v", jobs)
	}
}

// TestQueueingTheSameSignedPayloadTwiceIsRefused stops the control plane replaying an authorisation.
func TestQueueingTheSameSignedPayloadTwiceIsRefused(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	request, _ := signedRebootRequest(t, state.HostID)

	if status, _ := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", request); status != http.StatusCreated {
		t.Fatalf("the first attempt returned %d", status)
	}
	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", request)
	if status != http.StatusConflict {
		t.Errorf("queueing the same signed payload twice returned %d, want 409: %s", status, body)
	}
}

// TestAJobForAnUnknownOrRevokedHostIsRefused says so when nobody would ever collect it.
//
// A revoked host cannot authenticate, so its queue is a place jobs go to wait for ever. Refusing at
// creation puts the answer where somebody is looking, rather than leaving them to wonder why a job has
// been "queued" for a week.
func TestAJobForAnUnknownOrRevokedHostIsRefused(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	status, _ := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
		"hostId": "01JNOSUCHHOST", "intent": "facts.collect", "params": map[string]any{},
	})
	if status != http.StatusNotFound {
		t.Errorf("a job for an unknown host returned %d, want 404", status)
	}

	if status, body := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/hosts/"+state.HostID+"/revoke", nil); status != http.StatusOK && status != http.StatusNoContent {
		t.Fatalf("revoking returned %d: %s", status, body)
	}
	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
		"hostId": state.HostID, "intent": "facts.collect", "params": map[string]any{},
	})
	if status != http.StatusConflict {
		t.Errorf("a job for a revoked host returned %d, want 409: %s", status, body)
	}
}

// TestARequestTheCatalogueRejectsNeverBecomesAJob is the catalogue at the door.
//
// The same decoder the agent and the root helper run, run here first. It is not a second line of
// defence — the host's checks are the ones the guarantee rests on — it is so that an operator who typed
// a unit name wrong learns now rather than from a job result.
func TestARequestTheCatalogueRejectsNeverBecomesAJob(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	bad := []struct {
		intent string
		params map[string]any
	}{
		{"shell.exec", map[string]any{}},
		{"facts.collect", map[string]any{"unexpected": "field"}},
		{"service.restart", map[string]any{"unit": "nginx.service; rm -rf /"}},
		{"service.restart", map[string]any{"unit": "../../etc/systemd/system/evil.service"}},
	}
	for _, c := range bad {
		status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
			"hostId": state.HostID, "intent": c.intent, "params": c.params,
		})
		if status == http.StatusCreated {
			t.Errorf("%s with %v was queued: %s", c.intent, c.params, body)
		}
	}
	if listed := h.jobs(t); len(listed) != 0 {
		t.Errorf("%d jobs were queued from requests the catalogue rejects", len(listed))
	}
}

// TestAReadJobTakesNoSignatureNonceOrChosenID pins one rule for where those values come from.
//
// A read intent is authorised by mTLS and an agent verifies no signature for one, so accepting these
// would put values on a dashboard that mean less than they appear to — and a caller-chosen id on an
// unsigned job is a chance to collide with somebody else's for no benefit at all.
func TestAReadJobTakesNoSignatureNonceOrChosenID(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	for field, value := range map[string]any{
		"signature": "c2ln", "nonce": "n", "id": "01JCHOSEN", "signerKeyId": "ops-laptop",
	} {
		body := map[string]any{
			"hostId": state.HostID, "intent": "facts.collect", "params": map[string]any{},
			field: value,
		}
		if status, res := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", body); status != http.StatusBadRequest {
			t.Errorf("a read job carrying %s returned %d, want 400: %s", field, status, res)
		}
	}
}

// TestJobsAreListedNewestFirstAndCanBeNarrowedToAHost is what the fleet view reads.
func TestJobsAreListedNewestFirstAndCanBeNarrowedToAHost(t *testing.T) {
	h := newHarness(t)
	first := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	second := h.enrolHost(t, "web-02", h.issueToken(t, "web-prod"))

	for _, hostID := range []string{first.HostID, second.HostID, first.HostID} {
		if status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
			"hostId": hostID, "intent": "facts.collect", "params": map[string]any{},
		}); status != http.StatusCreated {
			t.Fatalf("creating a job returned %d: %s", status, body)
		}
	}

	if all := h.jobs(t); len(all) != 3 {
		t.Errorf("the fleet-wide listing has %d jobs, want 3", len(all))
	}

	status, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/jobs?host="+second.HostID, nil)
	if status != http.StatusOK {
		t.Fatalf("listing one host's jobs returned %d: %s", status, body)
	}
	var listing struct {
		Jobs []struct {
			HostID string `json:"hostId"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(listing.Jobs) != 1 || listing.Jobs[0].HostID != second.HostID {
		t.Errorf("narrowing to one host returned %+v", listing.Jobs)
	}
}

// TestCreatingAJobNeedsAnOperatorCredential asserts the endpoints are not open.
func TestCreatingAJobNeedsAnOperatorCredential(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	for _, call := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/jobs"},
		{http.MethodGet, "/api/v1/jobs"},
		{http.MethodGet, "/api/v1/jobs/01JANY"},
		{http.MethodPost, "/api/v1/jobs/01JANY/approve"},
	} {
		status, _ := h.adminJSON(t, "not-a-real-token", call.method, call.path, map[string]any{
			"hostId": state.HostID, "intent": "facts.collect", "params": map[string]any{},
		})
		if status != http.StatusUnauthorized {
			t.Errorf("%s %s without a credential returned %d, want 401", call.method, call.path, status)
		}
	}
}

// TestServerJobValidityIsGenerousEnoughForAnOfflineHost pins the one window this side chooses.
//
// A signed job's window comes from whoever signed it. Only an unsigned read job has one the control
// plane picks, and it has to outlast a host that was rebooting when the operator asked.
func TestServerJobValidityIsGenerousEnoughForAnOfflineHost(t *testing.T) {
	if server.ReadJobValidity < 6*time.Hour {
		t.Errorf("an unsigned job is valid for %s, which is shorter than a host is routinely away for",
			server.ReadJobValidity)
	}
}

// TestGuaranteeAQueuedReadJobHasNoLowerBound is the same property, from the side that creates it.
//
// The control plane must not pin a read job's window to its own clock. An agent checks the window
// against its own, so a host a second behind would refuse every on-demand report as expired — and read
// intents deliberately skip the clock-skew check, so nothing would catch it. The job that comes back
// from the API must carry no lower bound at all, and the one the agent claims must agree.
func TestGuaranteeAQueuedReadJobHasNoLowerBound(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
		"hostId": state.HostID, "intent": "facts.collect", "params": map[string]any{},
	})
	if status != http.StatusCreated {
		t.Fatalf("creating returned %d: %s", status, body)
	}
	if view := jobViewOf(t, body); view["notBefore"] != nil {
		t.Errorf("the API renders a lower bound of %v for an unsigned job; a host running behind this "+
			"control plane would refuse it as expired", view["notBefore"])
	}

	jobs, err := h.agentClient(t, state).PollJobs(context.Background(), 0)
	if err != nil {
		t.Fatalf("polling: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("claimed %d jobs, want 1", len(jobs))
	}
	if !jobs[0].NotBefore.IsZero() {
		t.Errorf("the delivered job carries notBefore %s; an agent checks that against its own clock",
			jobs[0].NotBefore)
	}
	if jobs[0].NotAfter.IsZero() {
		t.Error("the delivered job carries no upper bound either, so it would never expire")
	}
}

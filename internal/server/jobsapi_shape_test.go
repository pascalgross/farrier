package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/store"
)

// TestGuaranteeASignedJobIDMustBeOneAHostCanReportAgainst is the regression test for an id taken on
// trust.
//
// A signed job's id comes from the signer and is stored verbatim, which is correct — the signature
// covers it. What was missing is that it also has to be *usable*: the id is a path segment in
// POST /agent/v1/jobs/{id}/result and a filename in the agent's result spool. An id holding a slash
// produced a job the host would run and could never report, and the failure surfaced as a job stuck
// "running" for ever rather than as anything anybody could trace back to the id.
func TestGuaranteeASignedJobIDMustBeOneAHostCanReportAgainst(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	for _, id := range []string{
		"west/reboot",
		"reboot?force",
		"reboot#now",
		"reboot-web01-2026-08-23", // a hyphen is out too: the agent's spool refuses it.
		strings.Repeat("A", protocol.MaxJobIDBytes+1),
	} {
		t.Run(id[:min(len(id), 24)], func(t *testing.T) {
			request, _ := signedRebootRequest(t, state.HostID)
			request["id"] = id

			status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", request)
			if status != http.StatusBadRequest {
				t.Fatalf("an id of %q was accepted with %d: %s", id, status, body)
			}
			if !strings.Contains(string(body), "letters and digits") {
				t.Errorf("the refusal does not say what an id may be: %s", body)
			}
		})
	}
}

// TestGuaranteeAHostCannotNameItsOwnJobState is the regression test for a status passed through.
//
// jobState renders a reported status as the job's state, so an unchecked word let a host report
// "queued" for work it had just run: the control plane then showed a job nobody had picked up, and the
// operator re-issued it. On a destructive intent that is the difference between one reboot and two.
func TestGuaranteeAHostCannotNameItsOwnJobState(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
		"hostId": state.HostID, "intent": "facts.collect", "params": map[string]any{},
	})
	if status != http.StatusCreated {
		t.Fatalf("creating a read job returned %d: %s", status, body)
	}
	jobID := jobViewOf(t, body)["id"].(string)

	client := h.agentClient(t, state)
	if _, err := client.PollJobs(t.Context(), 0); err != nil {
		t.Fatalf("polling: %v", err)
	}

	for _, forged := range []string{"queued", "running", "awaiting_approval", "definitely-fine"} {
		err := client.ReportResult(t.Context(), protocol.ResultRequest{
			JobID: jobID, Status: forged,
		})
		if err == nil {
			t.Fatalf("the control plane accepted a result with status %q", forged)
		}
	}

	// And the job is still what it was: claimed, with nothing reported against it.
	status, body = h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/jobs/"+jobID, nil)
	if status != http.StatusOK {
		t.Fatalf("reading the job returned %d: %s", status, body)
	}
	if state := jobViewOf(t, body)["state"]; state != "running" {
		t.Errorf("the job is in state %v after four refused results, want running", state)
	}
}

// TestGuaranteeASecondJobInOneBodyIsRefusedRatherThanDropped is the regression test for a silent
// truncation at the JSON layer.
//
// encoding/json stops at the end of the first value, so a body holding two concatenated requests was
// answered 201 — for the first. The second host never got its job, and nothing in the exchange said so:
// the script that built the batch saw one success per call and moved on.
func TestGuaranteeASecondJobInOneBodyIsRefusedRatherThanDropped(t *testing.T) {
	h := newHarness(t)
	first := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	second := h.enrolHost(t, "web-02", h.issueToken(t, "web-prod"))

	body := `{"hostId":"` + first.HostID + `","intent":"facts.collect","params":{}}` +
		`{"hostId":"` + second.HostID + `","intent":"facts.collect","params":{}}`

	status, answer := h.postRaw(t, "/api/v1/jobs", body)
	if status != http.StatusBadRequest {
		t.Fatalf("two concatenated requests returned %d: %s", status, answer)
	}
	if !strings.Contains(string(answer), "more than one JSON value") {
		t.Errorf("the refusal does not say what was wrong: %s", answer)
	}
	if queued := h.jobs(t); len(queued) != 0 {
		t.Errorf("a refused body queued %d job(s); it must queue none", len(queued))
	}

	// Trailing junk after a complete object is the same failure and gets the same answer.
	status, answer = h.postRaw(t, "/api/v1/jobs",
		`{"hostId":"`+first.HostID+`","intent":"facts.collect","params":{}} GARBAGE`)
	if status != http.StatusBadRequest {
		t.Errorf("trailing data after a job request returned %d: %s", status, answer)
	}
}

// postRaw sends a body the JSON encoder would refuse to produce.
//
// adminJSON marshals what it is given, which is what almost every test wants and is exactly wrong for
// the two above: the whole question is what the server does with bytes no encoder would emit.
func (h *harness) postRaw(t *testing.T, path, body string) (int, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, h.server.URL+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.adminToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = res.Body.Close() }()

	answer, err := readAll(res)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	return res.StatusCode, answer
}

// TestGuaranteeAJobAwaitingApprovalStaysReachable is the regression test for a listing that hid the one
// row the approval model depends on.
//
// The listing is bounded, and it has to be. What was wrong is that the bound was silent and there was
// no way past it: a fleet doing routine collections pushes a destructive job out of the newest hundred
// within a working day, and the second operator docs/SECURITY.md §3 requires then has no way to reach
// the thing they are supposed to look at. Two answers, both tested here — the listing says when it
// truncated, and the awaiting filter is not subject to the drift at all.
func TestGuaranteeAJobAwaitingApprovalStaysReachable(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	request, _ := signedRebootRequest(t, state.HostID)
	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", request)
	if status != http.StatusCreated {
		t.Fatalf("queueing the reboot returned %d: %s", status, body)
	}
	reboot := jobViewOf(t, body)["id"].(string)

	// Bury it under a full page of routine work.
	for range store.DefaultJobLimit {
		status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
			"hostId": state.HostID, "intent": "facts.collect", "params": map[string]any{},
		})
		if status != http.StatusCreated {
			t.Fatalf("queueing filler returned %d: %s", status, body)
		}
	}

	listing := h.listJobs(t, "")
	if listing.Truncated != true {
		t.Error("a listing that filled its bound does not report itself truncated")
	}
	if len(listing.Jobs) != store.DefaultJobLimit {
		t.Fatalf("the default listing returned %d jobs, want %d", len(listing.Jobs), store.DefaultJobLimit)
	}
	if idsOf(listing.Jobs)[reboot] {
		t.Fatal("the fixture did not bury the reboot; the rest of this test proves nothing")
	}

	// Reachable by asking for more…
	wider := h.listJobs(t, "?limit=200")
	if !idsOf(wider.Jobs)[reboot] {
		t.Error("a wider listing does not contain the buried reboot")
	}
	if wider.Truncated {
		t.Error("a listing that did not fill its bound reports itself truncated")
	}

	// …and reachable without having to know how far back to look.
	awaiting := h.listJobs(t, "?awaiting=true")
	if len(awaiting.Jobs) != 1 || !idsOf(awaiting.Jobs)[reboot] {
		t.Errorf("the awaiting-approval listing returned %d jobs, want just the reboot", len(awaiting.Jobs))
	}

	// An approval takes it off that list, which is what makes the list worth reading.
	status, body = h.adminJSON(t, h.secondToken, http.MethodPost, "/api/v1/jobs/"+reboot+"/approve", nil)
	if status != http.StatusOK {
		t.Fatalf("approving returned %d: %s", status, body)
	}
	if after := h.listJobs(t, "?awaiting=true"); len(after.Jobs) != 0 {
		t.Errorf("an approved job is still listed as awaiting approval: %d row(s)", len(after.Jobs))
	}
}

// TestAnUnusableListingLimitIsRefusedRatherThanReplaced checks that a caller who asks for more than the
// ceiling is told so. Quietly returning the default would hand them a short list they would read as the
// whole answer.
func TestAnUnusableListingLimitIsRefusedRatherThanReplaced(t *testing.T) {
	h := newHarness(t)

	for _, query := range []string{"?limit=0", "?limit=-1", "?limit=abc", "?limit=100000"} {
		status, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/jobs"+query, nil)
		if status != http.StatusBadRequest {
			t.Errorf("GET /api/v1/jobs%s returned %d, want 400: %s", query, status, body)
		}
	}
}

// TestAJobListingCarriesTheServersClock pins the field the UI renders job ages from.
//
// Ages on the jobs page are decision inputs — the approval card shows "asked 4h ago" to the second
// operator deciding whether to release — and everything in this product measures them against the
// server's clock, as /api/v1/hosts already does. This field going missing would not break anything
// visibly; it would quietly put the browser's clock back in charge of an input to an authorisation
// decision, which in a project that treats clock skew as a security boundary is not a cosmetic drift.
func TestAJobListingCarriesTheServersClock(t *testing.T) {
	h := newHarness(t)

	listing := h.listJobs(t, "")
	if listing.ServerTime == "" {
		t.Fatal("the job listing carries no serverTime; the UI would fall back to the browser's clock")
	}
	if _, err := time.Parse(time.RFC3339, listing.ServerTime); err != nil {
		t.Errorf("serverTime %q is not RFC 3339: %v", listing.ServerTime, err)
	}
}

// jobListing is the shape of a job listing response, for the assertions above.
type jobListing struct {
	// Jobs is the page of rows.
	Jobs []map[string]any `json:"jobs"`

	// Limit is the bound that was applied, and Truncated reports that it bit.
	Limit     int  `json:"limit"`
	Truncated bool `json:"truncated"`

	// ServerTime is the control plane's clock, which the UI renders ages against.
	ServerTime string `json:"serverTime"`
}

// listJobs reads a job listing with an arbitrary query string.
func (h *harness) listJobs(t *testing.T, query string) jobListing {
	t.Helper()
	status, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/jobs"+query, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/jobs%s returned %d: %s", query, status, body)
	}
	var listing jobListing
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decoding a job listing: %v", err)
	}
	return listing
}

// idsOf indexes a page of jobs by id, so a test can ask whether a particular one is on it.
func idsOf(jobs []map[string]any) map[string]bool {
	out := make(map[string]bool, len(jobs))
	for _, job := range jobs {
		id, _ := job["id"].(string)
		out[id] = true
	}
	return out
}

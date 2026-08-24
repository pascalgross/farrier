package server_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/agent"
	"github.com/pascalgross/farrier/internal/protocol"
)

// listedEvent is the slice of an event row these tests read back.
type listedEvent struct {
	// ID identifies the event.
	ID string `json:"id"`

	// Kind is the vocabulary member.
	Kind string `json:"kind"`

	// HostID is the host it concerns.
	HostID string `json:"hostId"`

	// Summary is the one-line text.
	Summary string `json:"summary"`
}

// listEvents reads the inbox through the API.
func (h *harness) listEvents(t *testing.T, query string) []listedEvent {
	t.Helper()
	status, raw := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/events"+query, nil)
	if status != http.StatusOK {
		t.Fatalf("listing events: %d %s", status, raw)
	}
	var decoded struct {
		// Events is the inbox page.
		Events []listedEvent `json:"events"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decoding events: %v", err)
	}
	return decoded.Events
}

// countEvents tallies inbox entries of one kind.
func countEvents(events []listedEvent, kind string) int {
	n := 0
	for _, e := range events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// TestEnrolmentLandsInTheInbox is the smallest end-to-end proof of the durable half of #4: an event
// is on the page whether or not anybody's tab was open when it happened.
func TestEnrolmentLandsInTheInbox(t *testing.T) {
	h := newHarness(t)
	h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	events := h.listEvents(t, "")
	if countEvents(events, "host.enrolled") != 1 {
		t.Fatalf("the enrolment is not in the inbox: %+v", events)
	}

	// And the other tenant's inbox is empty: an event is a read of control-plane state and is scoped
	// like one.
	status, raw := h.adminJSON(t, h.otherToken, http.MethodGet, "/api/v1/events", nil)
	if status != http.StatusOK || strings.Contains(string(raw), "host.enrolled") {
		t.Fatalf("another tenant's inbox holds this fleet's event: %d %s", status, raw)
	}
}

// TestAFailedJobNotifiesExactlyOnce is the deduplication half of the job.failed event.
//
// The agent retries a result until acknowledged, and the retry is byte-identical — so the event has
// to key on "first recording", or every flaky network turns one failure into a stream of pages.
func TestAFailedJobNotifiesExactlyOnce(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)
	ctx := context.Background()

	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
		"hostId": state.HostID, "intent": "facts.collect", "params": map[string]any{},
	})
	if status != http.StatusCreated {
		t.Fatalf("creating the job: %d %s", status, raw)
	}
	jobs, err := client.PollJobs(ctx, 0)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claiming: %v (%d jobs)", err, len(jobs))
	}

	result := protocol.ResultRequest{
		JobID: jobs[0].ID, Status: protocol.StatusFailed, ExitCode: 1,
		Error: "the collector exploded\nwith a second line nobody's pager needs",
	}
	for range 3 {
		if err := client.ReportResult(ctx, result); err != nil {
			t.Fatalf("reporting: %v", err)
		}
	}

	events := h.listEvents(t, "?kind=job.failed")
	if len(events) != 1 {
		t.Fatalf("three deliveries of one failure produced %d events", len(events))
	}
	if strings.Contains(events[0].Summary, "second line") {
		t.Fatalf("the summary carries more than the first line: %q", events[0].Summary)
	}
}

// heartbeatWithFacts sends one full facts report for an enrolled host.
func heartbeatWithFacts(t *testing.T, h *harness, state *agent.State, facts map[string]any,
	policy map[string]any) {
	t.Helper()
	client := h.agentClient(t, state)
	req := protocol.HeartbeatRequest{
		AgentVersion: "test", BootID: "boot-1", Facts: facts,
		FactsDigest: "sha256:reported",
	}
	if policy != nil {
		req.Policy = policy
		req.PolicyDigest = "sha256:policy"
	}
	if _, err := client.Heartbeat(context.Background(), req); err != nil {
		t.Fatalf("heartbeating: %v", err)
	}
}

// unitFacts builds the facts document for one unit in one state.
func unitFacts(unit, active, sub string) map[string]any {
	return map[string]any{
		"services": []map[string]any{
			{"name": unit, "loadState": "loaded", "activeState": active, "subState": sub},
		},
	}
}

// TestUnitFailureIsObservedRecordedAndVisible walks issue #5 end to end: a unit failing between two
// heartbeats produces a service.failed event, a history row, and a hit on the fleet-wide failed view.
func TestUnitFailureIsObservedRecordedAndVisible(t *testing.T) {
	h := newHarness(t)
	enrolled := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	heartbeatWithFacts(t, h, enrolled, unitFacts("nginx.service", "active", "running"), nil)
	heartbeatWithFacts(t, h, enrolled, unitFacts("nginx.service", "failed", "failed"), nil)

	if n := countEvents(h.listEvents(t, "?kind=service.failed"), "service.failed"); n != 1 {
		t.Fatalf("a unit failure produced %d events", n)
	}

	status, raw := h.adminJSON(t, h.adminToken, http.MethodGet,
		"/api/v1/hosts/"+enrolled.HostID+"/services/history", nil)
	if status != http.StatusOK {
		t.Fatalf("history: %d %s", status, raw)
	}
	var history struct {
		// Transitions is the recorded state changes.
		Transitions []struct {
			// Unit names the systemd unit.
			Unit string `json:"unit"`

			// From is the previous active state.
			From string `json:"from"`

			// To is the new active state.
			To string `json:"to"`
		} `json:"transitions"`
	}
	if err := json.Unmarshal(raw, &history); err != nil {
		t.Fatalf("decoding history: %v", err)
	}
	if len(history.Transitions) != 1 || history.Transitions[0].From != "active" ||
		history.Transitions[0].To != "failed" {
		t.Fatalf("history: %+v", history.Transitions)
	}

	status, raw = h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/services/failed", nil)
	if status != http.StatusOK || !strings.Contains(string(raw), "nginx.service") {
		t.Fatalf("the fleet view does not show the failed unit: %d %s", status, raw)
	}

	// Recovery is an event too — a rule that fires must also un-fire, or operators learn to ignore
	// it.
	heartbeatWithFacts(t, h, enrolled, unitFacts("nginx.service", "active", "running"), nil)
	if n := countEvents(h.listEvents(t, "?kind=service.recovered"), "service.recovered"); n != 1 {
		t.Fatalf("the recovery produced %d events", n)
	}
}

// TestTheWatchListBoundsEventsButNotHistory pins the meaning of `[services] watched`: the host's own
// list decides what is event-worthy, and the history records everything regardless — the policy key
// bounds what is said out loud, not what is remembered.
func TestTheWatchListBoundsEventsButNotHistory(t *testing.T) {
	h := newHarness(t)
	enrolled := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	watching := map[string]any{"services": map[string]any{"watched": []string{"postgres*"}}}
	heartbeatWithFacts(t, h, enrolled, unitFacts("nginx.service", "active", "running"), watching)
	heartbeatWithFacts(t, h, enrolled, unitFacts("nginx.service", "failed", "failed"), watching)

	if n := countEvents(h.listEvents(t, "?kind=service.failed"), "service.failed"); n != 0 {
		t.Fatalf("an unwatched unit produced %d events", n)
	}
	status, raw := h.adminJSON(t, h.adminToken, http.MethodGet,
		"/api/v1/hosts/"+enrolled.HostID+"/services/history", nil)
	if status != http.StatusOK || !strings.Contains(string(raw), "nginx.service") {
		t.Fatalf("the unwatched transition is missing from history: %d %s", status, raw)
	}
}

// TestTheEventStreamDeliversLive is the tab-open half of #4: an event emitted while a stream is
// connected arrives on it, as JSON the inbox listing would also produce.
func TestTheEventStreamDeliversLive(t *testing.T) {
	h := newHarness(t)

	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.adminToken)
	res, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("connecting the stream: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream answered %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("the stream is cacheable: %q", cc)
	}

	reader := bufio.NewReader(res.Body)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, ": connected") {
		t.Fatalf("no greeting: %q, %v", line, err)
	}

	// The greeting has arrived, and the handler subscribes before writing it — so this event cannot
	// fall into a gap between the two. That ordering is what lets a client reconcile against the
	// inbox only after the greeting, rather than racing its own reconnect.
	h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	deadline := time.After(5 * time.Second)
	got := make(chan string, 1)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "data: ") {
				got <- strings.TrimPrefix(strings.TrimSpace(line), "data: ")
				return
			}
		}
	}()
	select {
	case payload := <-got:
		var view listedEvent
		if err := json.Unmarshal([]byte(payload), &view); err != nil {
			t.Fatalf("the stream payload is not an event: %q, %v", payload, err)
		}
		if view.Kind != "host.enrolled" || view.ID == "" {
			t.Fatalf("streamed: %+v", view)
		}
	case <-deadline:
		t.Fatal("no event arrived on the stream within five seconds")
	}
}

// alertRule is the slice of a rule these tests read back.
type alertRule struct {
	// ID identifies the rule.
	ID string `json:"id"`

	// Condition is what it watches.
	Condition string `json:"condition"`

	// LastDeliveryError is why its last mail did not go out, empty when it did.
	LastDeliveryError string `json:"lastDeliveryError"`
}

// awaitDeliveryReport polls one rule until its delivery outcome is recorded.
//
// Polling rather than a synchronisation point, because the delivery it waits for is deliberately
// detached: emit must not make an agent's heartbeat wait on somebody else's mail server, so the
// record lands shortly after the request that caused it rather than within it.
func (h *harness) awaitDeliveryReport(t *testing.T, ruleID string) alertRule {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, raw := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/alerts", nil)
		if status != http.StatusOK {
			t.Fatalf("listing rules: %d %s", status, raw)
		}
		var decoded struct {
			// Rules is the tenant's rule list.
			Rules []alertRule `json:"rules"`
		}
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("decoding rules: %v", err)
		}
		for _, rule := range decoded.Rules {
			if rule.ID == ruleID && rule.LastDeliveryError != "" {
				return rule
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no delivery outcome was recorded for %s within five seconds: %s", ruleID, raw)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestAnUndeliverableAlertSaysSoOnTheRule is the delivery-visibility half of #7.
//
// An alert that never went out and an alert that never fired are indistinguishable from an inbox, so
// the failure has to be on the rule an operator is already looking at rather than in a log line.
// The installation here has no relay, which is the commonest version of the mistake: somebody adds
// recipients to a rule on a control plane that was never given `--smtp-host`.
func TestAnUndeliverableAlertSaysSoOnTheRule(t *testing.T) {
	h := newHarness(t)
	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/alerts", map[string]any{
		"condition": "job_failed", "emailTo": []string{"oncall@example.com"},
	})
	if status != http.StatusCreated {
		t.Fatalf("creating the rule: %d %s", status, raw)
	}
	var created alertRule
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("decoding the rule: %v", err)
	}

	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)
	ctx := context.Background()
	status, raw = h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/jobs", map[string]any{
		"hostId": state.HostID, "intent": "facts.collect", "params": map[string]any{},
	})
	if status != http.StatusCreated {
		t.Fatalf("creating the job: %d %s", status, raw)
	}
	jobs, err := client.PollJobs(ctx, 0)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claiming: %v (%d jobs)", err, len(jobs))
	}
	if err := client.ReportResult(ctx, protocol.ResultRequest{
		JobID: jobs[0].ID, Status: protocol.StatusFailed, ExitCode: 1, Error: "the collector exploded",
	}); err != nil {
		t.Fatalf("reporting: %v", err)
	}

	rule := h.awaitDeliveryReport(t, created.ID)
	if !strings.Contains(rule.LastDeliveryError, "SMTP") {
		t.Fatalf("the recorded reason does not name the missing relay: %q", rule.LastDeliveryError)
	}
}

// TestSilencingARuleKeepsEverythingElseAboutIt pins what PATCH means on an alerting rule.
//
// `{"enabled": false}` is how somebody silences a rule during an incident, and it is the request most
// likely to be sent by hand. Under a body of plain values it decoded as "threshold zero, no cooldown,
// no recipients" and the update wrote all three — so the rule came back after the incident silenced
// *and* stripped of its mailing list, with nothing in the request that asked for either.
func TestSilencingARuleKeepsEverythingElseAboutIt(t *testing.T) {
	h := newHarness(t)
	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/alerts", map[string]any{
		"condition": "host_silent", "threshold": 30, "cooldownSeconds": 900,
		"emailTo": []string{"oncall@example.com"},
	})
	if status != http.StatusCreated {
		t.Fatalf("creating the rule: %d %s", status, raw)
	}
	var created struct {
		// ID identifies the rule.
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("decoding the rule: %v", err)
	}

	status, raw = h.adminJSON(t, h.adminToken, http.MethodPatch,
		"/api/v1/alerts/"+created.ID, map[string]any{"enabled": false})
	if status != http.StatusOK {
		t.Fatalf("silencing the rule: %d %s", status, raw)
	}

	var after struct {
		// Threshold is the minutes-silent line.
		Threshold int `json:"threshold"`

		// CooldownSeconds bounds re-notification.
		CooldownSeconds int `json:"cooldownSeconds"`

		// EmailTo lists the recipients.
		EmailTo []string `json:"emailTo"`

		// Enabled reports whether the rule is live.
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatalf("decoding the update: %v", err)
	}
	switch {
	case after.Enabled:
		t.Fatal("the rule is still enabled")
	case after.Threshold != 30:
		t.Fatalf("the threshold changed to %d", after.Threshold)
	case after.CooldownSeconds != 900:
		t.Fatalf("the cooldown changed to %d", after.CooldownSeconds)
	case len(after.EmailTo) != 1 || after.EmailTo[0] != "oncall@example.com":
		t.Fatalf("the recipients changed to %v", after.EmailTo)
	}

	// An explicit empty array still clears them: absent means unchanged, and present means what it
	// says. Without this the fix would have made recipients impossible to remove.
	status, raw = h.adminJSON(t, h.adminToken, http.MethodPatch,
		"/api/v1/alerts/"+created.ID, map[string]any{"emailTo": []string{}})
	if status != http.StatusOK {
		t.Fatalf("clearing the recipients: %d %s", status, raw)
	}
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatalf("decoding the update: %v", err)
	}
	if len(after.EmailTo) != 0 {
		t.Fatalf("an explicit empty list did not clear the recipients: %v", after.EmailTo)
	}
	if after.Threshold != 30 {
		t.Fatalf("clearing the recipients changed the threshold to %d", after.Threshold)
	}
}

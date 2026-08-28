package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/notify"
	"github.com/pascalgross/farrier/internal/store"
)

// alertHarness is the smallest control plane an evaluator pass needs: a memory store with one tenant.
//
// In-package rather than beside the API tests, because the evaluator has no route: it runs on a ticker
// and everything it produces is a side effect on rows and sinks. Driving it directly is the only way
// to pin what one pass does, and pinning that matters more than usual — an alerting system is judged
// on the pass nobody watched.
type alertHarness struct {
	// server is the control plane under test.
	server *Server

	// scoped is the tenant's store handle.
	scoped store.Scoped

	// tenant is the fleet these hosts belong to.
	tenant store.TenantID
}

// newAlertHarness builds a control plane with a memory store and one tenant.
func newAlertHarness(t *testing.T) *alertHarness {
	t.Helper()
	memory := store.NewMemory()
	tenant := store.TenantID("tenant-alpha")
	if err := memory.CreateTenant(context.Background(), store.Tenant{
		ID: tenant, Slug: "alpha", DisplayName: "Alpha", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("creating the tenant: %v", err)
	}
	s := &Server{cfg: Config{Store: memory, HeartbeatSeconds: 60}}
	s.outboundCtx, s.outboundStop = context.WithCancel(context.Background())
	t.Cleanup(s.outboundStop)
	return &alertHarness{server: s, scoped: memory.In(tenant), tenant: tenant}
}

// silentHosts enrols n hosts that were last heard from long ago.
func (h *alertHarness) silentHosts(t *testing.T, n int, lastSeen time.Time) {
	t.Helper()
	for i := range n {
		id := "host-" + strconv.Itoa(i)
		host := store.Host{
			ID: id, Hostname: id, Group: "web-prod", EnrolledAt: lastSeen, LastSeen: lastSeen,
		}
		cert := store.Certificate{
			Fingerprint: "fingerprint-" + id, HostID: id, TenantID: h.tenant,
			Serial: "00" + id, IssuedAt: lastSeen, NotAfter: lastSeen.Add(365 * 24 * time.Hour),
		}
		if err := h.scoped.CreateEnrolledHost(context.Background(), host, cert); err != nil {
			t.Fatalf("creating a host: %v", err)
		}
	}
}

// createRule stores one host_silent rule with no recipients.
func (h *alertHarness) createRule(t *testing.T) store.AlertRule {
	t.Helper()
	rule := store.AlertRule{
		ID: "rule-1", Condition: store.ConditionHostSilent, Threshold: 30,
		Enabled: true, CreatedAt: time.Now().UTC(), CreatedBy: "test",
	}
	if err := h.scoped.CreateAlertRule(context.Background(), rule); err != nil {
		t.Fatalf("creating the rule: %v", err)
	}
	return rule
}

// eventSummaries returns the tenant's inbox summaries for one kind, newest first.
func (h *alertHarness) eventSummaries(t *testing.T, kind string) []string {
	t.Helper()
	events, err := h.scoped.ListEvents(context.Background(), store.EventFilter{Kind: kind})
	if err != nil {
		t.Fatalf("listing events: %v", err)
	}
	summaries := make([]string, 0, len(events))
	for _, e := range events {
		summaries = append(summaries, e.Summary)
	}
	return summaries
}

// digestOf returns the one summary in a set that reads as a digest, and the rest.
//
// The two are asserted separately everywhere below, because they answer different questions: the
// digest is what interrupts somebody, and the remainder is what the inbox has to be able to answer
// afterwards.
func digestOf(summaries []string, count string) (digest string, rest []string) {
	for _, summary := range summaries {
		if strings.HasPrefix(summary, count+" hosts ") {
			digest = summary
			continue
		}
		rest = append(rest, summary)
	}
	return digest, rest
}

// TestARecoveringPartitionSendsOneNotification is the un-firing half of the digest rule.
//
// A partition that heals recovers every host at once. Firings already collapse past the threshold,
// and recoveries have to as well for the same reason and more so: three hundred "heartbeating again"
// lines are what bury the one host that did not come back.
//
// The collapse is a property of the *notification*, not of the inbox. The inbox is the durable,
// complete record — the answer to "what did I miss overnight" — so it still holds one row per host
// beside the digest, and this test asserts both halves: one digest, and nobody missing from the
// record behind it.
func TestARecoveringPartitionSendsOneNotification(t *testing.T) {
	h := newAlertHarness(t)
	rule := h.createRule(t)

	longAgo := time.Now().UTC().Add(-2 * time.Hour)
	h.silentHosts(t, 10, longAgo)

	// The pass that finds them silent: one digest, not ten pages — and ten rows behind it.
	h.server.evaluateAlerts(context.Background(), time.Now().UTC())
	digest, perHost := digestOf(h.eventSummaries(t, string(notify.KindHostSilent)), "10")
	if digest == "" {
		t.Fatalf("ten silent hosts produced no digest: %v", perHost)
	}
	if len(perHost) != 10 {
		t.Fatalf("the inbox holds %d per-host rows behind the digest, expected 10: %v",
			len(perHost), perHost)
	}
	for i := range 10 {
		name := "host-" + strconv.Itoa(i)
		found := false
		for _, summary := range perHost {
			if strings.HasPrefix(summary, name+":") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is in the digest's count and not in the inbox behind it", name)
		}
	}

	// Everybody comes back at once.
	hosts, err := h.scoped.ListHosts(context.Background())
	if err != nil {
		t.Fatalf("listing hosts: %v", err)
	}
	now := time.Now().UTC()
	for _, host := range hosts {
		if err := h.scoped.RecordHeartbeat(context.Background(), host.ID, store.HeartbeatUpdate{
			AgentVersion: "test", BootID: "boot-1", LastSeen: now,
		}); err != nil {
			t.Fatalf("heartbeating a host: %v", err)
		}
	}

	h.server.evaluateAlerts(context.Background(), now)
	recoveryDigest, recoveredHosts := digestOf(h.eventSummaries(t, string(notify.KindHostRecovered)), "10")
	if recoveryDigest == "" {
		t.Fatalf("ten recoveries produced no digest: %v", recoveredHosts)
	}
	if !strings.Contains(recoveryDigest, "heartbeating again") {
		t.Fatalf("the recovery digest does not read as one: %q", recoveryDigest)
	}
	if len(recoveredHosts) != 10 {
		t.Fatalf("the inbox holds %d per-host recoveries, expected 10: %v",
			len(recoveredHosts), recoveredHosts)
	}

	// And the rule is no longer firing for anybody, so a third pass says nothing at all.
	before := len(h.eventSummaries(t, string(notify.KindHostRecovered)))
	h.server.evaluateAlerts(context.Background(), now.Add(time.Minute))
	if again := h.eventSummaries(t, string(notify.KindHostRecovered)); len(again) != before {
		t.Fatalf("a quiet pass produced %d more recovery events", len(again)-before)
	}
	if rule.Condition != store.ConditionHostSilent {
		t.Fatalf("the rule under test is not the one this test describes: %s", rule.Condition)
	}
}

// TestASmallOutageNamesItsHosts keeps the digest from swallowing the case it is not for.
//
// Under the threshold an operator wants the hostnames, because two failing machines are something
// somebody acts on directly and "2 hosts silent for over 30 minutes" makes them go and look.
func TestASmallOutageNamesItsHosts(t *testing.T) {
	h := newAlertHarness(t)
	h.createRule(t)
	h.silentHosts(t, 2, time.Now().UTC().Add(-2*time.Hour))

	h.server.evaluateAlerts(context.Background(), time.Now().UTC())
	firing := h.eventSummaries(t, string(notify.KindHostSilent))
	if len(firing) != 2 {
		t.Fatalf("two silent hosts produced %d events: %v", len(firing), firing)
	}
	for _, summary := range firing {
		if !strings.Contains(summary, "silent for") {
			t.Fatalf("a per-host summary does not say what happened: %q", summary)
		}
	}
}

// routingFixture stores one event-routed rule with recipients and returns it.
func (h *alertHarness) routingFixture(t *testing.T) store.AlertRule {
	t.Helper()
	rule := store.AlertRule{
		ID: "rule-routed", Condition: store.ConditionJobFailed, CooldownSeconds: 3600,
		EmailTo: []string{"oncall@example.com"}, Enabled: true,
		CreatedAt: time.Now().UTC(), CreatedBy: "test",
	}
	if err := h.scoped.CreateAlertRule(context.Background(), rule); err != nil {
		t.Fatalf("creating the rule: %v", err)
	}
	return rule
}

// deliveryOutcome reads back what a rule says about its last mail attempt.
func (h *alertHarness) deliveryOutcome(t *testing.T, ruleID string) store.AlertRule {
	t.Helper()
	rules, err := h.scoped.ListAlertRules(context.Background())
	if err != nil {
		t.Fatalf("listing rules: %v", err)
	}
	for _, rule := range rules {
		if rule.ID == ruleID {
			return rule
		}
	}
	t.Fatalf("rule %s is gone", ruleID)
	return store.AlertRule{}
}

// TestRoutingHonoursALostCooldownClaim exercises the branch the race actually takes.
//
// The states slice a pass routes against was read before the claim: that is the whole shape of the
// bug — two events for one host, each in its own goroutine, both reading "nothing recent". So the
// fixture is a claim already held in the store and a states slice that does not know about it, which
// is precisely what the losing goroutine sees. Passing an up-to-date states slice would only re-prove
// the cheap filter in dueRules and would pass with the claim deleted, which an earlier version of
// this test did.
func TestRoutingHonoursALostCooldownClaim(t *testing.T) {
	h := newAlertHarness(t)
	rule := h.routingFixture(t)

	won, err := h.scoped.ClaimAlertNotification(context.Background(),
		store.AlertKey{RuleID: rule.ID, HostID: "host-1"}, time.Now().UTC(), time.Hour)
	if err != nil || !won {
		t.Fatalf("pre-claiming: won=%v err=%v", won, err)
	}

	h.server.routeToRules(context.Background(), h.scoped,
		notify.Event{Kind: notify.KindJobFailed, HostID: "host-1", Hostname: "web-01"},
		store.ConditionJobFailed, []store.AlertRule{rule}, nil)

	// Nothing was attempted, so nothing was recorded. This installation has no relay, so a rule that
	// *had* been attempted would carry the "no SMTP relay is configured" outcome.
	if after := h.deliveryOutcome(t, rule.ID); !after.LastDeliveryAt.IsZero() {
		t.Fatalf("a rule whose claim was lost still attempted mail: %q", after.LastDeliveryError)
	}
}

// TestRoutingMailsTheRuleThatWinsItsClaim is the other half, and the reason the test above means
// anything: without it, "nothing was recorded" would also be what a broken routing path produced.
func TestRoutingMailsTheRuleThatWinsItsClaim(t *testing.T) {
	h := newAlertHarness(t)
	rule := h.routingFixture(t)

	h.server.routeToRules(context.Background(), h.scoped,
		notify.Event{Kind: notify.KindJobFailed, HostID: "host-1", Hostname: "web-01"},
		store.ConditionJobFailed, []store.AlertRule{rule}, nil)

	after := h.deliveryOutcome(t, rule.ID)
	if after.LastDeliveryAt.IsZero() {
		t.Fatal("a rule that won its claim recorded no delivery outcome at all")
	}
	if !strings.Contains(after.LastDeliveryError, "SMTP") {
		t.Fatalf("the outcome does not name the missing relay: %q", after.LastDeliveryError)
	}

	// And the claim it took stops the next event for the same host inside the cooldown.
	states, err := h.scoped.ListAlertStates(context.Background())
	if err != nil {
		t.Fatalf("listing states: %v", err)
	}
	if len(states) != 1 || states[0].LastNotified.IsZero() {
		t.Fatalf("mailing left no cooldown behind it: %+v", states)
	}
}

// TestTwoEvaluatorsNotifyOnceBetweenThem is the horizontally-deployed case.
//
// Two control planes against one database both tick, both read the same state, and before the claim
// both would have paged. The two passes here are sequential rather than concurrent on purpose: the
// race is not about timing, it is about a read that does not reserve anything, and a second pass
// against the state the first left is the sharpest version of that — if the second still notifies,
// so would a replica.
//
// The store's own test covers the concurrent case against both backends.
func TestTwoEvaluatorsNotifyOnceBetweenThem(t *testing.T) {
	h := newAlertHarness(t)
	h.createRule(t)
	h.silentHosts(t, 2, time.Now().UTC().Add(-2*time.Hour))

	// Two servers, one store: the same shape as two replicas, minus the network.
	second := &Server{cfg: Config{Store: h.server.cfg.Store, HeartbeatSeconds: 60}}
	second.outboundCtx, second.outboundStop = context.WithCancel(context.Background())
	t.Cleanup(second.outboundStop)

	now := time.Now().UTC()
	h.server.evaluateAlerts(context.Background(), now)
	second.evaluateAlerts(context.Background(), now)

	if firing := h.eventSummaries(t, string(notify.KindHostSilent)); len(firing) != 2 {
		t.Fatalf("two hosts across two evaluators produced %d firing events: %v", len(firing), firing)
	}

	// And the recovery is claimed once too, which is the half a plain "have I notified" check misses
	// entirely: it reads the same "was firing, is not now" on both replicas.
	hosts, err := h.scoped.ListHosts(context.Background())
	if err != nil {
		t.Fatalf("listing hosts: %v", err)
	}
	back := now.Add(time.Minute)
	for _, host := range hosts {
		if err := h.scoped.RecordHeartbeat(context.Background(), host.ID, store.HeartbeatUpdate{
			AgentVersion: "test", BootID: "boot-1", LastSeen: back,
		}); err != nil {
			t.Fatalf("heartbeating: %v", err)
		}
	}
	h.server.evaluateAlerts(context.Background(), back)
	second.evaluateAlerts(context.Background(), back)

	if recovered := h.eventSummaries(t, string(notify.KindHostRecovered)); len(recovered) != 2 {
		t.Fatalf("two recoveries across two evaluators produced %d events: %v",
			len(recovered), recovered)
	}
}

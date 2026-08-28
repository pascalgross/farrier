package server

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/notify"
	"github.com/pascalgross/farrier/internal/store"
)

// countingScoped counts the delivery outcomes written through a tenant's store handle.
//
// It is the only honest way to count notifications in these tests. The rule row records the *last*
// attempt, so two mails and one mail leave the row looking identical — and "the second failing unit was
// swallowed" is precisely a difference of count with no difference of state. Every attempt, successful
// or not, ends at RecordAlertDelivery, so counting there counts deliveries without needing a relay.
//
// It embeds the real handle rather than reimplementing one, so everything the routing path reads comes
// from the same store the assertions read back.
type countingScoped struct {
	store.Scoped

	// mu guards attempts.
	mu sync.Mutex

	// attempts is the outcome recorded for each delivery, in order.
	attempts []string
}

// RecordAlertDelivery counts the attempt and lets the real store record it.
func (c *countingScoped) RecordAlertDelivery(ctx context.Context, ruleID string, at time.Time,
	failure string) error {

	c.mu.Lock()
	c.attempts = append(c.attempts, failure)
	c.mu.Unlock()
	return c.Scoped.RecordAlertDelivery(ctx, ruleID, at, failure)
}

// count returns how many deliveries have been attempted through this handle.
func (c *countingScoped) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.attempts)
}

// counting wraps the harness's store handle so a test can count what left through it.
func (h *alertHarness) counting() *countingScoped {
	return &countingScoped{Scoped: h.scoped}
}

// unitRule stores one enabled unit_failed rule with recipients and an hour of cooldown.
//
// Recipients are the point: a rule without them is delivered to the inbox and never routed to mail, so
// a fixture without them would exercise none of the path these tests are about. An hour is long enough
// that every test below runs entirely inside one cooldown, which is what makes suppression observable
// without any test having to manipulate time.
func (h *alertHarness) unitRule(t *testing.T, id string) store.AlertRule {
	t.Helper()
	rule := store.AlertRule{
		ID: id, Condition: store.ConditionUnitFailed, CooldownSeconds: 3600,
		EmailTo: []string{"oncall@example.com"}, Enabled: true,
		CreatedAt: time.Now().UTC(), CreatedBy: "test",
	}
	if err := h.scoped.CreateAlertRule(context.Background(), rule); err != nil {
		t.Fatalf("creating the rule: %v", err)
	}
	return rule
}

// unitEvent builds the event a heartbeat emits when a watched unit changes state.
//
// The Detail map carries the unit under the key eventSubject reads, because that key is the whole of
// how a firing is narrowed below the host. Building it here, once, keeps every test below asserting the
// routing rather than re-stating the convention it depends on.
func unitEvent(kind notify.Kind, hostID, unit string) notify.Event {
	return notify.Event{
		Kind: kind, HostID: hostID, Hostname: "web-01", At: time.Now().UTC(),
		Summary: "web-01: " + unit + " failed (failed)",
		Detail:  map[string]any{"unit": unit},
	}
}

// firingStates returns the alert states this tenant holds, keyed by the unit they are about.
//
// Keyed by subject rather than returned as a slice because that is the question every assertion below
// asks: is there a separate firing for each unit, or did one unit's claim stand in for another's.
func (h *alertHarness) firingStates(t *testing.T) map[string]store.AlertState {
	t.Helper()
	states, err := h.scoped.ListAlertStates(context.Background())
	if err != nil {
		t.Fatalf("listing states: %v", err)
	}
	bySubject := make(map[string]store.AlertState, len(states))
	for _, st := range states {
		bySubject[st.Subject] = st
	}
	return bySubject
}

// TestAUnitFailureReachesItsRuleAndTheOutcomeLandsOnIt is the end-to-end path no test covered.
//
// A `service.failed` event is not evaluated by the alert pass — nothing re-reads a unit's state on a
// ticker — so the event itself is the only thing that will ever route it. Everything between the event
// and the recipients is therefore in this one path: the kind maps to a condition, the rules are read,
// the cooldown is claimed, mail is attempted, and the outcome is stamped where an operator will look
// for it. This installation has no relay, so the outcome is the failure that names the missing one —
// which is the commonest real version of the mistake and, unlike a delivered mail, is observable.
func TestAUnitFailureReachesItsRuleAndTheOutcomeLandsOnIt(t *testing.T) {
	h := newAlertHarness(t)
	rule := h.unitRule(t, "rule-units")
	counting := h.counting()

	h.server.routeEventMail(context.Background(), counting,
		unitEvent(notify.KindServiceFailed, "host-1", "nginx.service"))

	if counting.count() != 1 {
		t.Fatalf("a unit failure produced %d delivery attempts, expected 1: %v",
			counting.count(), counting.attempts)
	}
	after := h.deliveryOutcome(t, rule.ID)
	if after.LastDeliveryAt.IsZero() {
		t.Fatal("the rule records no delivery attempt at all")
	}
	if !strings.Contains(after.LastDeliveryError, "SMTP") {
		t.Fatalf("the recorded outcome does not name the missing relay: %q", after.LastDeliveryError)
	}

	// And the claim it took is keyed on the unit, not merely on the host. This is the shape the next
	// test depends on, asserted here so that a failure there is about suppression rather than about
	// the key having quietly lost a dimension.
	states := h.firingStates(t)
	if st, ok := states["nginx.service"]; !ok || !st.Firing || st.LastNotified.IsZero() {
		t.Fatalf("the firing is not recorded against the unit: %+v", states)
	}
}

// TestASecondFailingUnitIsNotSilencedByTheFirst is the bug the Subject dimension was added for.
//
// nginx failing at 09:00 and postgresql failing at 09:05 are two incidents on one machine, and under a
// cooldown keyed on (rule, host) the second one lost the claim to the first: no mail, and — because
// losing a claim is not an error — no record that no mail went out either. The operator sees a rule
// whose last delivery is about nginx and has no way to learn that anything else happened.
//
// The two events are routed inside one cooldown deliberately. That is the whole difficulty: any pair of
// events far enough apart would mail twice regardless of how the key is built.
func TestASecondFailingUnitIsNotSilencedByTheFirst(t *testing.T) {
	h := newAlertHarness(t)
	h.unitRule(t, "rule-units")
	counting := h.counting()

	h.server.routeEventMail(context.Background(), counting,
		unitEvent(notify.KindServiceFailed, "host-1", "nginx.service"))
	h.server.routeEventMail(context.Background(), counting,
		unitEvent(notify.KindServiceFailed, "host-1", "postgresql.service"))

	if counting.count() != 2 {
		t.Fatalf("two failing units on one host produced %d delivery attempts, expected 2: %v",
			counting.count(), counting.attempts)
	}
	states := h.firingStates(t)
	for _, unit := range []string{"nginx.service", "postgresql.service"} {
		st, ok := states[unit]
		if !ok {
			t.Fatalf("%s has no firing of its own: %+v", unit, states)
		}
		if !st.Firing || st.HostID != "host-1" {
			t.Fatalf("%s: %+v", unit, st)
		}
	}
	if len(states) != 2 {
		t.Fatalf("two units produced %d firings: %+v", len(states), states)
	}

	// The same unit again, inside the cooldown, is the case the cooldown is *for*: a restart-looping
	// unit must not mail on every loop. Asserted here so that "two units notify twice" cannot be
	// satisfied by a build that simply stopped suppressing anything.
	h.server.routeEventMail(context.Background(), counting,
		unitEvent(notify.KindServiceFailed, "host-1", "nginx.service"))
	if counting.count() != 2 {
		t.Fatalf("the same unit failing again inside its cooldown mailed anyway: %v", counting.attempts)
	}
}

// TestARecoveryReleasesTheFiringAndOnlySpeaksForOneItToldAbout is the un-firing half.
//
// A rule that fires must also un-fire, and for a unit there is no evaluator pass that could notice: the
// recovery event is the only thing that knows. The second half is the one that is easy to get wrong in
// the other direction — a recovery for a unit nobody was ever told about must send nothing, because the
// alternative is a mail saying a service somebody never heard of is working again, which is how a
// recipient list learns to filter the folder.
func TestARecoveryReleasesTheFiringAndOnlySpeaksForOneItToldAbout(t *testing.T) {
	h := newAlertHarness(t)
	h.unitRule(t, "rule-units")
	counting := h.counting()

	h.server.routeEventMail(context.Background(), counting,
		unitEvent(notify.KindServiceFailed, "host-1", "nginx.service"))
	if counting.count() != 1 {
		t.Fatalf("the firing did not mail: %v", counting.attempts)
	}

	h.server.routeEventMail(context.Background(), counting,
		unitEvent(notify.KindServiceRecovered, "host-1", "nginx.service"))
	if counting.count() != 2 {
		t.Fatalf("the recovery of a firing unit produced %d attempts in total, expected 2: %v",
			counting.count(), counting.attempts)
	}
	if st := h.firingStates(t)["nginx.service"]; st.Firing {
		t.Fatalf("the recovery left the rule firing: %+v", st)
	}

	// A unit that never failed recovering: nothing was claimed for it, so nothing is released and
	// nobody is told. The release is the compare-and-set that decides, which is also what makes two
	// control planes send one recovery between them rather than one each.
	h.server.routeEventMail(context.Background(), counting,
		unitEvent(notify.KindServiceRecovered, "host-1", "redis.service"))
	if counting.count() != 2 {
		t.Fatalf("a recovery for a unit nobody was told about mailed anyway: %v", counting.attempts)
	}
	if _, told := h.firingStates(t)["redis.service"]; told {
		t.Fatal("a recovery created firing state for a unit that never fired")
	}
}

// TestAFlappingUnitNotifiesOnceInsideItsCooldown is the property that replaced a real bug.
//
// A unit in a restart loop crosses its line every few seconds: fail, recover, fail again. The recovery
// clears the firing — it has to, or the rule shows an incident that has resolved — but it must *keep*
// the cooldown stamp, because clearing both hands the next firing a clean slate and the condition mails
// on every crossing, for ever. That was the behaviour before ReleaseAlertFiring existed as something
// separate from claiming.
//
// The count that matters is the firing one: one mail about nginx failing, not two. The recovery in
// between is a second delivery and is meant to be — it is the end of the story whose beginning was
// told, and it is deliberately not cooled down.
func TestAFlappingUnitNotifiesOnceInsideItsCooldown(t *testing.T) {
	h := newAlertHarness(t)
	h.unitRule(t, "rule-units")
	counting := h.counting()
	ctx := context.Background()

	h.server.routeEventMail(ctx, counting, unitEvent(notify.KindServiceFailed, "host-1", "nginx.service"))
	afterFiring := counting.count()

	h.server.routeEventMail(ctx, counting,
		unitEvent(notify.KindServiceRecovered, "host-1", "nginx.service"))
	afterRecovery := counting.count()

	h.server.routeEventMail(ctx, counting, unitEvent(notify.KindServiceFailed, "host-1", "nginx.service"))
	afterSecondFiring := counting.count()

	switch {
	case afterFiring != 1:
		t.Fatalf("the first firing produced %d attempts: %v", afterFiring, counting.attempts)
	case afterRecovery != 2:
		t.Fatalf("the recovery produced %d attempts in total: %v", afterRecovery, counting.attempts)
	case afterSecondFiring != 2:
		t.Fatalf("a second firing inside the cooldown mailed again; the recovery reset the "+
			"cooldown: %v", counting.attempts)
	}

	// And the cooldown stamp is still there afterwards, which is the mechanism rather than the
	// symptom: the release cleared Firing and left LastNotified alone.
	st := h.firingStates(t)["nginx.service"]
	if st.LastNotified.IsZero() {
		t.Fatalf("the firing lost its cooldown stamp: %+v", st)
	}
}

// TestARuleWatchingSomethingElseIsNotMailedAboutAUnit keeps event routing narrow.
//
// The condition a rule watches is what it is subscribed to, and a unit_failed event reaching a
// job_failed rule would be an alert about something the recipient did not ask to hear about — which
// costs more than a missed mail, because a rule that pages about the wrong thing gets disabled and then
// misses the thing it was for.
func TestARuleWatchingSomethingElseIsNotMailedAboutAUnit(t *testing.T) {
	h := newAlertHarness(t)
	other := h.routingFixture(t)
	counting := h.counting()

	h.server.routeEventMail(context.Background(), counting,
		unitEvent(notify.KindServiceFailed, "host-1", "nginx.service"))

	if counting.count() != 0 {
		t.Fatalf("a job_failed rule was mailed about a unit: %v", counting.attempts)
	}
	if after := h.deliveryOutcome(t, other.ID); !after.LastDeliveryAt.IsZero() {
		t.Fatalf("the rule records a delivery it should never have attempted: %q",
			after.LastDeliveryError)
	}
}

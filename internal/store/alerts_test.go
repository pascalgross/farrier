package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestOnlyOneClaimantMayNotifyPerCooldown is what makes the cooldown a cooldown.
//
// Reading the last notification and then writing it are two statements, and the control plane delivers
// every event on its own goroutine: two units failing on one heartbeat both read "nothing recent" and
// both mail, which is the restart-loop noise the cooldown exists to stop. On a hosted installation
// there is more than one control-plane process, so nothing in Go could fix it either — the claim has
// to be one operation in the store.
//
// Run against both implementations, because the two solve it with different primitives — one statement
// with a WHERE on the conflict target, and a mutex — and the in-memory one is what most of the server
// tests run against.
func TestOnlyOneClaimantMayNotifyPerCooldown(t *testing.T) {
	eachScoped(t, func(t *testing.T, _ Store, tenant Scoped) {
		ctx := context.Background()
		now := time.Now().UTC().Truncate(time.Millisecond)
		if err := tenant.CreateAlertRule(ctx, AlertRule{
			ID: "01JRULE", Condition: ConditionUnitFailed, CooldownSeconds: 3600,
			EmailTo: []string{"oncall@example.com"}, Enabled: true, CreatedAt: now, CreatedBy: "test",
		}); err != nil {
			t.Fatalf("creating the rule: %v", err)
		}

		const racers = 8
		var wg sync.WaitGroup
		results := make([]bool, racers)
		errs := make([]error, racers)
		start := make(chan struct{})
		for i := range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[i], errs[i] = tenant.ClaimAlertNotification(
					ctx, "01JRULE", "01JHOST", now, time.Hour)
			}()
		}
		close(start)
		wg.Wait()

		won := 0
		for i := range racers {
			if errs[i] != nil {
				t.Fatalf("claim %d failed: %v", i, errs[i])
			}
			if results[i] {
				won++
			}
		}
		if won != 1 {
			t.Fatalf("%d of %d concurrent claims won; exactly one may", won, racers)
		}

		// Inside the cooldown, nobody else gets it.
		if again, err := tenant.ClaimAlertNotification(
			ctx, "01JRULE", "01JHOST", now.Add(time.Minute), time.Hour); err != nil || again {
			t.Fatalf("a claim inside the cooldown: won=%v err=%v", again, err)
		}

		// Past it, the next caller does — a claim that never released would be a rule that notified
		// once and then went quiet for ever, which is worse than notifying twice.
		if later, err := tenant.ClaimAlertNotification(
			ctx, "01JRULE", "01JHOST", now.Add(2*time.Hour), time.Hour); err != nil || !later {
			t.Fatalf("a claim past the cooldown: won=%v err=%v", later, err)
		}

		// And the claim left a state row the evaluator can read, rather than a bare timestamp.
		states, err := tenant.ListAlertStates(ctx)
		if err != nil {
			t.Fatalf("listing states: %v", err)
		}
		if len(states) != 1 || states[0].RuleID != "01JRULE" || !states[0].Firing {
			t.Fatalf("the claim did not record a usable state: %+v", states)
		}
	})
}

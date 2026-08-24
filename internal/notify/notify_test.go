package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestTheEventVocabularyIsTheExpectedSet keeps the kind list closed the way the intent catalogue is.
//
// Adding a kind means editing this literal in the same commit, which is deliberate friction: a kind is
// a word operators build filters and dashboards on, and it should arrive through review rather than
// through a handler inventing one under deadline.
func TestTheEventVocabularyIsTheExpectedSet(t *testing.T) {
	expected := map[Kind]bool{
		"host.enrolled":     true,
		"host.silent":       true,
		"host.recovered":    true,
		"job.created":       true,
		"job.approved":      true,
		"job.failed":        true,
		"job.expired":       true,
		"service.failed":    true,
		"service.recovered": true,
		"updates.pending":   true,
		"updates.resolved":  true,
		"reboot.overdue":    true,
		"reboot.done":       true,
	}
	for kind := range expected {
		if !Kinds[kind] {
			t.Errorf("%q is expected and missing from the vocabulary", kind)
		}
	}
	for kind := range Kinds {
		if !expected[kind] {
			t.Errorf("%q is in the vocabulary and not in the expected set; add it here in the same "+
				"commit, with a reason", kind)
		}
	}
	if Kind("job.fail").Valid() || !KindJobFailed.Valid() {
		t.Error("Valid does not answer for the set")
	}
}

// countingSink records how often it was asked to deliver and fails a fixed number of times first.
type countingSink struct {
	// failures is how many attempts fail before one succeeds; more than DeliveryAttempts never
	// succeeds.
	failures int

	// attempts counts every call.
	attempts int
}

// Name identifies the sink.
func (c *countingSink) Name() string { return "counting" }

// Deliver fails for the first `failures` calls and then succeeds.
func (c *countingSink) Deliver(context.Context, Event) error {
	c.attempts++
	if c.attempts <= c.failures {
		return errors.New("the relay was restarting")
	}
	return nil
}

// withBackoff shortens the retry pause for the length of one test and puts it back afterwards.
//
// The package-level variable is the seam, and leaving it shortened would make a later test's timing
// assertion pass for the wrong reason — the failure mode that makes a suite stop meaning anything.
func withBackoff(t *testing.T, pauses ...time.Duration) {
	t.Helper()
	held := deliveryBackoff
	deliveryBackoff = pauses
	t.Cleanup(func() { deliveryBackoff = held })
}

// TestARetriedDeliverySurvivesATransientFailure is the case the retry exists for: an alert lost to a
// relay that was restarting is an alert whose absence somebody would have trusted.
func TestARetriedDeliverySurvivesATransientFailure(t *testing.T) {
	withBackoff(t, time.Millisecond, time.Millisecond)
	sink := &countingSink{failures: 1}
	if err := DeliverWithRetry(context.Background(), sink, Event{Kind: "host.silent"}); err != nil {
		t.Fatalf("a delivery that succeeded on the second attempt reported failure: %v", err)
	}
	if sink.attempts != 2 {
		t.Fatalf("expected two attempts, got %d", sink.attempts)
	}
}

// TestAPermanentFailureIsReportedRatherThanRetriedForEver bounds the retry and returns the reason.
//
// The returned error is the whole point: it is what the caller stamps on the alert rule, and "it
// never went out" has to be something an operator can read rather than something only a log knows.
func TestAPermanentFailureIsReportedRatherThanRetriedForEver(t *testing.T) {
	withBackoff(t, time.Millisecond, time.Millisecond)
	sink := &countingSink{failures: DeliveryAttempts}
	err := DeliverWithRetry(context.Background(), sink, Event{Kind: "host.silent"})
	if err == nil {
		t.Fatal("a sink that never succeeded reported success")
	}
	if sink.attempts != DeliveryAttempts {
		t.Fatalf("expected %d attempts, got %d", DeliveryAttempts, sink.attempts)
	}
	if !strings.Contains(err.Error(), "the relay was restarting") {
		t.Fatalf("the reason did not survive into the error an operator reads: %v", err)
	}
}

// TestACancelledContextStopsRetryingImmediately keeps a shutdown from waiting out the backoff.
func TestACancelledContextStopsRetryingImmediately(t *testing.T) {
	withBackoff(t, time.Hour, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sink := &countingSink{failures: DeliveryAttempts}
	start := time.Now()
	if err := DeliverWithRetry(ctx, sink, Event{Kind: "host.silent"}); err == nil {
		t.Fatal("a cancelled delivery reported success")
	}
	if sink.attempts != 1 {
		t.Fatalf("a cancelled context still made %d attempts", sink.attempts)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the backoff was waited out despite cancellation: %s", elapsed)
	}
}

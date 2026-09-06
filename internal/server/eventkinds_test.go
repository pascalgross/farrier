package server

import (
	"context"
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/notify"
	"github.com/pascalgross/hostseal/internal/store"
)

// TestAnEventOutsideTheVocabularyIsRefusedRatherThanDelivered pins the closed set at the emit boundary.
//
// The vocabulary is closed the way the intent catalogue is, and for the same reason: a kind is what a
// webhook filter, an alert-rule condition and the interface's icon table each match on. An event
// carrying a kind none of them knows reaches all three looking delivered and is read by none, which is
// a worse outcome than its absence — the absence is at least findable by somebody going to look.
//
// Recorded and broadcast are checked together because they are the two halves of "it got in": the inbox
// is the durable copy and the stream is the live one, and an event that reached either would be an
// event a filter cannot match sitting where operators read.
func TestAnEventOutsideTheVocabularyIsRefusedRatherThanDelivered(t *testing.T) {
	h := newAlertHarness(t)

	live, release := h.server.events.subscribe(h.tenant)
	defer release()

	_, _, recorded := h.server.record(context.Background(), h.tenant, notify.Event{
		Kind:    notify.Kind("job.fail"),
		HostID:  "host-1",
		Summary: "a kind one letter away from a real one",
		At:      time.Now().UTC(),
	})
	if recorded {
		t.Error("record reported that it stored an event whose kind is outside the closed set")
	}

	events, err := h.scoped.ListEvents(context.Background(), store.EventFilter{})
	if err != nil {
		t.Fatalf("listing the inbox: %v", err)
	}
	for _, e := range events {
		if e.Kind == "job.fail" {
			t.Errorf("an event with the invented kind %q reached the inbox", e.Kind)
		}
	}

	select {
	case got := <-live:
		t.Errorf("an event with the invented kind %q reached an open tab", got.Kind)
	default:
	}
}

// TestAValidEventIsStillRecorded is what makes the refusal above mean anything.
//
// Without it, "nothing reached the inbox" would also be what a record() broken in some entirely
// different way produced, and the test above would pass on a control plane that recorded no events at
// all.
func TestAValidEventIsStillRecorded(t *testing.T) {
	h := newAlertHarness(t)

	_, _, recorded := h.server.record(context.Background(), h.tenant, notify.Event{
		Kind:    notify.KindJobFailed,
		HostID:  "host-1",
		Summary: "a real kind",
		At:      time.Now().UTC(),
	})
	if !recorded {
		t.Fatal("record refused an event whose kind is in the closed set")
	}

	if summaries := h.eventSummaries(t, string(notify.KindJobFailed)); len(summaries) != 1 {
		t.Fatalf("a valid event produced %d inbox rows, want 1: %v", len(summaries), summaries)
	}
}

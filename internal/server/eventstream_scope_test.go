package server_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/server"
	"github.com/pascalgross/hostseal/internal/store"
)

// issueTokenIn mints an enrolment token in a named fleet.
//
// The harness's own issueToken always writes into its first tenant, which is what almost every test
// wants and is exactly wrong here: a cross-tenant assertion needs an event that genuinely belongs to
// the *other* fleet, and an event manufactured in the first one would prove nothing about the boundary.
func (h *harness) issueTokenIn(t *testing.T, tenant store.TenantID, group string) string {
	t.Helper()

	token, hash, err := server.NewEnrollmentToken()
	if err != nil {
		t.Fatalf("generating a token: %v", err)
	}
	err = h.store.In(tenant).CreateEnrollmentToken(context.Background(), store.EnrollmentToken{
		Hash: hash, Label: "test", Group: group,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("storing a token in %s: %v", tenant, err)
	}
	return token
}

// openEventStream connects one operator's live feed and returns the frames it receives.
//
// The greeting is consumed here, and that is the synchronisation this whole test rests on: the handler
// subscribes before writing it, so an event emitted after the greeting has arrived cannot fall into a
// gap between the subscription and the read. Without that, "no event arrived" would be indistinguishable
// from "the event was emitted a moment too early".
//
// The frames channel is closed when the connection ends, so a reader can tell a stream that finished
// from one that has merely gone quiet.
func (h *harness) openEventStream(t *testing.T, token string) <-chan listedEvent {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("connecting the stream: %v", err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the stream answered %d", res.StatusCode)
	}

	reader := bufio.NewReader(res.Body)
	greeting, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(greeting, ": connected") {
		t.Fatalf("no greeting: %q, %v", greeting, err)
	}

	frames := make(chan listedEvent, 16)
	go func() {
		defer close(frames)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			payload, ok := strings.CutPrefix(strings.TrimSpace(line), "data: ")
			if !ok {
				continue
			}
			var view listedEvent
			if json.Unmarshal([]byte(payload), &view) != nil {
				continue
			}
			frames <- view
		}
	}()
	return frames
}

// TestGuaranteeTheEventStreamNeverCrossesATenantBoundary applies docs/SECURITY.md §5 to the newest read
// path in the control plane.
//
// The listing endpoint is already asserted across two fleets and the live stream is already asserted to
// deliver — but nothing put the two together, and the stream is the one read path where the scoping is
// not a store predicate at all. Every other tenant-scoped read reaches the database through a handle
// that cannot be built without a tenant, and layer 3 of §5.2 refuses the row underneath it if the
// handler somehow forgets. A broadcast has neither: it is an in-process map from tenant to open
// sockets, and the only thing standing between one customer's incidents and another customer's browser
// is the key this handler subscribes under. That is exactly the kind of boundary §5 says is enforced by
// a rule rather than by remembering, and here it is enforced by remembering — so it belongs in the
// check that cannot be skipped.
//
// The test is built so that it cannot pass by nothing arriving. Alpha's event is emitted first and
// beta's second, and the assertion is on the frames beta actually received: a leak puts alpha's event
// on the wire *before* the one that proves the stream was working at all.
func TestGuaranteeTheEventStreamNeverCrossesATenantBoundary(t *testing.T) {
	h := newHarness(t)
	frames := h.openEventStream(t, h.otherToken)

	// One fleet's event, then the other's, in that order.
	h.enrolHost(t, "alpha-host", h.issueToken(t, "web-prod"))
	h.enrolHost(t, "beta-host", h.issueTokenIn(t, h.otherTenant, "beta-prod"))

	var received []listedEvent
	deadline := time.After(5 * time.Second)
	for {
		select {
		case view, open := <-frames:
			if !open {
				t.Fatalf("the stream closed before beta's own event arrived: %+v", received)
			}
			received = append(received, view)
			if view.Summary != "" && strings.Contains(view.Summary, "beta-host") {
				// Beta's event has arrived, so anything of alpha's that was going to leak has had at
				// least as long to. A short drain catches an implementation that delivers in the other
				// order.
				drain := time.After(300 * time.Millisecond)
				for draining := true; draining; {
					select {
					case more, open := <-frames:
						if !open {
							draining = false
							break
						}
						received = append(received, more)
					case <-drain:
						draining = false
					}
				}
				assertOnlyBetasEvents(t, received)
				return
			}
		case <-deadline:
			t.Fatalf("beta's own event never reached beta's stream; received %+v", received)
		}
	}
}

// assertOnlyBetasEvents fails unless every frame belongs to the fleet that opened the stream.
//
// Split out so the failure names the offending event rather than a boolean: the whole value of this
// assertion in an incident is being able to say which event crossed and from where.
func assertOnlyBetasEvents(t *testing.T, received []listedEvent) {
	t.Helper()
	if len(received) == 0 {
		t.Fatal("no events arrived at all; this test cannot distinguish a scoped stream from a broken one")
	}
	for _, view := range received {
		if strings.Contains(view.Summary, "alpha-host") {
			t.Errorf("another fleet's event arrived on this stream: %+v", view)
		}
	}
	if len(received) != 1 {
		t.Errorf("the stream carried %d events for one enrolment: %+v", len(received), received)
	}
}

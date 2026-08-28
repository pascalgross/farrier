// Package notify delivers events from the control plane to things outside it.
//
// This is the one seam the *server* may extend at run time: an operator can configure a webhook without
// recompiling anything. It is safe for one reason, and the reason is the whole asymmetry the design
// rests on — **sinks send data out; nothing sends code in.** Everything that runs on a managed host is
// closed at compile time; everything that leaves the control plane is open.
//
// A sink is therefore allowed to be a URL from a configuration file, which no part of the agent ever
// is.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Event is something worth telling an operator about.
type Event struct {
	// Kind is a stable machine-readable event type, such as "host.enrolled".
	//
	// Typed rather than a plain string, so that the closed vocabulary in kinds.go is visible at every
	// site that fills this in. It does not make an invalid kind impossible — an untyped literal still
	// assigns — and that is why the server refuses one at the boundary where events are recorded. What
	// the type does is make the other route, a kind derived from a field at run time, an explicit
	// conversion that a reviewer sees rather than an assignment that reads like every other.
	Kind Kind `json:"kind"`

	// TenantID is the fleet this event belongs to.
	//
	// Carried on the event rather than only known by the caller so that a sink, a log line or a future
	// audit reader can say whose event it was without having to have been told separately — and so that
	// an event which somehow reached the wrong endpoint is identifiable as such rather than looking
	// like an ordinary one.
	TenantID string `json:"tenantId,omitempty"`

	// HostID is the host the event concerns, empty for fleet-wide events.
	HostID string `json:"hostId,omitempty"`

	// Hostname is included for readability, because a webhook lands in a chat window where an opaque
	// identifier helps nobody.
	Hostname string `json:"hostname,omitempty"`

	// Summary is one line of human-readable text.
	Summary string `json:"summary"`

	// At is when the event happened, by the control plane's clock.
	At time.Time `json:"at"`

	// Detail carries event-specific fields.
	Detail map[string]any `json:"detail,omitempty"`
}

// Sink delivers an event to something outside Farrier.
type Sink interface {
	// Name identifies the sink in logs and in the UI.
	Name() string

	// Deliver sends one event.
	//
	// It must not block indefinitely: a slow webhook endpoint must not be able to hold up the control
	// plane, so every implementation carries its own deadline rather than trusting the caller's.
	Deliver(ctx context.Context, ev Event) error
}

// Webhook posts events as JSON to a URL.
type Webhook struct {
	// name identifies this sink.
	name string

	// url is where events are posted.
	url string

	// client carries the timeout.
	client *http.Client
}

// NewWebhook returns a sink that posts events as JSON.
func NewWebhook(name, url string) *Webhook {
	return &Webhook{
		name: name,
		url:  url,
		// A short timeout on purpose. An event that did not reach a chat channel is a small loss; a
		// control plane whose event loop is held open by an unresponsive endpoint is a large one.
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Name identifies the sink in logs and in the UI.
func (w *Webhook) Name() string { return w.name }

// Deliver posts one event as JSON.
func (w *Webhook) Deliver(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("notify: encoding event: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: posting to %s: %w", w.name, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode >= 300 {
		return fmt.Errorf("notify: %s returned %s", w.name, res.Status)
	}
	return nil
}

// DeliveryAttempts is how many times a delivery is tried before it is given up on.
//
// Three, with a short backoff between them, because the failures alerting actually hits are transient
// — a relay refusing a connection during its own restart, a webhook endpoint behind a rolling deploy
// — and one attempt turns a ten-second outage into a page nobody received. Beyond three the failure
// is not transient, and the honest answer is the recorded error rather than a queue that retries into
// next week.
const DeliveryAttempts = 3

// deliveryBackoff is the pause after each failed attempt.
//
// Bounded deliberately: the whole retry sequence has to fit inside the caller's patience, because the
// path this runs on is a request handler or one tick of the evaluator, not a background queue.
var deliveryBackoff = []time.Duration{2 * time.Second, 6 * time.Second}

// DeliverWithRetry attempts one delivery up to DeliveryAttempts times and returns the last failure.
//
// It exists because Deliver is required not to block, which makes each individual attempt short and
// therefore fragile. Retrying is what turns "the relay was restarting" into a delivered mail; the
// returned error is what turns "it never went out" into something the caller can record rather than
// only log — which for an alert is the difference between a silence somebody investigates and a
// silence somebody trusts.
//
// A cancelled context stops the sequence immediately: the process is shutting down, and finishing a
// backoff to attempt a delivery that will be cancelled anyway only delays the shutdown.
func DeliverWithRetry(ctx context.Context, sink Sink, ev Event) error {
	var err error
	for attempt := range DeliveryAttempts {
		if err = sink.Deliver(ctx, ev); err == nil {
			return nil
		}
		if attempt == DeliveryAttempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("notify: %s: %w (giving up: %w)", sink.Name(), err, ctx.Err())
		case <-time.After(deliveryBackoff[attempt]):
		}
	}
	return fmt.Errorf("notify: %s failed %d times, last error: %w", sink.Name(), DeliveryAttempts, err)
}

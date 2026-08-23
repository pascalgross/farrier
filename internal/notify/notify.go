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
	Kind string `json:"kind"`

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

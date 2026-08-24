package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/pascalgross/farrier/internal/notify"
	"github.com/pascalgross/farrier/internal/store"
)

// eventView is one event as the API renders it, on the list and on the stream alike.
//
// One type for both on purpose: a client that reconciles its live stream against the inbox must not
// have to translate between two spellings of the same event.
type eventView struct {
	// ID identifies the event, for reconciling the stream against the inbox.
	ID string `json:"id"`

	// Kind is one member of the closed vocabulary in internal/notify.
	Kind string `json:"kind"`

	// HostID is the host the event concerns, empty for fleet-wide events.
	HostID string `json:"hostId,omitempty"`

	// Hostname is carried for display.
	Hostname string `json:"hostname,omitempty"`

	// Summary is one line of human-readable text.
	Summary string `json:"summary"`

	// At is when the event happened, by the control plane's clock.
	At time.Time `json:"at"`

	// Detail carries event-specific fields.
	Detail map[string]any `json:"detail,omitempty"`
}

// eventStream fans live events out to the browser tabs subscribed to one tenant.
//
// It is in-process state, deliberately: the durable copy is the inbox in the store, and a subscriber
// that misses a broadcast — full buffer, reconnect, deploy — reconciles by reading the inbox, which
// is why dropping is an acceptable failure mode here and blocking is not.
type eventStream struct {
	// mu guards subscribers.
	mu sync.Mutex

	// subscribers holds each tenant's live channels.
	subscribers map[store.TenantID]map[chan eventView]struct{}
}

// subscribe registers one listener for a tenant and returns its channel and a release function.
//
// The channel is buffered so a briefly slow reader keeps its events; a reader slower than the buffer
// loses the oldest pending broadcast rather than holding the emitter, and recovers from the inbox.
func (b *eventStream) subscribe(tenant store.TenantID) (chan eventView, func()) {
	ch := make(chan eventView, 16)
	b.mu.Lock()
	if b.subscribers == nil {
		b.subscribers = map[store.TenantID]map[chan eventView]struct{}{}
	}
	if b.subscribers[tenant] == nil {
		b.subscribers[tenant] = map[chan eventView]struct{}{}
	}
	b.subscribers[tenant][ch] = struct{}{}
	b.mu.Unlock()

	return ch, func() {
		b.mu.Lock()
		delete(b.subscribers[tenant], ch)
		if len(b.subscribers[tenant]) == 0 {
			delete(b.subscribers, tenant)
		}
		b.mu.Unlock()
	}
}

// broadcast hands one event to every live subscriber of its tenant, never blocking.
//
// Deliver must not block is the Sink contract, and it binds here too even though this is not a Sink:
// a browser tab that stopped reading must not be able to hold up an enrolment. The dropped event is
// in the inbox.
func (b *eventStream) broadcast(tenant store.TenantID, view eventView) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subscribers[tenant] {
		select {
		case ch <- view:
		default:
		}
	}
}

// deliveryBudget bounds one sink's full retry sequence.
//
// Sized from the retry policy rather than guessed: three attempts at a fifteen-second sink plus the
// eight seconds of backoff between them, rounded up. A budget shorter than the retries it is meant to
// allow would turn "the relay was restarting" into a cancellation that looks like a relay fault.
//
// It is per sink and not per pass, so that a dead webhook cannot silently eat the alert mail behind
// it — the two have nothing to do with each other and fail independently.
const deliveryBudget = 60 * time.Second

// outboundPassBudget bounds one detached pass end to end.
//
// Every sink has its own budget, so this is not what stops a slow relay; it is what stops a pass that
// is *not* talking to a sink at all. A pass reads the tenant row, the rules and their states, and an
// unreachable database has no deadline of its own here — without this ceiling those reads would park
// a goroutine until the process stopped. Three minutes is comfortably more than a webhook and a
// handful of rules' mail need, and finite, which is the property that matters.
const outboundPassBudget = 3 * time.Minute

// maxOutboundInFlight caps the detached passes running at once.
//
// The cap and outboundPassBudget together are the whole bound: at worst this many goroutines for that
// long. Without them, a fleet flapping against a sink that is down converts every event into a
// goroutine, and the pile-up outlasts the incident that caused it. Past the cap a pass is refused with
// a log line — which is the correct loss, because the event is already in the inbox and the inbox is
// the delivery that was promised.
const maxOutboundInFlight = 64

// emit records an event durably, shows it to open tabs, and delivers it outside best-effort.
//
// The order is the design. The inbox write comes first because it is the only delivery with a
// guarantee: the stream is a tab that may be closed, the webhook is an endpoint that may be down, and
// best-effort delivery must look best-effort — an event that reached nobody live is still on the page
// when somebody looks. Failures beyond the inbox are logged and never propagated; a webhook being
// down must not fail an enrolment.
//
// Everything that leaves the process runs detached from the caller, and that is not an optimisation.
// emit is called from request handlers an agent is waiting on, and a sink that has gone away costs
// its full timeout — three retries against a dead relay would otherwise add a minute to a heartbeat,
// which is a control plane made slow by somebody else's mail server. The detachment is bounded and
// drained: each pass carries outboundPassBudget, no more than maxOutboundInFlight run at once, and
// ListenAndServe waits for the outstanding ones so a shutdown does not abandon an alert mid-SMTP.
//
// The tenant is a parameter and not a convenience. An event goes to the endpoint and the tabs of its
// own tenant, and to nowhere else, and it carries its tenant so that one which somehow arrived in the
// wrong place is identifiable as such rather than looking like an ordinary event.
func (s *Server) emit(ctx context.Context, tenantID store.TenantID, ev notify.Event) {
	ev.TenantID = string(tenantID)
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	if !notify.Kind(ev.Kind).Valid() {
		// A programming error, not a data error: kinds are compile-time constants. Logged loudly and
		// still delivered, because losing the event would hide the incident behind the typo.
		slog.Error("an event was emitted with a kind outside the closed vocabulary", "kind", ev.Kind)
	}

	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()

	view := eventView{
		Kind:     ev.Kind,
		HostID:   ev.HostID,
		Hostname: ev.Hostname,
		Summary:  ev.Summary,
		At:       ev.At,
		Detail:   ev.Detail,
	}
	if id, err := NewID(); err == nil {
		view.ID = id
	} else {
		slog.Error("could not generate an event id", "error", err)
	}

	scoped := s.cfg.Store.In(tenantID)
	if err := scoped.RecordEvent(recordCtx, store.Event{
		ID:       view.ID,
		Kind:     view.Kind,
		HostID:   view.HostID,
		Hostname: view.Hostname,
		Summary:  view.Summary,
		At:       view.At,
		Detail:   view.Detail,
	}); err != nil {
		slog.Error("could not record an event in the inbox",
			"tenant", tenantID, "kind", ev.Kind, "error", err)
	}

	s.events.broadcast(tenantID, view)

	// The refusal is logged by detach and otherwise ignored here, unlike in notifyAlert. A refused
	// pass means the webhook and any event-routed mail did not go out, which leaves an event in the
	// inbox with no delivery beside it — whereas a refused *alert* pass has a rule whose cooldown the
	// evaluator has already stamped, so there is both somewhere to record it and an obligation to.
	_, _ = s.detach("event delivery", func(outCtx context.Context) {
		s.deliverOutside(outCtx, scoped, ev)
	})
}

// detach runs work outside the caller's request, tracked so a shutdown can drain it.
//
// The context it hands over is derived from the server's own rather than from the caller's, which is
// the whole point: emit is called from handlers an agent is waiting on and from the evaluator's tick,
// and neither should be able to end a delivery early or be held open by one. Each sink inside applies
// its own deliveryBudget; drainOutbound bounds how long a stopping process honours them.
//
// Once the drain has begun, work is refused rather than started. That is what makes the WaitGroup
// safe — a counter going from zero back up while somebody is waiting on it is a documented misuse —
// and it is also the honest behaviour: a delivery begun during shutdown would be cancelled seconds
// later, and the event is in the inbox either way.
func (s *Server) detach(what string, work func(context.Context)) (started bool, reason string) {
	s.outboundMu.Lock()
	switch {
	case s.draining:
		s.outboundMu.Unlock()
		reason = "the control plane was stopping and did not start this delivery"
		slog.Warn("an outbound delivery was dropped: "+reason, "delivery", what)
		return false, reason
	case s.inFlight >= maxOutboundInFlight:
		s.outboundMu.Unlock()
		reason = "too many deliveries were already in flight; this one was not started"
		slog.Warn("an outbound delivery was dropped: "+reason,
			"delivery", what, "limit", maxOutboundInFlight)
		return false, reason
	}
	s.inFlight++
	s.outbound.Add(1)
	s.outboundMu.Unlock()

	go func() {
		defer func() {
			s.outboundMu.Lock()
			s.inFlight--
			s.outboundMu.Unlock()
			s.outbound.Done()
		}()
		passCtx, done := context.WithTimeout(s.outboundCtx, outboundPassBudget)
		defer done()
		work(passCtx)
	}()
	return true, ""
}

// deliverOutside posts the event to the tenant's webhook and mails the rules that route it.
//
// Split out of emit so the part that leaves the process is one function with one budget, and so the
// part that must be synchronous — the inbox, the stream — cannot accidentally grow a network call.
func (s *Server) deliverOutside(ctx context.Context, scoped store.Scoped, ev notify.Event) {
	tenantID := scoped.Tenant()

	// The webhook read is allowed to fail without taking mail with it. The two deliveries have
	// nothing to do with each other, and an unreadable tenant row silently suppressing every alert
	// mail for an event — with nothing stamped on the rule to say so — is the failure this whole
	// section exists to avoid.
	switch tenant, err := s.cfg.Store.GetTenant(ctx, tenantID); {
	case err != nil:
		slog.Warn("could not read a tenant to deliver its events to a webhook",
			"tenant", tenantID, "kind", ev.Kind, "error", err)
	case tenant.WebhookURL != "":
		// Constructed per event rather than cached. Events are rare, and a cache keyed on a URL an
		// administrator can change is a cache that eventually posts a customer's events to an
		// endpoint they have already revoked.
		sink := notify.NewWebhook("tenant-webhook", tenant.WebhookURL)
		hookCtx, done := context.WithTimeout(ctx, deliveryBudget)
		err := notify.DeliverWithRetry(hookCtx, sink, ev)
		done()
		if err != nil {
			slog.Warn("event delivery failed",
				"tenant", tenantID, "sink", sink.Name(), "kind", ev.Kind, "error", err)
		}
	}

	s.routeEventMail(ctx, scoped, ev)
}

// handleListEvents returns the inbox, newest first.
//
// This is the durable half of the notification design: the stream tells an open tab, and this tells
// everybody else — including the operator asking "what did I miss overnight", which is the question
// the whole feature exists for.
func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request, who operator) {
	query := r.URL.Query()
	limit := 0
	if raw := query.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > store.MaxEventLimit {
			writeError(w, http.StatusBadRequest, "malformed",
				"limit must be a whole number between 1 and "+strconv.Itoa(store.MaxEventLimit))
			return
		}
		limit = n
	}

	events, err := who.Store.ListEvents(r.Context(), store.EventFilter{
		Kind:  query.Get("kind"),
		Limit: limit,
	})
	if err != nil {
		slog.Error("could not list events", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the events")
		return
	}

	views := make([]eventView, 0, len(events))
	for _, e := range events {
		views = append(views, eventView{
			ID: e.ID, Kind: e.Kind, HostID: e.HostID, Hostname: e.Hostname,
			Summary: e.Summary, At: e.At, Detail: e.Detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events":     views,
		"serverTime": time.Now().UTC(),
	})
}

// streamHeartbeatInterval paces the comment lines that keep an idle stream's connection alive.
//
// Below the server's own 120-second idle timeout and below the common proxy defaults, for the same
// reason the job long-poll holds twenty-five seconds: an idle timeout firing mid-stream looks like
// network flakiness and is debugged as such for weeks.
const streamHeartbeatInterval = 25 * time.Second

// handleEventStream is the in-app live feed: server-sent events, one per emitted event.
//
// SSE rather than WebSocket because the traffic is strictly one-way — a notification is never
// actionable, so there is nothing for the browser to send — and because EventSource reconnects by
// itself, which is the half of the protocol somebody would otherwise write badly in a weekend.
//
// A tab that falls behind is dropped from the broadcast, not waited for; it reconciles against
// GET /api/v1/events, which is the durable copy. Scoping is the operator's tenant, like every other
// admin route: a notification is a read of control-plane state and is authorised like one.
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request, who operator) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "unstreamable",
			"this connection cannot stream")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	// no-store, and never buffered by an intermediary: an event stream in a shared cache is one
	// customer's incidents replayed to whoever asks next.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	events, release := s.events.subscribe(who.Store.Tenant())
	defer release()

	heartbeat := time.NewTicker(streamHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			// A comment line, not an event: it keeps NAT tables and proxies convinced the connection
			// is alive without every client having to filter a fake event kind.
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		case view := <-events:
			encoded, err := json.Marshal(view)
			if err != nil {
				slog.Error("could not encode an event for the stream", "error", err)
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", encoded)
			flusher.Flush()
		}
	}
}

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/pascalgross/farrier/internal/notify"
	"github.com/pascalgross/farrier/internal/store"
)

// DefaultAlertCooldownSeconds is the re-notification pace a rule gets when its creator names none.
//
// Four hours: long enough that a condition which stays broken over lunch does not mail twice, short
// enough that a condition which stays broken overnight is not a single 03:00 mail somebody slept
// through. A rule that wants different says so.
const DefaultAlertCooldownSeconds = 4 * 60 * 60

// alertDigestThreshold is how many hosts may newly fire one rule in one pass before the
// notifications collapse into a single digest.
//
// The scenario is a network partition: a "host silent" rule evaluated against 300 unreachable hosts
// must send one mail, not 300 — an inbox full of identical pages is how the one different page gets
// missed.
const alertDigestThreshold = 3

// AlertEvaluationInterval is how often the evaluator re-reads fleet state.
//
// A minute matches the default heartbeat: evaluating faster than hosts report would only re-read the
// same answers, and slower would add latency to exactly the notifications that exist to be prompt.
const AlertEvaluationInterval = time.Minute

// RunAlertEvaluator evaluates every tenant's alert rules until the context ends.
//
// It runs in the server process rather than as a separate service because the rules are read from the
// same store and the notifications leave through the same sinks — a fourth deployable unit would buy
// nothing but a Compose file entry, which is the shape of cost this project refuses.
func (s *Server) RunAlertEvaluator(ctx context.Context) {
	ticker := time.NewTicker(AlertEvaluationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.evaluateAlerts(ctx, time.Now().UTC())
		}
	}
}

// evaluateAlerts runs one pass over every tenant.
//
// Failures are per tenant and logged: one customer's unreadable rules must not stop another
// customer's pager.
func (s *Server) evaluateAlerts(ctx context.Context, now time.Time) {
	tenants, err := s.cfg.Store.ListTenants(ctx)
	if err != nil {
		slog.Error("could not list tenants for alert evaluation", "error", err)
		return
	}
	for _, tenant := range tenants {
		if err := s.evaluateTenantAlerts(ctx, tenant.ID, now); err != nil {
			slog.Error("alert evaluation failed for a tenant", "tenant", tenant.ID, "error", err)
		}
	}
}

// factsProbe is the narrow slice of a stored facts document the evaluator and the services API read.
//
// A subset on purpose: unknown fields are ignored exactly as they are on the wire, so a facts
// document that grows does not break the reader that only ever wanted three numbers.
type factsProbe struct {
	// Packages carries the security backlog.
	Packages struct {
		// UpgradableSecurity is the number the product exists to show.
		UpgradableSecurity int `json:"upgradableSecurity"`
	} `json:"packages"`

	// Reboot carries the reboot-required flag.
	Reboot struct {
		// Required reports whether a reboot is needed.
		Required bool `json:"required"`
	} `json:"reboot"`

	// Services is systemd unit state, truncated to the protocol's cap.
	Services []unitProbe `json:"services"`

	// ServicesTruncated reports that the unit list was cut short — which means "no failed units"
	// and "the failed unit sorts after the cap" must not render identically.
	ServicesTruncated bool `json:"servicesTruncated"`
}

// unitProbe is one unit's state as the server reads it back out of stored facts.
type unitProbe struct {
	// Name is the unit name.
	Name string `json:"name"`

	// LoadState distinguishes a masked or missing unit from a loaded one.
	LoadState string `json:"loadState"`

	// ActiveState is the state transitions are detected on.
	ActiveState string `json:"activeState"`

	// SubState is the finer-grained state, carried for display.
	SubState string `json:"subState"`
}

// parseFactsProbe reads the evaluator's slice of a stored facts document.
func parseFactsProbe(raw []byte) (factsProbe, bool) {
	var probe factsProbe
	if len(raw) == 0 || json.Unmarshal(raw, &probe) != nil {
		return factsProbe{}, false
	}
	return probe, true
}

// evaluateTenantAlerts runs one pass over one tenant's evaluated rules.
//
// The state machine per (rule, host) is deliberately small: Since records when the raw condition
// started holding, Firing records whether the rule considers it an incident, and LastNotified is the
// cooldown's memory. Everything a restart must not forget lives in those three fields, persisted.
func (s *Server) evaluateTenantAlerts(ctx context.Context, tenantID store.TenantID, now time.Time) error {
	scoped := s.cfg.Store.In(tenantID)
	rules, err := scoped.ListAlertRules(ctx)
	if err != nil {
		return fmt.Errorf("listing rules: %w", err)
	}
	evaluated := make([]store.AlertRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Enabled && rule.Condition.Evaluated() {
			evaluated = append(evaluated, rule)
		}
	}
	if len(evaluated) == 0 {
		return nil
	}

	hosts, err := scoped.ListHosts(ctx)
	if err != nil {
		return fmt.Errorf("listing hosts: %w", err)
	}
	states, err := scoped.ListAlertStates(ctx)
	if err != nil {
		return fmt.Errorf("listing states: %w", err)
	}
	held := map[string]store.AlertState{}
	for _, st := range states {
		held[st.RuleID+"\x00"+st.HostID] = st
	}

	for _, rule := range evaluated {
		s.evaluateRule(ctx, scoped, rule, hosts, held, now)
	}
	return nil
}

// firingHost pairs a host with the summary its notification carries.
type firingHost struct {
	// host is the machine that crossed the rule's line.
	host store.Host

	// summary is the one line a notification carries for it.
	summary string
}

// evaluateRule advances one rule's state machine across the fleet and notifies on the transitions.
func (s *Server) evaluateRule(ctx context.Context, scoped store.Scoped, rule store.AlertRule,
	hosts []store.Host, held map[string]store.AlertState, now time.Time) {

	cooldown := time.Duration(rule.CooldownSeconds) * time.Second
	if cooldown <= 0 {
		cooldown = DefaultAlertCooldownSeconds * time.Second
	}

	var firing []firingHost
	for _, host := range hosts {
		if host.Revoked {
			continue
		}
		state := held[rule.ID+"\x00"+host.ID]
		state.RuleID, state.HostID = rule.ID, host.ID

		raw, summary := s.conditionHolds(rule, host, state, now)

		switch {
		case raw && state.Since.IsZero():
			state.Since = now
		case !raw:
			state.Since = time.Time{}
		}

		fire := raw && conditionRipe(rule, state, now)
		switch {
		case fire && !state.Firing:
			state.Firing = true
			state.LastNotified = now
			firing = append(firing, firingHost{host: host, summary: summary})
		case fire && state.Firing && now.Sub(state.LastNotified) >= cooldown:
			// Still broken past the cooldown: one reminder, not silence — a condition that fired
			// once at 03:00 and never again is indistinguishable from one that resolved.
			state.LastNotified = now
			firing = append(firing, firingHost{host: host, summary: summary})
		case !fire && state.Firing:
			state.Firing = false
			state.LastNotified = time.Time{}
			s.notifyAlert(ctx, scoped, rule, notify.Event{
				Kind:     string(recoveryKind(rule.Condition)),
				HostID:   host.ID,
				Hostname: host.Hostname,
				At:       now,
				Summary:  recoverySummary(rule, host),
				Detail:   map[string]any{"ruleId": rule.ID, "condition": string(rule.Condition)},
			})
		}

		if state != held[rule.ID+"\x00"+host.ID] {
			held[rule.ID+"\x00"+host.ID] = state
			if err := scoped.UpsertAlertState(ctx, state); err != nil {
				slog.Error("could not persist an alert state",
					"tenant", scoped.Tenant(), "rule", rule.ID, "host", host.ID, "error", err)
			}
		}
	}

	if len(firing) == 0 {
		return
	}
	if len(firing) > alertDigestThreshold {
		// The digest form: one notification naming the count and the first few hosts, because 300
		// identical pages during a partition is how the one different page gets missed.
		names := make([]string, 0, alertDigestThreshold)
		for _, f := range firing[:alertDigestThreshold] {
			names = append(names, f.host.Hostname)
		}
		s.notifyAlert(ctx, scoped, rule, notify.Event{
			Kind: string(firingKind(rule.Condition)),
			At:   now,
			Summary: strconv.Itoa(len(firing)) + " hosts " + conditionPhrase(rule) + ": " +
				strings.Join(names, ", ") + ", …",
			Detail: map[string]any{
				"ruleId": rule.ID, "condition": string(rule.Condition), "hosts": len(firing),
			},
		})
		return
	}
	for _, f := range firing {
		s.notifyAlert(ctx, scoped, rule, notify.Event{
			Kind:     string(firingKind(rule.Condition)),
			HostID:   f.host.ID,
			Hostname: f.host.Hostname,
			At:       now,
			Summary:  f.summary,
			Detail:   map[string]any{"ruleId": rule.ID, "condition": string(rule.Condition)},
		})
	}
}

// conditionHolds reports whether the raw condition is true for one host right now, and the summary a
// notification would carry.
func (s *Server) conditionHolds(rule store.AlertRule, host store.Host, state store.AlertState,
	now time.Time) (bool, string) {

	switch rule.Condition {
	case store.ConditionHostSilent:
		if host.LastSeen.IsZero() {
			// Never heard from at all: enrolment succeeded moments ago, or the agent was never
			// started. Both are visible on the fleet page and neither is a host that "went" silent.
			return false, ""
		}
		silent := now.Sub(host.LastSeen)
		return silent > time.Duration(rule.Threshold)*time.Minute,
			host.Hostname + ": silent for " + silent.Round(time.Minute).String() +
				", last heard " + host.LastSeen.Format(time.RFC3339)

	case store.ConditionSecurityUpdates:
		probe, ok := parseFactsProbe(host.Facts)
		if !ok {
			return false, ""
		}
		return probe.Packages.UpgradableSecurity >= rule.Threshold,
			host.Hostname + ": " + strconv.Itoa(probe.Packages.UpgradableSecurity) +
				" security updates pending"

	case store.ConditionRebootRequired:
		probe, ok := parseFactsProbe(host.Facts)
		if !ok {
			return false, ""
		}
		summary := host.Hostname + ": reboot required"
		if !state.Since.IsZero() {
			summary += " for " + now.Sub(state.Since).Round(time.Hour).String()
		}
		return probe.Reboot.Required, summary

	default:
		return false, ""
	}
}

// conditionRipe reports whether a raw condition has held long enough to count as firing.
//
// Only reboot_required carries a duration — its threshold is days outstanding, because "a reboot is
// needed" is Tuesday and "a reboot has been needed for a fortnight" is the thing that never gets done
// until it is an incident. The other conditions bake their duration into the condition itself.
func conditionRipe(rule store.AlertRule, state store.AlertState, now time.Time) bool {
	if rule.Condition != store.ConditionRebootRequired {
		return true
	}
	if state.Since.IsZero() {
		return false
	}
	return now.Sub(state.Since) >= time.Duration(rule.Threshold)*24*time.Hour
}

// firingKind maps an evaluated condition to the event kind its firing emits.
func firingKind(c store.AlertCondition) notify.Kind {
	switch c {
	case store.ConditionHostSilent:
		return notify.KindHostSilent
	case store.ConditionSecurityUpdates:
		return notify.KindUpdatesPending
	default:
		return notify.KindRebootOverdue
	}
}

// recoveryKind maps an evaluated condition to the event kind its resolution emits.
func recoveryKind(c store.AlertCondition) notify.Kind {
	switch c {
	case store.ConditionHostSilent:
		return notify.KindHostRecovered
	case store.ConditionSecurityUpdates:
		return notify.KindUpdatesResolved
	default:
		return notify.KindRebootDone
	}
}

// conditionPhrase renders a condition for a digest summary.
func conditionPhrase(rule store.AlertRule) string {
	switch rule.Condition {
	case store.ConditionHostSilent:
		return "silent for over " + strconv.Itoa(rule.Threshold) + " minutes"
	case store.ConditionSecurityUpdates:
		return "with " + strconv.Itoa(rule.Threshold) + "+ security updates pending"
	default:
		return "awaiting a reboot for over " + strconv.Itoa(rule.Threshold) + " days"
	}
}

// recoverySummary renders the un-firing line.
func recoverySummary(rule store.AlertRule, host store.Host) string {
	switch rule.Condition {
	case store.ConditionHostSilent:
		return host.Hostname + ": heartbeating again"
	case store.ConditionSecurityUpdates:
		return host.Hostname + ": security backlog back under " + strconv.Itoa(rule.Threshold)
	default:
		return host.Hostname + ": no longer needs a reboot"
	}
}

// notifyAlert delivers one rule-driven notification: the event everywhere, and mail where the rule
// asks for it.
//
// A rule produces a notification. A rule never produces a job — there is deliberately nothing here
// that could, and any future "auto-remediate" is a different feature with a different threat model
// that gets its own argument.
func (s *Server) notifyAlert(ctx context.Context, scoped store.Scoped, rule store.AlertRule,
	ev notify.Event) {

	s.emit(ctx, scoped.Tenant(), ev)
	s.mailRule(ctx, scoped, rule, ev)
}

// mailRule sends one event to a rule's recipients, when there are any and a relay exists.
//
// The outcome is stamped on the rule either way. An alert that was the only thing between a fleet and
// an outage must not fail into a log line nobody reads: the operator looking at the rule is the one
// who needs to know that its last mail never went out, and "no mail arrived" and "no mail was sent"
// are indistinguishable from an inbox.
func (s *Server) mailRule(ctx context.Context, scoped store.Scoped, rule store.AlertRule,
	ev notify.Event) {

	if len(rule.EmailTo) == 0 {
		return
	}
	if !s.cfg.SMTP.Configured() {
		const reason = "no SMTP relay is configured on this control plane; the event was delivered " +
			"everywhere except mail"
		slog.Warn("an alert rule names mail recipients and "+reason, "rule", rule.ID, "kind", ev.Kind)
		s.recordDelivery(ctx, scoped, rule.ID, reason)
		return
	}

	sink := notify.NewSMTP(s.cfg.SMTP, rule.EmailTo)
	failure := ""
	if err := notify.DeliverWithRetry(ctx, sink, ev); err != nil {
		slog.Warn("alert mail delivery failed", "rule", rule.ID, "sink", sink.Name(),
			"kind", ev.Kind, "error", err)
		failure = err.Error()
	}
	s.recordDelivery(ctx, scoped, rule.ID, failure)
}

// recordDelivery stamps one rule with the outcome of its most recent mail attempt.
//
// Its own failure is logged and dropped: this is the reporting path, and a control plane that gave up
// on an alert because it could not write down how the alert went is the wrong trade in every case.
func (s *Server) recordDelivery(ctx context.Context, scoped store.Scoped, ruleID, failure string) {
	if err := scoped.RecordAlertDelivery(ctx, ruleID, time.Now().UTC(), failure); err != nil {
		slog.Warn("could not record an alert delivery outcome", "rule", ruleID, "error", err)
	}
}

// routeEventMail mails the event-routed rules: the conditions that watch events which fire on their
// own rather than out of the evaluator.
//
// Cooldown applies per (rule, host) through the same persisted state the evaluator uses, because the
// noisiest case — a restart-looping unit — is event-shaped: each loop is a fresh transition, and a
// rule that mailed every flap would train its recipients to filter the folder.
func (s *Server) routeEventMail(ctx context.Context, scoped store.Scoped, ev notify.Event) {
	var condition store.AlertCondition
	switch notify.Kind(ev.Kind) {
	case notify.KindServiceFailed:
		condition = store.ConditionUnitFailed
	case notify.KindJobFailed, notify.KindJobExpired:
		condition = store.ConditionJobFailed
	default:
		return
	}

	rules, err := scoped.ListAlertRules(ctx)
	if err != nil {
		slog.Warn("could not list alert rules to route an event", "kind", ev.Kind, "error", err)
		return
	}
	states, err := scoped.ListAlertStates(ctx)
	if err != nil {
		slog.Warn("could not list alert states to route an event", "kind", ev.Kind, "error", err)
		return
	}
	now := time.Now().UTC()

	for _, rule := range rules {
		if !rule.Enabled || rule.Condition != condition || len(rule.EmailTo) == 0 {
			continue
		}
		cooldown := time.Duration(rule.CooldownSeconds) * time.Second
		if cooldown <= 0 {
			cooldown = DefaultAlertCooldownSeconds * time.Second
		}
		var last time.Time
		for _, st := range states {
			if st.RuleID == rule.ID && st.HostID == ev.HostID {
				last = st.LastNotified
			}
		}
		if !last.IsZero() && now.Sub(last) < cooldown {
			continue
		}
		s.mailRule(ctx, scoped, rule, ev)
		if err := scoped.UpsertAlertState(ctx, store.AlertState{
			RuleID: rule.ID, HostID: ev.HostID, Firing: true, Since: now, LastNotified: now,
		}); err != nil {
			slog.Warn("could not persist an event-routing cooldown", "rule", rule.ID, "error", err)
		}
	}
}

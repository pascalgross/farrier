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

	var firing, recovered []firingHost
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
			recovered = append(recovered, firingHost{host: host, summary: recoverySummary(rule, host)})
		}

		if state != held[rule.ID+"\x00"+host.ID] {
			held[rule.ID+"\x00"+host.ID] = state
			if err := scoped.UpsertAlertState(ctx, state); err != nil {
				slog.Error("could not persist an alert state",
					"tenant", scoped.Tenant(), "rule", rule.ID, "host", host.ID, "error", err)
			}
		}
	}

	// Recoveries collapse into a digest on the same threshold firings do, and they have to: a
	// partition that heals recovers every host at once, and three hundred "heartbeating again" mails
	// are the ones that bury the one host that did not come back.
	refused := s.notifyBatch(ctx, scoped, rule, firing, now, firingKind(rule.Condition), true)
	if reason := s.notifyBatch(ctx, scoped, rule, recovered, now,
		recoveryKind(rule.Condition), false); reason != "" {
		refused = reason
	}

	// One record per rule per pass, not one per host. The refusal this describes is a property of the
	// control plane rather than of any particular host, and the field it lands in is on the rule —
	// writing it three hundred times during the overload it reports would serialise three hundred
	// round trips into the tick that is already behind.
	if refused != "" {
		s.recordDelivery(scoped, rule.ID, refused)
	}
}

// notifyBatch sends one rule's firings or recoveries, collapsing to a digest past the threshold.
//
// It returns the reason a delivery was refused, empty when none was, so the caller can record it once
// for the whole pass.
func (s *Server) notifyBatch(ctx context.Context, scoped store.Scoped, rule store.AlertRule,
	batch []firingHost, now time.Time, kind notify.Kind, isFiring bool) string {

	if len(batch) == 0 {
		return ""
	}
	if len(batch) > alertDigestThreshold {
		// The digest form: one notification naming the count and the first few hosts, because 300
		// identical pages during a partition is how the one different page gets missed.
		names := make([]string, 0, alertDigestThreshold)
		for _, f := range batch[:alertDigestThreshold] {
			names = append(names, f.host.Hostname)
		}
		verb := recoveryPhrase(rule)
		if isFiring {
			verb = conditionPhrase(rule)
		}
		return s.notifyAlert(ctx, scoped, rule, notify.Event{
			Kind: string(kind),
			At:   now,
			Summary: strconv.Itoa(len(batch)) + " hosts " + verb + ": " +
				strings.Join(names, ", ") + ", …",
			Detail: map[string]any{
				"ruleId": rule.ID, "condition": string(rule.Condition), "hosts": len(batch),
			},
		})
	}

	var refused string
	for _, f := range batch {
		if reason := s.notifyAlert(ctx, scoped, rule, notify.Event{
			Kind:     string(kind),
			HostID:   f.host.ID,
			Hostname: f.host.Hostname,
			At:       now,
			Summary:  f.summary,
			Detail:   map[string]any{"ruleId": rule.ID, "condition": string(rule.Condition)},
		}); reason != "" {
			refused = reason
		}
	}
	return refused
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

// recoveryPhrase renders a resolution for a digest summary.
//
// Its own function rather than "recovered from " prefixed to conditionPhrase, because that produces
// "300 hosts recovered from silent for over 30 minutes" — a sentence somebody has to read twice at
// three in the morning, which is the only hour this line is ever read.
func recoveryPhrase(rule store.AlertRule) string {
	switch rule.Condition {
	case store.ConditionHostSilent:
		return "are heartbeating again"
	case store.ConditionSecurityUpdates:
		return "are back under " + strconv.Itoa(rule.Threshold) + " security updates"
	default:
		return "no longer need a reboot"
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
//
// It returns the reason the mail could not be started, empty when it was. The caller records that
// once per pass: this pair's cooldown has already been stamped, so nothing will try again for hours — and a
// dropped recovery is not retried at all — which is precisely the silence the delivery record exists
// to distinguish from a rule that never fired.
func (s *Server) notifyAlert(ctx context.Context, scoped store.Scoped, rule store.AlertRule,
	ev notify.Event) string {

	s.emit(ctx, scoped.Tenant(), ev)
	if len(rule.EmailTo) == 0 {
		return ""
	}

	// Detached like every other delivery that leaves the process, and here the reason is the
	// evaluator's own context: it is cancelled by the shutdown signal, so mailing on it directly
	// would abort exactly the alert a stopping control plane most needs to have sent.
	_, reason := s.detach("alert mail", func(outCtx context.Context) {
		s.mailRule(outCtx, scoped, rule, ev)
	})
	return reason
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
		s.recordDelivery(scoped, rule.ID, reason)
		return
	}

	sink := notify.NewSMTP(s.cfg.SMTP, rule.EmailTo)
	mailCtx, done := context.WithTimeout(ctx, deliveryBudget)
	err := notify.DeliverWithRetry(mailCtx, sink, ev)
	done()

	failure := ""
	if err != nil {
		slog.Warn("alert mail delivery failed", "rule", rule.ID, "sink", sink.Name(),
			"kind", ev.Kind, "error", err)
		failure = err.Error()
	}
	s.recordDelivery(scoped, rule.ID, failure)
}

// deliveryRecordTimeout bounds the write that says how a delivery went.
//
// Short, because it is one narrow UPDATE and the process it runs in may be stopping.
const deliveryRecordTimeout = 10 * time.Second

// recordDelivery stamps one rule with the outcome of its most recent mail attempt.
//
// It takes no context from its caller, deliberately. This runs after a delivery that may have been
// cancelled — by its own sink budget, or by the shutdown drain — and writing the outcome on that same
// cancelled context would fail with "context canceled" and leave the rule showing nothing at all:
// indistinguishable from a rule that never fired, which is the exact confusion the whole record
// exists to prevent. It writes on a context nothing cancels, with a short deadline of its own, so the
// record survives every failure it is meant to describe and still cannot hold up a stopping process
// for long.
//
// Its own failure is logged and dropped: this is the reporting path, and a control plane that gave up
// on an alert because it could not write down how the alert went is the wrong trade in every case.
func (s *Server) recordDelivery(scoped store.Scoped, ruleID, failure string) {
	recordCtx, done := context.WithTimeout(context.WithoutCancel(s.outboundCtx),
		deliveryRecordTimeout)
	defer done()
	if err := scoped.RecordAlertDelivery(recordCtx, ruleID, time.Now().UTC(), failure); err != nil {
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

	// Each read is bounded on its own, because the pass around them deliberately is not: a ceiling
	// above the webhook would let a black-holed one eat the mail behind it. An unreachable database
	// therefore has to be stopped here or not at all.
	rules, err := readBounded(ctx, scoped.ListAlertRules)
	if err != nil {
		slog.Warn("could not read the alert rules to route an event", "kind", ev.Kind, "error", err)
		return
	}
	states, err := readBounded(ctx, scoped.ListAlertStates)
	if err != nil {
		// Returning rather than routing with an empty list, which is the whole reason this is its own
		// statement: `states` is the cooldown's memory, and treating an unreadable one as "nobody has
		// been notified" would mail every recipient on every flap of a restart-looping unit.
		slog.Warn("could not read the alert states to route an event", "kind", ev.Kind, "error", err)
		return
	}
	s.routeToRules(ctx, scoped, ev, condition, rules, states)
}

// readBounded runs one store read under outboundStoreTimeout.
//
// A tiny helper because the alternative is the same four lines around every read on this path, and
// the version of those four lines that shares one context between two reads is a bug that already
// happened here once: the second read inherits whatever the first left of the budget.
func readBounded[T any](ctx context.Context, read func(context.Context) ([]T, error)) ([]T, error) {
	readCtx, done := context.WithTimeout(ctx, outboundStoreTimeout)
	defer done()
	return read(readCtx)
}

// perRuleMailBudget is the worst case for mailing one rule: the relay, the record, the cooldown stamp.
//
// Written as the sum rather than as a round number so that changing any of the three keeps the reserve
// below honest. A reserve that counted only the relay would let a rule start with sixty seconds left,
// take seventy-three, and overrun the ceiling by the difference every time.
const perRuleMailBudget = deliveryBudget + deliveryRecordTimeout + outboundStoreTimeout

// mailRoutingBudget bounds the whole mail phase of one pass.
//
// The webhook keeps its own budget and is unaffected by this, which is the separation that matters:
// two deliveries with nothing to do with each other must not be able to starve one another. Rules
// routing the same event kind are not independent in that way — they are one queue against one relay
// — so a ceiling over them is what keeps a pass finite when somebody has written twenty of them and
// the relay is black-holing.
//
// Three rules' worth, because that is how many an event kind reaching more than a couple of distinct
// recipient lists ever plausibly needs, and because a number expressed as a multiple of the per-rule
// cost stays true when the per-rule cost changes.
//
// It is a wall-clock deadline rather than a context, and that is deliberate: the per-rule work
// includes a cooldown stamp and a delivery record, which must not be truncated halfway, so the loop
// checks how much is left rather than handing a shrinking context to the next rule.
const mailRoutingBudget = 3 * perRuleMailBudget

// routeToRules mails each rule that routes this event kind and is past its cooldown.
func (s *Server) routeToRules(ctx context.Context, scoped store.Scoped, ev notify.Event,
	condition store.AlertCondition, rules []store.AlertRule, states []store.AlertState) {

	now := time.Now().UTC()
	due := dueRules(rules, states, condition, ev.HostID, now)
	deadline := time.Now().Add(mailRoutingBudget)

	for i, rule := range due {
		// Enough budget for a *whole* attempt, or none at all. A rule mailed on the last four seconds
		// of the ceiling fails for want of time and then has its four-hour cooldown stamped, which
		// suppresses the real attempt — the outcome this guard exists to prevent, and the one a bare
		// "is the context dead yet" check walks straight into. The reserve is the whole per-rule cost
		// and not just the relay's share, because the record and the stamp are inside the ceiling too.
		if ctx.Err() != nil || time.Until(deadline) < perRuleMailBudget {
			reason := "the control plane ran out of time to mail this event; " +
				"the relay or the database is not keeping up"
			if ctx.Err() != nil {
				reason = "the control plane stopped before mailing this event"
			}
			slog.Warn("some alert rules were not mailed for this event",
				"kind", ev.Kind, "skipped", len(due)-i, "reason", reason)
			s.recordSkipped(scoped, due[i:], reason)
			return
		}

		s.mailRule(ctx, scoped, rule, ev)

		stampCtx, stampDone := context.WithTimeout(ctx, outboundStoreTimeout)
		err := scoped.UpsertAlertState(stampCtx, store.AlertState{
			RuleID: rule.ID, HostID: ev.HostID, Firing: true, Since: now, LastNotified: now,
		})
		stampDone()
		if err != nil {
			slog.Warn("could not persist an event-routing cooldown", "rule", rule.ID, "error", err)
		}
	}
}

// dueRules picks the rules that route this event kind, name recipients, and are past their cooldown.
//
// Separated from the loop that mails them so that "which rules should have been mailed" is answerable
// as a list — which is what lets the skipped ones be recorded rather than only counted.
func dueRules(rules []store.AlertRule, states []store.AlertState, condition store.AlertCondition,
	hostID string, now time.Time) []store.AlertRule {

	var due []store.AlertRule
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
			if st.RuleID == rule.ID && st.HostID == hostID {
				last = st.LastNotified
			}
		}
		if !last.IsZero() && now.Sub(last) < cooldown {
			continue
		}
		due = append(due, rule)
	}
	return due
}

// recordSkipped stamps every rule that was never attempted with why.
//
// It matters most for the event-routed conditions, which is where it is used: a failed job fires once
// and nothing re-triggers it, so a rule skipped here would otherwise go on displaying its last
// successful delivery — "no mail arrived" and "no mail was sent" indistinguishable again.
//
// One budget for the whole set rather than one each, because the reason for skipping is usually a
// database that is not answering, and a ten-second write per rule would turn a slow pass into a stuck
// one. What does not fit is logged as a count.
func (s *Server) recordSkipped(scoped store.Scoped, rules []store.AlertRule, reason string) {
	ctx, done := context.WithTimeout(context.WithoutCancel(s.outboundCtx), deliveryRecordTimeout)
	defer done()

	now := time.Now().UTC()
	for i, rule := range rules {
		if ctx.Err() != nil {
			slog.Warn("could not record why some alert rules were not mailed",
				"unrecorded", len(rules)-i, "error", ctx.Err())
			return
		}
		if err := scoped.RecordAlertDelivery(ctx, rule.ID, now, reason); err != nil {
			slog.Warn("could not record a skipped alert delivery", "rule", rule.ID, "error", err)
		}
	}
}

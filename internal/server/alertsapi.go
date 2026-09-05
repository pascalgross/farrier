package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pascalgross/hostseal/internal/store"
)

// alertRuleView is one rule as the API renders it.
type alertRuleView struct {
	// ID identifies the rule.
	ID string `json:"id"`

	// Condition is what the rule watches.
	Condition string `json:"condition"`

	// Threshold parameterises the condition: minutes silent, pending updates, or days outstanding.
	Threshold int `json:"threshold"`

	// CooldownSeconds bounds re-notification, zero rendering the server default.
	CooldownSeconds int `json:"cooldownSeconds"`

	// EmailTo lists the rule's mail recipients.
	EmailTo []string `json:"emailTo"`

	// Enabled reports whether the rule is live.
	Enabled bool `json:"enabled"`

	// CreatedAt is when the rule was created.
	CreatedAt time.Time `json:"createdAt"`

	// CreatedBy is the operator who created it.
	CreatedBy string `json:"createdBy"`

	// LastDeliveryAt is when this rule last tried to mail somebody, absent for never.
	LastDeliveryAt *time.Time `json:"lastDeliveryAt,omitempty"`

	// LastDeliveryError is why that attempt failed, empty when it succeeded.
	//
	// Rendered on the rule rather than left in a log, because an alert that never went out and an
	// alert that never fired look identical from an inbox — and the operator reading the rule is the
	// one who can fix the relay.
	LastDeliveryError string `json:"lastDeliveryError,omitempty"`
}

// toAlertRuleView converts a stored rule to its API shape.
func toAlertRuleView(r store.AlertRule) alertRuleView {
	view := alertRuleView{
		ID:                r.ID,
		Condition:         string(r.Condition),
		Threshold:         r.Threshold,
		CooldownSeconds:   r.CooldownSeconds,
		EmailTo:           r.EmailTo,
		Enabled:           r.Enabled,
		CreatedAt:         r.CreatedAt,
		CreatedBy:         r.CreatedBy,
		LastDeliveryError: r.LastDeliveryError,
	}
	if !r.LastDeliveryAt.IsZero() {
		at := r.LastDeliveryAt
		view.LastDeliveryAt = &at
	}
	if view.EmailTo == nil {
		view.EmailTo = []string{}
	}
	return view
}

// alertRuleRequest is the body of POST /api/v1/alerts and PATCH /api/v1/alerts/{id}.
//
// Every changeable field is a pointer, and that is what makes PATCH mean what the method says. With
// plain values, `{"enabled": false}` — the obvious way to silence a rule during an incident — decodes
// with a zero threshold, a zero cooldown and no recipients, and the update writes all three: the rule
// is silenced and its mailing list is gone, with nothing in the request that asked for that. An absent
// field now leaves the stored value alone.
type alertRuleRequest struct {
	// Condition is what to watch; required on create, refused on update.
	Condition string `json:"condition,omitempty"`

	// Threshold parameterises the condition. Absent means zero on create, unchanged on update.
	Threshold *int `json:"threshold,omitempty"`

	// CooldownSeconds bounds re-notification; zero is the server default, absent is unchanged.
	CooldownSeconds *int `json:"cooldownSeconds,omitempty"`

	// EmailTo lists mail recipients. An explicit empty array clears them; absent leaves them.
	EmailTo *[]string `json:"emailTo,omitempty"`

	// Enabled defaults to true on create and is unchanged when absent on update.
	Enabled *bool `json:"enabled,omitempty"`
}

// resolvedRule is a rule's changeable fields after a request has been applied to what was stored.
type resolvedRule struct {
	// Threshold parameterises the condition.
	Threshold int

	// CooldownSeconds bounds re-notification.
	CooldownSeconds int

	// EmailTo lists mail recipients.
	EmailTo []string

	// Enabled reports whether the rule is live.
	Enabled bool
}

// resolve applies a request to a base, which is the stored rule on update and the zero value on create.
func (r alertRuleRequest) resolve(base resolvedRule) resolvedRule {
	if r.Threshold != nil {
		base.Threshold = *r.Threshold
	}
	if r.CooldownSeconds != nil {
		base.CooldownSeconds = *r.CooldownSeconds
	}
	if r.EmailTo != nil {
		base.EmailTo = *r.EmailTo
	}
	if r.Enabled != nil {
		base.Enabled = *r.Enabled
	}
	return base
}

// maxAlertThreshold bounds a rule's threshold, because the units it is read in multiply.
//
// reboot_required reads it as days and multiplies by 24 hours, and a time.Duration is nanoseconds in
// an int64: past about 106,751 days the product wraps negative and the rule fires immediately for
// every host — a threshold set absurdly high turning into no threshold at all, which is the worst
// direction for a mistake like this to fail in. A hundred thousand is under the wrap in every unit
// this field is read in, and is 274 years of anything.
const maxAlertThreshold = 100_000

// validateAlertRule checks the resolved fields create and update share.
//
// The resolved fields rather than the request's, because a PATCH that changes only the cooldown must
// still be judged against the threshold the rule will have afterwards — which is the one it already
// had.
func validateAlertRule(rule resolvedRule, condition store.AlertCondition) string {
	if condition.Evaluated() && rule.Threshold < 1 {
		return "an evaluated condition needs a positive threshold: minutes for host_silent, a count " +
			"for security_updates, days for reboot_required"
	}
	if rule.Threshold > maxAlertThreshold {
		return "threshold cannot exceed " + strconv.Itoa(maxAlertThreshold) +
			"; a larger one overflows the duration it is read as and fires on every host instead of none"
	}
	if rule.CooldownSeconds < 0 {
		return "cooldownSeconds cannot be negative"
	}
	if rule.CooldownSeconds > maxAlertThreshold*int(time.Hour/time.Second) {
		// Same reasoning in the other field: cooldownSeconds becomes a Duration too.
		return "cooldownSeconds is implausibly large"
	}
	for _, address := range rule.EmailTo {
		// Light-touch on purpose: real address validation is the relay's job, and a regex that
		// refuses a valid address is worse than a bounce the operator can read. What this catches is
		// the field being used for something that is not an address at all.
		if !strings.Contains(address, "@") || strings.ContainsAny(address, " \r\n") {
			return "emailTo holds something that is not a mail address: " + address
		}
	}
	return ""
}

// handleListAlertRules returns every rule, oldest first.
func (s *Server) handleListAlertRules(w http.ResponseWriter, r *http.Request, who operator) {
	rules, err := who.Store.ListAlertRules(r.Context())
	if err != nil {
		slog.Error("could not list alert rules", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the rules")
		return
	}
	views := make([]alertRuleView, 0, len(rules))
	for _, rule := range rules {
		views = append(views, toAlertRuleView(rule))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rules": views,
		// Rendered beside the rules so the UI can say what "no cooldown" means without hard-coding
		// the server's number.
		"defaultCooldownSeconds": DefaultAlertCooldownSeconds,
		"mailConfigured":         s.cfg.SMTP.Configured(),
	})
}

// handleCreateAlertRule records a new rule.
func (s *Server) handleCreateAlertRule(w http.ResponseWriter, r *http.Request, who operator) {
	var req alertRuleRequest
	if err := decodeJSON(w, r, 64<<10, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		return
	}
	condition := store.AlertCondition(req.Condition)
	if !condition.Valid() {
		writeError(w, http.StatusBadRequest, "malformed",
			"condition must be one of host_silent, security_updates, reboot_required, unit_failed, "+
				"job_failed")
		return
	}
	// A new rule starts enabled: somebody who just described a condition wants it watched, and a rule
	// that has to be switched on after creation is a rule half the fleet forgets to switch on.
	resolved := req.resolve(resolvedRule{Enabled: true})
	if message := validateAlertRule(resolved, condition); message != "" {
		writeError(w, http.StatusBadRequest, "malformed", message)
		return
	}

	id, err := NewID()
	if err != nil {
		slog.Error("could not generate a rule id", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not allocate a rule id")
		return
	}
	rule := store.AlertRule{
		ID:              id,
		Condition:       condition,
		Threshold:       resolved.Threshold,
		CooldownSeconds: resolved.CooldownSeconds,
		EmailTo:         resolved.EmailTo,
		Enabled:         resolved.Enabled,
		CreatedAt:       time.Now().UTC(),
		CreatedBy:       who.Principal(),
	}
	if err := who.Store.CreateAlertRule(r.Context(), rule); err != nil {
		slog.Error("could not create an alert rule", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not create the rule")
		return
	}

	slog.Info("alert rule created", "rule", id, "condition", condition,
		"tenant", who.Store.Tenant(), "operator", who.Principal())
	writeJSON(w, http.StatusCreated, toAlertRuleView(rule))
}

// handleUpdateAlertRule applies a rule's threshold, cooldown, recipients and enabled flag.
func (s *Server) handleUpdateAlertRule(w http.ResponseWriter, r *http.Request, who operator) {
	var req alertRuleRequest
	if err := decodeJSON(w, r, 64<<10, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		return
	}
	if req.Condition != "" {
		// The condition never changes in place: firing state keyed to it would mean something else
		// entirely afterwards. This is a refusal with the alternative named, not a silent ignore.
		writeError(w, http.StatusBadRequest, "malformed",
			"a rule's condition cannot change; delete this rule and create one that watches the "+
				"other thing")
		return
	}

	id := r.PathValue("id")
	rules, err := who.Store.ListAlertRules(r.Context())
	if err != nil {
		slog.Error("could not list alert rules", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the rules")
		return
	}
	var current *store.AlertRule
	for i := range rules {
		if rules[i].ID == id {
			current = &rules[i]
			break
		}
	}
	if current == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such rule")
		return
	}
	resolved := req.resolve(resolvedRule{
		Threshold:       current.Threshold,
		CooldownSeconds: current.CooldownSeconds,
		EmailTo:         current.EmailTo,
		Enabled:         current.Enabled,
	})
	if message := validateAlertRule(resolved, current.Condition); message != "" {
		writeError(w, http.StatusBadRequest, "malformed", message)
		return
	}

	updated := *current
	updated.Threshold = resolved.Threshold
	updated.CooldownSeconds = resolved.CooldownSeconds
	updated.EmailTo = resolved.EmailTo
	updated.Enabled = resolved.Enabled
	if err := who.Store.UpdateAlertRule(r.Context(), updated); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such rule")
			return
		}
		slog.Error("could not update an alert rule", "error", err, "rule", id)
		writeError(w, http.StatusInternalServerError, "internal", "could not update the rule")
		return
	}

	slog.Info("alert rule updated", "rule", id, "tenant", who.Store.Tenant(),
		"operator", who.Principal())
	writeJSON(w, http.StatusOK, toAlertRuleView(updated))
}

// handleDeleteAlertRule removes a rule and its firing state.
func (s *Server) handleDeleteAlertRule(w http.ResponseWriter, r *http.Request, who operator) {
	id := r.PathValue("id")
	if err := who.Store.DeleteAlertRule(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such rule")
			return
		}
		slog.Error("could not delete an alert rule", "error", err, "rule", id)
		writeError(w, http.StatusInternalServerError, "internal", "could not delete the rule")
		return
	}
	slog.Info("alert rule deleted", "rule", id, "tenant", who.Store.Tenant(),
		"operator", who.Principal())
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

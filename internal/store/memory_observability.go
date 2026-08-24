package store

import (
	"context"
	"sort"
	"time"
)

// eventRow is an event together with the tenant that owns it.
type eventRow struct {
	// event is the record as callers see it.
	event Event

	// tenant is the fleet it belongs to.
	tenant TenantID
}

// transitionRow is a unit transition together with the tenant that owns it.
type transitionRow struct {
	// transition is the record as callers see it.
	transition UnitTransition

	// tenant is the fleet it belongs to.
	tenant TenantID
}

// ruleKey identifies one alert rule the way the schema does, by tenant and id together.
type ruleKey struct {
	// tenant owns the rule.
	tenant TenantID

	// id is the rule's identifier.
	id string
}

// stateKey identifies one alert state by tenant, rule and host together.
type stateKey struct {
	// tenant owns the state.
	tenant TenantID

	// rule is the rule half of the pair.
	rule string

	// host is the host half, empty for a digest row.
	host string
}

// RecordEvent appends one event to the tenant's inbox, evicting past MaxEventsPerTenant.
func (s *scopedMemory) RecordEvent(_ context.Context, e Event) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	if _, ok := s.store.tenants[s.tenant]; !ok {
		return errUnknownTenant(s.tenant)
	}
	s.store.events = append(s.store.events, eventRow{event: e, tenant: s.tenant})

	// Evicting by scan, like the DELETE in PostgreSQL. The slice holds every tenant's events, so the
	// count and the eviction are both per tenant rather than per slice.
	var mine int
	for _, row := range s.store.events {
		if row.tenant == s.tenant {
			mine++
		}
	}
	if mine > MaxEventsPerTenant {
		kept := s.store.events[:0]
		toDrop := mine - MaxEventsPerTenant
		for _, row := range s.store.events {
			if row.tenant == s.tenant && toDrop > 0 {
				toDrop--
				continue
			}
			kept = append(kept, row)
		}
		s.store.events = kept
	}
	return nil
}

// ListEvents returns inbox events, newest first.
func (s *scopedMemory) ListEvents(_ context.Context, f EventFilter) ([]Event, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	var out []Event
	for _, row := range s.store.events {
		if row.tenant != s.tenant {
			continue
		}
		if f.Kind != "" && row.event.Kind != f.Kind {
			continue
		}
		out = append(out, row.event)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].ID > out[j].ID
	})
	if limit := clampEventLimit(f.Limit); len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// RecordUnitTransitions appends observed unit-state changes for one host, bounded per host.
//
// A batch aimed at a host this tenant does not own is refused, matching the composite foreign key in
// the schema — the probe for this method asserts an error, and a memory store that silently accepted
// would let a test pass against a boundary PostgreSQL enforces.
func (s *scopedMemory) RecordUnitTransitions(_ context.Context, hostID string, transitions []UnitTransition) error {
	if len(transitions) == 0 {
		return nil
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	row, ok := s.store.hosts[hostID]
	if !ok || row.tenant != s.tenant {
		return errUnknownTenant(s.tenant)
	}
	for _, tr := range transitions {
		tr.HostID = hostID
		s.store.transitions = append(s.store.transitions, transitionRow{transition: tr, tenant: s.tenant})
	}

	var mine int
	for _, r := range s.store.transitions {
		if r.tenant == s.tenant && r.transition.HostID == hostID {
			mine++
		}
	}
	if mine > MaxUnitTransitionsPerHost {
		kept := s.store.transitions[:0]
		toDrop := mine - MaxUnitTransitionsPerHost
		for _, r := range s.store.transitions {
			if r.tenant == s.tenant && r.transition.HostID == hostID && toDrop > 0 {
				toDrop--
				continue
			}
			kept = append(kept, r)
		}
		s.store.transitions = kept
	}
	return nil
}

// ListUnitTransitions returns one host's unit-state history, newest first.
func (s *scopedMemory) ListUnitTransitions(_ context.Context, hostID string, limit int) ([]UnitTransition, error) {
	if limit <= 0 || limit > MaxUnitTransitionsPerHost {
		limit = MaxUnitTransitionsPerHost
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	var out []UnitTransition
	for _, r := range s.store.transitions {
		if r.tenant == s.tenant && r.transition.HostID == hostID {
			out = append(out, r.transition)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// CreateAlertRule records a new rule.
func (s *scopedMemory) CreateAlertRule(_ context.Context, r AlertRule) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	if _, ok := s.store.tenants[s.tenant]; !ok {
		return errUnknownTenant(s.tenant)
	}
	key := ruleKey{tenant: s.tenant, id: r.ID}
	if _, exists := s.store.rules[key]; exists {
		return ErrConflict
	}
	s.store.rules[key] = r
	return nil
}

// ListAlertRules returns every rule, oldest first.
func (s *scopedMemory) ListAlertRules(_ context.Context) ([]AlertRule, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	var out []AlertRule
	for key, r := range s.store.rules {
		if key.tenant == s.tenant {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// UpdateAlertRule applies a rule's threshold, cooldown, recipients and enabled flag.
func (s *scopedMemory) UpdateAlertRule(_ context.Context, r AlertRule) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	key := ruleKey{tenant: s.tenant, id: r.ID}
	held, exists := s.store.rules[key]
	if !exists {
		return ErrNotFound
	}
	// The condition survives the update, exactly as the SQL leaves the column out of its SET list.
	held.Threshold = r.Threshold
	held.CooldownSeconds = r.CooldownSeconds
	held.EmailTo = r.EmailTo
	held.Enabled = r.Enabled
	s.store.rules[key] = held
	return nil
}

// RecordAlertDelivery stamps a rule with the outcome of its most recent mail attempt.
//
// A rule deleted between the attempt and the report is not an error, exactly as in SQL: the outcome
// has nowhere to go and nobody to tell.
func (s *scopedMemory) RecordAlertDelivery(_ context.Context, ruleID string, at time.Time,
	failure string) error {

	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	key := ruleKey{tenant: s.tenant, id: ruleID}
	held, exists := s.store.rules[key]
	if !exists {
		return nil
	}
	held.LastDeliveryAt, held.LastDeliveryError = at, failure
	s.store.rules[key] = held
	return nil
}

// DeleteAlertRule removes a rule and its firing state.
func (s *scopedMemory) DeleteAlertRule(_ context.Context, id string) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	key := ruleKey{tenant: s.tenant, id: id}
	if _, exists := s.store.rules[key]; !exists {
		return ErrNotFound
	}
	delete(s.store.rules, key)
	for sk := range s.store.states {
		if sk.tenant == s.tenant && sk.rule == id {
			delete(s.store.states, sk)
		}
	}
	return nil
}

// ListAlertStates returns the evaluator's memory for every (rule, host) pair.
func (s *scopedMemory) ListAlertStates(_ context.Context) ([]AlertState, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	var out []AlertState
	for key, st := range s.store.states {
		if key.tenant == s.tenant {
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].HostID < out[j].HostID
	})
	return out, nil
}

// UpsertAlertState records one (rule, host) pair's state.
//
// A state naming a rule this tenant does not hold is refused, matching the schema's composite foreign
// key from alert_states to alert_rules.
func (s *scopedMemory) UpsertAlertState(_ context.Context, st AlertState) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	if _, exists := s.store.rules[ruleKey{tenant: s.tenant, id: st.RuleID}]; !exists {
		return errUnknownTenant(s.tenant)
	}
	s.store.states[stateKey{tenant: s.tenant, rule: st.RuleID, host: st.HostID}] = st
	return nil
}

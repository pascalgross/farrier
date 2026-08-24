package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RecordEvent appends one event to the tenant's inbox, evicting past MaxEventsPerTenant.
//
// Eviction runs in the same transaction as the insert, so the bound is a property of the table rather
// than of a sweep somebody has to keep scheduled. Events are rare — an enrolment, a failure, an alert
// firing — so the extra statement costs nothing measurable.
func (s *scopedPostgres) RecordEvent(ctx context.Context, e Event) error {
	detail, err := json.Marshal(e.Detail)
	if err != nil {
		return fmt.Errorf("store: encoding event detail: %w", err)
	}
	if e.Detail == nil {
		detail = []byte("{}")
	}

	return s.withTenant(ctx, "recording an event", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO events (tenant_id, id, kind, host_id, hostname, summary, at, detail)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			string(s.tenant), e.ID, e.Kind, e.HostID, e.Hostname, e.Summary, e.At, detail,
		); err != nil {
			return wrap(err, "recording an event")
		}
		_, err := tx.Exec(ctx, `
			DELETE FROM events
			 WHERE tenant_id = $1
			   AND (at, id) < (SELECT at, id FROM events
			                    WHERE tenant_id = $1
			                    ORDER BY at DESC, id DESC
			                    OFFSET $2 LIMIT 1)`,
			string(s.tenant), MaxEventsPerTenant-1)
		return wrap(err, "evicting old events")
	})
}

// ListEvents returns inbox events, newest first.
func (s *scopedPostgres) ListEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	limit := clampEventLimit(f.Limit)
	var out []Event
	err := s.withTenant(ctx, "listing events", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, kind, host_id, hostname, summary, at, detail
			  FROM events
			 WHERE tenant_id = $1
			   AND ($2 = '' OR kind = $2)
			 ORDER BY at DESC, id DESC
			 LIMIT $3`, string(s.tenant), f.Kind, limit)
		if err != nil {
			return wrap(err, "listing events")
		}
		defer rows.Close()

		for rows.Next() {
			var e Event
			var detail []byte
			if err := rows.Scan(&e.ID, &e.Kind, &e.HostID, &e.Hostname, &e.Summary, &e.At,
				&detail); err != nil {
				return wrap(err, "scanning an event")
			}
			if err := json.Unmarshal(detail, &e.Detail); err != nil {
				return fmt.Errorf("store: decoding event detail: %w", err)
			}
			out = append(out, e)
		}
		return wrap(rows.Err(), "listing events")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RecordUnitTransitions appends observed unit-state changes for one host, bounded per host.
//
// The host reference is a composite foreign key, so a batch aimed at another tenant's host is refused
// by the database — the same shape of answer AddCertificate gets, and the reason the isolation probe
// for this method can assert an error rather than an absence.
func (s *scopedPostgres) RecordUnitTransitions(ctx context.Context, hostID string, transitions []UnitTransition) error {
	if len(transitions) == 0 {
		return nil
	}
	return s.withTenant(ctx, "recording unit transitions", func(tx pgx.Tx) error {
		for _, tr := range transitions {
			if _, err := tx.Exec(ctx, `
				INSERT INTO unit_transitions (tenant_id, host_id, unit, from_state, to_state, at)
				VALUES ($1, $2, $3, $4, $5, $6)`,
				string(s.tenant), hostID, tr.Unit, tr.From, tr.To, tr.At,
			); err != nil {
				return wrap(err, "recording a unit transition")
			}
		}
		_, err := tx.Exec(ctx, `
			DELETE FROM unit_transitions
			 WHERE tenant_id = $1 AND host_id = $2
			   AND at < (SELECT at FROM unit_transitions
			              WHERE tenant_id = $1 AND host_id = $2
			              ORDER BY at DESC
			              OFFSET $3 LIMIT 1)`,
			string(s.tenant), hostID, MaxUnitTransitionsPerHost-1)
		return wrap(err, "evicting old unit transitions")
	})
}

// ListUnitTransitions returns one host's unit-state history, newest first.
func (s *scopedPostgres) ListUnitTransitions(ctx context.Context, hostID string, limit int) ([]UnitTransition, error) {
	if limit <= 0 || limit > MaxUnitTransitionsPerHost {
		limit = MaxUnitTransitionsPerHost
	}
	var out []UnitTransition
	err := s.withTenant(ctx, "listing unit transitions", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT host_id, unit, from_state, to_state, at
			  FROM unit_transitions
			 WHERE tenant_id = $1 AND host_id = $2
			 ORDER BY at DESC
			 LIMIT $3`, string(s.tenant), hostID, limit)
		if err != nil {
			return wrap(err, "listing unit transitions")
		}
		defer rows.Close()

		for rows.Next() {
			var tr UnitTransition
			if err := rows.Scan(&tr.HostID, &tr.Unit, &tr.From, &tr.To, &tr.At); err != nil {
				return wrap(err, "scanning a unit transition")
			}
			out = append(out, tr)
		}
		return wrap(rows.Err(), "listing unit transitions")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// alertRuleColumns is the projection every rule read shares, in the order scanAlertRule expects.
const alertRuleColumns = `id, condition, threshold, cooldown_seconds, email_to, enabled, created_at,
	created_by, last_delivery_at, last_delivery_error`

// scanAlertRule reads one rule using the alertRuleColumns projection.
func scanAlertRule(row pgx.Row) (AlertRule, error) {
	var r AlertRule
	var emailTo []byte
	var lastDeliveryAt *time.Time
	err := row.Scan(&r.ID, &r.Condition, &r.Threshold, &r.CooldownSeconds, &emailTo, &r.Enabled,
		&r.CreatedAt, &r.CreatedBy, &lastDeliveryAt, &r.LastDeliveryError)
	if errors.Is(err, pgx.ErrNoRows) {
		return AlertRule{}, ErrNotFound
	}
	if err != nil {
		return AlertRule{}, wrap(err, "reading an alert rule")
	}
	if err := json.Unmarshal(emailTo, &r.EmailTo); err != nil {
		return AlertRule{}, fmt.Errorf("store: decoding rule recipients: %w", err)
	}
	if lastDeliveryAt != nil {
		r.LastDeliveryAt = *lastDeliveryAt
	}
	return r, nil
}

// CreateAlertRule records a new rule.
func (s *scopedPostgres) CreateAlertRule(ctx context.Context, r AlertRule) error {
	emailTo, err := json.Marshal(r.EmailTo)
	if err != nil {
		return fmt.Errorf("store: encoding rule recipients: %w", err)
	}
	if r.EmailTo == nil {
		emailTo = []byte("[]")
	}
	return s.withTenant(ctx, "creating an alert rule", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO alert_rules (tenant_id, id, condition, threshold, cooldown_seconds, email_to,
			                         enabled, created_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			string(s.tenant), r.ID, string(r.Condition), r.Threshold, r.CooldownSeconds, emailTo,
			r.Enabled, r.CreatedAt, r.CreatedBy)
		return wrap(err, "creating an alert rule")
	})
}

// ListAlertRules returns every rule, oldest first.
func (s *scopedPostgres) ListAlertRules(ctx context.Context) ([]AlertRule, error) {
	var out []AlertRule
	err := s.withTenant(ctx, "listing alert rules", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+alertRuleColumns+`
			  FROM alert_rules
			 WHERE tenant_id = $1
			 ORDER BY created_at, id`, string(s.tenant))
		if err != nil {
			return wrap(err, "listing alert rules")
		}
		defer rows.Close()

		for rows.Next() {
			rule, err := scanAlertRule(rows)
			if err != nil {
				return err
			}
			out = append(out, rule)
		}
		return wrap(rows.Err(), "listing alert rules")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateAlertRule applies a rule's threshold, cooldown, recipients and enabled flag.
//
// The condition column is deliberately absent from the SET list — see the interface. ErrNotFound for
// a rule that does not exist, so the API can answer 404 rather than 200 for a typo.
func (s *scopedPostgres) UpdateAlertRule(ctx context.Context, r AlertRule) error {
	emailTo, err := json.Marshal(r.EmailTo)
	if err != nil {
		return fmt.Errorf("store: encoding rule recipients: %w", err)
	}
	if r.EmailTo == nil {
		emailTo = []byte("[]")
	}
	return s.withTenant(ctx, "updating an alert rule", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE alert_rules
			   SET threshold = $3, cooldown_seconds = $4, email_to = $5, enabled = $6
			 WHERE tenant_id = $1 AND id = $2`,
			string(s.tenant), r.ID, r.Threshold, r.CooldownSeconds, emailTo, r.Enabled)
		if err != nil {
			return wrap(err, "updating an alert rule")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// RecordAlertDelivery stamps a rule with the outcome of its most recent mail attempt.
//
// One narrow UPDATE rather than a rule-shaped write, so a delivery report arriving mid-edit cannot
// put back the threshold an operator just changed. A rule deleted in the meantime is not an error.
func (s *scopedPostgres) RecordAlertDelivery(ctx context.Context, ruleID string, at time.Time,
	failure string) error {

	return s.withTenant(ctx, "recording an alert delivery", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE alert_rules
			   SET last_delivery_at = $3, last_delivery_error = $4
			 WHERE tenant_id = $1 AND id = $2`, string(s.tenant), ruleID, at, failure)
		return wrap(err, "recording an alert delivery")
	})
}

// DeleteAlertRule removes a rule; its firing state follows by cascade.
func (s *scopedPostgres) DeleteAlertRule(ctx context.Context, id string) error {
	return s.withTenant(ctx, "deleting an alert rule", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			DELETE FROM alert_rules WHERE tenant_id = $1 AND id = $2`, string(s.tenant), id)
		if err != nil {
			return wrap(err, "deleting an alert rule")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ListAlertStates returns the evaluator's memory for every key it holds one for.
func (s *scopedPostgres) ListAlertStates(ctx context.Context) ([]AlertState, error) {
	var out []AlertState
	err := s.withTenant(ctx, "listing alert states", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT rule_id, host_id, subject, firing,
			       COALESCE(since, 'epoch'::timestamptz),
			       COALESCE(last_notified, 'epoch'::timestamptz)
			  FROM alert_states
			 WHERE tenant_id = $1`, string(s.tenant))
		if err != nil {
			return wrap(err, "listing alert states")
		}
		defer rows.Close()

		for rows.Next() {
			var st AlertState
			if err := rows.Scan(&st.RuleID, &st.HostID, &st.Subject, &st.Firing, &st.Since,
				&st.LastNotified); err != nil {
				return wrap(err, "scanning an alert state")
			}
			if st.Since.Unix() == 0 {
				st.Since = time.Time{}
			}
			if st.LastNotified.Unix() == 0 {
				st.LastNotified = time.Time{}
			}
			out = append(out, st)
		}
		return wrap(rows.Err(), "listing alert states")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertAlertState records one key's state.
func (s *scopedPostgres) UpsertAlertState(ctx context.Context, st AlertState) error {
	return s.withTenant(ctx, "recording an alert state", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO alert_states
			            (tenant_id, rule_id, host_id, subject, firing, since, last_notified)
			VALUES ($1, $2, $3, $4, $5,
			        NULLIF($6, 'epoch'::timestamptz), NULLIF($7, 'epoch'::timestamptz))
			ON CONFLICT (tenant_id, rule_id, host_id, subject) DO UPDATE
			   SET firing = EXCLUDED.firing, since = EXCLUDED.since,
			       last_notified = EXCLUDED.last_notified`,
			string(s.tenant), st.RuleID, st.HostID, st.Subject, st.Firing,
			zeroAsEpoch(st.Since), zeroAsEpoch(st.LastNotified))
		return wrap(err, "recording an alert state")
	})
}

// ClaimAlertNotification takes the right to notify for one (rule, host) pair, atomically.
//
// One statement, and every part of it is load-bearing. The INSERT ... ON CONFLICT ... DO UPDATE with a
// WHERE on the conflict target is PostgreSQL's compare-and-set: the row is written only when the held
// last_notified is null or older than the cooldown, and RETURNING tells the caller whether that
// happened. A losing caller gets no row and sends nothing.
//
// A read followed by a write would not do. Event-routed alerts run one detached goroutine per event,
// so two units failing on the same heartbeat race here; and a hosted installation runs more than one
// control plane, where a mutex would not help at all.
func (s *scopedPostgres) ClaimAlertNotification(ctx context.Context, key AlertKey,
	at time.Time, cooldown time.Duration) (bool, error) {

	claimed := false
	err := s.withTenant(ctx, "claiming an alert notification", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			INSERT INTO alert_states
			            (tenant_id, rule_id, host_id, subject, firing, since, last_notified)
			VALUES ($1, $2, $3, $4, true, $5, $5)
			ON CONFLICT (tenant_id, rule_id, host_id, subject) DO UPDATE
			   SET firing = true, last_notified = $5,
			       since = COALESCE(alert_states.since, $5)
			 WHERE alert_states.last_notified IS NULL
			    OR alert_states.last_notified <= $6
			RETURNING rule_id`,
			string(s.tenant), key.RuleID, key.HostID, key.Subject, at, at.Add(-cooldown))
		if err != nil {
			return wrap(err, "claiming an alert notification")
		}
		defer rows.Close()
		claimed = rows.Next()
		return wrap(rows.Err(), "claiming an alert notification")
	})
	if err != nil {
		return false, err
	}
	return claimed, nil
}

// ReleaseAlertFiring clears one key's firing flag, atomically, and keeps its cooldown.
//
// The WHERE clause is the compare-and-set: only a row that is currently firing is updated, and
// RETURNING says whether one was. A second control plane arriving after the first matches nothing and
// sends no second recovery.
//
// last_notified is deliberately left standing. Clearing it made the cooldown unreachable for anything
// that oscillates — every recovery handed the next firing a clean claim, so a host crossing its
// threshold, dropping back and crossing again mailed on every crossing for ever. Keeping the stamp is
// what makes one firing per cooldown true whatever the condition does in between.
func (s *scopedPostgres) ReleaseAlertFiring(ctx context.Context, key AlertKey) (bool, error) {
	released := false
	err := s.withTenant(ctx, "releasing an alert firing", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			UPDATE alert_states
			   SET firing = false, since = NULL
			 WHERE tenant_id = $1 AND rule_id = $2 AND host_id = $3 AND subject = $4 AND firing
			RETURNING rule_id`, string(s.tenant), key.RuleID, key.HostID, key.Subject)
		if err != nil {
			return wrap(err, "releasing an alert firing")
		}
		defer rows.Close()
		released = rows.Next()
		return wrap(rows.Err(), "releasing an alert firing")
	})
	if err != nil {
		return false, err
	}
	return released, nil
}

// zeroAsEpoch maps a zero time onto the epoch sentinel the SQL above turns into NULL.
//
// The dance exists because a Go zero time is year 1, which PostgreSQL stores happily and then returns
// as a value nothing recognises as "never". Epoch is the sentinel the rest of this file already uses
// for the reverse direction.
func zeroAsEpoch(t time.Time) time.Time {
	if t.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return t
}

// clampEventLimit turns a caller's requested inbox size into one the store will run.
func clampEventLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultEventLimit
	case n > MaxEventLimit:
		return MaxEventLimit
	default:
		return n
	}
}

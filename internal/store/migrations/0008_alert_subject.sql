-- A firing is about a subject, not only about a host.
--
-- alert_states was keyed on (tenant, rule, host), which is the "cooldown per rule per host" the
-- design asked for and is one dimension short for the conditions that route events. A unit_failed
-- rule can fire about more than one unit on one machine: nginx failing at 09:00 claimed the pair,
-- and postgresql failing at 09:05 lost the claim to it and was dropped in silence — no mail, and no
-- delivery record saying none had been sent, which is the one outcome the whole delivery-record
-- column exists to prevent.
--
-- Empty is the subject for everything that is about the machine as a whole, which is what every
-- existing row means and what the column defaults to, so this widens the key without moving any row
-- that already exists.
ALTER TABLE alert_states
    ADD COLUMN IF NOT EXISTS subject text NOT NULL DEFAULT '';

ALTER TABLE alert_states DROP CONSTRAINT IF EXISTS alert_states_pkey;
ALTER TABLE alert_states ADD  PRIMARY KEY (tenant_id, rule_id, host_id, subject);

-- The age half of "pending security updates > N, or older than N days".
--
-- The condition list is a CHECK rather than a lookup table because the set is closed at compile time
-- in Go as well, and two places that must agree are better as two literals a reviewer can compare
-- than as a table somebody can INSERT into. Widening it is therefore a migration, deliberately.
ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_condition_known;
ALTER TABLE alert_rules
    ADD CONSTRAINT alert_rules_condition_known
    CHECK (condition IN ('host_silent', 'security_updates', 'security_updates_age',
                         'reboot_required', 'unit_failed', 'job_failed'));

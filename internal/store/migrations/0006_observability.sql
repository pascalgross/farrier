-- Observability: the event inbox, unit-state history, and alerting rules with their firing state.
--
-- These four tables share one purpose — telling an operator something happened without them looking
-- at the UI — and one boundary: all of them are tenant-owned, so all of them get row-level security
-- enabled AND forced, exactly as migration 0004 built it. One customer's incidents are not another
-- customer's reading material.
--
-- Sizing note: events and unit_transitions are bounded by eviction in the store (MaxEventsPerTenant,
-- MaxUnitTransitionsPerHost) rather than by a retention job. The inbox answers "what happened
-- recently"; the permanent audit trail for jobs is the jobs table, which is kept for ever.

-- The event inbox. The SSE stream and the webhook are best-effort; this is the copy that makes a
-- missed delivery visible on the next page load rather than simply absent.
CREATE TABLE IF NOT EXISTS events (
    tenant_id text        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    id        text        NOT NULL,
    kind      text        NOT NULL,
    -- No foreign key to hosts: an event about a host legitimately outlives the host, and "web-07 was
    -- deleted" is exactly the kind of entry an inbox exists to keep.
    host_id   text        NOT NULL DEFAULT '',
    hostname  text        NOT NULL DEFAULT '',
    summary   text        NOT NULL,
    at        timestamptz NOT NULL,
    detail    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS events_tenant_at ON events (tenant_id, at DESC, id DESC);

ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS events_tenant_isolation ON events;
CREATE POLICY events_tenant_isolation ON events
    USING      (tenant_id = current_setting('hostseal.tenant', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

-- Unit-state history, at heartbeat resolution. A unit that fails and recovers between two beats is
-- invisible here, which is a stated property of the digest-first design rather than a bug.
CREATE TABLE IF NOT EXISTS unit_transitions (
    tenant_id  text        NOT NULL,
    host_id    text        NOT NULL,
    unit       text        NOT NULL,
    from_state text        NOT NULL,
    to_state   text        NOT NULL,
    at         timestamptz NOT NULL,
    -- The composite key carries the tenant beside the host reference, so a row claiming one tenant
    -- while pointing at another's host is refused by the database rather than noticed in review.
    CONSTRAINT unit_transitions_host_fk
        FOREIGN KEY (host_id, tenant_id) REFERENCES hosts (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS unit_transitions_host_at
    ON unit_transitions (tenant_id, host_id, at DESC);

ALTER TABLE unit_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE unit_transitions FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS unit_transitions_tenant_isolation ON unit_transitions;
CREATE POLICY unit_transitions_tenant_isolation ON unit_transitions
    USING      (tenant_id = current_setting('hostseal.tenant', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

-- Alerting rules. They live here and not in policy.toml, deliberately: that file is the host's
-- authority over what may be done to it, and an alerting rule is the control plane's business.
CREATE TABLE IF NOT EXISTS alert_rules (
    tenant_id           text        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    id                  text        NOT NULL,
    condition           text        NOT NULL
        CONSTRAINT alert_rules_condition_known
        CHECK (condition IN ('host_silent', 'security_updates', 'reboot_required',
                             'unit_failed', 'job_failed')),
    threshold           integer     NOT NULL DEFAULT 0,
    cooldown_seconds    integer     NOT NULL DEFAULT 0,
    email_to            jsonb       NOT NULL DEFAULT '[]'::jsonb,
    enabled             boolean     NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now(),
    created_by          text        NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rules FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alert_rules_tenant_isolation ON alert_rules;
CREATE POLICY alert_rules_tenant_isolation ON alert_rules
    USING      (tenant_id = current_setting('hostseal.tenant', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

-- The evaluator's memory of one (rule, host) pair: firing or not, since when, and when it last
-- notified. Persisted so that a control plane deploy at 09:00 does not re-page everybody about the
-- host that has been down since 03:00, and so the recovery event survives a restart.
CREATE TABLE IF NOT EXISTS alert_states (
    tenant_id     text        NOT NULL,
    rule_id       text        NOT NULL,
    -- Empty for the digest row a fleet-wide notification keeps its cooldown under. No foreign key to
    -- hosts for the same reason events carry none: the state that says "already notified about this
    -- host" must not evaporate the moment somebody deletes the row it was about.
    host_id       text        NOT NULL DEFAULT '',
    firing        boolean     NOT NULL DEFAULT false,
    since         timestamptz,
    last_notified timestamptz,
    PRIMARY KEY (tenant_id, rule_id, host_id),
    CONSTRAINT alert_states_rule_fk
        FOREIGN KEY (tenant_id, rule_id) REFERENCES alert_rules (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE alert_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_states FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alert_states_tenant_isolation ON alert_states;
CREATE POLICY alert_states_tenant_isolation ON alert_states
    USING      (tenant_id = current_setting('hostseal.tenant', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

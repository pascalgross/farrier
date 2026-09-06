-- Multi-tenancy, and the approval rule that stops being a constant.
--
-- One control plane serves many independent fleets. That is a hosting requirement, and it changes what
-- "isolation" has to mean here: until now every row in this schema belonged to the same people, so a
-- query that forgot a predicate returned too much to somebody who was already entitled to see it. With
-- tenants, the same forgotten predicate is a disclosure to a different customer.
--
-- So the boundary is not left to the twenty-odd hand-written predicates in postgres.go. Every table
-- holding tenant data has row-level security enabled AND forced, with a policy keyed on a session
-- setting the application sets inside the transaction that runs the query. A query that forgets its
-- WHERE clause returns nothing rather than everything, and a query issued with no tenant set returns
-- nothing at all: current_setting(..., true) is NULL when unset, and `tenant_id = NULL` is NULL, which
-- is not true. The failure mode is an empty result, which is loud, rather than another tenant's fleet,
-- which is silent.
--
-- FORCE is the half that is easy to omit and worthless to omit: without it the table owner — which is
-- the role running the application — bypasses every policy below and the isolation is decoration. A
-- role with BYPASSRLS or SUPERUSER bypasses them too, whatever this file says, which is why
-- hostseal-server refuses to start on such a role rather than serving without the boundary it claims.
--
-- Two rows have to be findable before the tenant is known, because finding them is *how* the tenant
-- becomes known: the certificate presented on an agent request, and the enrolment token presented by a
-- machine that is not yet a host. Rather than exempting those two tables, the policies admit exactly
-- one row — the row whose key the caller can already name — through a second session setting. Naming a
-- SHA-256 you already hold is not an enumeration path, and it keeps the exemption to a single row
-- instead of a whole table.
--
-- A note for whoever writes migration 0005: FORCE applies to this file's successors too. A migration
-- that has to touch existing tenant rows must either set hostseal.tenant per tenant or disable the
-- policy around itself. This one does its backfill before the policies exist, which is why the
-- ALTER ... ENABLE statements are all at the end.

CREATE TABLE IF NOT EXISTS tenants (
    id           text PRIMARY KEY,
    -- A short stable handle for URLs, logs and support tickets. Separate from the display name because
    -- a customer renaming themselves must not change the identifier anything else refers to.
    slug         text        NOT NULL UNIQUE,
    display_name text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    -- How a destructive job is released, per tenant rather than per installation. A control plane
    -- serving a one-person shop and a regulated customer cannot answer this question once for both,
    -- which is the whole reason it is a column and not a flag.
    --
    --   none          the offline signature is the entire control-plane-side authorisation and the job
    --                 is claimable as soon as it is created;
    --   self          somebody must release it, and it may be whoever created it;
    --   second_person somebody other than its creator must release it.
    --
    -- The default is 'none'. A destructive job already carries a signature made offline by a key this
    -- control plane does not hold, which is what docs/SECURITY.md §1 actually rests on; approval is a
    -- control-plane control that defends against a careless operator and not a compromised one. An
    -- installation with one operator could not satisfy 'second_person' at all, so making it the default
    -- would ship a tier nobody could reach.
    approval_mode text NOT NULL DEFAULT 'none'
        CONSTRAINT tenants_approval_mode_known
        CHECK (approval_mode IN ('none', 'self', 'second_person')),
    -- Where this tenant's events go, empty for nowhere.
    --
    -- Per tenant rather than per process, and that is a correctness matter rather than a feature. The
    -- server previously held one list of sinks and delivered every event to all of them; on a hosted
    -- installation that is one customer's hostnames, intents and operator names arriving at another
    -- customer's chat channel. No test would have caught it and the customer would have.
    webhook_url text NOT NULL DEFAULT ''
);

-- The tenant every existing row joins. Installations that predate this migration have exactly one
-- fleet and one operator, and inventing a name for it here is better than requiring a manual step
-- between two versions of the same binary.
INSERT INTO tenants (id, slug, display_name, approval_mode)
VALUES ('default', 'default', 'Default', 'none')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------------------------------
-- The tenant column, backfilled while there are no policies to get in the way.
-- ---------------------------------------------------------------------------------------------------

ALTER TABLE hosts             ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE jobs              ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE job_results       ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE certificates      ADD COLUMN IF NOT EXISTS tenant_id text;

UPDATE hosts             SET tenant_id = 'default' WHERE tenant_id IS NULL;
UPDATE enrollment_tokens SET tenant_id = 'default' WHERE tenant_id IS NULL;
UPDATE jobs              SET tenant_id = 'default' WHERE tenant_id IS NULL;
UPDATE job_results       SET tenant_id = 'default' WHERE tenant_id IS NULL;
UPDATE certificates      SET tenant_id = 'default' WHERE tenant_id IS NULL;

ALTER TABLE hosts             ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE enrollment_tokens ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE jobs              ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE job_results       ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE certificates      ALTER COLUMN tenant_id SET NOT NULL;

-- ---------------------------------------------------------------------------------------------------
-- Composite foreign keys, so a row cannot claim one tenant while pointing at another's.
--
-- The wider key is the point. A jobs row naming tenant B and a tenant-A host is the exact shape of a
-- successful cross-tenant write, and this is the difference between the database refusing it and a
-- reviewer noticing it.
-- ---------------------------------------------------------------------------------------------------

ALTER TABLE hosts ADD CONSTRAINT hosts_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE;
ALTER TABLE enrollment_tokens ADD CONSTRAINT enrollment_tokens_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE;

ALTER TABLE hosts ADD CONSTRAINT hosts_id_tenant_unique UNIQUE (id, tenant_id);

ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_host_id_fkey;
ALTER TABLE certificates ADD CONSTRAINT certificates_host_fk
    FOREIGN KEY (host_id, tenant_id) REFERENCES hosts (id, tenant_id) ON DELETE CASCADE;

ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_host_id_fkey;
ALTER TABLE jobs ADD CONSTRAINT jobs_host_fk
    FOREIGN KEY (host_id, tenant_id) REFERENCES hosts (id, tenant_id) ON DELETE CASCADE;

-- Host ids stay globally unique, and jobs_signed_nonce_once depends on that.
--
-- The uniqueness rules here are deliberately mixed, so it is worth saying which is which. A host id is
-- generated by the control plane and a certificate fingerprint is the SHA-256 of a certificate it
-- issued; both are unique across the installation by construction, and the composite key added above is
-- there for the foreign keys rather than because a collision was possible. A job id is not in that
-- category: it comes from a customer's offline signer for a signed job, so it is unique per tenant.
--
-- The consequence to keep in mind is that 0002's jobs_signed_nonce_once — UNIQUE (host_id, nonce) WHERE
-- signature IS NOT NULL — carries no tenant column and does not need one *only because* a host belongs
-- to exactly one tenant. If host ids ever become per-tenant, that index silently becomes a constraint
-- spanning tenants, which is the same existence oracle the machine-id index gave up two paragraphs
-- above. Whoever makes that change has to widen this index in the same commit.

-- A job id is unique within a tenant, not across the installation.
--
-- For an unsigned job this control plane generates the id and a collision is not a practical concern.
-- For a signed one the id arrives from the customer's offline signer, is as short as they like, and is
-- theirs to choose — "reboot-2026-08-23" is a reasonable thing for two different customers to pick on
-- the same day. A global key would make the second one a 409, which is both a denial and an existence
-- oracle: it tells one customer that another has queued a job by that name.
ALTER TABLE job_results DROP CONSTRAINT IF EXISTS job_results_job_id_fkey;
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_pkey;
ALTER TABLE jobs ADD CONSTRAINT jobs_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE job_results DROP CONSTRAINT IF EXISTS job_results_pkey;
ALTER TABLE job_results ADD CONSTRAINT job_results_pkey PRIMARY KEY (tenant_id, job_id);
ALTER TABLE job_results ADD CONSTRAINT job_results_job_fk
    FOREIGN KEY (tenant_id, job_id) REFERENCES jobs (tenant_id, id) ON DELETE CASCADE;

-- One live host per machine, per tenant.
--
-- It was one live host per machine across the installation, which under tenancy is an oracle of the
-- same kind: enrolling a machine that is already somebody else's tells you that it is somebody else's.
-- A machine can only run one agent with one credential, so the narrower constraint gives up nothing
-- real.
DROP INDEX IF EXISTS hosts_live_machine_id;
CREATE UNIQUE INDEX IF NOT EXISTS hosts_live_machine_id
    ON hosts (tenant_id, machine_id_hash)
    WHERE machine_id_hash IS NOT NULL AND NOT revoked;

CREATE INDEX IF NOT EXISTS hosts_tenant ON hosts (tenant_id);
CREATE INDEX IF NOT EXISTS enrollment_tokens_tenant ON enrollment_tokens (tenant_id, created_at DESC);

-- The three indexes the job listing runs against, and it had none.
--
-- Migration 0001 built a partial index so that *claiming* would not slow down over a year, and said so.
-- The listing added afterwards reads exactly the rows that index excludes — completed ones — so every
-- load of the jobs page sequentially scanned the whole history and sorted it to return a hundred rows.
-- Measured on a seeded million-row table: 1.6 seconds and a sort spilling to disk, against 1.5
-- milliseconds with these. The web client re-reads the list after every create and every approve, so
-- the cost is paid per interaction and grows for as long as the installation keeps its audit trail —
-- which is for ever, deliberately.
--
-- Three rather than one because a leading tenant_id serves the fleet-wide order, but a leading
-- (tenant_id, host_id) cannot serve an ORDER BY that has no host predicate, and the awaiting-approval
-- listing is a different, much smaller set that deserves its own partial index rather than a scan of
-- everything the tenant has ever run.
CREATE INDEX IF NOT EXISTS jobs_tenant_issued
    ON jobs (tenant_id, issued_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS jobs_tenant_host_issued
    ON jobs (tenant_id, host_id, issued_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS jobs_tenant_awaiting
    ON jobs (tenant_id, issued_at DESC, id DESC)
    WHERE approval_required AND approved_at IS NULL;

-- ---------------------------------------------------------------------------------------------------
-- The approval rule, recorded on the row.
--
-- approval_required already works this way and migration 0002 wrote down why: a later build that
-- classified an intent differently must not silently change what an already-queued job required. The
-- same argument applies with more force to a setting an operator can edit — queue a job under the
-- two-person rule, relax the tenant's setting, approve your own job. Stamping both halves at creation
-- closes that, and it is why this is a column rather than a join.
-- ---------------------------------------------------------------------------------------------------

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS approval_distinct_operator boolean NOT NULL DEFAULT false;

-- Every job that already exists was created when the rule was unconditional.
UPDATE jobs SET approval_distinct_operator = true WHERE approval_required;

-- ---------------------------------------------------------------------------------------------------
-- Row-level security.
--
-- Enabled and FORCED. Everything above this line ran without it; nothing below this line can.
-- ---------------------------------------------------------------------------------------------------

ALTER TABLE hosts       ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosts       FORCE  ROW LEVEL SECURITY;
ALTER TABLE jobs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs        FORCE  ROW LEVEL SECURITY;
ALTER TABLE job_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_results FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS hosts_tenant_isolation ON hosts;
CREATE POLICY hosts_tenant_isolation ON hosts
    USING      (tenant_id = current_setting('hostseal.tenant', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

DROP POLICY IF EXISTS jobs_tenant_isolation ON jobs;
CREATE POLICY jobs_tenant_isolation ON jobs
    USING      (tenant_id = current_setting('hostseal.tenant', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

DROP POLICY IF EXISTS job_results_tenant_isolation ON job_results;
CREATE POLICY job_results_tenant_isolation ON job_results
    USING      (tenant_id = current_setting('hostseal.tenant', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

-- The two tables that have to be readable before the tenant is known.
--
-- An agent presents a certificate and a new machine presents an enrolment token, and in both cases
-- discovering which tenant the caller belongs to *is* the lookup. Exempting the tables would put two
-- whole tables outside the boundary; instead the policy admits the single row whose key the caller
-- named in hostseal.resolve_key. That key is a SHA-256 the caller already holds — of a certificate this
-- CA issued, or of a token issued to that tenant — so naming one is not a way of finding another. Every
-- other access to these tables goes through hostseal.tenant like everything else.
ALTER TABLE certificates      ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificates      FORCE  ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS certificates_tenant_isolation ON certificates;
CREATE POLICY certificates_tenant_isolation ON certificates
    USING      (tenant_id = current_setting('hostseal.tenant', true)
                OR fingerprint = current_setting('hostseal.resolve_key', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

DROP POLICY IF EXISTS enrollment_tokens_tenant_isolation ON enrollment_tokens;
CREATE POLICY enrollment_tokens_tenant_isolation ON enrollment_tokens
    USING      (tenant_id = current_setting('hostseal.tenant', true)
                OR hash = current_setting('hostseal.resolve_key', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true)
                OR hash = current_setting('hostseal.resolve_key', true));

-- tenants itself is deliberately not under a tenant policy: it is the table a platform administrator
-- manages, and a row in it is the tenant rather than something belonging to one. Reaching it at all
-- requires the platform credential, which is a separate identity holding no tenant of its own — see
-- internal/auth.

-- Operators as people rather than as a shared string.
--
-- Until now a fleet had one credential: a bearer token compared against a SHA-256 in the process, with
-- the same identity — `static-token:operator` — recorded against every job anybody queued. That is
-- enough to keep strangers out and not enough to answer "who rebooted it", and it makes the
-- second-person approval rule unsatisfiable by construction: the rule compares the approver's principal
-- against the job's creator, and under one shared token those two strings are always equal.
--
-- So an account, with an address and a password, per person and per fleet. The token stays: it is what
-- a script uses and what a fresh control plane hands whoever started it, and removing it would put
-- account creation between `docker compose up` and the fleet list.
--
-- Two tables, and the split between them is the same one migration 0004 drew. An account belongs to a
-- tenant exactly as a host does, so it lives under row-level security like everything else a tenant
-- owns; a session belongs to the account that created it and carries its tenant for the same reason a
-- certificate row does — resolving one is how a request finds out whose data it may touch.
--
-- The platform credential is deliberately not here. It remains a bearer token, because it is the
-- installation's own credential rather than a person's, because docs/SECURITY.md §5.3 turns on it
-- holding no tenant at all, and because an account table for it would be a second, unpoliced copy of
-- this machinery for exactly one row.

-- ---------------------------------------------------------------------------------------------------
-- The accounts.
-- ---------------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS operator_accounts (
    -- Generated here, and the tenant travels with it in the key, matching every other tenant-owned
    -- table since 0004.
    id            text        NOT NULL,
    tenant_id     text        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,

    -- The address as the operator typed it, kept for display, and the lookup key derived from it.
    --
    -- Two columns rather than one because they answer different questions. `email` is what a person
    -- reads in an audit log and what they see on the sign-in form; `email_key` is the SHA-256 of the
    -- normalised address, and it is what the row is found by. Hashing the lookup key is not privacy
    -- theatre — it is what lets the sign-in path name a single row through farrier.resolve_key, the
    -- same mechanism 0004 built for certificates and enrolment tokens, without a second kind of
    -- session setting for a second shape of key.
    email         text        NOT NULL,
    email_key     text        NOT NULL,

    display_name  text        NOT NULL DEFAULT '',

    -- Argon2id in the PHC string format, parameters and salt included. See internal/auth/password.go
    -- for why the parameters travel with the digest rather than living only in the binary.
    password_hash text        NOT NULL,

    created_at    timestamptz NOT NULL DEFAULT now(),

    -- When this account last signed in, NULL for never. It is the one thing that makes a stale account
    -- visible before somebody has to guess which of six colleagues has left.
    last_signed_in_at timestamptz,

    PRIMARY KEY (tenant_id, id)
);

-- An address identifies a person across the installation, not within a fleet.
--
-- Unique globally rather than per tenant, and that is a decision with a cost worth naming. Sign-in
-- names an address and nothing else — there is no fleet on the form, because a fleet in a login form is
-- a field an operator could edit to point at somebody else's — so two accounts sharing an address in
-- different fleets would make "which fleet am I signing in to" unanswerable. The cost is that creating
-- an account with an address another fleet already uses is refused, which tells whoever created it that
-- the address exists somewhere. That is an existence oracle of the kind 0004 removed from the machine-id
-- index, and it is acceptable here for a reason that does not apply there: creating an account is not an
-- operation any tenant's operator can perform. It happens on the machine, through
-- `farrier-server accounts`, by somebody who can already read the table.
CREATE UNIQUE INDEX IF NOT EXISTS operator_accounts_email ON operator_accounts (email_key);

-- ---------------------------------------------------------------------------------------------------
-- The sessions.
--
-- A browser cannot hold a password, so signing in exchanges one for an opaque 256-bit token kept in an
-- HttpOnly cookie. Only its SHA-256 is stored, exactly as for an enrolment token and for the same
-- reason: a database dump must not be a set of live credentials. Unsalted and unstretched is right here
-- and wrong for the password column two tables up — the difference is that this input is uniform
-- randomness this process generated, so there is no dictionary to attack.
-- ---------------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS operator_sessions (
    token_hash text        PRIMARY KEY,

    -- The account, and its tenant beside it so that resolving a session answers both questions at once.
    -- The composite foreign key is 0004's rule applied again: a session row claiming one tenant while
    -- pointing at another's account is refused by the database rather than noticed in review.
    tenant_id  text        NOT NULL,
    account_id text        NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),

    -- Checked against the local clock on every request. A row past it authenticates nobody and is
    -- deleted by the next sign-in of the account that owns it; there is no sweeper, because the table
    -- grows by one row per sign-in and shrinks by all of that account's dead rows at the next one.
    expires_at timestamptz NOT NULL,

    CONSTRAINT operator_sessions_account_fk
        FOREIGN KEY (tenant_id, account_id) REFERENCES operator_accounts (tenant_id, id)
        ON DELETE CASCADE
);

-- The index the sign-in sweep and a sign-out-everywhere would both run against.
CREATE INDEX IF NOT EXISTS operator_sessions_account
    ON operator_sessions (tenant_id, account_id, expires_at);

-- ---------------------------------------------------------------------------------------------------
-- Row-level security, enabled and FORCED, exactly as for every other tenant-owned table.
--
-- Both tables have to be readable before the tenant is known, because finding the row *is* how the
-- tenant becomes known — the third and fourth instance of what 0004 built farrier.resolve_key for, and
-- deliberately the same mechanism rather than a second one.
--
-- One difference from certificates and enrolment tokens is worth writing down rather than leaving for
-- somebody to notice. There, the key a caller names is a SHA-256 of something they already hold, so
-- naming one is not a way of finding another. A session token is exactly that. An address is not: it is
-- guessable, so the policy below admits a row whose key an attacker can construct. What keeps that from
-- being a disclosure is not the policy but the endpoint that sets the key — POST /api/v1/session
-- answers a wrong address and a wrong password with the same refusal, in the same time, under a rate
-- limit — and this comment exists so that a later change to that endpoint knows it is load-bearing.
-- ---------------------------------------------------------------------------------------------------

ALTER TABLE operator_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_accounts FORCE  ROW LEVEL SECURITY;
ALTER TABLE operator_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_sessions FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS operator_accounts_tenant_isolation ON operator_accounts;
CREATE POLICY operator_accounts_tenant_isolation ON operator_accounts
    USING      (tenant_id = current_setting('farrier.tenant', true)
                OR email_key = current_setting('farrier.resolve_key', true))
    WITH CHECK (tenant_id = current_setting('farrier.tenant', true));

DROP POLICY IF EXISTS operator_sessions_tenant_isolation ON operator_sessions;
CREATE POLICY operator_sessions_tenant_isolation ON operator_sessions
    USING      (tenant_id = current_setting('farrier.tenant', true)
                OR token_hash = current_setting('farrier.resolve_key', true))
    WITH CHECK (tenant_id = current_setting('farrier.tenant', true));

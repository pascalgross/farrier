-- Two invariants that were true because every writer remembered them.
--
-- The codebase's own position is that tenant isolation is "enforced by PostgreSQL, not by remembering".
-- These are the two places where that was not quite so: one predicate the database would have accepted
-- a cross-tenant write through, and one value the database would have accepted that nothing in the
-- schema forbade. Neither is reachable today. Both are the kind of thing a later change reaches by
-- accident, and neither would produce an error when it did — the wrong rows would simply become
-- writable, or readable, in silence.
--
-- Why a new file rather than edits to 0004. `Migrate` keys the schema-version ledger on the filename,
-- so an edit to an already-applied migration reaches a fresh database and no existing one — which is
-- the shape where the fix appears to be everywhere and is in fact only on the machines that had no
-- problem. 0007 states the rule and gives the reason: append-only from the moment a migration can have
-- run anywhere, which is the moment it was pushed.

-- ---------------------------------------------------------------------------------------------------
-- The resolve-key exemption is a read, and only a read.
-- ---------------------------------------------------------------------------------------------------
--
-- 0004 built hostseal.resolve_key for the lookups that must happen *before* the tenant is known: an
-- agent presenting a certificate, and a machine presenting an enrolment token. The exemption is narrow
-- by construction — it admits exactly the row whose key the caller already holds, and that key is a
-- SHA-256 of something they have.
--
-- What makes it safe is that it is a read. A `WITH CHECK` carrying the same disjunct says something
-- else entirely: that a writer inside such a transaction may create or move a row into *any* tenant, so
-- long as the row's key equals the one they named. `hostseal.tenant` is unset in exactly those
-- transactions, so the tenant half of the predicate is NULL and the resolve-key half is the whole rule.
--
-- certificates got this right and enrollment_tokens did not, with nothing to say why the siblings
-- differed. Nothing writes to enrollment_tokens inside a resolve-key transaction today; the reason to
-- fix it now is that `WITH CHECK` is precisely the guard the writer who eventually does would be
-- relying on. A "touch the last-used timestamp" optimisation is all it would take.
--
-- The policy is otherwise unchanged: the `USING` half keeps the exemption, because that is what the
-- pre-tenant lookup needs.

DROP POLICY IF EXISTS enrollment_tokens_tenant_isolation ON enrollment_tokens;
CREATE POLICY enrollment_tokens_tenant_isolation ON enrollment_tokens
    USING      (tenant_id = current_setting('hostseal.tenant', true)
                OR hash = current_setting('hostseal.resolve_key', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

COMMENT ON TABLE enrollment_tokens IS
    'Single-use bootstrap tokens, by hash. The row-level security policy admits one row by '
    'hostseal.resolve_key for the pre-tenant lookup at enrolment; that exemption is read-only and must '
    'never appear in a WITH CHECK, or a writer in such a transaction could place a row in any tenant.';

COMMENT ON TABLE certificates IS
    'Issued agent certificates, by fingerprint. The row-level security policy admits one row by '
    'hostseal.resolve_key for the pre-tenant lookup on every authenticated agent request; that '
    'exemption is read-only and must never appear in a WITH CHECK.';

-- ---------------------------------------------------------------------------------------------------
-- A tenant id is never the empty string.
-- ---------------------------------------------------------------------------------------------------
--
-- This one is load-bearing in a way its size hides. A pooled connection that has set hostseal.tenant and
-- let it lapse reports `''` from `current_setting('hostseal.tenant', true)` for the rest of its life,
-- not NULL — so a tenant whose id were `''` would be the single fleet every statement that named no
-- tenant could reach, including every resolve-key lookup. The failure is invisible: nothing errors, the
-- wrong rows simply become readable.
--
-- CreateTenant refuses it in Go and explains why. That guard is one function, and any INSERT that does
-- not go through it — a maintenance script, a data import, a refactor — recreates the state. So the
-- database says it too.

ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_id_nonempty;
ALTER TABLE tenants ADD  CONSTRAINT tenants_id_nonempty CHECK (id <> '');

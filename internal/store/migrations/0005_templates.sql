-- Provisioning templates: Tier 1 of docs/SECURITY.md §7.
--
-- A template is stored, versioned and rendered here, and never delivered to a host by this control
-- plane — the rendered user-data goes to a human or to Terraform, and the one exception is the Tier 2
-- bootstrap at enrolment, which hands over stored bytes together with a signature this control plane
-- did not and cannot produce.
--
-- Two decisions in the shape of this table carry the design:
--
--   * A row is one immutable version, and (name, version) is the identity. Tier 2 records "web-07 was
--     bootstrapped with standard-server v3", and that record is worthless if the row it names can be
--     edited afterwards — it has to resolve to the bytes that actually ran, not to whatever
--     standard-server says today. So there is no UPDATE path for a body anywhere in the store: a
--     change is a new version.
--
--   * The body column holds ciphertext. docs/SECURITY.md §7 requires template bodies encrypted at
--     rest, because rendered user-data carries a live enrolment token and operators will put more into
--     template bodies than they should. The key lives beside the CA (see internal/seal and
--     docs/INSTALL.md), so this database — and every backup of it — is unreadable without a file that
--     is backed up separately and deliberately.
--
-- The signature columns hold a detached signature over the canonical {name, body} payload, produced
-- offline by `hostseal sign-template` with a key this control plane does not hold. They are stored
-- verbatim and handed over verbatim at enrolment: the control plane can no more mint one than it can
-- mint a destructive job signature, and internal/server's guarantee tests assert that rather than this
-- comment claiming it.

CREATE TABLE IF NOT EXISTS templates (
    tenant_id        text        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name             text        NOT NULL,
    version          integer     NOT NULL CHECK (version > 0),
    -- AES-256-GCM ciphertext, nonce-prefixed; see internal/seal. One column rather than body+nonce so
    -- that the two halves cannot be updated independently of each other.
    body_sealed      bytea       NOT NULL,
    -- Detached signature over the canonical {name, body} payload, base64; empty for an unsigned
    -- version. An unsigned version can be rendered for Terraform and can never be issued at enrolment.
    signature        text        NOT NULL DEFAULT '',
    signer_key_id    text        NOT NULL DEFAULT '',
    signer_algorithm text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    created_by       text        NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, name, version)
);

-- The listing reads "the latest version of every name", newest names first; the primary key already
-- serves the per-name lookups, and this serves the ordering without a scan.
CREATE INDEX IF NOT EXISTS templates_tenant_created
    ON templates (tenant_id, created_at DESC);

-- Row-level security, exactly as migration 0004 built it for every other tenant-owned table: enabled
-- AND forced, keyed on the transaction-local setting. A statement that forgets its WHERE clause
-- returns nothing rather than another customer's provisioning secrets.
ALTER TABLE templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE templates FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS templates_tenant_isolation ON templates;
CREATE POLICY templates_tenant_isolation ON templates
    USING      (tenant_id = current_setting('hostseal.tenant', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

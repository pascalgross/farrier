-- The wallboard, and the one credential that opens it.
--
-- A wallboard is one screen of a fleet's own status on a television in a corridor. What makes it a
-- table rather than a route is that the room has no account: a screen on a wall cannot sign in, and
-- lending it an operator's session would hand whoever walks past a credential that can queue a reboot.
-- So a share is a credential of its own kind — it reaches one fixed-shape summary of one fleet, over
-- one endpoint, and can do nothing else at all.
--
-- docs/SECURITY.md §4.5 removed a bearer token from this system, so putting one back deserves the
-- comparison rather than the silence. `FARRIER_ADMIN_TOKEN` was a *write* credential for a whole
-- installation, held in a flag, naming nobody in the audit trail, never expiring, and withdrawable only
-- by restarting the control plane and telling everybody. Every one of those is inverted here: a share
-- reads a summary and writes nothing, it records who published it, it expires on a date somebody chose,
-- and it is withdrawn by deleting one row. The property it does not have is a name for its reader — a
-- link can be forwarded, and nothing here can tell that it was. That is the honest cost of a screen
-- nobody signs in to, and it is why the summary is fixed in shape: there is no query behind it for a
-- forwarded link to widen.
--
-- **Why the policy needs no resolve-key exemption, and must never acquire one.** The published key is
-- `frb_<tenant>.<secret>`, so the tenant travels inside the credential: the server splits it, opens the
-- handle for that tenant, and only then looks the secret up. That is the opposite of a certificate
-- fingerprint or an enrolment token, where finding the row *is* how the tenant is discovered and the
-- narrow `farrier.resolve_key` disjunct exists to permit exactly that. Here the tenant is already known
-- one statement earlier, so such a disjunct would buy nothing and widen the policy to "any row in any
-- fleet whose key the caller can name". The digest below covers the whole key rather than its secret
-- half, which is what makes the tenant segment load-bearing rather than decorative: a key edited to
-- name a neighbouring fleet hashes to a value no row holds, so it is refused by the lookup before the
-- policy is consulted at all.
--
-- **Why there is no `revoked` column.** Revoking is a DELETE, exactly as it is for an API token. A
-- withdrawn share leaves nothing behind, and that is the honest state rather than a gap: a share names
-- no reader, so there is no history hanging off the row that anybody could answer a question with. A
-- flag would keep a dead credential's hash in the table for ever and put one forgotten `AND NOT
-- revoked` between a deleted wallboard and a live one.
--
-- **Why there is no column for what an unlocked screen holds.** A wallboard cannot re-derive Argon2id
-- on every poll — one derivation allocates 64 MiB — so a passphrase is proved once and exchanged for
-- something cheap to check afterwards. The obvious shape for that is a second stored digest, and it is
-- the wrong one twice over: it would be a live credential sitting in the row next to the thing it
-- opens, and it would need a rotation path of its own, since changing a passphrase has to drop every
-- screen unlocked under the old one. Deriving the proof from the key the screen already holds together
-- with the password hash below needs no column and gets that rotation for nothing — the hash changes,
-- so every proof computed from the old one stops verifying at the next poll.
--
-- **Why `expires_at` is NOT NULL.** api_tokens made it nullable and wrote down why — "this one does not
-- expire" is a decision somebody makes, and a token dated 2124 reads as a mistake. That argument does
-- not carry across. An API token belongs to a person who can be asked about it; a share belongs to a
-- screen in a room, and a share that never expires is precisely the credential §4.5 removed wearing a
-- different name. So the column is NOT NULL and the API caps the span it will accept: every published
-- link stops working on a date, whether or not anybody remembers it exists.

CREATE TABLE IF NOT EXISTS wallboard_shares (
    tenant_id     text        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,

    -- What names the share in the interface and in the route that withdraws it. Separate from the
    -- secret because an operator has to be able to revoke a link without holding it — the link is shown
    -- once, at creation, and after that it exists only on a television.
    id            text        NOT NULL,

    -- The SHA-256 of the whole key, including its tenant segment. Unsalted and unstretched, which is
    -- right here for the reason it is right for an enrolment token and wrong for a password: the input
    -- is 256 bits of uniform randomness this process generated, so there is no dictionary to attack.
    secret_hash   text        NOT NULL,

    -- Argon2id in PHC string format, empty for a share with no passphrase. Empty rather than NULL,
    -- matching accounts.password_hash, so that "no passphrase" has one representation instead of two.
    password_hash text        NOT NULL DEFAULT '',

    -- What the operator called it, and the heading the published screen shows. Not defaulted: four
    -- shares called "share" is a list nobody revokes from, and a blank heading tells the room nothing
    -- about which fleet is on the wall.
    label         text        NOT NULL,

    created_at    timestamptz NOT NULL DEFAULT now(),

    -- Whoever published it. The one name a share carries, and the one that matters: since it names no
    -- reader, the question it can answer is who decided this fleet could be published at all.
    created_by    text        NOT NULL DEFAULT '',

    expires_at    timestamptz NOT NULL,

    -- When a screen last polled, NULL for never. Throttled by the caller the way api_tokens.last_used_at
    -- is, and read no more precisely than "somebody is still showing this" — which is what has to be
    -- answerable before anybody revokes a link and waits to see who complains.
    last_seen_at  timestamptz,

    PRIMARY KEY (tenant_id, id)
);

-- The index the public poll seeks on, and the constraint that keeps one secret naming one share.
--
-- Composite rather than a bare UNIQUE on secret_hash: the lookup already knows its tenant, so this is
-- the seek it performs, and a globally unique index would be a cross-tenant constraint standing in for
-- a collision that 256 bits of randomness does not have.
--
-- There is deliberately no second index for the listing. A fleet holds at most
-- MaxWallboardSharesPerTenant live shares — twenty — so the primary key's leading tenant_id is the
-- whole scan, and an index to sort twenty rows would be a line to maintain for a plan nobody would
-- notice.
CREATE UNIQUE INDEX IF NOT EXISTS wallboard_shares_secret ON wallboard_shares (tenant_id, secret_hash);

-- Row-level security, exactly as migration 0004 built it for every other tenant-owned table: enabled
-- AND forced, keyed on the transaction-local setting, and with no exemption of any kind. A statement
-- that forgets its WHERE clause returns nothing rather than another customer's fleet on a wall.
ALTER TABLE wallboard_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallboard_shares FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS wallboard_shares_tenant_isolation ON wallboard_shares;
CREATE POLICY wallboard_shares_tenant_isolation ON wallboard_shares
    USING      (tenant_id = current_setting('farrier.tenant', true))
    WITH CHECK (tenant_id = current_setting('farrier.tenant', true));

COMMENT ON TABLE wallboard_shares IS
    'Public read-only links to one fleet''s status screen, by hash of the whole key. The row-level '
    'security policy has no farrier.resolve_key disjunct and must never acquire one: the tenant '
    'travels inside the key, so it is known before the lookup runs, and an exemption would admit a row '
    'from any fleet to a transaction that has named no tenant at all.';

-- A renewed-away certificate stops working, rather than lasting until its ninetieth day.
--
-- The agent generates a fresh key at every renewal, which is what makes a leaked agent.pem a bounded
-- loss — except that it was not bounded by anything: the superseded certificate stayed valid until its
-- natural expiry, so somebody who read the file on day 10 kept a working authentication path until day
-- 90, and could spend the renewals themselves to extend it indefinitely. Rotation was doing almost none
-- of the work it appears to do.
--
-- What a certificate lets somebody do is impersonate a host *to the server* — never run code on a host,
-- which is the boundary docs/SECURITY.md §4.2 and §9 draw. So this is not a §1 fix. It is the
-- difference between a leaked key being worth two days and being worth three months.

-- NULL means "not superseded", which is every row that exists today and every certificate currently in
-- use. A timestamp is the moment the certificate stops being accepted, set at renewal to a short
-- overlap after it — not to the instant of renewal, because the agent promotes its new credential with
-- one rename and a host that crashed mid-renewal has to be able to come back on the old one.
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS superseded_at timestamptz;

-- The partial index is for the count behind the per-host cap, which asks how many of a host's
-- certificates are still live. Partial because the answer never involves an expired or revoked row, and
-- a fleet's certificates table is mostly those.
CREATE INDEX IF NOT EXISTS certificates_live_by_host
    ON certificates (host_id)
 WHERE NOT revoked;

COMMENT ON COLUMN certificates.superseded_at IS
    'When this certificate stops being accepted because a renewal replaced it, NULL if it has not been '
    'replaced. Set to a short overlap after the renewal rather than to the renewal itself, so a host '
    'interrupted between obtaining a certificate and promoting it can still authenticate on the old one.';

-- Job creation, and the two things docs/SECURITY.md §3 requires around a destructive one.
--
-- The jobs table has been here since 0001, because the delivery path was built and tested a phase
-- before anything created a job to deliver. What it lacked was any record of *who* asked, and the
-- second-person approval §3 promises for the destructive tier. Both are added here rather than being
-- inferred later, because "who authorised this reboot" is the first question after an incident and the
-- worst one to answer with a guess.

-- The operator who created the job. Empty for a row created before this migration, of which there are
-- none in practice: nothing created jobs.
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS created_by text NOT NULL DEFAULT '';

-- Whether this job needs a second person before a host may claim it.
--
-- Stored rather than derived from `class` on every read, for the same reason protocol.Job carries a
-- class the agent then ignores: this records the decision that was made when the job was created. A
-- later build that classified an intent differently must not silently change what an already-queued job
-- required.
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS approval_required boolean NOT NULL DEFAULT false;

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS approved_at timestamptz;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS approved_by text NOT NULL DEFAULT '';

-- A signed payload may be queued once.
--
-- The host refuses a replayed nonce itself, and that is the check the guarantee rests on. This one is
-- earlier and cheaper: a control plane that queued the same signed job twice would have the second
-- delivered, refused on the host, and reported as a failure nobody could explain. Partial, because only
-- a signed job has a nonce that means anything — an unsigned read job gets a random one so the column
-- can stay NOT NULL, and two of those colliding is not a thing that happens.
CREATE UNIQUE INDEX IF NOT EXISTS jobs_signed_nonce_once
    ON jobs (host_id, nonce)
    WHERE signature IS NOT NULL;

-- The claim index, narrowed to what a host may actually take.
--
-- Recreated rather than added alongside: an unapproved destructive job is not claimable, and leaving it
-- in the index would mean every claim scanned rows it could never return. Dropping and recreating is
-- safe here because the index is not a constraint — nothing depends on it existing for an instant.
DROP INDEX IF EXISTS jobs_claimable;
CREATE INDEX IF NOT EXISTS jobs_claimable
    ON jobs (host_id, issued_at)
    WHERE claimed_at IS NULL
      AND completed_at IS NULL
      AND (NOT approval_required OR approved_at IS NOT NULL);

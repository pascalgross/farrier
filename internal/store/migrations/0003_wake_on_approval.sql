-- Wake a waiting agent when a job is approved, not only when it is created.
--
-- 0001's trigger fires AFTER INSERT, which was the whole story while every job became claimable the
-- moment it existed. A destructive job does not: it is created waiting for a second operator, and the
-- INSERT that created it woke every agent to tell them about work none of them could take. The
-- approval, which is what actually makes it claimable, fired nothing at all.
--
-- The cost was latency and it was charged to the wrong account. An agent holding a long poll would not
-- hear about the approval until its own poll expired — up to sixty seconds — and for a *signed* job
-- that delay is measured against the signed notBefore, because the age limit deliberately runs from the
-- value the signer chose rather than from one the control plane can pick. So a slow wake spends the
-- operator's authorisation window rather than the server's.
--
-- The in-memory store woke immediately all along, which is why no test saw the difference.

-- Narrow on purpose. jobs is also UPDATEd when a host claims a job and again when its result arrives,
-- and a trigger on every update would notify the fleet each time somebody's job started — waking agents
-- to re-read a queue that has nothing new in it. The WHEN clause fires on the one transition that
-- changes what a host may claim.
DROP TRIGGER IF EXISTS jobs_notify_approved ON jobs;
CREATE TRIGGER jobs_notify_approved
    AFTER UPDATE ON jobs
    FOR EACH ROW
    WHEN (OLD.approved_at IS NULL AND NEW.approved_at IS NOT NULL)
EXECUTE FUNCTION farrier_notify_job();

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/canonical"
	"github.com/pascalgross/farrier/internal/protocol"
)

// eachStore runs a test body against both implementations.
//
// Every behaviour asserted below is one the two must share, and the two are written in different
// languages against different primitives — a WHERE clause in one and a mutex in the other. A test that
// ran against Memory alone would prove nothing about what ships; one that ran against PostgreSQL alone
// would let the in-memory store drift until a server test started passing for the wrong reason.
func eachStore(t *testing.T, body func(t *testing.T, s Store)) {
	t.Helper()

	t.Run("memory", func(t *testing.T) { body(t, NewMemory()) })
	t.Run("postgres", func(t *testing.T) { body(t, newPostgres(t)) })
}

// jobFor builds a job addressed to a host, with the fields every row needs.
func jobFor(id, intent string) protocol.Job {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return protocol.Job{
		ID: id, Intent: intent, Params: map[string]any{}, Class: "read",
		IssuedAt: now, NotBefore: now, NotAfter: now.Add(time.Hour), Nonce: "nonce-" + id,
	}
}

// TestCreateJobPutsWorkInFrontOfExactlyOneHost is the ordinary path.
func TestCreateJobPutsWorkInFrontOfExactlyOneHost(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		target := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")
		other := enrolTestHost(t, tenant, "01JHOSTB", "b.example.org")

		if err := tenant.CreateJob(ctx, NewJob{
			Job: jobFor("01JOB1", "facts.collect"), HostID: target.ID, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("creating a job: %v", err)
		}

		elsewhere, err := tenant.ClaimJobs(ctx, other.ID, 10)
		if err != nil {
			t.Fatalf("claiming for the other host: %v", err)
		}
		if len(elsewhere) != 0 {
			t.Fatalf("a job addressed to %s was offered to %s", target.ID, other.ID)
		}

		claimed, err := tenant.ClaimJobs(ctx, target.ID, 10)
		if err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if len(claimed) != 1 || claimed[0].ID != "01JOB1" {
			t.Fatalf("claimed %+v", claimed)
		}

		rec, err := tenant.GetJob(ctx, "01JOB1")
		if err != nil {
			t.Fatalf("reading the job back: %v", err)
		}
		if rec.CreatedBy != "alice" {
			t.Errorf("the job records its creator as %q, want alice; that is the first question after "+
				"an incident and the worst one to answer with a guess", rec.CreatedBy)
		}
		if rec.ClaimedAt.IsZero() {
			t.Error("a claimed job is not stamped as claimed, so an operator watching it sees nothing " +
				"happen between the claim and the result")
		}
	})
}

// TestGuaranteeAJobWaitingForASecondOperatorIsNeverClaimable is docs/SECURITY.md §3 at the queue.
//
// The destructive tier requires second-person approval. A host that could claim an unapproved job would
// make that requirement a note in a document rather than a property of the system, and the check must
// live below the handler: the handler is not the only thing that will ever claim, and a requirement
// enforced by whoever remembers to ask is not a requirement.
func TestGuaranteeAJobWaitingForASecondOperatorIsNeverClaimable(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		job := jobFor("01JOB1", "host.reboot")
		job.Class = "destructive"
		job.Signature = "c2lnbmF0dXJl"
		if err := tenant.CreateJob(ctx, NewJob{
			Job: job, HostID: host.ID, CreatedBy: "alice", ApprovalRequired: true,
		}); err != nil {
			t.Fatalf("creating a job: %v", err)
		}

		claimed, err := tenant.ClaimJobs(ctx, host.ID, 10)
		if err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if len(claimed) != 0 {
			t.Fatalf("a host claimed a job that no second operator had approved: %+v", claimed)
		}

		rec, err := tenant.GetJob(ctx, "01JOB1")
		if err != nil {
			t.Fatalf("reading the job: %v", err)
		}
		if rec.Claimable() {
			t.Error("an unapproved job reports itself claimable, so the API and the UI would disagree " +
				"with the claim query about the one row where it matters")
		}

		if err := tenant.ApproveJob(ctx, "01JOB1", "bob", time.Now()); err != nil {
			t.Fatalf("approving: %v", err)
		}

		claimed, err = tenant.ClaimJobs(ctx, host.ID, 10)
		if err != nil {
			t.Fatalf("claiming after approval: %v", err)
		}
		if len(claimed) != 1 {
			t.Fatalf("an approved job was not delivered: %+v", claimed)
		}
	})
}

// TestGuaranteeNobodyApprovesTheirOwnJob is the "second person" in second-person approval.
//
// The rule is now a tenant's setting rather than a constant — a fleet with one operator chooses "self"
// or "none" instead, because requiring a second person where there is only one is a tier nobody can
// reach. What has not changed is what the rule means when a fleet does choose it, and where it is
// enforced: in the store rather than only in the handler, because it has to hold against two requests
// arriving at once. A read-then-write in the caller would let the same operator release their own job
// by racing it against itself, which is the one way this check could be defeated by somebody who
// already holds the credential.
//
// The rule is read from the job row rather than from the tenant, so this creates the job saying so.
// That is the same property asserted from the other side in
// TestGuaranteeATenantsApprovalModeCannotRewriteAJobAlreadyQueued.
func TestGuaranteeNobodyApprovesTheirOwnJob(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		job := jobFor("01JOB1", "service.restart")
		job.Class = "destructive"
		job.Signature = "c2lnbmF0dXJl"
		if err := tenant.CreateJob(ctx, NewJob{
			Job: job, HostID: host.ID, CreatedBy: "alice",
			ApprovalRequired: true, ApprovalDistinctOperator: true,
		}); err != nil {
			t.Fatalf("creating a job: %v", err)
		}

		if err := tenant.ApproveJob(ctx, "01JOB1", "alice", time.Now()); !errors.Is(err, ErrConflict) {
			t.Fatalf("the operator who created the job approved it, producing %v; want ErrConflict", err)
		}
		if err := tenant.ApproveJob(ctx, "01JOB1", "bob", time.Now()); err != nil {
			t.Fatalf("a second operator could not approve: %v", err)
		}
		if err := tenant.ApproveJob(ctx, "01JOB1", "carol", time.Now()); !errors.Is(err, ErrConflict) {
			t.Errorf("an already-approved job was approved again, producing %v; want ErrConflict", err)
		}

		rec, err := tenant.GetJob(ctx, "01JOB1")
		if err != nil {
			t.Fatalf("reading the job: %v", err)
		}
		if rec.ApprovedBy != "bob" || rec.ApprovedAt.IsZero() {
			t.Errorf("the approval is recorded as %q at %s", rec.ApprovedBy, rec.ApprovedAt)
		}
	})
}

// TestApprovingWhatNeedsNoApprovalIsRefused keeps the audit trail honest.
//
// A read job carries no approval, and recording one against it would put a name in the log beside a
// decision that person never made.
func TestApprovingWhatNeedsNoApprovalIsRefused(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		if err := tenant.CreateJob(ctx, NewJob{
			Job: jobFor("01JOB1", "facts.collect"), HostID: host.ID, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("creating a job: %v", err)
		}
		if err := tenant.ApproveJob(ctx, "01JOB1", "bob", time.Now()); !errors.Is(err, ErrConflict) {
			t.Errorf("approving a job that needs no approval produced %v, want ErrConflict", err)
		}
		if err := tenant.ApproveJob(ctx, "01JNOSUCHJOB", "bob", time.Now()); !errors.Is(err, ErrNotFound) {
			t.Errorf("approving an unknown job produced %v, want ErrNotFound", err)
		}
	})
}

// TestGuaranteeASignedPayloadIsQueuedOnce refuses a replay before it reaches a host.
//
// The host refuses a replayed nonce itself and that is the check the guarantee rests on. This one is
// earlier and cheaper: a job queued twice is delivered twice, refused on the host, and reported as a
// failure nobody can explain — so the control plane declines to be the thing that replays it.
func TestGuaranteeASignedPayloadIsQueuedOnce(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		signed := jobFor("01JOB1", "host.reboot")
		signed.Class = "destructive"
		signed.Signature = "c2lnbmF0dXJl"
		if err := tenant.CreateJob(ctx, NewJob{Job: signed, HostID: host.ID, ApprovalRequired: true}); err != nil {
			t.Fatalf("creating the first job: %v", err)
		}

		replay := signed
		replay.ID = "01JOB2"
		if err := tenant.CreateJob(ctx, NewJob{Job: replay, HostID: host.ID, ApprovalRequired: true}); !errors.Is(err, ErrConflict) {
			t.Fatalf("the same signed payload was queued twice, producing %v; want ErrConflict", err)
		}

		// A different nonce is a different authorisation and is accepted.
		fresh := signed
		fresh.ID = "01JOB3"
		fresh.Nonce = "nonce-fresh"
		if err := tenant.CreateJob(ctx, NewJob{Job: fresh, HostID: host.ID, ApprovalRequired: true}); err != nil {
			t.Errorf("a differently-nonced signed job was refused: %v", err)
		}

		// And an unsigned job's nonce means nothing, so it is not checked. Read jobs get a random one
		// only so the column can stay NOT NULL.
		unsigned := jobFor("01JOB4", "facts.collect")
		unsigned.Nonce = signed.Nonce
		if err := tenant.CreateJob(ctx, NewJob{Job: unsigned, HostID: host.ID}); err != nil {
			t.Errorf("an unsigned job sharing a nonce was refused: %v", err)
		}
	})
}

// TestCreateJobForAnUnknownHostIsNotFound stops a job being queued for nobody.
//
// Without the check the row would be rejected by the foreign key in one implementation and accepted
// into a map in the other, and the two would disagree about what a typo in a host id does.
func TestCreateJobForAnUnknownHostIsNotFound(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		err := tenant.CreateJob(context.Background(), NewJob{
			Job: jobFor("01JOB1", "facts.collect"), HostID: "01JNOSUCHHOST",
		})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("creating a job for an unknown host produced %v, want ErrNotFound", err)
		}
	})
}

// TestAJobCarriesItsResultOnceTheHostReports is what an operator actually looks at.
func TestAJobCarriesItsResultOnceTheHostReports(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		if err := tenant.CreateJob(ctx, NewJob{
			Job: jobFor("01JOB1", "facts.collect"), HostID: host.ID, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("creating a job: %v", err)
		}

		before, err := tenant.GetJob(ctx, "01JOB1")
		if err != nil {
			t.Fatalf("reading the job: %v", err)
		}
		if before.Result != nil {
			t.Error("a job carries a result before the host has reported one; a nil result is how a " +
				"caller tells 'not reported yet' from 'reported nothing'")
		}

		if _, err := tenant.ClaimJobs(ctx, host.ID, 10); err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if _, err := tenant.RecordResult(ctx, host.ID, protocol.ResultRequest{
			JobID: "01JOB1", Status: protocol.StatusSucceeded, ExitCode: 0,
			StartedAt: time.Now(), FinishedAt: time.Now(), Output: "done",
		}); err != nil {
			t.Fatalf("recording a result: %v", err)
		}

		after, err := tenant.GetJob(ctx, "01JOB1")
		if err != nil {
			t.Fatalf("reading the job back: %v", err)
		}
		if after.Result == nil || after.Result.Status != protocol.StatusSucceeded {
			t.Fatalf("the job carries result %+v", after.Result)
		}
		if after.Result.Output != "done" {
			t.Errorf("the output is %q", after.Result.Output)
		}
		if after.CompletedAt.IsZero() {
			t.Error("a job with a result is not stamped as completed")
		}

		listed, err := tenant.ListJobs(ctx, JobFilter{HostID: host.ID})
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(listed) != 1 || listed[0].Result == nil {
			t.Fatalf("the listing is %+v", listed)
		}
	})
}

// TestGuaranteeAStoredJobCanonicalisesToWhatWasSigned is the one that must not be wrong.
//
// A destructive job's signature is computed over the canonical encoding of
// {jobId, hostId, intent, params, notBefore, notAfter, nonce}, and the agent recomputes those bytes
// from the job it receives. Everything in between — a JSON round trip through map[string]any, jsonb's
// own normalisation, timestamptz precision, whatever pgx decodes a JSON number into — sits between the
// signer and the verifier, and any of it changing one byte makes a correct signature fail on a host.
//
// The failure would be perfectly silent until somebody needed a reboot, and it would look like a broken
// key rather than a storage layer. It is asserted against both implementations because they store
// parameters in completely different ways, and it is asserted on the bytes rather than on the decoded
// value because the bytes are what is signed.
func TestGuaranteeAStoredJobCanonicalisesToWhatWasSigned(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		// Every parameter shape the catalogue can produce: the two integers bounding a reboot delay,
		// a message from the constrained character set, and the boolean an update job carries.
		cases := []map[string]any{
			{},
			{"delaySeconds": 0, "message": ""},
			{"delaySeconds": 3600, "message": "patching web tier, back in ten"},
			{"rebootIfRequired": true},
			{"rebootIfRequired": false},
			{"unit": "getty@tty1.service"},
		}

		for i, params := range cases {
			id := "01JOB" + string(rune('A'+i))
			now := time.Now().UTC().Truncate(time.Second)
			job := protocol.Job{
				ID: id, Intent: "host.reboot", Params: params, Class: "destructive",
				IssuedAt: now, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
				Nonce: "nonce-" + id, Signature: "c2ln", SignerKeyID: "ops", SignerAlgorithm: "ed25519",
			}
			signed, err := canonical.Marshal(job.SignedPayload(host.ID))
			if err != nil {
				t.Fatalf("canonicalising %v before storing: %v", params, err)
			}

			if err := tenant.CreateJob(ctx, NewJob{Job: job, HostID: host.ID}); err != nil {
				t.Fatalf("creating a job with %v: %v", params, err)
			}
			claimed, err := tenant.ClaimJobs(ctx, host.ID, 1)
			if err != nil {
				t.Fatalf("claiming: %v", err)
			}
			if len(claimed) != 1 {
				t.Fatalf("claimed %d jobs, want 1", len(claimed))
			}

			delivered, err := canonical.Marshal(claimed[0].SignedPayload(host.ID))
			if err != nil {
				t.Fatalf("canonicalising %v after the round trip: %v", params, err)
			}
			if string(delivered) != string(signed) {
				t.Errorf("the signed payload changed in storage.\n signed:    %s\n delivered: %s",
					signed, delivered)
			}
		}
	})
}

// TestGuaranteeAJobIDIsTakenOnce keeps the two implementations agreeing about the primary key.
//
// PostgreSQL enforces it for free and the in-memory store has to state it, which is exactly the shape
// of divergence that goes unnoticed: every server test runs against Memory, so a rule only the database
// enforces is one those tests would prove nothing about. Here it would be worse than a missing error —
// the record would be overwritten while both copies stayed in the queue, so a host would receive one
// job and the operator would read another under the same id.
func TestGuaranteeAJobIDIsTakenOnce(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		if err := tenant.CreateJob(ctx, NewJob{
			Job: jobFor("01JOB1", "facts.collect"), HostID: host.ID,
		}); err != nil {
			t.Fatalf("creating the first job: %v", err)
		}

		second := jobFor("01JOB1", "services.list")
		second.Nonce = "a-different-nonce"
		if err := tenant.CreateJob(ctx, NewJob{Job: second, HostID: host.ID}); !errors.Is(err, ErrConflict) {
			t.Fatalf("a second job took an id that was already in use, producing %v; want ErrConflict", err)
		}

		listed, err := tenant.ListJobs(ctx, JobFilter{})
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(listed) != 1 {
			t.Errorf("%d jobs exist under one id", len(listed))
		}
		rec, err := tenant.GetJob(ctx, "01JOB1")
		if err != nil {
			t.Fatalf("reading the job: %v", err)
		}
		if rec.Job.Intent != "facts.collect" {
			t.Errorf("the job under this id is now %q; the first one was replaced", rec.Job.Intent)
		}
	})
}

// TestGuaranteeApprovingAJobWakesAWaitingAgent closes a gap that costs the operator's own window.
//
// A destructive job is created waiting, so the insert that created it wakes agents to tell them about
// work none of them can take, and the approval — which is what actually makes it claimable — is an
// UPDATE. With only an insert trigger, an agent holding a long poll hears nothing until its own poll
// expires: up to a minute. For a signed job that minute is charged against the signed notBefore, because
// the age limit deliberately runs from the value the signer chose rather than one the control plane can
// pick, so a slow wake spends the operator's authorisation rather than the server's.
//
// The in-memory store woke immediately all along, which is exactly why this needs asserting against both.
func TestGuaranteeApprovingAJobWakesAWaitingAgent(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		job := jobFor("01JOB1", "host.reboot")
		job.Class = "destructive"
		job.Signature = "c2ln"
		if err := tenant.CreateJob(ctx, NewJob{
			Job: job, HostID: host.ID, CreatedBy: "alice", ApprovalRequired: true,
		}); err != nil {
			t.Fatalf("creating: %v", err)
		}

		// Subscribed before the queue is read, which is the order the handler uses and the reason the
		// insert's own notification cannot be mistaken for the approval's.
		notified, unsubscribe := s.Subscribe(host.ID)
		defer unsubscribe()
		waitForListener(t, s)
		claimed, err := tenant.ClaimJobs(ctx, host.ID, 10)
		if err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if len(claimed) != 0 {
			t.Fatalf("an unapproved job was claimable: %+v", claimed)
		}

		if err := tenant.ApproveJob(ctx, "01JOB1", "bob", time.Now()); err != nil {
			t.Fatalf("approving: %v", err)
		}

		select {
		case <-notified:
		case <-time.After(5 * time.Second):
			t.Fatal("approving a job did not wake an agent already waiting for work; it would sit " +
				"undelivered until the long poll expired, and for a signed job that delay is spent " +
				"from the window the operator signed")
		}
	})
}

// waitForListener blocks until a PostgreSQL store has actually issued its LISTEN.
//
// The listener starts on the first Subscribe and connects asynchronously, so a NOTIFY sent immediately
// afterwards can be delivered to nobody. Waiting for it rather than sleeping is what keeps this test
// from passing on a fast machine and failing on a loaded one — this is the assertion that would be
// quietly disabled first. The in-memory store has nothing to wait for.
func waitForListener(t *testing.T, s Store) {
	t.Helper()

	pg, ok := s.(*Postgres)
	if !ok {
		return
	}
	select {
	case <-pg.ready:
	case <-time.After(15 * time.Second):
		t.Fatal("the notification listener never issued its LISTEN")
	}
}

// TestGuaranteeJobsAreListedByCreationTimeNotByIdentifier stops a queued reboot hiding.
//
// A signed job's id comes from whoever signed it — it is covered by the signature, so the control plane
// cannot choose it — and nothing constrains its shape. Ordering a listing by id therefore files such a
// job wherever its identifier happens to sort, which on a busy fleet can be past the end of the page
// the second operator reads before approving it. The one job that needs a human to find it is the one
// that goes missing.
func TestGuaranteeJobsAreListedByCreationTimeNotByIdentifier(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		// Two ids that sort high, then — created last — one that sorts low, as an operator-chosen id
		// easily can.
		for i, id := range []string{"06AAAA", "06BBBB", "01SIGNED"} {
			job := jobFor(id, "facts.collect")
			job.IssuedAt = time.Now().UTC().Add(time.Duration(i) * time.Second)
			if err := tenant.CreateJob(ctx, NewJob{Job: job, HostID: host.ID}); err != nil {
				t.Fatalf("creating %s: %v", id, err)
			}
		}

		listed, err := tenant.ListJobs(ctx, JobFilter{})
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(listed) != 3 {
			t.Fatalf("listed %d jobs, want 3", len(listed))
		}
		if listed[0].Job.ID != "01SIGNED" {
			t.Errorf("the newest job is %q, want the one created last (01SIGNED). Ordering by "+
				"identifier hides a signed job wherever its id happens to sort.", listed[0].Job.ID)
		}
	})
}

// TestGuaranteeDeletingAHostCancelsTheWorkWaitingForIt keeps the two implementations agreeing.
//
// PostgreSQL cascades the jobs away with the host row and the in-memory store has to be told, which is
// the shape of divergence that goes unnoticed — every server test runs against Memory, and the shipped
// binary offers a memory-backed mode. Left alone, a deleted host's pending destructive job stays listed
// and stays approvable, and approving it puts the job back on the queue of a host that no longer
// exists: deleting a host would not cancel the work waiting for it.
func TestGuaranteeDeletingAHostCancelsTheWorkWaitingForIt(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		job := jobFor("01JOB1", "host.reboot")
		job.Class = "destructive"
		job.Signature = "c2ln"
		if err := tenant.CreateJob(ctx, NewJob{
			Job: job, HostID: host.ID, CreatedBy: "alice", ApprovalRequired: true,
		}); err != nil {
			t.Fatalf("creating: %v", err)
		}

		if err := tenant.DeleteHost(ctx, host.ID); err != nil {
			t.Fatalf("deleting the host: %v", err)
		}

		if _, err := tenant.GetJob(ctx, "01JOB1"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a deleted host's job is still readable, producing %v; want ErrNotFound", err)
		}
		listed, err := tenant.ListJobs(ctx, JobFilter{})
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(listed) != 0 {
			t.Errorf("a deleted host's job is still listed: %+v", listed)
		}
		if err := tenant.ApproveJob(ctx, "01JOB1", "bob", time.Now()); !errors.Is(err, ErrNotFound) {
			t.Errorf("a deleted host's job was approvable, producing %v; want ErrNotFound", err)
		}
	})
}

// TestGuaranteeAResultIsOnlyAcceptedForWorkTheHostWasGiven closes a way to burn an authorisation.
//
// A host is authenticated and is not trusted. Without this check a compromised one could report a
// result for a destructive job that was still waiting for its second operator: that stamps the job
// completed, excludes it from the claim for ever, and leaves it impossible to re-queue because the
// partial unique index has taken its signed nonce. The dashboard would show "succeeded" for work nobody
// had authorised, let alone performed.
//
// A host can always lie about work it actually did — that is inside the threat model, and the policy
// file and the signature are what bound it. What it must not be able to do is answer for work it was
// never given.
func TestGuaranteeAResultIsOnlyAcceptedForWorkTheHostWasGiven(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		job := jobFor("01JOB1", "host.reboot")
		job.Class = "destructive"
		job.Signature = "c2ln"
		if err := tenant.CreateJob(ctx, NewJob{
			Job: job, HostID: host.ID, CreatedBy: "alice", ApprovalRequired: true,
		}); err != nil {
			t.Fatalf("creating: %v", err)
		}

		forged := protocol.ResultRequest{
			JobID: "01JOB1", Status: protocol.StatusSucceeded,
			StartedAt: time.Now(), FinishedAt: time.Now(), Output: "definitely rebooted",
		}
		if _, err := tenant.RecordResult(ctx, host.ID, forged); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a result was accepted for a job the host was never given, producing %v; "+
				"want ErrNotFound", err)
		}

		// And the job survives it: approved by a second operator, it is still delivered.
		if err := tenant.ApproveJob(ctx, "01JOB1", "bob", time.Now()); err != nil {
			t.Fatalf("approving: %v", err)
		}
		claimed, err := tenant.ClaimJobs(ctx, host.ID, 10)
		if err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if len(claimed) != 1 {
			t.Fatalf("the approved job was not delivered after the forged result: %+v", claimed)
		}

		// Once it has genuinely been given out, the real result is accepted.
		if _, err := tenant.RecordResult(ctx, host.ID, forged); err != nil {
			t.Errorf("the result of a claimed job was refused: %v", err)
		}
	})
}

// TestGuaranteeTheAwaitingApprovalFilterFindsWhatTheListingBuried is the store half of a job that
// scrolled out of reach.
//
// The listing is bounded, so on a fleet doing routine work a destructive job leaves the newest page
// within a working day. That is only a display problem until you remember what is on that page: the
// second operator docs/SECURITY.md §3 requires cannot approve a job they cannot find. This filter is
// the answer that does not depend on how far back anybody thought to look, and it has to mean the same
// thing in both implementations, because every server test runs against the one that does not ship.
func TestGuaranteeTheAwaitingApprovalFilterFindsWhatTheListingBuried(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		reboot := jobFor("01JREBOOT", "host.reboot")
		reboot.Class = "destructive"
		reboot.Signature = "c2lnbmF0dXJl"
		// Explicitly the oldest. The listing orders by issued_at and breaks ties on the id, and jobFor
		// stamps whatever the clock says truncated to the millisecond — so a fixture that created all
		// of these in the same millisecond would be ordered by identifier, and "01JREBOOT" sorts above
		// "01JFILL…". The test would then pass or fail on how fast the machine was.
		reboot.IssuedAt = reboot.IssuedAt.Add(-time.Hour)
		reboot.NotBefore = reboot.IssuedAt
		if err := tenant.CreateJob(ctx, NewJob{
			Job: reboot, HostID: host.ID, CreatedBy: "alice", ApprovalRequired: true,
		}); err != nil {
			t.Fatalf("creating the reboot: %v", err)
		}

		// A full page of routine work on top of it, plus one, so the default listing cannot reach it.
		for i := range DefaultJobLimit + 1 {
			id := "01JFILL" + string(rune('A'+i/26)) + string(rune('A'+i%26))
			if err := tenant.CreateJob(ctx, NewJob{
				Job: jobFor(id, "facts.collect"), HostID: host.ID, CreatedBy: "alice",
			}); err != nil {
				t.Fatalf("creating filler %s: %v", id, err)
			}
		}

		listed, err := tenant.ListJobs(ctx, JobFilter{})
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(listed) != DefaultJobLimit {
			t.Fatalf("the default listing returned %d rows, want %d", len(listed), DefaultJobLimit)
		}
		for _, rec := range listed {
			if rec.Job.ID == "01JREBOOT" {
				t.Fatal("the fixture did not bury the reboot; the rest of this test proves nothing")
			}
		}

		awaiting, err := tenant.ListJobs(ctx, JobFilter{AwaitingApproval: true})
		if err != nil {
			t.Fatalf("listing what awaits approval: %v", err)
		}
		if len(awaiting) != 1 || awaiting[0].Job.ID != "01JREBOOT" {
			t.Fatalf("the awaiting-approval listing returned %d rows: %+v", len(awaiting), awaiting)
		}

		if err := tenant.ApproveJob(ctx, "01JREBOOT", "bob", time.Now().UTC()); err != nil {
			t.Fatalf("approving: %v", err)
		}
		after, err := tenant.ListJobs(ctx, JobFilter{AwaitingApproval: true})
		if err != nil {
			t.Fatalf("listing after the approval: %v", err)
		}
		if len(after) != 0 {
			t.Errorf("an approved job is still awaiting approval: %+v", after)
		}
	})
}

// TestGuaranteeBothStoresBoundAListingTheSameWay is the drift check the constants exist for.
//
// A page size that differed between the two would make every server test — all of which run on Memory —
// prove a bound the shipped store does not have, and the first place that surfaces is somebody's
// missing row.
func TestGuaranteeBothStoresBoundAListingTheSameWay(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		for i := range 12 {
			id := "01JFILL" + string(rune('A'+i))
			if err := tenant.CreateJob(ctx, NewJob{
				Job: jobFor(id, "facts.collect"), HostID: host.ID, CreatedBy: "alice",
			}); err != nil {
				t.Fatalf("creating %s: %v", id, err)
			}
		}

		for _, c := range []struct {
			// asked is the filter's Limit, and want is how many rows must come back.
			asked int
			want  int
		}{
			{asked: 0, want: 12},                  // the default is above what is stored
			{asked: 5, want: 5},                   // an explicit bound is honoured
			{asked: MaxJobLimit + 1000, want: 12}, // above the ceiling is clamped, not refused
		} {
			listed, err := tenant.ListJobs(ctx, JobFilter{Limit: c.asked})
			if err != nil {
				t.Fatalf("listing with limit %d: %v", c.asked, err)
			}
			if len(listed) != c.want {
				t.Errorf("limit %d returned %d rows, want %d", c.asked, len(listed), c.want)
			}
		}
	})
}

// TestGuaranteeAJobIsNotDeliveredBeforeItsWindowOpens is what makes scheduling work at all.
//
// Delivering a job early does not delay it, it destroys it. The agent checks the validity window
// against its own clock, finds it shut, and reports StatusExpired — which completes the job
// permanently. So a maintenance window signed on Thursday for Sunday would be claimed on Thursday,
// burned, and could never run, while `farrier sign --not-before` advertises exactly that use.
//
// The scheduled job is created FIRST on purpose. The queue is in creation order, so this also pins that
// a job waiting for next week does not hold up the one queued behind it for now — a claim that stopped
// at the first undue job would pass a weaker version of this test and starve the host.
func TestGuaranteeAJobIsNotDeliveredBeforeItsWindowOpens(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		scheduled := jobFor("01JOBLATER", "host.reboot")
		scheduled.NotBefore = time.Now().UTC().Add(72 * time.Hour)
		scheduled.NotAfter = scheduled.NotBefore.Add(time.Hour)
		if err := tenant.CreateJob(ctx, NewJob{
			Job: scheduled, HostID: host.ID, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("creating the scheduled job: %v", err)
		}

		if err := tenant.CreateJob(ctx, NewJob{
			Job: jobFor("01JOBNOW", "facts.collect"), HostID: host.ID, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("creating the due job: %v", err)
		}

		claimed, err := tenant.ClaimJobs(ctx, host.ID, 10)
		if err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if len(claimed) != 1 {
			t.Fatalf("claimed %d jobs, want only the due one: %+v", len(claimed), claimed)
		}
		if claimed[0].ID != "01JOBNOW" {
			t.Fatalf("claimed %q; the job scheduled for three days out was delivered, and the agent "+
				"would report it expired and complete it for good", claimed[0].ID)
		}

		// And it is still there, unclaimed, rather than having been quietly consumed.
		rec, err := tenant.GetJob(ctx, "01JOBLATER")
		if err != nil {
			t.Fatalf("reading the scheduled job: %v", err)
		}
		if !rec.ClaimedAt.IsZero() {
			t.Errorf("the scheduled job was stamped as claimed at %s", rec.ClaimedAt)
		}
		if !rec.CompletedAt.IsZero() {
			t.Errorf("the scheduled job was completed at %s without ever running", rec.CompletedAt)
		}
	})
}

// TestGuaranteeAScheduledJobIsDeliveredOnceItsWindowOpens is the other half.
//
// A filter that never let anything through would satisfy the test above perfectly, and would be a
// worse bug than the one it replaced: jobs that vanish are at least visible, jobs that never arrive
// look like an idle fleet.
func TestGuaranteeAScheduledJobIsDeliveredOnceItsWindowOpens(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		host := enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		// Its window opened a minute ago: the same shape as a job scheduled earlier and reached now.
		job := jobFor("01JOBDUE", "host.reboot")
		job.NotBefore = time.Now().UTC().Add(-time.Minute)
		job.NotAfter = time.Now().UTC().Add(time.Hour)
		if err := tenant.CreateJob(ctx, NewJob{
			Job: job, HostID: host.ID, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("creating the job: %v", err)
		}

		claimed, err := tenant.ClaimJobs(ctx, host.ID, 10)
		if err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if len(claimed) != 1 || claimed[0].ID != "01JOBDUE" {
			t.Fatalf("a job whose window is open was not delivered: %+v", claimed)
		}
	})
}

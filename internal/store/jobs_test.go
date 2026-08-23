package store

import (
	"context"
	"errors"
	"testing"
	"time"

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
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		target := enrolTestHost(t, s, "01JHOSTA", "a.example.org")
		other := enrolTestHost(t, s, "01JHOSTB", "b.example.org")

		if err := s.CreateJob(ctx, NewJob{
			Job: jobFor("01JOB1", "facts.collect"), HostID: target.ID, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("creating a job: %v", err)
		}

		elsewhere, err := s.ClaimJobs(ctx, other.ID, 10)
		if err != nil {
			t.Fatalf("claiming for the other host: %v", err)
		}
		if len(elsewhere) != 0 {
			t.Fatalf("a job addressed to %s was offered to %s", target.ID, other.ID)
		}

		claimed, err := s.ClaimJobs(ctx, target.ID, 10)
		if err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if len(claimed) != 1 || claimed[0].ID != "01JOB1" {
			t.Fatalf("claimed %+v", claimed)
		}

		rec, err := s.GetJob(ctx, "01JOB1")
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
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		host := enrolTestHost(t, s, "01JHOSTA", "a.example.org")

		job := jobFor("01JOB1", "host.reboot")
		job.Class = "destructive"
		job.Signature = "c2lnbmF0dXJl"
		if err := s.CreateJob(ctx, NewJob{
			Job: job, HostID: host.ID, CreatedBy: "alice", ApprovalRequired: true,
		}); err != nil {
			t.Fatalf("creating a job: %v", err)
		}

		claimed, err := s.ClaimJobs(ctx, host.ID, 10)
		if err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if len(claimed) != 0 {
			t.Fatalf("a host claimed a job that no second operator had approved: %+v", claimed)
		}

		rec, err := s.GetJob(ctx, "01JOB1")
		if err != nil {
			t.Fatalf("reading the job: %v", err)
		}
		if rec.Claimable() {
			t.Error("an unapproved job reports itself claimable, so the API and the UI would disagree " +
				"with the claim query about the one row where it matters")
		}

		if err := s.ApproveJob(ctx, "01JOB1", "bob", time.Now()); err != nil {
			t.Fatalf("approving: %v", err)
		}

		claimed, err = s.ClaimJobs(ctx, host.ID, 10)
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
// The rule is enforced in the store rather than only in the handler because it has to hold against two
// requests arriving at once: a read-then-write in the caller would let the same operator approve their
// own job by racing it against itself, which is the one way this check could be defeated by somebody
// who already holds the credential.
func TestGuaranteeNobodyApprovesTheirOwnJob(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		host := enrolTestHost(t, s, "01JHOSTA", "a.example.org")

		job := jobFor("01JOB1", "service.restart")
		job.Class = "destructive"
		job.Signature = "c2lnbmF0dXJl"
		if err := s.CreateJob(ctx, NewJob{
			Job: job, HostID: host.ID, CreatedBy: "alice", ApprovalRequired: true,
		}); err != nil {
			t.Fatalf("creating a job: %v", err)
		}

		if err := s.ApproveJob(ctx, "01JOB1", "alice", time.Now()); !errors.Is(err, ErrConflict) {
			t.Fatalf("the operator who created the job approved it, producing %v; want ErrConflict", err)
		}
		if err := s.ApproveJob(ctx, "01JOB1", "bob", time.Now()); err != nil {
			t.Fatalf("a second operator could not approve: %v", err)
		}
		if err := s.ApproveJob(ctx, "01JOB1", "carol", time.Now()); !errors.Is(err, ErrConflict) {
			t.Errorf("an already-approved job was approved again, producing %v; want ErrConflict", err)
		}

		rec, err := s.GetJob(ctx, "01JOB1")
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
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		host := enrolTestHost(t, s, "01JHOSTA", "a.example.org")

		if err := s.CreateJob(ctx, NewJob{
			Job: jobFor("01JOB1", "facts.collect"), HostID: host.ID, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("creating a job: %v", err)
		}
		if err := s.ApproveJob(ctx, "01JOB1", "bob", time.Now()); !errors.Is(err, ErrConflict) {
			t.Errorf("approving a job that needs no approval produced %v, want ErrConflict", err)
		}
		if err := s.ApproveJob(ctx, "01JNOSUCHJOB", "bob", time.Now()); !errors.Is(err, ErrNotFound) {
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
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		host := enrolTestHost(t, s, "01JHOSTA", "a.example.org")

		signed := jobFor("01JOB1", "host.reboot")
		signed.Class = "destructive"
		signed.Signature = "c2lnbmF0dXJl"
		if err := s.CreateJob(ctx, NewJob{Job: signed, HostID: host.ID, ApprovalRequired: true}); err != nil {
			t.Fatalf("creating the first job: %v", err)
		}

		replay := signed
		replay.ID = "01JOB2"
		if err := s.CreateJob(ctx, NewJob{Job: replay, HostID: host.ID, ApprovalRequired: true}); !errors.Is(err, ErrConflict) {
			t.Fatalf("the same signed payload was queued twice, producing %v; want ErrConflict", err)
		}

		// A different nonce is a different authorisation and is accepted.
		fresh := signed
		fresh.ID = "01JOB3"
		fresh.Nonce = "nonce-fresh"
		if err := s.CreateJob(ctx, NewJob{Job: fresh, HostID: host.ID, ApprovalRequired: true}); err != nil {
			t.Errorf("a differently-nonced signed job was refused: %v", err)
		}

		// And an unsigned job's nonce means nothing, so it is not checked. Read jobs get a random one
		// only so the column can stay NOT NULL.
		unsigned := jobFor("01JOB4", "facts.collect")
		unsigned.Nonce = signed.Nonce
		if err := s.CreateJob(ctx, NewJob{Job: unsigned, HostID: host.ID}); err != nil {
			t.Errorf("an unsigned job sharing a nonce was refused: %v", err)
		}
	})
}

// TestCreateJobForAnUnknownHostIsNotFound stops a job being queued for nobody.
//
// Without the check the row would be rejected by the foreign key in one implementation and accepted
// into a map in the other, and the two would disagree about what a typo in a host id does.
func TestCreateJobForAnUnknownHostIsNotFound(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		err := s.CreateJob(context.Background(), NewJob{
			Job: jobFor("01JOB1", "facts.collect"), HostID: "01JNOSUCHHOST",
		})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("creating a job for an unknown host produced %v, want ErrNotFound", err)
		}
	})
}

// TestAJobCarriesItsResultOnceTheHostReports is what an operator actually looks at.
func TestAJobCarriesItsResultOnceTheHostReports(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		host := enrolTestHost(t, s, "01JHOSTA", "a.example.org")

		if err := s.CreateJob(ctx, NewJob{
			Job: jobFor("01JOB1", "facts.collect"), HostID: host.ID, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("creating a job: %v", err)
		}

		before, err := s.GetJob(ctx, "01JOB1")
		if err != nil {
			t.Fatalf("reading the job: %v", err)
		}
		if before.Result != nil {
			t.Error("a job carries a result before the host has reported one; a nil result is how a " +
				"caller tells 'not reported yet' from 'reported nothing'")
		}

		if _, err := s.ClaimJobs(ctx, host.ID, 10); err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if err := s.RecordResult(ctx, host.ID, protocol.ResultRequest{
			JobID: "01JOB1", Status: protocol.StatusSucceeded, ExitCode: 0,
			StartedAt: time.Now(), FinishedAt: time.Now(), Output: "done",
		}); err != nil {
			t.Fatalf("recording a result: %v", err)
		}

		after, err := s.GetJob(ctx, "01JOB1")
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

		listed, err := s.ListJobs(ctx, JobFilter{HostID: host.ID})
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(listed) != 1 || listed[0].Result == nil {
			t.Fatalf("the listing is %+v", listed)
		}
	})
}

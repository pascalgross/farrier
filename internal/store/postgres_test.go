package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/protocol"
)

// databaseEnv names the environment variable holding a PostgreSQL URL for these tests.
//
// The tests skip when it is unset rather than failing, so that `go test ./...` works on a machine with
// no database. They are not optional in CI: the workflow sets it, because the PostgreSQL behaviour this
// store depends on — atomic claiming, LISTEN/NOTIFY, conditional updates — is not exercised by the
// in-memory store at all, and a test suite that only ran against Memory would prove nothing about the
// code that actually ships.
const databaseEnv = "FARRIER_TEST_DATABASE_URL"

// newPostgres opens a migrated store and empties it, or skips the test.
//
// Every test starts from an empty schema rather than sharing state, because these tests assert things
// about counts and about uniqueness, and a leftover row from an earlier test is the kind of failure
// that only appears when the tests run in a different order.
func newPostgres(t *testing.T) *Postgres {
	t.Helper()

	dsn := os.Getenv(databaseEnv)
	if dsn == "" {
		t.Skipf("%s is not set; skipping the PostgreSQL store tests", databaseEnv)
	}

	ctx := context.Background()
	pg, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })

	if err := pg.Migrate(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	truncate(t, pg)
	return pg
}

// enrolTestHost creates a host and returns it.
func enrolTestHost(t *testing.T, s Store, id, hostname string) Host {
	t.Helper()

	host := Host{
		ID:            id,
		Hostname:      hostname,
		MachineIDHash: "sha256:" + id,
		Group:         "web-prod",
		AgentVersion:  "0.0.0-test",
		EnrolledAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
	if err := s.CreateEnrolledHost(context.Background(), host, Certificate{
		Fingerprint: "fp-" + id, HostID: id, Serial: "01",
		IssuedAt: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("creating host %s: %v", id, err)
	}
	return host
}

// TestMigrateIsIdempotent asserts a restart does not fail on an already-migrated database.
//
// Every replica calls Migrate on start, so this happens on every deploy. A migration that failed the
// second time would turn a rolling restart into an outage.
func TestMigrateIsIdempotent(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	for i := range 3 {
		if err := pg.Migrate(ctx); err != nil {
			t.Fatalf("migration %d: %v", i+1, err)
		}
	}
}

// TestEnrollmentTokensAreConsumedAtomically is the property that stops one token enrolling two hosts.
//
// The condition is in the UPDATE rather than in a preceding SELECT precisely so that concurrent
// redemptions cannot both succeed. This runs them concurrently, because a check-then-update would pass
// a sequential test every time.
func TestEnrollmentTokensAreConsumedAtomically(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	now := time.Now()

	if err := pg.CreateEnrollmentToken(ctx, EnrollmentToken{
		Hash: "hash-atomic", Label: "test", Group: "web-prod",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("creating a token: %v", err)
	}

	const racers = 8
	results := make(chan error, racers)
	start := make(chan struct{})
	for i := range racers {
		go func(i int) {
			<-start
			_, err := pg.ConsumeEnrollmentToken(ctx, "hash-atomic", "host-"+string(rune('a'+i)), time.Now())
			results <- err
		}(i)
	}
	close(start)

	succeeded := 0
	for range racers {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrTokenUnusable):
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded; exactly one must", succeeded, racers)
	}
}

// TestExpiredAndUnknownTokensAreIndistinguishable asserts the store reveals nothing.
//
// Telling a caller whether a token was unknown, expired or already used is free reconnaissance for
// whoever is guessing, so the distinction is not carried out of the store at all.
func TestExpiredAndUnknownTokensAreIndistinguishable(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	now := time.Now()

	if err := pg.CreateEnrollmentToken(ctx, EnrollmentToken{
		Hash: "hash-expired", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("creating an expired token: %v", err)
	}
	if err := pg.CreateEnrollmentToken(ctx, EnrollmentToken{
		Hash: "hash-used", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("creating a token: %v", err)
	}
	if _, err := pg.ConsumeEnrollmentToken(ctx, "hash-used", "host-1", now); err != nil {
		t.Fatalf("consuming: %v", err)
	}

	for _, hash := range []string{"hash-unknown", "hash-expired", "hash-used"} {
		_, err := pg.ConsumeEnrollmentToken(ctx, hash, "host-2", now)
		if !errors.Is(err, ErrTokenUnusable) {
			t.Errorf("%s produced %v, want ErrTokenUnusable", hash, err)
		}
	}
}

// TestDuplicateMachineIDIsAConflict asserts a host cannot enrol twice under a new identity.
func TestDuplicateMachineIDIsAConflict(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()

	first := enrolTestHost(t, pg, "01JHOSTA", "web-01")
	second := first
	second.ID = "01JHOSTB"

	if err := pg.CreateEnrolledHost(ctx, second, Certificate{
		Fingerprint: "fp-second", HostID: second.ID, Serial: "01",
		IssuedAt: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second host with the same machine id produced %v, want ErrConflict", err)
	}

	// The rejected enrolment left nothing behind. A certificate recorded for a host that was never
	// created would authenticate a request the fingerprint lookup then could not attribute.
	if _, err := pg.LookupCertificate(ctx, "fp-second"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the refused enrolment recorded a certificate anyway: %v", err)
	}

	found, err := pg.GetHostByMachineID(ctx, first.MachineIDHash)
	if err != nil {
		t.Fatalf("looking up by machine id: %v", err)
	}
	if found.ID != first.ID {
		t.Errorf("machine id lookup returned %s, want %s", found.ID, first.ID)
	}

	if _, err := pg.GetHostByMachineID(ctx, "sha256:nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown machine id produced %v, want ErrNotFound", err)
	}
}

// TestHeartbeatDoesNotClobberFieldsItDoesNotCarry is the reason HeartbeatUpdate is its own type.
//
// A heartbeat writes only the columns it carries. Updating the whole row would let it overwrite the
// enrolment group or a stored facts document with a zero value, which is the sort of bug that shows up
// as data quietly disappearing.
func TestHeartbeatDoesNotClobberFieldsItDoesNotCarry(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	host := enrolTestHost(t, pg, "01JHOSTC", "web-01")

	if err := pg.StoreFacts(ctx, host.ID, "sha256:facts", []byte(`{"hostname":"web-01"}`)); err != nil {
		t.Fatalf("storing facts: %v", err)
	}

	if err := pg.RecordHeartbeat(ctx, host.ID, HeartbeatUpdate{
		AgentVersion: "0.1.0", BootID: "boot-1", UptimeSeconds: 4242, LastSeen: time.Now(),
	}); err != nil {
		t.Fatalf("recording a heartbeat: %v", err)
	}

	after, err := pg.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("reading the host back: %v", err)
	}
	if after.Group != "web-prod" {
		t.Errorf("the heartbeat cleared the group: %q", after.Group)
	}
	if len(after.Facts) == 0 {
		t.Error("the heartbeat cleared the stored facts document")
	}
	if after.Hostname != "web-01" {
		t.Errorf("the heartbeat cleared the hostname: %q", after.Hostname)
	}
	if after.AgentVersion != "0.1.0" || after.UptimeSeconds != 4242 {
		t.Errorf("the heartbeat did not apply its own fields: %+v", after)
	}
	// The digest columns record what the server holds and are written only when a document arrives, so
	// the one stored above must survive a heartbeat untouched.
	if after.FactsDigest != "sha256:facts" {
		t.Errorf("the heartbeat changed the stored facts digest to %q", after.FactsDigest)
	}

	if err := pg.RecordHeartbeat(ctx, "01JNOSUCHHOST", HeartbeatUpdate{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("a heartbeat for an unknown host produced %v, want ErrNotFound", err)
	}
}

// TestStoreDocumentRejectsInvalidJSON asserts a bad document cannot poison a JSONB column.
func TestStoreDocumentRejectsInvalidJSON(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	host := enrolTestHost(t, pg, "01JHOSTD", "web-01")

	if err := pg.StoreFacts(ctx, host.ID, "sha256:bad", []byte("not json at all")); err == nil {
		t.Error("an invalid facts document was accepted")
	}
	if err := pg.StorePolicy(ctx, "01JNOSUCHHOST", "sha256:x", []byte(`{}`)); !errors.Is(err, ErrNotFound) {
		t.Errorf("storing a document for an unknown host produced %v, want ErrNotFound", err)
	}
}

// TestRevokeHostRevokesItsCertificatesInTheSameTransaction is the revocation mechanism.
//
// A host marked revoked whose certificates were not would keep authenticating; certificates revoked
// without the host would leave a host that could re-enrol. Both must happen or neither.
func TestRevokeHostRevokesItsCertificatesInTheSameTransaction(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	host := enrolTestHost(t, pg, "01JHOSTE", "web-01")

	for _, fingerprint := range []string{"fp-1", "fp-2"} {
		if err := pg.AddCertificate(ctx, Certificate{
			Fingerprint: fingerprint, HostID: host.ID, Serial: "01",
			IssuedAt: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		}); err != nil {
			t.Fatalf("adding %s: %v", fingerprint, err)
		}
	}

	// Adding the same fingerprint twice must not fail: an agent that retried a renewal whose response
	// was lost would otherwise be unable to re-key.
	if err := pg.AddCertificate(ctx, Certificate{
		Fingerprint: "fp-1", HostID: host.ID, Serial: "01",
		IssuedAt: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("re-adding a certificate: %v", err)
	}

	if err := pg.RevokeHost(ctx, host.ID); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	for _, fingerprint := range []string{"fp-1", "fp-2"} {
		cert, err := pg.LookupCertificate(ctx, fingerprint)
		if err != nil {
			t.Fatalf("looking up %s: %v", fingerprint, err)
		}
		if !cert.Revoked {
			t.Errorf("%s was not revoked with its host", fingerprint)
		}
		if cert.RevokedAt.IsZero() {
			t.Errorf("%s was revoked with no timestamp", fingerprint)
		}
	}

	after, err := pg.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("reading the host: %v", err)
	}
	if !after.Revoked {
		t.Error("the host was not marked revoked")
	}
	if err := pg.RevokeHost(ctx, "01JNOSUCHHOST"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown host produced %v, want ErrNotFound", err)
	}
}

// TestClaimJobsDeliversEachJobExactlyOnce is what lets the control plane run more than one replica.
//
// SELECT ... FOR UPDATE SKIP LOCKED against the partial index means two instances claiming for the same
// host at the same moment take disjoint rows rather than blocking or double-delivering. Delivering a
// reboot twice is the failure this prevents.
func TestClaimJobsDeliversEachJobExactlyOnce(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	host := enrolTestHost(t, pg, "01JHOSTF", "web-01")

	const jobs = 20
	for i := range jobs {
		enqueue(t, pg, host.ID, protocol.Job{
			ID: "01JJOB" + string(rune('A'+i)), Intent: "facts.collect", Class: "read",
			Params: map[string]any{}, IssuedAt: time.Now(),
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Nonce: "n",
		})
	}

	const claimers = 6
	type claim struct {
		jobs []protocol.Job
		err  error
	}
	results := make(chan claim, claimers)
	start := make(chan struct{})
	for range claimers {
		go func() {
			<-start
			claimed, err := pg.ClaimJobs(ctx, host.ID, 5)
			results <- claim{claimed, err}
		}()
	}
	close(start)

	seen := map[string]int{}
	total := 0
	for range claimers {
		result := <-results
		if result.err != nil {
			t.Errorf("claiming: %v", result.err)
			continue
		}
		for _, j := range result.jobs {
			seen[j.ID]++
			total++
		}
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("job %s was delivered %d times", id, count)
		}
	}
	if total != jobs {
		t.Errorf("%d of %d jobs were delivered", total, jobs)
	}

	// A second round must find nothing: claimed jobs are excluded by the partial index.
	remaining, err := pg.ClaimJobs(ctx, host.ID, 100)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d jobs were still claimable after every one had been claimed", len(remaining))
	}
}

// TestRecordResultIsIdempotent asserts a redelivered result changes nothing.
//
// The agent retries until it gets a 2xx, so a lost response means a second delivery. Work that
// succeeded but whose result was lost must never re-execute, and overwriting a genuine record with a
// retry's view of it would be the same class of mistake.
func TestRecordResultIsIdempotent(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	host := enrolTestHost(t, pg, "01JHOSTG", "web-01")

	enqueue(t, pg, host.ID, protocol.Job{
		ID: "01JJOBRESULT", Intent: "facts.collect", Class: "read", Params: map[string]any{},
		IssuedAt: time.Now(), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Nonce: "n",
	})
	if _, err := pg.ClaimJobs(ctx, host.ID, 1); err != nil {
		t.Fatalf("claiming: %v", err)
	}

	result := protocol.ResultRequest{
		JobID: "01JJOBRESULT", Status: protocol.StatusSucceeded,
		StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now(),
		Result: map[string]any{"hostname": "web-01"},
	}
	for i := range 3 {
		if err := pg.RecordResult(ctx, host.ID, result); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}

	// A completed job must not become claimable again, however many times its result arrives.
	claimable, err := pg.ClaimJobs(ctx, host.ID, 10)
	if err != nil {
		t.Fatalf("claiming after completion: %v", err)
	}
	if len(claimable) != 0 {
		t.Errorf("a completed job was claimable again")
	}
}

// TestSubscribeWakesOnNotify is what makes the long-poll a long-poll rather than a sleep.
//
// Without it, jobs would still be delivered — on the next poll, up to twenty-five seconds later — and
// nothing would look broken. It is the failure people notice as "why is this so slow" months
// afterwards.
func TestSubscribeWakesOnNotify(t *testing.T) {
	pg := newPostgres(t)

	host := enrolTestHost(t, pg, "01JHOSTH", "web-01")

	notified, unsubscribe := pg.Subscribe(host.ID)
	defer unsubscribe()

	// Wait for the listener rather than sleeping for it. A fixed sleep is a test that passes on a fast
	// machine and fails on a loaded one, and this is the assertion that would be quietly disabled first.
	select {
	case <-pg.ready:
	case <-time.After(15 * time.Second):
		t.Fatal("the notification listener never issued its LISTEN")
	}

	started := time.Now()
	enqueue(t, pg, host.ID, protocol.Job{
		ID: "01JJOBWAKE", Intent: "facts.collect", Class: "read", Params: map[string]any{},
		IssuedAt: time.Now(), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Nonce: "n",
	})

	select {
	case <-notified:
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Errorf("the wake-up took %s; LISTEN/NOTIFY is not delivering", elapsed.Round(time.Millisecond))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Subscribe was never woken by an enqueued job")
	}
}

// TestSubscribeReleasesItsWaiter asserts a released subscription leaves nothing behind.
//
// A fleet whose agents time out and reconnect every twenty-five seconds would otherwise accumulate a
// dead channel per poll for the process's lifetime — a leak that only shows after a week of uptime,
// which is the worst kind.
func TestSubscribeReleasesItsWaiter(t *testing.T) {
	pg := newPostgres(t)

	_, unsubscribe := pg.Subscribe("01JNOBODY")
	if waiterCount(pg) != 1 {
		t.Fatalf("%d waiters after subscribing once", waiterCount(pg))
	}
	unsubscribe()
	if n := waiterCount(pg); n != 0 {
		t.Errorf("%d waiter(s) were left behind after releasing the subscription", n)
	}
	// Releasing twice must not panic or corrupt the map: the caller always releases, and the waker has
	// usually already removed the waiter.
	unsubscribe()
	if n := waiterCount(pg); n != 0 {
		t.Errorf("%d waiter(s) after a second release", n)
	}
}

// TestListHostsIsOrdered asserts the fleet list does not reshuffle between page loads.
//
// Hostnames are not unique, so the secondary sort on id is what makes the order stable. Without it a
// reader watching a fleet list would see rows move for no reason they could see.
func TestListHostsIsOrdered(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()

	enrolTestHost(t, pg, "01JHOSTZ", "web-02")
	enrolTestHost(t, pg, "01JHOSTY", "web-01")
	enrolTestHost(t, pg, "01JHOSTX", "web-01")

	hosts, err := pg.ListHosts(ctx)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("listed %d hosts, want 3", len(hosts))
	}
	want := []string{"01JHOSTX", "01JHOSTY", "01JHOSTZ"}
	for i, id := range want {
		if hosts[i].ID != id {
			t.Errorf("position %d is %s (%s), want %s", i, hosts[i].ID, hosts[i].Hostname, id)
		}
	}
}

// truncate empties every table, so each test starts from a known schema.
//
// These tests assert things about counts and about uniqueness, and a row left over from an earlier test
// is the kind of failure that only appears when the tests happen to run in a different order.
func truncate(t *testing.T, pg *Postgres) {
	t.Helper()
	_, err := pg.pool.Exec(context.Background(),
		`TRUNCATE job_results, jobs, certificates, hosts, enrollment_tokens RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("emptying the schema: %v", err)
	}
}

// enqueue inserts a job directly, bypassing CreateJob.
//
// It predates CreateJob and is kept deliberately: the tests below are about the *delivery* path, and
// writing the row with plain SQL means they still fail if CreateJob is what breaks, rather than both
// going quiet together. The tests that exercise CreateJob itself are in jobs_test.go and run against
// both implementations.
func enqueue(t *testing.T, pg *Postgres, hostID string, job protocol.Job) {
	t.Helper()
	params, err := json.Marshal(job.Params)
	if err != nil {
		t.Fatalf("encoding job parameters: %v", err)
	}
	_, err = pg.pool.Exec(context.Background(), `
		INSERT INTO jobs (id, host_id, intent, params, class, issued_at, not_before, not_after, nonce)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		job.ID, hostID, job.Intent, params, job.Class,
		job.IssuedAt, job.NotBefore, job.NotAfter, job.Nonce)
	if err != nil {
		t.Fatalf("enqueueing %s: %v", job.ID, err)
	}
}

// waiterCount reports how many long-polls are currently registered.
//
// It reaches into the store's internals because that is the only way to observe a leak: a waiter that
// is never released is invisible from outside until the process has been up for a week.
func waiterCount(pg *Postgres) int {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	total := 0
	for _, waiters := range pg.waiters {
		total += len(waiters)
	}
	return total
}

// TestRevokingAHostReleasesItsMachineForReEnrolment is the recovery path out of a 409.
//
// A machine-id hash held for ever by a row nobody can authenticate as is a wedge: the machine cannot
// talk, and enrolling it again is refused because it is "already enrolled". Revocation has to be the
// way out, and it has to leave the old row in place — an audit asking what that host reported before it
// was revoked is exactly the question revocation exists to make answerable.
func TestRevokingAHostReleasesItsMachineForReEnrolment(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()

	first := enrolTestHost(t, pg, "01JHOSTM", "web-01")
	if err := pg.RevokeHost(ctx, first.ID); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	// The machine no longer resolves to a live host, which is what the enrolment handler checks.
	if _, err := pg.GetHostByMachineID(ctx, first.MachineIDHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a revoked host still claims its machine id: %v", err)
	}

	second := first
	second.ID = "01JHOSTN"
	if err := pg.CreateEnrolledHost(ctx, second, Certificate{
		Fingerprint: "fp-rejoin", HostID: second.ID, Serial: "02",
		IssuedAt: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("re-enrolling a revoked machine: %v", err)
	}

	found, err := pg.GetHostByMachineID(ctx, first.MachineIDHash)
	if err != nil {
		t.Fatalf("looking up the re-enrolled host: %v", err)
	}
	if found.ID != second.ID {
		t.Errorf("the machine id resolves to %s, want the re-enrolled %s", found.ID, second.ID)
	}

	// The revoked row is still there, with its history.
	if _, err := pg.GetHost(ctx, first.ID); err != nil {
		t.Errorf("re-enrolment erased the revoked host: %v", err)
	}
}

// TestDeleteHostTakesItsDependentRowsWithIt covers the operator's other way out of a wedge.
//
// Revocation keeps the history; deletion is for the row that should not exist at all. Either way the
// machine must be able to enrol again, and nothing may be left pointing at a host that is gone — a
// certificate outliving its host would be a fingerprint that authenticates and resolves to nobody.
func TestDeleteHostTakesItsDependentRowsWithIt(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()

	host := enrolTestHost(t, pg, "01JHOSTP", "web-01")
	if err := pg.DeleteHost(ctx, host.ID); err != nil {
		t.Fatalf("deleting: %v", err)
	}
	if _, err := pg.GetHost(ctx, host.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the deleted host is still readable: %v", err)
	}
	if _, err := pg.LookupCertificate(ctx, "fp-"+host.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a certificate outlived the host it was issued to: %v", err)
	}
	if _, err := pg.GetHostByMachineID(ctx, host.MachineIDHash); !errors.Is(err, ErrNotFound) {
		t.Errorf("the deleted host still claims its machine id: %v", err)
	}
	if err := pg.DeleteHost(ctx, "01JNOSUCHHOST"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting an unknown host produced %v, want ErrNotFound", err)
	}
}

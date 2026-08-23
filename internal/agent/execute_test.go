package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/collect"
	"github.com/pascalgross/farrier/internal/privsep"
	"github.com/pascalgross/farrier/internal/protocol"
)

// stubPlatform is a collect.Platform whose answers the test controls.
//
// A stub is used here, and only here, because what is being tested is the agent's job path — accept,
// execute, produce a result — rather than fact collection itself. Collection is tested against real
// captured apt and needrestart output in internal/collect, and against real machines in testfleet;
// putting a real platform behind this test would make it fail on a developer's laptop for reasons that
// have nothing to do with what it asserts.
type stubPlatform struct {
	// dist is what Identify reports.
	dist collect.Distribution

	// packages is what UpgradablePackages reports.
	packages []collect.Package

	// reboot is what RebootRequired reports.
	reboot collect.RebootReport

	// err, when set, is returned by every method that can fail.
	err error
}

// Identify reports which distribution this is.
func (s *stubPlatform) Identify() (collect.Distribution, error) {
	if s.err != nil {
		return collect.Distribution{}, s.err
	}
	return s.dist, nil
}

// UpgradablePackages lists pending updates.
func (s *stubPlatform) UpgradablePackages(context.Context) ([]collect.Package, error) {
	return s.packages, s.err
}

// SecurityOrigins returns the unattended-upgrades origin patterns for this family.
func (s *stubPlatform) SecurityOrigins() []string { return []string{"stub"} }

// RebootRequired reports whether the host needs a reboot.
func (s *stubPlatform) RebootRequired(context.Context) (collect.RebootReport, error) {
	return s.reboot, s.err
}

// SubscriptionStatus reports Ubuntu Pro state.
func (s *stubPlatform) SubscriptionStatus(context.Context) (*collect.Subscription, error) {
	return &collect.Subscription{Applicable: true}, s.err
}

// newStubPlatform returns a platform with plausible answers.
func newStubPlatform() *stubPlatform {
	return &stubPlatform{
		dist: collect.Distribution{
			ID: "ubuntu", Family: collect.FamilyUbuntu, Codename: "noble",
			Version: "24.04", PrettyName: "Ubuntu 24.04.1 LTS", Supported: true,
		},
		packages: []collect.Package{
			{Name: "libssl3t64", CandidateVersion: "3.0.13-0ubuntu3.5", Security: true},
			{Name: "base-files", CandidateVersion: "13ubuntu10.2"},
		},
		reboot: collect.RebootReport{
			Required: true,
			Reasons:  []string{"linux-image-generic"},
			Services: []string{"ssh.service"},
			Source:   "/var/run/reboot-required",
		},
	}
}

// fakeElevator stands in for the route to the root helpers.
//
// The agent's job path has to be exercisable without a root helper and without systemd, for the same
// reason the platform is a stub: a test that needed either would be a test of the developer's machine
// rather than of the agent. What it records is the request that crossed the boundary, because for a
// privileged job that request *is* what the agent did.
type fakeElevator struct {
	// seen is the last request the agent sent, for assertions about what crossed the boundary.
	seen privsep.Request

	// calls counts invocations, so a test can assert that nothing crossed at all.
	calls int

	// reply is what to answer with.
	reply privsep.Response

	// err, when set, is returned instead of a reply.
	err error
}

// Invoke records the request and returns the configured reply.
func (f *fakeElevator) Invoke(_ context.Context, req privsep.Request) (privsep.Response, error) {
	f.seen = req
	f.calls++
	return f.reply, f.err
}

// testRunner assembles a Runner with the fixtures these tests share.
//
// It exists so that a test names only the thing it is varying. The spool is a real function writing to
// a temporary directory rather than nil, because nil is no longer merely "do not spool": Run refuses an
// operation that may not return when it has no way to record a result first.
func testRunner(t *testing.T, plat collect.Platform, elevate privsep.Invoker) Runner {
	t.Helper()
	dir := t.TempDir()
	return Runner{
		HostID:   testHostID,
		Policy:   permissivePolicy(t),
		Signers:  newSignerFixture(t, "ops-laptop").set,
		Nonces:   newNonceStore(t),
		Platform: plat,
		Elevate:  elevate,
		Spool:    func(r protocol.ResultRequest) error { return SpoolResult(dir, r) },
	}
}

// readJob builds an unsigned read-only job.
//
// Read intents carry no signature: mTLS is sufficient authorisation, because they run unprivileged and
// read nothing an unprivileged local user could not read.
func readJob(id, intent string) protocol.Job {
	now := time.Now()
	return protocol.Job{
		ID: id, Intent: intent, Params: map[string]any{}, Class: "read",
		IssuedAt: now, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
	}
}

// TestRunExecutesReadIntentsAndProducesAResult is the agent's job path for work it does itself.
//
// Read intents are the only ones the agent performs in its own process; everything privileged crosses
// the socket to a root helper and is covered further down this file. It asserts the result carries the
// collected data rather than merely reporting success, because a job that succeeded and returned
// nothing is indistinguishable from one that worked, right up until somebody looks at the dashboard.
func TestRunExecutesReadIntentsAndProducesAResult(t *testing.T) {
	plat := newStubPlatform()
	runner := testRunner(t, plat, nil)
	ctx := context.Background()

	t.Run("packages.listUpgradable", func(t *testing.T) {
		result := runner.Run(ctx, readJob("01JA", "packages.listUpgradable"))
		if result.Status != protocol.StatusSucceeded {
			t.Fatalf("status %q: %s", result.Status, result.Error)
		}
		report, ok := result.Result.(collect.PackageReport)
		if !ok {
			t.Fatalf("result is %T, want collect.PackageReport", result.Result)
		}
		if report.UpgradableTotal != 2 || report.UpgradableSecurity != 1 {
			t.Errorf("reported %d security of %d total, want 1 of 2",
				report.UpgradableSecurity, report.UpgradableTotal)
		}
	})

	t.Run("reboot.checkRequired", func(t *testing.T) {
		result := runner.Run(ctx, readJob("01JB", "reboot.checkRequired"))
		if result.Status != protocol.StatusSucceeded {
			t.Fatalf("status %q: %s", result.Status, result.Error)
		}
		report, ok := result.Result.(collect.RebootReport)
		if !ok {
			t.Fatalf("result is %T, want collect.RebootReport", result.Result)
		}
		if !report.Required || len(report.Services) != 1 {
			t.Errorf("result is %+v", report)
		}
	})

	t.Run("facts.collect", func(t *testing.T) {
		result := runner.Run(ctx, readJob("01JC", "facts.collect"))
		if result.Status != protocol.StatusSucceeded {
			t.Fatalf("status %q: %s", result.Status, result.Error)
		}
		facts, ok := result.Result.(collect.Facts)
		if !ok {
			t.Fatalf("result is %T, want collect.Facts", result.Result)
		}
		if facts.Distribution.Codename != "noble" {
			t.Errorf("facts carry distribution %+v", facts.Distribution)
		}
		if facts.Packages.UpgradableSecurity != 1 {
			t.Errorf("facts carry %d security updates, want 1", facts.Packages.UpgradableSecurity)
		}
		// Hostname and kernel are read from the host rather than the stub, and must not be empty:
		// a fleet list of hosts called "" would be a fleet list of nothing.
		if facts.Hostname == "" || facts.Kernel == "" {
			t.Errorf("facts are missing host-derived fields: hostname=%q kernel=%q",
				facts.Hostname, facts.Kernel)
		}
	})
}

// TestRunReportsAFailureRatherThanReturningNothing asserts every outcome becomes a result.
//
// A job that produced no result at all would sit in the queue looking like a host that had gone quiet,
// which is the least useful thing a fleet tool can do.
func TestRunReportsAFailureRatherThanReturningNothing(t *testing.T) {
	plat := newStubPlatform()
	plat.err = errors.New("apt is locked by another process")

	result := testRunner(t, plat, nil).Run(context.Background(), readJob("01JD", "packages.listUpgradable"))

	if result.Status != protocol.StatusFailed {
		t.Fatalf("status %q, want %q", result.Status, protocol.StatusFailed)
	}
	if result.Error == "" {
		t.Error("a failed job carries no error message")
	}
	if result.JobID != "01JD" {
		t.Errorf("the result is keyed %q, want 01JD", result.JobID)
	}
	if result.FinishedAt.Before(result.StartedAt) {
		t.Error("the result finished before it started")
	}
}

// TestRunRefusesAnIntentOutsideTheCatalogue asserts an unknown job is reported, not guessed at.
//
// An agent that receives an intent it does not recognise reports unsupported_intent and must not
// attempt any fallback interpretation. It is what makes old agents safe to leave running: they refuse
// what they do not understand rather than approximating it.
func TestRunRefusesAnIntentOutsideTheCatalogue(t *testing.T) {
	for _, name := range []string{"shell.exec", "facts.collect.extra", "", "FACTS.COLLECT"} {
		result := testRunner(t, newStubPlatform(), nil).Run(context.Background(), readJob("01JE", name))
		if result.Status != protocol.StatusUnsupportedIntent {
			t.Errorf("intent %q produced status %q, want %q",
				name, result.Status, protocol.StatusUnsupportedIntent)
		}
	}
}

// TestRunDoesNotGateReadIntentsOnTheJobAgeLimit pins a decision that is easy to reverse by accident.
//
// The age limit exists to bound the damage of a job that sat in a queue across an outage: a restart
// signed on Tuesday must not execute on Friday. A *read* has no damage to bound — a stale read is still
// a true read, and refusing it would blind an operator to the state of a host that has just come back
// from the outage they are investigating.
//
// If that ever changes it should change here, visibly, rather than as a side effect of moving the check.
func TestRunDoesNotGateReadIntentsOnTheJobAgeLimit(t *testing.T) {
	signers := newSignerFixture(t, "ops-laptop")
	strict := permissivePolicy(t)
	strict.Limits.MaxJobAgeSeconds = 1

	stale := readJob("01JF", "facts.collect")
	stale.IssuedAt = time.Now().Add(-time.Hour)

	runner := testRunner(t, newStubPlatform(), nil)
	runner.Policy = strict
	result := runner.Run(context.Background(), stale)

	if result.Status != protocol.StatusSucceeded {
		t.Errorf("an hour-old read intent produced %q under a one-second age limit: %s",
			result.Status, result.Error)
	}

	// The same limit must still bite on a privileged intent, or this test would be proving that the
	// limit does not work rather than that reads are exempt from it.
	privileged := destructiveJob("nonce-age-limit")
	privileged.IssuedAt = time.Now().Add(-time.Hour)
	privileged.Signature = signers.sign(t, privileged)

	decision := accept(privileged, testHostID, strict, signers.set, noOnlineKey(), newNonceStore(t), 0, time.Now())
	if decision.accepted() {
		t.Error("an hour-old privileged job was accepted under a one-second age limit")
	}
}

// signedJob builds a destructive job signed by a fixture key, ready to be Run.
//
// The signature is over the payload addressed to testHostID, which is the host id every Runner these
// tests build carries. A job signed for one host and offered to another is a different test, and the
// acceptance sequence already has one.
func signedJob(t *testing.T, signers signerFixture, id string, name string,
	params map[string]any) protocol.Job {

	t.Helper()
	now := time.Now()
	job := protocol.Job{
		ID: id, Intent: name, Params: params, Class: "destructive",
		IssuedAt: now, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		Nonce: "nonce-" + id, SignerAlgorithm: "ed25519",
	}
	job.Signature = signers.sign(t, job)
	return job
}

// privilegedRunner returns a Runner whose trust anchor is the returned fixture's key.
//
// The signer has to be the same one that signs the job, so it is built here and handed back rather than
// created inside testRunner: a destructive job signed by a key the runner does not trust is a different
// test, and it already exists.
func privilegedRunner(t *testing.T, elevate privsep.Invoker) (Runner, signerFixture) {
	t.Helper()
	signers := newSignerFixture(t, "ops-laptop")
	runner := testRunner(t, newStubPlatform(), elevate)
	runner.Signers = signers.set
	return runner, signers
}

// TestAPrivilegedJobCrossesTheBoundaryWithTheBytesThatArrived is what the agent's whole privileged
// path amounts to.
//
// The agent performs nothing. It names an intent, forwards the parameter object exactly as it received
// it, and reports what came back — so what is asserted here is the request, not an effect. The bytes
// matter: the helper decodes them again itself, as root, with the same catalogue decoder, and a
// re-encoding of the agent's decoded value would make the two decodes different decodes.
func TestAPrivilegedJobCrossesTheBoundaryWithTheBytesThatArrived(t *testing.T) {
	elevator := &fakeElevator{reply: privsep.Response{ExitCode: 0, Output: "restart nginx.service: done"}}
	runner, signers := privilegedRunner(t, elevator)
	job := signedJob(t, signers, "01JR", "service.restart", map[string]any{"unit": "nginx.service"})

	result := runner.Run(context.Background(), job)

	if result.Status != protocol.StatusSucceeded {
		t.Fatalf("status %q: %s", result.Status, result.Error)
	}
	if elevator.calls != 1 {
		t.Fatalf("the boundary was crossed %d times, want 1", elevator.calls)
	}
	if elevator.seen.Intent != "service.restart" {
		t.Errorf("the helper was asked for %q", elevator.seen.Intent)
	}
	if elevator.seen.JobID != job.ID {
		t.Errorf("the request carries job id %q, want %q", elevator.seen.JobID, job.ID)
	}
	if string(elevator.seen.Params) != `{"unit":"nginx.service"}` {
		t.Errorf("the request carries parameters %s, which are not the bytes that arrived",
			elevator.seen.Params)
	}
	if result.Output != "restart nginx.service: done" {
		t.Errorf("the helper's output was not reported: %q", result.Output)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code %d was reported", result.ExitCode)
	}
}

// TestTheAgeLimitCrossesTheBoundaryAsTheSignedTime closes a bypass on the far side.
//
// issuedAt is not covered by a job's signature, so for a signed job it is a number a compromised
// control plane chooses freely; notBefore is signed. The agent measures the local age limit from
// notBefore for exactly that reason — and the helper runs the same check again, as root, against
// whatever the agent hands it. Handing it the unsigned value would reopen the bypass on the privileged
// side of the boundary, where nothing else would catch it.
func TestTheAgeLimitCrossesTheBoundaryAsTheSignedTime(t *testing.T) {
	elevator := &fakeElevator{}
	runner, signers := privilegedRunner(t, elevator)
	job := signedJob(t, signers, "01JR", "service.restart", map[string]any{"unit": "nginx.service"})

	// A control plane claiming the job was issued just now, over a signature that says otherwise.
	job.NotBefore = time.Now().Add(-10 * time.Minute)
	job.IssuedAt = time.Now()
	job.Signature = signers.sign(t, job)

	runner.Run(context.Background(), job)

	if !elevator.seen.IssuedAt.Equal(job.NotBefore) {
		t.Errorf("the helper was told the job was issued at %s; it must be told the signed notBefore "+
			"(%s), or limits.max_job_age_seconds can be defeated by a control plane that lies about "+
			"issuedAt", elevator.seen.IssuedAt, job.NotBefore)
	}
}

// TestAHelperRefusalIsReportedAsARefusalRatherThanAFailure is the distinction operators live by.
//
// A job local policy declined and a job that broke are different events with different responses. An
// operator told "failed" for every refusal learns to ignore failures, which is the wrong lesson to
// take from the mechanism working exactly as designed.
func TestAHelperRefusalIsReportedAsARefusalRatherThanAFailure(t *testing.T) {
	cases := []struct {
		exit int
		want string
	}{
		{privsep.ExitOK, protocol.StatusSucceeded},
		{privsep.ExitRefused, protocol.StatusRefusedByPolicy},
		{privsep.ExitNotImplemented, protocol.StatusUnsupportedIntent},
		{privsep.ExitFailed, protocol.StatusFailed},
		{privsep.ExitUsage, protocol.StatusFailed},
		{99, protocol.StatusFailed},
	}
	for _, c := range cases {
		elevator := &fakeElevator{reply: privsep.Response{ExitCode: c.exit, Error: "because"}}
		runner, signers := privilegedRunner(t, elevator)
		job := signedJob(t, signers, "01JR", "service.restart",
			map[string]any{"unit": "nginx.service"})

		result := runner.Run(context.Background(), job)
		if result.Status != c.want {
			t.Errorf("exit %d was reported as %q, want %q", c.exit, result.Status, c.want)
		}
		if result.ExitCode != c.exit {
			t.Errorf("exit %d was reported as exit code %d", c.exit, result.ExitCode)
		}
	}
}

// TestAnUnreachableHelperIsReportedRatherThanFatal asserts a broken host still says so.
//
// A host whose helper sockets are masked, or whose package was half installed, must appear on the
// dashboard as a host whose jobs fail with a reason. An agent that crashed instead would take the
// host's reporting down along with the capability it had lost, which is the wrong way round.
func TestAnUnreachableHelperIsReportedRatherThanFatal(t *testing.T) {
	elevator := &fakeElevator{err: privsep.ErrUnreachable}
	runner, signers := privilegedRunner(t, elevator)
	job := signedJob(t, signers, "01JR", "service.restart", map[string]any{"unit": "nginx.service"})

	result := runner.Run(context.Background(), job)
	if result.Status != protocol.StatusFailed {
		t.Errorf("status %q, want %q", result.Status, protocol.StatusFailed)
	}
	if result.Error == "" {
		t.Error("an unreachable helper produced no reason")
	}
}

// TestAnAgentWithNoRouteToRootSaysSo covers the build that was assembled wrongly.
//
// It is a programming error rather than a host condition, and it must not read as a policy refusal:
// an operator sent looking at policy.toml for a Runner that was built without an Elevate would never
// find anything.
func TestAnAgentWithNoRouteToRootSaysSo(t *testing.T) {
	runner, signers := privilegedRunner(t, nil)
	job := signedJob(t, signers, "01JR", "service.restart", map[string]any{"unit": "nginx.service"})

	result := runner.Run(context.Background(), job)
	if result.Status != protocol.StatusFailed {
		t.Errorf("status %q, want %q", result.Status, protocol.StatusFailed)
	}
	if result.Status == protocol.StatusRefusedByPolicy {
		t.Error("a missing route to root was reported as a policy refusal")
	}
}

// TestAnUpdateThatRebootsSpoolsItsResultFirst is the failure that reports nothing at all.
//
// packages.applyAll with rebootIfRequired ends by rebooting the host, exactly as host.reboot does,
// while its catalogue entry quite correctly says that applying updates does not normally take a machine
// away. Without the parameters being consulted, no provisional result is written, the host reboots, and
// the job sits in the queue looking like a host that has gone quiet.
func TestAnUpdateThatRebootsSpoolsItsResultFirst(t *testing.T) {
	for _, rebooting := range []bool{false, true} {
		elevator := &fakeElevator{reply: privsep.Response{ExitCode: 0}}
		runner, signers := privilegedRunner(t, elevator)

		var spooled []protocol.ResultRequest
		runner.Spool = func(r protocol.ResultRequest) error {
			spooled = append(spooled, r)
			return nil
		}

		job := signedJob(t, signers, "01JU", "packages.applyAll",
			map[string]any{"rebootIfRequired": rebooting})
		runner.Run(context.Background(), job)

		switch {
		case rebooting && len(spooled) == 0:
			t.Error("packages.applyAll with rebootIfRequired wrote no result before starting; the host " +
				"would reboot and the job would never be reported")
		case !rebooting && len(spooled) != 0:
			t.Errorf("an ordinary update job spooled %d provisional results; the record exists to be "+
				"replaced, and one written for a job that will not reboot is a claim of success sitting "+
				"on disk for the length of the upgrade", len(spooled))
		}
	}
}

// TestAnOperationThatMayNotReturnIsRefusedWhenItsResultCannotBeRecorded is the harder half of that.
//
// An operation that may take the host away, whose result cannot be written down first, is one whose
// outcome nobody would ever learn. Refusing is the only honest answer, and the refusal must happen
// before anything crosses the privilege boundary.
func TestAnOperationThatMayNotReturnIsRefusedWhenItsResultCannotBeRecorded(t *testing.T) {
	for _, spool := range []func(protocol.ResultRequest) error{
		nil,
		func(protocol.ResultRequest) error { return errors.New("the spool directory is read-only") },
	} {
		elevator := &fakeElevator{}
		runner, signers := privilegedRunner(t, elevator)
		runner.Spool = spool

		job := signedJob(t, signers, "01JB", "host.reboot", map[string]any{})
		result := runner.Run(context.Background(), job)

		if result.Status != protocol.StatusFailed {
			t.Errorf("status %q, want %q", result.Status, protocol.StatusFailed)
		}
		if elevator.calls != 0 {
			t.Error("the reboot was started even though its result could not be recorded first")
		}
	}
}

// TestOverSizeHelperOutputIsTruncatedOnThisSideToo asserts the bound is not only the helper's.
//
// The helper truncates before replying, but a helper from an older package might not have, and an
// over-size result is not merely untidy: the server rejects a body past its limit, the spool file is
// only removed after a 2xx, and the host would retry the same over-size body for ever.
func TestOverSizeHelperOutputIsTruncatedOnThisSideToo(t *testing.T) {
	elevator := &fakeElevator{reply: privsep.Response{
		ExitCode: 0,
		Output:   strings.Repeat("x", protocol.MaxJobOutputBytes+4096) + "TAIL",
	}}
	runner, signers := privilegedRunner(t, elevator)
	job := signedJob(t, signers, "01JR", "service.restart", map[string]any{"unit": "nginx.service"})

	result := runner.Run(context.Background(), job)

	if len(result.Output) != protocol.MaxJobOutputBytes {
		t.Errorf("the reported output is %d bytes, and the protocol carries %d",
			len(result.Output), protocol.MaxJobOutputBytes)
	}
	if !result.OutputTruncated {
		t.Error("over-size output was not flagged as truncated")
	}
	if !strings.HasSuffix(result.Output, "TAIL") {
		t.Error("the head was kept rather than the tail; the failure is at the end")
	}
}

// TestGuaranteeAJobWithNoLowerBoundIsNotRefusedAsExpired is why an unsigned job carries none.
//
// The validity window is checked against the *local* clock — it must be, or a compromised control plane
// could extend a signature's validity by lying about the time — so a notBefore taken from the control
// plane's clock is refused by any host running even slightly behind it. Read intents deliberately skip
// the clock-skew check, so nothing else would catch it, and the result would be that every on-demand
// report failed on exactly the host whose clock is wrong: the one an operator most wants to look at.
//
// A job nothing signed has no authorisation whose start needs pinning, so it carries no lower bound at
// all. This asserts both halves: that an absent bound is not a refusal, and that a real one still is.
func TestGuaranteeAJobWithNoLowerBoundIsNotRefusedAsExpired(t *testing.T) {
	runner := testRunner(t, newStubPlatform(), nil)

	noLowerBound := readJob("01JA", "facts.collect")
	noLowerBound.NotBefore = time.Time{}
	if result := runner.Run(context.Background(), noLowerBound); result.Status != protocol.StatusSucceeded {
		t.Errorf("a job with no lower bound was refused as %q: %s", result.Status, result.Error)
	}

	// And the check is still live: a window that genuinely has not opened is still refused, or the
	// assertion above would be about a check that had been removed rather than one that was not reached.
	notYet := readJob("01JB", "facts.collect")
	notYet.NotBefore = time.Now().Add(time.Hour)
	if result := runner.Run(context.Background(), notYet); result.Status != protocol.StatusExpired {
		t.Errorf("a job whose window has not opened produced %q, want %q",
			result.Status, protocol.StatusExpired)
	}
}

package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/collect"
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

// TestRunExecutesReadIntentsAndProducesAResult is the agent's job path end to end.
//
// Read intents are the only ones with an executor in phase 0, so this is the whole of what an agent can
// currently be asked to do. It asserts the result carries the collected data rather than merely
// reporting success, because a job that succeeded and returned nothing is indistinguishable from one
// that worked, right up until somebody looks at the dashboard.
func TestRunExecutesReadIntentsAndProducesAResult(t *testing.T) {
	plat := newStubPlatform()
	signers := newSignerFixture(t, "ops-laptop")
	policy := permissivePolicy(t)
	ctx := context.Background()

	t.Run("packages.listUpgradable", func(t *testing.T) {
		result := Run(ctx, readJob("01JA", "packages.listUpgradable"), testHostID, policy,
			signers.set, newNonceStore(t), plat, 0, nil)
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
		result := Run(ctx, readJob("01JB", "reboot.checkRequired"), testHostID, policy,
			signers.set, newNonceStore(t), plat, 0, nil)
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
		result := Run(ctx, readJob("01JC", "facts.collect"), testHostID, policy,
			signers.set, newNonceStore(t), plat, 0, nil)
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
	signers := newSignerFixture(t, "ops-laptop")

	result := Run(context.Background(), readJob("01JD", "packages.listUpgradable"), testHostID,
		permissivePolicy(t), signers.set, newNonceStore(t), plat, 0, nil)

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
	signers := newSignerFixture(t, "ops-laptop")

	for _, name := range []string{"shell.exec", "facts.collect.extra", "", "FACTS.COLLECT"} {
		result := Run(context.Background(), readJob("01JE", name), testHostID,
			permissivePolicy(t), signers.set, newNonceStore(t), newStubPlatform(), 0, nil)
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

	result := Run(context.Background(), stale, testHostID, strict, signers.set,
		newNonceStore(t), newStubPlatform(), 0, nil)

	if result.Status != protocol.StatusSucceeded {
		t.Errorf("an hour-old read intent produced %q under a one-second age limit: %s",
			result.Status, result.Error)
	}

	// The same limit must still bite on a privileged intent, or this test would be proving that the
	// limit does not work rather than that reads are exempt from it.
	privileged := destructiveJob("nonce-age-limit")
	privileged.IssuedAt = time.Now().Add(-time.Hour)
	privileged.Signature = signers.sign(t, privileged)

	decision := accept(privileged, testHostID, strict, signers.set, newNonceStore(t), 0, time.Now())
	if decision.accepted() {
		t.Error("an hour-old privileged job was accepted under a one-second age limit")
	}
}

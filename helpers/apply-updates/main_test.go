package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/privsep"
	"github.com/pascalgross/farrier/internal/run"
)

// TestGuaranteeTheConffileOptionsAreOnEveryUpdateRun is the cheap early warning for a real trap.
//
// testfleet/scenarios/050-conffile-prompt.sh proves against real dpkg on a real machine that a run
// without --force-confdef and --force-confold does not complete cleanly on a host whose conffile has
// been edited, and that DEBIAN_FRONTEND=noninteractive alone is not enough. That scenario needs LXD and
// five virtual machines. This one needs neither, and fails in a second if somebody tidies the options
// away — which is the edit that would look harmless in review.
func TestGuaranteeTheConffileOptionsAreOnEveryUpdateRun(t *testing.T) {
	program, args, err := updateCommand(intent.PackagesApplyAll)
	if err != nil {
		t.Fatalf("building the argument vector: %v", err)
	}
	if program != run.AptGet {
		t.Errorf("packages.applyAll runs %q, expected apt-get: apt's output format changed in 3.0 and "+
			"apt-get's has not", program)
	}

	joined := strings.Join(args, " ")
	for _, required := range []string{
		"Dpkg::Options::=--force-confdef",
		"Dpkg::Options::=--force-confold",
		"DPkg::Lock::Timeout=" + lockTimeoutSeconds,
		"dist-upgrade",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("the argument vector is missing %q: %v", required, args)
		}
	}

	env := strings.Join(updateEnv(), " ")
	if !strings.Contains(env, "DEBIAN_FRONTEND=noninteractive") {
		t.Errorf("the environment does not set DEBIAN_FRONTEND: %v", updateEnv())
	}
	if !strings.Contains(env, "APT_CONFIG="+AptConfigPath) {
		t.Errorf("the environment does not name the shipped apt configuration: %v", updateEnv())
	}
}

// TestSecurityUpdatesGoThroughUnattendedUpgrade pins the choice not to reimplement origin filtering.
//
// Deciding what counts as a security origin is different on Ubuntu and on Debian, and different again
// on a host attached to Ubuntu Pro. unattended-upgrades already gets all three right; a second
// implementation would be wrong on exactly the release nobody tested, and the failure would be a host
// reporting a successful security run having applied nothing.
func TestSecurityUpdatesGoThroughUnattendedUpgrade(t *testing.T) {
	program, args, err := updateCommand(intent.PackagesApplySecurity)
	if err != nil {
		t.Fatalf("building the argument vector: %v", err)
	}
	if program != run.UnattendedUpgrade {
		t.Errorf("packages.applySecurity runs %q, expected unattended-upgrade", program)
	}
	for _, arg := range args {
		// unattended-upgrade takes no -o. Passing one would not be rejected loudly; optparse would
		// stop at an unrecognised option and the run would not happen at all.
		if strings.HasPrefix(arg, "-o") {
			t.Errorf("unattended-upgrade was given %q, and it accepts no -o: apt options reach it "+
				"through APT_CONFIG instead", arg)
		}
	}
}

// TestGuaranteeUpdateCommandsAreOnlyBuiltForIntentsThisHelperServes asserts the routing agrees.
//
// The socket, the routing table in internal/privsep and this switch have to name the same two members.
// If they drift, the symptom is a job that reaches root and then fails on a default case, which reads
// as a bug on the host rather than as an omission in a commit.
func TestGuaranteeUpdateCommandsAreOnlyBuiltForIntentsThisHelperServes(t *testing.T) {
	for _, name := range intent.Names() {
		endpoint, routed := privsep.Endpoint(name)
		mine := routed && endpoint == privsep.ApplyUpdatesSocket
		_, _, err := updateCommand(name)
		switch {
		case mine && err != nil:
			t.Errorf("intent %q is routed to this helper but has no command: %v", name, err)
		case !mine && err == nil:
			t.Errorf("intent %q is not routed to this helper but this helper builds a command for it", name)
		}
	}
}

// TestTheShippedAptConfigurationLivesWhereThePackagePutsIt catches a path edited on one side only.
//
// The constant here and the contents entry in packaging/nfpm.yaml are the same path written twice. apt
// ignores a missing APT_CONFIG silently, so if they ever disagree the consequence is not an error: it
// is packages with locally edited conffiles being held back, on every host, with the job still
// reporting success.
func TestTheShippedAptConfigurationLivesWhereThePackagePutsIt(t *testing.T) {
	if !filepath.IsAbs(AptConfigPath) {
		t.Fatalf("%q is not an absolute path", AptConfigPath)
	}
	packaged, err := filepath.Abs("../../packaging/apt.conf")
	if err != nil {
		t.Fatalf("resolving the packaged fragment: %v", err)
	}
	body, err := readFileIfPresent(packaged)
	if err != nil {
		t.Fatalf("reading %s: %v", packaged, err)
	}
	if body == "" {
		t.Fatalf("packaging/apt.conf is missing or empty; %s would not exist on a host", AptConfigPath)
	}
	for _, required := range []string{"--force-confdef", "--force-confold"} {
		if !strings.Contains(body, required) {
			t.Errorf("packaging/apt.conf does not set %s, so unattended-upgrade would hold back every "+
				"package whose conffile has been edited", required)
		}
	}
}

// readFileIfPresent returns a file's contents, or the empty string if it does not exist.
//
// Separate from the assertion so that "the file is absent" and "the file could not be read" stay
// distinguishable: the first is the failure this test exists to catch and the second is a broken
// checkout.
func readFileIfPresent(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

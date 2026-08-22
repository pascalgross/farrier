// Command apply-updates is the root helper that applies package updates, subject to local policy.
//
// It is installed as /usr/libexec/farrier/apply-updates and is reachable from the agent only through
// the fixed-argv entry in /etc/sudoers.d/farrier. It accepts no command to run, no path to execute and
// no shell fragment; its entire input is an intent name, a job id, an issue time and one boolean.
//
// It re-reads /etc/farrier/policy.toml itself, as root, on every invocation. The agent has already
// evaluated the same policy before calling — that check exists to save a round trip and produce a
// better error message. This one is the check docs/SECURITY.md §1 depends on, because it runs as root
// against the root-owned file and does not trust its caller.
//
// Phase 0 ships no write capability. The authorisation sequence below is real and complete; the
// execution at the end is absent and the helper exits 4. That is deliberate: the enforcement code runs
// in its real position from the first release rather than being written later against a path that has
// never executed.
package main

import (
	"flag"
	"fmt"

	"github.com/pascalgross/farrier/internal/buildinfo"
	"github.com/pascalgross/farrier/internal/helper"
	"github.com/pascalgross/farrier/internal/intent"
)

// main parses the fixed command line, enforces local policy, and would then apply updates.
func main() {
	var (
		intentName = flag.String("intent", "", "packages.applySecurity or packages.applyAll")
		jobID      = flag.String("job-id", "", "control-plane job id, recorded in the audit log")
		issuedAt   = flag.String("issued-at", "", "RFC 3339 time the job was issued")
		reboot     = flag.Bool("reboot-if-required", false, "reboot afterwards if the update needs it")
		dryRun     = flag.Bool("dry-run", false, "evaluate policy and print the decision, changing nothing")
		version    = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Println("farrier apply-updates " + buildinfo.String())
		return
	}
	if flag.NArg() > 0 {
		helper.Fatalf(helper.ExitUsage, "takes no positional arguments, got %q", flag.Args())
	}
	helper.SetupLogging("apply-updates")

	name := intent.Name(*intentName)
	if name != intent.PackagesApplySecurity && name != intent.PackagesApplyAll {
		helper.Fatalf(helper.ExitUsage, "--intent must be %s or %s, got %q",
			intent.PackagesApplySecurity, intent.PackagesApplyAll, *intentName)
	}

	params := helper.Dispatch(helper.Request{
		JobID:    *jobID,
		Intent:   name,
		Params:   helper.ParamsJSON(map[string]any{"rebootIfRequired": *reboot}),
		IssuedAt: helper.ParseIssuedAt(*issuedAt),
	}, *dryRun)

	// Phase 1 replaces this with a wrapper around unattended-upgrade, invoked by absolute path with a
	// fixed argv. It will not reimplement origin filtering: unattended-upgrades already does that
	// correctly on both distribution families, and a second implementation would be wrong on exactly
	// the release nobody tested. It will pass --force-confdef and --force-confold, because
	// DEBIAN_FRONTEND=noninteractive alone is not enough — a changed conffile stops the run dead
	// waiting for input that never comes — and DPkg::Lock::Timeout, to avoid colliding with the host's
	// own apt-daily.timer.
	helper.Fatalf(helper.ExitNotImplemented,
		"this build has no update executor: phase 0 ships no write capability. "+
			"Local policy permitted %q; nothing was changed.", params.Describe())
}

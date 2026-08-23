// Command apply-updates is the root helper that applies package updates, subject to local policy.
//
// It is installed as /usr/libexec/farrier/apply-updates and is reachable from the agent only through
// the socket its unit is activated on, /run/farrier/apply-updates.sock, which is owned root:farrier and
// mode 0660. See internal/privsep for why that replaced sudo. It accepts no command to run, no path to
// execute and no shell fragment; its entire input is an intent name, a job id, an issue time and one
// boolean.
//
// It re-reads /etc/farrier/policy.toml itself, as root, on every invocation. The agent has already
// evaluated the same policy before calling — that check exists to save a round trip and produce a
// better error message. This one is the check docs/SECURITY.md §1 depends on, because it runs as root
// against the root-owned file and does not trust its caller.
//
// Two invocations, chosen for different reasons:
//
//   - packages.applySecurity runs unattended-upgrade, because the distribution's own origin filtering
//     is correct on both families and a second implementation would be wrong on exactly the release
//     nobody tested. The host's /etc/apt/apt.conf.d/50unattended-upgrades decides what "security"
//     means, which is the right place for it: that is the host's own configuration, and local policy
//     sovereignty means the host's answer wins.
//   - packages.applyAll runs apt-get dist-upgrade, because there is no origin to filter by and
//     apt-get's output format has been stable for two decades where apt's has not.
//
// Neither refreshes the package lists first. What gets applied is what was reported: the fact
// collection an operator saw in the UI came from the same lists, and a job that quietly ran apt-get
// update would apply updates nobody had looked at. The host's own apt-daily.timer is what keeps the
// lists current, on the host's schedule.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pascalgross/farrier/internal/buildinfo"
	"github.com/pascalgross/farrier/internal/collect/platform"
	"github.com/pascalgross/farrier/internal/helper"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/policy"
	"github.com/pascalgross/farrier/internal/privsep"
	"github.com/pascalgross/farrier/internal/run"
)

// AptConfigPath is the apt configuration fragment the package ships for update runs.
//
// It exists because unattended-upgrade accepts no -o: its option set is --debug, --apt-debug,
// --verbose, --dry-run, --download-only and the two --minimal-upgrade-steps forms, and nothing else.
// Without --force-confdef and --force-confold in DPkg::Options it does not hang — it is more subtle
// than that — it *blacklists* every package whose conffile changed and upgrades the rest, so the host
// reports a successful run and quietly stays vulnerable in exactly the packages that were edited. That
// is the silent-wrong-answer class this project exists not to ship.
//
// apt reads the file named by APT_CONFIG first, then /etc/apt/apt.conf.d, then /etc/apt/apt.conf, so an
// administrator's own settings still land on top of these and DPkg::Options accumulates rather than
// being replaced. Verified against apt 2.8.3 with `APT_CONFIG=… apt-config dump`.
const AptConfigPath = "/usr/share/farrier/apt.conf"

// updateTimeout bounds one update run.
//
// It is deliberately below internal/privsep's InvokeTimeout, so that a run which overruns produces a
// helper that says so rather than an agent that gives up on a helper still working. Forty minutes is
// sized for the bad case — a small host with a slow mirror applying a release's worth of accumulated
// updates — because an upgrade interrupted part way is worse than one that took too long.
const updateTimeout = 40 * time.Minute

// lockTimeoutSeconds is how long apt waits for the dpkg lock rather than failing.
//
// Colliding with the host's own apt-daily.timer is the failure that only appears on a busy fleet, and
// it appears as a job that failed for no reason anybody can see. Ten minutes is longer than any
// apt-daily run and short enough that a genuinely wedged lock is still reported within the job.
const lockTimeoutSeconds = "600"

// main parses the fixed command line and either answers the socket or applies updates once.
func main() {
	var (
		intentName = flag.String("intent", "", "packages.applySecurity or packages.applyAll")
		jobID      = flag.String("job-id", "", "control-plane job id, recorded in the audit log")
		issuedAt   = flag.String("issued-at", "", "RFC 3339 time the job was issued")
		reboot     = flag.Bool("reboot-if-required", false, "reboot afterwards if the update needs it")
		serve      = flag.Bool("serve", false, "answer one request from the socket systemd activated")
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

	h := helper.Helper{
		Component: "apply-updates",
		Socket:    privsep.ApplyUpdatesSocket,
		Execute:   apply,
	}
	if *serve {
		h.Serve()
		return
	}

	name := intent.Name(*intentName)
	if name != intent.PackagesApplySecurity && name != intent.PackagesApplyAll {
		helper.Fatalf(helper.ExitUsage, "--intent must be %s or %s, got %q",
			intent.PackagesApplySecurity, intent.PackagesApplyAll, *intentName)
	}

	h.Main(helper.Request{
		JobID:    *jobID,
		Intent:   name,
		Params:   helper.ParamsJSON(map[string]any{"rebootIfRequired": *reboot}),
		IssuedAt: helper.ParseIssuedAt(*issuedAt),
	}, *dryRun)
}

// apply runs the update the validated parameters describe, and the follow-up reboot if one was asked
// for and the host needs one.
func apply(ctx context.Context, job helper.Job) (string, error) {
	params, ok := job.Params.(intent.ApplyParams)
	if !ok {
		return "", fmt.Errorf("apply-updates: %s did not decode to update parameters", job.Intent)
	}

	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	var report strings.Builder
	if _, err := os.Stat(AptConfigPath); err != nil {
		// A warning rather than a refusal. Refusing to patch a host because a configuration fragment is
		// missing would be a worse outcome than patching most of it; but apt tolerates a missing
		// APT_CONFIG silently, so without this line the consequence — packages with changed conffiles
		// held back — would be invisible in the job result too.
		report.WriteString("warning: " + AptConfigPath + " is missing, so packages whose conffiles " +
			"have been edited locally may be held back\n")
	}

	res, err := runUpdate(ctx, job.Intent)
	report.WriteString(commandOutput(res))
	if err != nil {
		return report.String(), fmt.Errorf("apply-updates: %s: %w", job.Intent, err)
	}

	if !params.RebootIfRequired {
		return report.String(), nil
	}
	note, err := rebootIfRequired(ctx, job.ID)
	report.WriteString("\n" + note)
	return report.String(), err
}

// updateEnv is the environment one update run gets.
//
// internal/run replaces the environment rather than inheriting it, so everything the run needs is named
// here, at the one call site that needs it, instead of being whatever the agent happened to be started
// with.
func updateEnv() []string {
	return []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C.UTF-8",
		// Necessary and not sufficient: on its own it makes debconf stop asking, and dpkg still stops
		// dead on a changed conffile. The Dpkg::Options below are the other half.
		"DEBIAN_FRONTEND=noninteractive",
		"APT_CONFIG=" + AptConfigPath,
	}
}

// updateCommand returns the program and the exact argument vector one update intent runs.
//
// It is separate from the invocation so that the argument vector can be asserted by a test. The options
// it carries are not decoration: testfleet/scenarios/050-conffile-prompt.sh demonstrates against real
// dpkg that without --force-confdef and --force-confold a run with an edited conffile does not complete
// cleanly, and the lock timeout is what stops a collision with the host's own apt-daily.timer from
// looking like a job that failed for no reason.
func updateCommand(name intent.Name) (run.Program, []string, error) {
	switch name {
	case intent.PackagesApplySecurity:
		// --verbose so the job result names the packages that were upgraded. A run that reports only
		// "done" is a run nobody can audit afterwards.
		return run.UnattendedUpgrade, []string{"--verbose"}, nil

	case intent.PackagesApplyAll:
		// The options are repeated on the command line as well as being in AptConfigPath. That is
		// deliberate: here they are visible in the process list and in the journal, where somebody
		// debugging a stalled upgrade will look, and the run does not depend on a file being installed.
		return run.AptGet, []string{
			"--yes",
			"--quiet",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold",
			"-o", "DPkg::Lock::Timeout=" + lockTimeoutSeconds,
			"dist-upgrade",
		}, nil

	default:
		// Unreachable while Perform checks the intent against this helper's socket, and a hard failure
		// rather than a silent success so that serving a third intent from here would be visible.
		return "", nil, fmt.Errorf("apply-updates: %s is not an update intent", name)
	}
}

// runUpdate invokes the program that applies the updates for one intent.
func runUpdate(ctx context.Context, name intent.Name) (*run.Result, error) {
	program, args, err := updateCommand(name)
	if err != nil {
		return nil, err
	}
	return run.CommandWith(ctx, run.Options{Timeout: updateTimeout, Env: updateEnv()}, program, args...)
}

// rebootIfRequired reboots the host when the update left it needing one and policy still permits it.
//
// The policy file is read again rather than reused from the decision at the top of the job. That is the
// rule this package works by — act on what the file says now, not on what it said when a long-running
// process started — and it matters most here: forty minutes of dpkg is long enough for a maintenance
// window to close and long enough for an administrator to have changed their mind and edited the file.
//
// A refusal at this point is reported as a failure rather than a success with a note. The job asked for
// two things; one of them did not happen, and a host that is patched but still running the replaced
// libraries is exactly the state an operator must not be told is finished.
func rebootIfRequired(ctx context.Context, jobID string) (string, error) {
	plat, _, err := platform.Detect()
	if err != nil {
		return "", fmt.Errorf("apply-updates: the updates were applied, but this host could not be "+
			"identified to decide whether it needs a reboot: %w", err)
	}
	status, err := plat.RebootRequired(ctx)
	if err != nil {
		// Degraded rather than fatal on its own: RebootRequired returns a usable report alongside its
		// error. Whether that report can be acted on is the next check's business, not this one's.
		fmt.Fprintf(os.Stderr, "farrier-helper: reading the reboot signal: %v\n", err)
	}

	// "No reboot is needed" and "nothing here can tell me whether one is needed" both arrive as
	// Required=false, and the second is the common case on a Debian host: the marker file is an Ubuntu
	// update-notifier convention, needrestart is a Recommends rather than a Depends, and an install
	// with --no-install-recommends has neither. Reporting that host as finished after a kernel upgrade
	// would leave it running the replaced kernel with a green job beside it — which is precisely the
	// silent wrong answer the whole platform seam exists to prevent, and it must not be reintroduced
	// here at the end of it.
	if !status.Conclusive {
		return "", fmt.Errorf("apply-updates: the updates were applied, but nothing on this host can "+
			"say whether they left it needing a reboot (%s), and the job asked for one if they did. "+
			"Reporting that as finished would be a guess. Install needrestart: on Debian it is the "+
			"only reliable signal", status.Source)
	}
	if !status.Required {
		return "no reboot was required (" + status.Source + ")", nil
	}

	p, loadErr := policy.Load()
	if loadErr != nil && !errors.Is(loadErr, policy.ErrNoPolicyFile) {
		return "", fmt.Errorf("apply-updates: the updates were applied, but the policy could not be "+
			"re-read to authorise the follow-up reboot: %w", loadErr)
	}
	_, rebootParams, err := intent.Decode(intent.HostReboot, []byte(`{}`))
	if err != nil {
		return "", fmt.Errorf("apply-updates: building the follow-up reboot request: %w", err)
	}
	decision := policy.Decide(p, policy.Request{Intent: intent.HostReboot, Params: rebootParams},
		policy.Env{Now: time.Now(), Paused: policy.Paused()})
	if !decision.Allowed {
		return "", fmt.Errorf("apply-updates: the updates were applied and this host now needs a "+
			"reboot, which local policy refuses: %w", decision.Error())
	}

	// "--" for the same reason helpers/reboot-host uses it: the message is a positional argument and
	// shutdown(8) would read a leading hyphen there as an option. This message is a constant and cannot
	// begin with one, so nothing is wrong here today — the separator is present so that the safe form is
	// what the next person copies.
	res, err := run.Command(ctx, run.Shutdown, "-r", "--", "now",
		"farrier: rebooting after applying updates")
	if err != nil {
		return commandOutput(res), fmt.Errorf("apply-updates: the updates were applied but the "+
			"reboot could not be scheduled: %w", err)
	}
	return fmt.Sprintf("a reboot was required and has been scheduled (job %s)\n%s",
		jobID, commandOutput(res)), nil
}

// commandOutput renders a command result as the text to report, stderr after stdout.
//
// Both halves are kept: apt writes progress to stdout and warnings to stderr, and the warning is
// usually the interesting one — a held-back package, a mirror that timed out, a conffile decision.
func commandOutput(res *run.Result) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	b.Write(res.Stdout)
	if len(res.Stderr) > 0 {
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteString("\n")
		}
		b.Write(res.Stderr)
	}
	return b.String()
}

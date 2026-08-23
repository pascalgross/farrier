// Command reboot-host is the root helper that reboots the machine, subject to local policy.
//
// It is installed as /usr/libexec/farrier/reboot-host and is reachable from the agent only through the
// socket its unit is activated on, /run/farrier/reboot-host.sock, which is owned root:farrier and mode
// 0660. See internal/privsep for why that replaced sudo.
//
// Two policy settings must both hold: updates.reboot must be "window", and the current local time must
// fall inside the configured maintenance window. Both are read from the root-owned file, here, as root,
// on this invocation — not from anything the agent passed in.
//
// The agent is responsible for the other half of a reboot working at all: the job's result must be
// fsynced to /var/lib/farrier/pending-results before this helper is invoked, because the job completes
// by the host disappearing and the naive ordering reports nothing at all. See docs/PROTOCOL.md §6.2.
package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/pascalgross/farrier/internal/buildinfo"
	"github.com/pascalgross/farrier/internal/helper"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/privsep"
	"github.com/pascalgross/farrier/internal/run"
)

// main parses the fixed command line and either answers the socket or performs one reboot.
func main() {
	var (
		delay    = flag.Int("delay-seconds", 0, "seconds to wait before rebooting, 0 to 3600")
		message  = flag.String("message", "", "wall message shown to logged-in users")
		jobID    = flag.String("job-id", "", "control-plane job id, recorded in the audit log")
		issuedAt = flag.String("issued-at", "", "RFC 3339 time the job was issued")
		serve    = flag.Bool("serve", false, "answer one request from the socket systemd activated")
		dryRun   = flag.Bool("dry-run", false, "evaluate policy and print the decision, changing nothing")
		version  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Println("farrier reboot-host " + buildinfo.String())
		return
	}
	if flag.NArg() > 0 {
		helper.Fatalf(helper.ExitUsage, "takes no positional arguments, got %q", flag.Args())
	}
	helper.SetupLogging("reboot-host")

	h := helper.Helper{
		Component: "reboot-host",
		Socket:    privsep.RebootHostSocket,
		Execute:   reboot,
	}
	if *serve {
		h.Serve()
		return
	}

	h.Main(helper.Request{
		JobID:  *jobID,
		Intent: intent.HostReboot,
		Params: helper.ParamsJSON(map[string]any{
			"delaySeconds": *delay,
			"message":      *message,
		}),
		IssuedAt: helper.ParseIssuedAt(*issuedAt),
	}, *dryRun)
}

// rebootArgs builds the exact argument vector one reboot invokes shutdown(8) with.
//
// Separated from reboot so it can be asserted, because the property worth pinning is not observable
// once the process has been started: the "--" is the whole point of this function and a maintainer
// tidying the slice would remove it without any test noticing.
//
// That separator matters because the message is a positional argument and shutdown(8)'s options are
// anything but harmless in that slot. "-h" is poweroff and overrides "-r", so the host does not come
// back and needs a console. "-k" sends the wall message and reboots nothing — a reboot job that
// reports success and did not happen, which is the same silent wrong answer the platform seam exists
// to prevent, arriving at a different point. "-c" cancels a shutdown already pending.
//
// internal/intent already refuses a message beginning with a hyphen, and that is the defence that
// should hold. This is the second one, kept because it is this call site that would be wrong if the
// first were ever relaxed, and because "--" costs nothing.
func rebootArgs(params intent.RebootParams) []string {
	args := []string{"-r", "--", shutdownTime(params.DelaySeconds)}
	if params.Message != "" {
		args = append(args, params.Message)
	}
	return args
}

// reboot schedules the reboot described by the validated parameters.
//
// The delay and the message come from job.Params rather than from the flags, so the values reaching
// shutdown(8) are the ones the catalogue's validators accepted, and that is only worth having if this
// is where the value comes from.
//
// It returns as soon as the reboot is scheduled. The host going away is what completes the job, which
// is why the agent fsyncs a provisional result before invoking this at all.
func reboot(ctx context.Context, job helper.Job) (string, error) {
	params, ok := job.Params.(intent.RebootParams)
	if !ok {
		return "", fmt.Errorf("reboot-host: %s did not decode to reboot parameters", job.Intent)
	}

	res, err := run.Command(ctx, run.Shutdown, rebootArgs(params)...)
	when := shutdownTime(params.DelaySeconds)
	if err != nil {
		return output(res), fmt.Errorf("reboot-host: scheduling a reboot for %s: %w", when, err)
	}
	note := fmt.Sprintf("reboot scheduled for %s", when)
	if params.Message != "" {
		note += fmt.Sprintf(" with the wall message %q", params.Message)
	}
	// Said out loud whenever shutdown's minute granularity moved the time, so that an operator
	// staggering a batch reads the difference in the job result rather than discovering it from a
	// timestamp weeks later.
	if rounded := params.DelaySeconds % 60; params.DelaySeconds > 0 && rounded != 0 {
		note += fmt.Sprintf(" (%ds was asked for; shutdown(8) has no seconds, so it was rounded up)",
			params.DelaySeconds)
	}
	return strings.TrimSpace(note + "\n" + output(res)), nil
}

// shutdownTime renders a delay in seconds as a time specification shutdown(8) understands.
//
// shutdown takes "now", "+m" in whole minutes, or "hh:mm"; it has no seconds. The catalogue accepts a
// delay in seconds because staggering a signed batch across a group is what the parameter is for, so
// something has to give, and the direction it gives in matters: this rounds **up**, so a host never
// reboots earlier than the operator authorised. Rounding down would take a machine away before the
// person who signed for it expected, which is the one error here that cannot be undone.
//
// The rounding is stated in the job's output rather than left for somebody to discover, because a
// thirty-second stagger silently becoming a one-minute one is exactly the kind of quiet difference this
// project tries not to ship.
func shutdownTime(delaySeconds int) string {
	if delaySeconds <= 0 {
		return "now"
	}
	minutes := (delaySeconds + 59) / 60
	return "+" + strconv.Itoa(minutes)
}

// output renders a command result as the text to report, stderr after stdout.
//
// Both halves are kept because shutdown(8) writes its confirmation to stderr on some releases and to
// stdout on others, and a helper that reported only one of them would be silent on exactly the machine
// somebody was trying to debug.
func output(res *run.Result) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	b.Write(res.Stdout)
	if len(res.Stderr) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.Write(res.Stderr)
	}
	return strings.TrimSpace(b.String())
}

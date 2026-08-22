// Command reboot-host is the root helper that reboots the machine, subject to local policy.
//
// It is installed as /usr/libexec/farrier/reboot-host and is reachable from the agent only through the
// fixed-argv entry in /etc/sudoers.d/farrier.
//
// Two policy settings must both hold: updates.reboot must be "window", and the current local time must
// fall inside the configured maintenance window. Both are read from the root-owned file, here, as
// root, on this invocation — not from anything the agent passed in.
//
// The agent is responsible for the other half of a reboot working at all: the job's result must be
// fsynced to /var/lib/farrier/pending-results before this helper is invoked, because the job completes
// by the host disappearing and the naive ordering reports nothing at all. See docs/PROTOCOL.md §6.2.
//
// Phase 0 ships no write capability: the authorisation sequence is complete and the execution is
// absent.
package main

import (
	"flag"
	"fmt"

	"github.com/pegasusnetworks/farrier/internal/buildinfo"
	"github.com/pegasusnetworks/farrier/internal/helper"
	"github.com/pegasusnetworks/farrier/internal/intent"
)

// main parses the fixed command line, enforces local policy, and would then reboot the host.
func main() {
	var (
		delay    = flag.Int("delay-seconds", 0, "seconds to wait before rebooting, 0 to 3600")
		message  = flag.String("message", "", "wall message shown to logged-in users")
		jobID    = flag.String("job-id", "", "control-plane job id, recorded in the audit log")
		issuedAt = flag.String("issued-at", "", "RFC 3339 time the job was issued")
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

	params := helper.Dispatch(helper.Request{
		JobID:  *jobID,
		Intent: intent.HostReboot,
		Params: helper.ParamsJSON(map[string]any{
			"delaySeconds": *delay,
			"message":      *message,
		}),
		IssuedAt: helper.ParseIssuedAt(*issuedAt),
	}, *dryRun)

	// Phase 1 replaces this with an absolute-path invocation of the distribution's shutdown binary,
	// with the delay and message taken from the decoded params rather than from the flags.
	helper.Fatalf(helper.ExitNotImplemented,
		"this build has no reboot executor: phase 0 ships no write capability. "+
			"Local policy permitted %q; nothing was changed.", params.Describe())
}

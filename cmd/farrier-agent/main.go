// Command farrier-agent is the Farrier agent that runs on a managed Ubuntu or Debian host.
//
// It connects outbound to a control plane and never listens. There is no server-to-agent direction in
// the protocol at all: every byte moves on a connection this process opened, which is why a managed
// host needs no inbound firewall rule and why putting the fleet behind a VPN buys nothing. See
// docs/PROTOCOL.md.
//
// The agent holds no privilege. It runs as the farrier user with an empty capability bounding set
// under the hardened unit in packaging/farrier-agent.service; the three helpers in /usr/libexec/farrier
// are the only privileged operations that exist, and each re-enforces the root-owned policy itself.
//
// Phase 0 ships no write capability. This binary reports what it can see and does not change anything.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pegasusnetworks/farrier/internal/buildinfo"
	"github.com/pegasusnetworks/farrier/internal/intent"
	"github.com/pegasusnetworks/farrier/internal/policy"
)

// StateDir is where the agent keeps everything it writes.
//
// It is the only writable location the systemd unit grants, which is deliberate: an agent that can
// write nowhere else cannot be talked into leaving something behind in a directory that matters.
const StateDir = "/var/lib/farrier"

// usage prints the command list.
//
// It is written out rather than generated because the agent's surface is meant to stay small enough to
// list, and a help text that grows without anyone noticing is the first sign that it has not.
func usage() {
	fmt.Fprintf(os.Stderr, `farrier-agent %s

usage:
  farrier-agent run             run the agent in the foreground, as systemd does
  farrier-agent policy check    validate /etc/farrier/policy.toml and print the effective policy
  farrier-agent version         print the version

The agent connects outbound only. It has no listening port and no server-to-agent channel.
`, buildinfo.String())
}

// main dispatches to a subcommand.
func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "run":
		os.Exit(run(args[1:]))
	case "policy":
		os.Exit(policyCommand(args[1:]))
	case "version":
		fmt.Println("farrier-agent " + buildinfo.String())
	default:
		fmt.Fprintf(os.Stderr, "farrier-agent: unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
}

// setupLogging configures structured logging to stderr, which systemd routes to the journal.
//
// The agent logs JSON for the same reason the helpers do: what an operator needs six months after an
// incident is a machine-readable trail of what was asked, what was decided and why, and grepping that
// out of prose does not work.
func setupLogging() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With(
		"component", "agent",
		"version", buildinfo.Version,
		"commit", buildinfo.Revision(),
	))
}

// run starts the agent and blocks until it is asked to stop.
//
// Phase 0 has nothing to poll for, so the loop reports the host's local configuration and then idles.
// It exists in this shape now so that the process lifecycle — signal handling, structured logging,
// clean shutdown — is exercised by the packaging tests before there is any protocol traffic to confuse
// a failure with.
func run(argv []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	policyPath := fs.String("policy", policy.Path, "policy file to read")
	interval := fs.Duration("report-interval", 15*time.Minute, "how often to re-read and report local state")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	setupLogging()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("farrier agent starting",
		"version", buildinfo.Version,
		"commit", buildinfo.Revision(),
		"state_dir", StateDir,
		"intents", len(intent.Names()),
		"write_capability", false,
	)
	slog.Info("hello from farrier-agent: this build reports and changes nothing")

	reportState(*policyPath)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("farrier agent stopping")
			return 0
		case <-ticker.C:
			reportState(*policyPath)
		}
	}
}

// reportState logs the host's effective local configuration.
//
// It re-reads the policy on every call rather than caching it, because an administrator who edits
// policy.toml expects the change to take effect without restarting a service, and because the same
// re-read discipline is what the root helpers rely on.
func reportState(policyPath string) {
	p, err := policy.LoadFrom(policyPath)
	switch {
	case errors.Is(err, policy.ErrNoPolicyFile):
		slog.Warn("no policy file; using the built-in default", "path", policyPath)
	case err != nil:
		slog.Error("policy could not be read; this host will refuse all privileged work",
			"path", policyPath, "error", err)
	}

	slog.Info("effective local policy",
		"source", p.Source(),
		"updates_allow", p.Updates.Allow,
		"auto_apply", p.Updates.AutoApply,
		"window", p.Window().String(),
		"timezone", p.Updates.Timezone,
		"reboot", p.Updates.Reboot,
		"restartable", p.Services.Restartable,
		"max_job_age_seconds", p.Limits.MaxJobAgeSeconds,
		"paused", policy.Paused(),
	)
}

// policyCommand implements `farrier-agent policy check`.
//
// It exists so that an administrator can validate an edit before restarting anything. A policy file
// that does not parse causes the host to refuse all privileged work rather than fall back to a
// default, which is the right behaviour and a miserable way to discover a typo.
func policyCommand(argv []string) int {
	if len(argv) == 0 || argv[0] != "check" {
		fmt.Fprintln(os.Stderr, "usage: farrier-agent policy check [--policy PATH]")
		return 2
	}
	fs := flag.NewFlagSet("policy check", flag.ExitOnError)
	policyPath := fs.String("policy", policy.Path, "policy file to validate")
	if err := fs.Parse(argv[1:]); err != nil {
		return 2
	}

	p, err := policy.LoadFrom(*policyPath)
	if errors.Is(err, policy.ErrNoPolicyFile) {
		fmt.Printf("no policy file at %s; the built-in default would be used:\n", *policyPath)
		err = nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s is not valid: %v\n", *policyPath, err)
		fmt.Fprintln(os.Stderr, "this host would refuse all privileged work until it is fixed")
		return 1
	}

	fmt.Printf("source              %s\n", p.Source())
	fmt.Printf("updates.allow       %s\n", p.Updates.Allow)
	fmt.Printf("updates.auto_apply  %t\n", p.Updates.AutoApply)
	fmt.Printf("updates.window      %s (%s)\n", p.Window(), p.Updates.Timezone)
	fmt.Printf("updates.reboot      %s\n", p.Updates.Reboot)
	fmt.Printf("services.restartable %v\n", p.Services.Restartable)
	fmt.Printf("limits.max_job_age_seconds %d\n", p.Limits.MaxJobAgeSeconds)
	fmt.Printf("paused              %t\n", policy.Paused())
	if !p.Window().Always() {
		fmt.Printf("window next opens   %s\n", p.Window().NextOpen(time.Now()).Format(time.RFC3339))
	}
	return 0
}

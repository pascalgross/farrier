package collect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/pascalgross/farrier/internal/policy"
)

// KernelReleasePath is where the running kernel version can be read without executing anything.
//
// Reading a file rather than running uname is deliberate: it is one fewer process to start from a
// service that is meant to start as few as possible, and it works under a seccomp filter that would
// make an exec awkward.
const KernelReleasePath = "/proc/sys/kernel/osrelease"

// Gather collects every fact a heartbeat carries, including any registered collectors.
//
// The collectors are passed in rather than read from a registry here, because the registry package must
// import this one for its types and the cycle would be real. The agent supplies collector.All().
//
// The local policy is passed in for the same reason it is passed to everything else that acts on this
// host: there is one policy in force at a time, read once, and a caller that loaded its own would be
// enforcing a different one. It bounds what is *reported* rather than what may be done — see
// PolicyGated — and a section the policy refuses is absent rather than empty.
//
// Partial failure is normal and is handled rather than propagated. A host where needrestart is missing,
// or where apt is momentarily locked by the distribution's own timer, still has a hostname, a kernel
// and a unit list worth reporting — and an agent that returned an error instead would remove exactly
// the host an operator most wants to look at from the fleet list. Every failure is logged with enough
// detail to act on and recorded in the affected section.
func Gather(ctx context.Context, p Platform, local policy.Policy, extra ...Collector) (Facts, error) {
	dist, err := p.Identify()
	if err != nil {
		// Identity is the one fact with no useful degraded form: without it the server cannot decide
		// what the host is or which numbers mean what.
		return Facts{}, err
	}

	facts := Facts{
		Distribution: dist,
		Hostname:     hostname(),
		Kernel:       p.KernelRelease(),
		Architecture: runtime.GOARCH,
	}

	if packages, err := upgradablePackages(ctx, p, local); err != nil {
		// Marked rather than left zero. The zero PackageReport serialises as "no updates pending",
		// which is a claim this host is in no position to make: the commonest reason to be here is
		// that another process held the apt lock, and on Windows it is a host whose own policy declines
		// the scan. See PackageReport.Incomplete.
		slog.Warn("could not list upgradable packages", "error", err)
		facts.Packages = PackageReport{Incomplete: true}
	} else {
		facts.Packages = Summarise(packages)
	}

	if reboot, err := p.RebootRequired(ctx); err != nil {
		slog.Warn("reboot check was incomplete", "error", err)
		facts.Reboot = reboot
	} else {
		facts.Reboot = reboot
	}

	switch sub, err := p.SubscriptionStatus(ctx); {
	case err != nil:
		slog.Warn("could not read subscription status", "error", err)
		facts.Subscription = Subscription{Applicable: true, Note: "status could not be read"}
	case sub == nil:
		// nil means the concept does not exist on this platform. It is rendered as "not applicable",
		// never as "unknown": a Debian host wearing a permanent amber ESM badge teaches its operator
		// to ignore the dashboard.
		facts.Subscription = Subscription{Applicable: false}
	default:
		facts.Subscription = *sub
	}

	if units, truncated, err := p.Services(ctx); err != nil {
		slog.Warn("could not list services", "error", err)
	} else {
		facts.Services = units
		facts.ServicesTruncated = truncated
	}

	for _, c := range extra {
		if gated, ok := c.(PolicyGated); ok && !gated.PermittedBy(local) {
			// Withheld, not failed. The host's own policy travels in the same heartbeat, so the
			// control plane can tell "this host does not report that" from "that collector broke"
			// without a log line on every cycle saying so.
			slog.Debug("a collector's section is withheld by local policy",
				"collector", c.Name(), "policy", local.Source())
			continue
		}
		section, err := c.Collect(ctx)
		if err != nil {
			// Absent rather than present-and-empty. A missing section is visibly missing; an empty one
			// reads as an answer, and "no network interfaces" is a very different claim from "the
			// network collector failed".
			slog.Warn("a collector failed; its section is absent from this report",
				"collector", c.Name(), "error", err)
			continue
		}
		if facts.Extra == nil {
			facts.Extra = map[string]any{}
		}
		facts.Extra[c.Name()] = section
	}

	return facts, nil
}

// upgradablePackages asks the platform for its pending updates, unless local policy refuses.
//
// It exists so that Gather reads as one sequence of questions rather than growing a branch for a
// platform it should not know about. The refusal is expressed as an error for the same reason a failed
// scan is: both mean the numbers are not an answer, both must reach the wire as PackageReport.Incomplete
// rather than as zero pending, and a caller made to tell them apart is a caller that could get it wrong.
//
// A platform that does not implement PolicyGatedPackages is asked nothing, which is what keeps this from
// being a change to the Linux agent: Ubuntu and Debian reach p.UpgradablePackages exactly as before.
func upgradablePackages(ctx context.Context, p Platform, local policy.Policy) ([]Package, error) {
	if gated, ok := p.(PolicyGatedPackages); ok {
		if permitted, why := gated.PackagesPermittedBy(local); !permitted {
			return nil, fmt.Errorf("local policy refuses it: %s (%s)", why, local.Source())
		}
	}
	return p.UpgradablePackages(ctx)
}

// hostname returns the host's name, or "unknown" if it cannot be read.
//
// It never fails, because a heartbeat with an odd hostname is far more useful than no heartbeat, and
// the host is identified by its certificate rather than by this string anyway.
func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "unknown"
	}
	return name
}

// KernelRelease reads the running kernel version from KernelReleasePath.
//
// It is exported so that the Linux platform implementations share one reader rather than two, and it
// lives here rather than in that package because the path it reads is declared here beside it. It never
// fails: a heartbeat carrying "unknown" is worth more than no heartbeat, and nothing downstream treats
// this string as anything but display.
func KernelRelease() string {
	raw, err := os.ReadFile(KernelReleasePath)
	if errors.Is(err, os.ErrNotExist) || err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(raw))
}

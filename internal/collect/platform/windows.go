//go:build windows

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/pascalgross/farrier/internal/collect"
	"github.com/pascalgross/farrier/internal/policy"
	"github.com/pascalgross/farrier/internal/run"
	"github.com/pascalgross/farrier/internal/updatescan"
	"github.com/pascalgross/farrier/internal/winapi"
)

// Windows implements collect.Platform for the Windows Server releases in standard support.
//
// What it does about the four silent-wrong-answer traps this package's documentation names, and about
// the two more that are specific to this platform:
//
//  1. Security origins. Windows has none. There is no archive a package comes from and nothing to
//     match against, so the security classification is made from the update's own Security Updates
//     category — matched by its stable CategoryID rather than its localised display name, because a
//     German host reports "Sicherheitsupdates" and a classifier keyed on English would report every
//     security update there as ordinary. SecurityOrigins returns nil rather than an invented pattern.
//  2. Reboot marker. Four independent registry signals are consulted rather than one, because each is
//     complete only on the hosts where it happens to be right. The answer is always conclusive: every
//     source is a registry read this account can perform, so an absent key is an answer rather than a
//     failure to look.
//  3. Subscription. The concept does not exist, so SubscriptionStatus returns nil and the UI renders
//     "not applicable" — never "unknown", which would put a permanent amber badge on every Windows host
//     and teach operators to ignore the dashboard, exactly as it would on Debian.
//  4. apt-check. No analogue, and nothing is guessed in its place. Where the scan cannot run, the report
//     is marked incomplete rather than reported as zero pending.
//
// And two that only exist here:
//
//  5. GetVersionEx lies. An executable without the right application-manifest entries is told it is
//     running on Windows 8, whatever it is really on. Identify uses RtlGetVersion, which is not shimmed.
//  6. The service list is silently short. EnumServicesStatusEx omits services the caller cannot query
//     rather than failing, so a hardened host would report a clean subset as though it were everything.
//     Services reports the truncation flag the seam already carries.
type Windows struct {
	// mu guards the cached scan below. Gather is called from the heartbeat loop and a job can run
	// concurrently with it, so two scans could otherwise start at once — which Windows Update serialises
	// anyway, leaving the second waiting minutes for the first.
	mu sync.Mutex

	// scanned is when the cached result was produced, zero if there is none.
	scanned time.Time

	// cached is the last successful scan.
	//
	// It exists because Gather calls UpgradablePackages on every full heartbeat, and on Linux that is
	// free — `apt-get --just-print` is local and takes milliseconds. On Windows it is a network
	// conversation measured in minutes, so an uncached implementation would leave a host scanning
	// continuously and reporting facts almost never. Caching is what makes the same seam affordable on
	// both platforms without the heartbeat learning which one it is talking to.
	cached []collect.Package
}

// Identify reports which release of Windows this is.
func (w *Windows) Identify() (collect.Distribution, error) {
	v, err := winapi.OSVersion()
	if err != nil {
		return collect.Distribution{}, fmt.Errorf("platform: identifying this Windows host: %w", err)
	}
	release, supported := v.Release()
	return collect.Distribution{
		ID:     "windows",
		Family: collect.FamilyWindows,
		// No codename. Distribution.String falls back to "${id} ${version} (${codename})" when
		// PrettyName is empty, so PrettyName is always populated below — a host that left it empty would
		// appear in the fleet list as "windows 2022 ()".
		Version:    release,
		PrettyName: v.PrettyName(),
		Supported:  supported,
	}, nil
}

// SecurityOrigins reports that Windows has no origin concept.
//
// nil rather than an empty slice, and rather than an invented pattern. The Linux implementations return
// the unattended-upgrades patterns so that an operator can see which origins their host treats as
// security; there is nothing equivalent to show here, and a plausible-looking string would suggest a
// mechanism that does not exist.
func (w *Windows) SecurityOrigins() []string { return nil }

// KernelRelease returns the operating-system build, such as "10.0.20348.4648".
func (w *Windows) KernelRelease() string { return winapi.KernelRelease() }

// SubscriptionStatus reports that Ubuntu Pro does not exist here.
func (w *Windows) SubscriptionStatus(context.Context) (*collect.Subscription, error) { return nil, nil }

// Services reports Windows service state, and whether the list was cut short.
func (w *Windows) Services(context.Context) ([]collect.Unit, bool, error) {
	services, truncated, err := winapi.ListServices()
	if err != nil {
		return nil, false, err
	}
	units := make([]collect.Unit, 0, len(services))
	for _, s := range services {
		units = append(units, collect.Unit{
			Name: s.Name,
			// The display name, which is what an operator recognises in services.msc. The service's own
			// long description is a second query per service and says less.
			Description: s.DisplayName,
			// LoadState carries the start type. The mapping is an overload of a systemd-shaped field and
			// is deliberate: renaming these three fields would be a wire-format change reaching the
			// server, the store and the Angular app, to express something the values already say. What
			// the field means on Windows is documented in docs/PROTOCOL.md §4.2 rather than left for a
			// reader to infer from "auto" appearing where "loaded" was expected.
			LoadState: s.StartType,
			// ActiveState is the coarse answer a fleet list sorts on. Only "running" is active; every
			// pending state is reported as inactive, because a service that is still starting is not one
			// an operator should read as up.
			ActiveState: activeState(s.State),
			// SubState is the precise state, which is where "start-pending" survives.
			SubState: s.State,
		})
	}
	return units, truncated, nil
}

// activeState reduces a Windows service state to the three words systemd's ActiveState uses.
//
// Windows has no "failed" state: a service that died is simply stopped, and the distinction lives in the
// SCM's failure-action configuration and the event log rather than in the status. Reporting "failed" for
// anything would be inventing a fact, so this returns only active and inactive — and SubState carries
// the detail that was reduced away.
func activeState(state string) string {
	if state == "running" {
		return "active"
	}
	return "inactive"
}

// RebootRequired reports whether Windows believes a restart is outstanding, and why.
//
// ServiceScanComplete is false and always will be, and that is the honest answer rather than a missing
// feature. Its Linux meaning is "needrestart could see every process", and the question needrestart asks
// — which running services still hold libraries that have already been replaced on disk — cannot arise
// on Windows at all: a file mapped by a running process cannot be replaced, so an installer defers the
// swap to boot with MoveFileEx. Reporting true would claim a scan happened and found nothing.
func (w *Windows) RebootRequired(context.Context) (collect.RebootReport, error) {
	signals, err := winapi.RebootPending()
	if err != nil {
		return collect.RebootReport{Conclusive: false}, err
	}
	report := collect.RebootReport{
		Required:   len(signals) > 0,
		Conclusive: true,
	}
	for _, s := range signals {
		reason := s.Reason
		if s.Stale {
			reason += " (this signal can outlive the restart that should clear it)"
		}
		report.Reasons = append(report.Reasons, reason)
	}
	if len(report.Reasons) > collect.MaxRebootReasons {
		report.Reasons = report.Reasons[:collect.MaxRebootReasons]
		report.ReasonsTruncated = true
	}
	return report, nil
}

// UpgradablePackages lists the updates Windows Update reports as pending.
//
// It starts farrier-update-scan and reads one JSON document from its output, which is the same shape the
// Linux implementations use with apt-get: ask a program, parse what comes back, never reach into the
// platform's own state. Here the separation carries more weight than convenience — enumerating updates
// means loading wuapi.dll, and docs/SECURITY.md §3 refuses a runtime code loader in the process holding
// the host's mTLS private key. See internal/wua.
//
// A scan that did not complete is returned as an error, so that Gather marks the report incomplete
// rather than reporting zero pending. That distinction is the whole reason PackageReport.Incomplete
// exists, and it is the direction a fleet-health reader must never be wrong in.
func (w *Windows) UpgradablePackages(ctx context.Context) ([]collect.Package, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// A recent answer is reused rather than asked for again. Windows Update does not change its own
	// answer more often than this, and the alternative is a host that spends most of its life scanning:
	// Gather runs on every full heartbeat, and a scan takes minutes.
	if !w.scanned.IsZero() && time.Since(w.scanned) < minScanInterval && w.cached != nil {
		return w.cached, nil
	}

	res, err := run.CommandWith(ctx, run.Options{Timeout: scanTimeout}, run.UpdateScan)
	if err != nil {
		return nil, fmt.Errorf("platform: running the update scan: %w", err)
	}

	var result updatescan.ScanResult
	if err := json.Unmarshal(res.Stdout, &result); err != nil {
		return nil, fmt.Errorf("platform: the update scan produced no usable result: %w", err)
	}
	if !result.Complete {
		reason := result.Error
		if reason == "" {
			reason = "the scan did not say why"
		}
		return nil, fmt.Errorf("platform: the update scan did not complete: %s", reason)
	}

	packages := make([]collect.Package, 0, len(result.Updates))
	for _, u := range result.Updates {
		packages = append(packages, collect.Package{
			// The title, because that is what an operator recognises and searches for. It is not a
			// package name in apt's sense, and Windows has no equivalent of one.
			Name: u.Title,
			// The KB article identifies the specific update, which is the closest thing to a candidate
			// version. Empty where Windows Update reported none, which happens for definition updates.
			CandidateVersion: u.KB,
			// Categories stand in for apt's release origins, and are reported for the same reason: the
			// classification decides the security count, so an operator has to be able to see what the
			// classification actually was rather than only its conclusion.
			Origins:  u.Categories,
			Security: u.Security,
		})
	}

	w.cached = packages
	w.scanned = time.Now()
	return packages, nil
}

// minScanInterval is how often this host will actually ask Windows Update what is pending.
//
// Six hours, and the number is chosen from what the answer is worth rather than from what the API can
// stand. Windows Update's own default detection cadence is measured in hours; a fleet dashboard that is
// six hours stale on patch counts is telling an operator the same thing a fresh one would, and a host
// that scanned on every heartbeat would spend most of its life scanning and report facts almost never.
//
// It is a constant rather than a policy key on purpose. A key would be a second thing to get wrong, and
// the decision it would express — how stale a patch count may be — is not one that differs usefully
// between hosts. The key that does exist, [updates] scan, answers the question that does: whether this
// host performs the scan at all.
//
// The cache lives in memory, so an agent restart costs one scan. That is the right trade: persisting it
// would mean a file the agent writes and later trusts, and a stale count surviving a reboot is a worse
// failure than an extra scan after one.
const minScanInterval = 6 * time.Hour

// PackagesPermittedBy reports whether local policy lets this host enumerate its updates.
//
// This is the knob docs/SECURITY.md §12.4 requires. On Linux the same question is `apt-get --just-print`
// and no host has ever needed a way to refuse it; here it is a network conversation that mutates state
// under %windir% and takes minutes, which makes it privileged work wearing a read class. Without a local
// refusal, a control plane holding nothing but mTLS could drive every Windows host into a continuous
// scan loop, and the host would have been given no policy to exceed.
func (w *Windows) PackagesPermittedBy(p policy.Policy) (bool, string) {
	if p.Updates.Scan {
		return true, ""
	}
	return false, "[updates] scan is false, so this host does not run a Windows Update scan"
}

// scanTimeout bounds how long the update scan may take.
//
// Twenty minutes, and it is chosen for the worst realistic case rather than the common one. An online
// Windows Update scan is minutes of work on a healthy host and considerably more on one that has not
// been patched for a year or is talking to a distant WSUS server; Microsoft's own documentation warns
// that a scan may need more memory than a small machine has spare. A bound that expired during a real
// scan would report a host as unmeasurable every cycle, which is worse than a slow answer — and unlike
// an interrupted apt run, an abandoned scan leaves nothing half-applied.
const scanTimeout = 20 * time.Minute

// Detect returns the Windows platform implementation.
//
// It takes no os-release path and consults no file: a Windows host is identified by asking the kernel,
// and there is only one implementation to return. The distribution is read here rather than lazily so
// that a host whose version cannot be read fails at start-up with an error naming the reason, rather
// than reporting facts with an empty operating system in them.
func Detect() (collect.Platform, collect.Distribution, error) {
	p := &Windows{}
	dist, err := p.Identify()
	if err != nil {
		return nil, collect.Distribution{}, err
	}
	return p, dist, nil
}

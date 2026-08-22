package platform

import (
	"context"
	"fmt"
	"strings"

	"github.com/pascalgross/farrier/internal/collect"
)

// Debian implements collect.Platform for Debian stable and oldstable.
//
// What it does about the four silent-wrong-answer traps:
//
//  1. Security origins. Debian does not mark security updates by archive suffix alone the way Ubuntu
//     does: the authoritative signal is the origin label "Debian-Security", which is what
//     unattended-upgrades matches on with origin=Debian,codename=${distro_codename}-security. The
//     archive suffix is accepted as well, because both "stable-security" and "bookworm-security" appear
//     in the wild depending on how sources.list was written. Matching on only the suffix would miss
//     security updates whose archive is named after the suite; matching on only the label would miss
//     mirrors that relabel. Both are checked.
//  2. Reboot marker. /var/run/reboot-required is an Ubuntu convention and is usually absent here, so
//     needrestart is the reliable source. The marker is still read, because a Debian host with
//     update-notifier-common installed does set it, but it is never the only input.
//  3. Ubuntu Pro. It does not exist. SubscriptionStatus returns nil, meaning "not applicable", so that
//     clients render that rather than "unknown" — a Debian host carrying a permanent amber ESM warning
//     teaches its operator to ignore the dashboard, which costs more than the warning was ever worth.
//  4. apt-check. Not used, same as Ubuntu; the simulation parse is the only path.
type Debian struct {
	// dist is the distribution this instance was built for.
	dist collect.Distribution
}

// Identify reports which distribution this is.
func (d *Debian) Identify() (collect.Distribution, error) { return d.dist, nil }

// SecurityOrigins returns the unattended-upgrades origin patterns for Debian.
//
// The form differs from Ubuntu's: Debian's unattended-upgrades configuration uses Origins-Pattern with
// origin and codename keys rather than the ${distro_id}:${distro_codename} shorthand. Rendering the
// Ubuntu form into a Debian host's configuration produces a file that parses and matches nothing.
func (d *Debian) SecurityOrigins() []string {
	return []string{
		"origin=Debian,codename=${distro_codename}-security,label=Debian-Security",
		"origin=Debian,codename=${distro_codename},label=Debian",
	}
}

// isSecurityRelease reports whether an apt release string names a Debian security archive.
func (d *Debian) isSecurityRelease(release string) bool {
	label, archive := splitRelease(release)
	if strings.EqualFold(label, "Debian-Security") {
		return true
	}
	return strings.HasSuffix(archive, "-security")
}

// UpgradablePackages lists pending updates with the security ones marked.
func (d *Debian) UpgradablePackages(ctx context.Context) ([]collect.Package, error) {
	out, err := collect.SimulateUpgrade(ctx)
	if err != nil {
		return nil, err
	}
	return collect.ParseSimulation(out, d.isSecurityRelease), nil
}

// RebootRequired reports whether the host needs a reboot and why.
//
// needrestart carries the weight here. Where Ubuntu's marker file is authoritative and needrestart adds
// detail, on Debian the marker is usually absent and needrestart is the answer — so a needrestart
// failure is reported as an error rather than swallowed, and the resulting report says explicitly that
// it had nothing to go on.
func (d *Debian) RebootRequired(ctx context.Context) (collect.RebootReport, error) {
	present, reasons := collect.RebootMarker()
	nr, err := collect.RunNeedrestart(ctx)
	report := collect.CombineRebootSignals(present, reasons, nr)
	if err != nil {
		return report, fmt.Errorf("platform: needrestart is the reliable reboot signal on Debian "+
			"and it failed: %w", err)
	}
	if !nr.Available && !present {
		report.Source = "needrestart is not installed and there is no reboot marker; " +
			"install needrestart for a reliable answer on Debian"
	}
	return report, nil
}

// SubscriptionStatus reports that Ubuntu Pro does not apply to this host.
//
// nil means "not applicable" and must be rendered as such. Returning a zero-valued struct would make a
// Debian host indistinguishable from an Ubuntu host whose subscription status could not be read, which
// is the difference between "this does not exist here" and "something is wrong".
func (d *Debian) SubscriptionStatus(_ context.Context) (*collect.Subscription, error) {
	return nil, nil
}

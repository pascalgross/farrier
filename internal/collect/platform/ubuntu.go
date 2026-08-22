package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/pegasusnetworks/farrier/internal/collect"
	"github.com/pegasusnetworks/farrier/internal/run"
)

// Ubuntu implements collect.Platform for the Ubuntu LTS releases in standard support.
//
// What it does about the four silent-wrong-answer traps:
//
//  1. Security origins. Ubuntu marks security updates by archive suffix — the archive part of an apt
//     release string ends in "-security". The ESM archives (noble-infra-security, noble-apps-security)
//     follow the same suffix under different labels, so the suffix rule catches them without an ESM
//     special case. SecurityOrigins reports the unattended-upgrades patterns, including both ESM ones,
//     because a host attached to Pro that omits them silently stops applying ESM security updates.
//  2. Reboot marker. /var/run/reboot-required is Ubuntu's own convention and is reliable here, but it
//     is still combined with needrestart rather than trusted alone, so that a host missing
//     update-notifier-common does not report that it never needs rebooting.
//  3. Ubuntu Pro. Applicable is true here. An unreadable or absent `pro` is reported as attached=false
//     with a note explaining why, never as an error and never as silence.
//  4. apt-check. Not used. The simulation parse is the only path, so a host without
//     update-notifier-common reports the same numbers as one with it.
type Ubuntu struct {
	// dist is the distribution this instance was built for.
	dist collect.Distribution
}

// Identify reports which distribution this is.
func (u *Ubuntu) Identify() (collect.Distribution, error) { return u.dist, nil }

// SecurityOrigins returns the unattended-upgrades origin patterns for Ubuntu.
//
// The two ESM entries are included deliberately. A host attached to Ubuntu Pro whose configuration
// lists only the plain security origin silently stops applying ESM security updates — the very updates
// it is paying for — and nothing about that failure is visible except a number that looks fine.
func (u *Ubuntu) SecurityOrigins() []string {
	return []string{
		"${distro_id}:${distro_codename}-security",
		"${distro_id}ESMApps:${distro_codename}-apps-security",
		"${distro_id}ESM:${distro_codename}-infra-security",
	}
}

// isSecurityRelease reports whether an apt release string names an Ubuntu security archive.
func (u *Ubuntu) isSecurityRelease(release string) bool {
	_, archive := splitRelease(release)
	return strings.HasSuffix(archive, "-security")
}

// UpgradablePackages lists pending updates with the security ones marked.
func (u *Ubuntu) UpgradablePackages(ctx context.Context) ([]collect.Package, error) {
	out, err := collect.SimulateUpgrade(ctx)
	if err != nil {
		return nil, err
	}
	return collect.ParseSimulation(out, u.isSecurityRelease), nil
}

// RebootRequired reports whether the host needs a reboot and why.
func (u *Ubuntu) RebootRequired(ctx context.Context) (collect.RebootReport, error) {
	present, reasons := collect.RebootMarker()
	nr, err := collect.RunNeedrestart(ctx)
	report := collect.CombineRebootSignals(present, reasons, nr)
	if err != nil {
		// needrestart failing is not fatal: the marker file is authoritative on Ubuntu for whether a
		// reboot is needed, and losing the service list degrades the answer rather than invalidating
		// it. The error is returned so the caller can log it, alongside a usable report.
		return report, fmt.Errorf("platform: needrestart: %w", err)
	}
	return report, nil
}

// proStatus is the subset of `pro status --format json` Farrier reads.
//
// Only three fields are decoded because only three are displayed. Decoding the whole document would
// mean a schema change in ubuntu-advantage-tools breaking fact collection for a host, which is a large
// consequence for information nobody asked for.
type proStatus struct {
	// Attached reports whether the host has a subscription attached.
	Attached bool `json:"attached"`

	// Services lists each Pro service and its status.
	Services []struct {
		// Name is the service name, such as "esm-apps" or "livepatch".
		Name string `json:"name"`

		// Status is its state, such as "enabled" or "disabled".
		Status string `json:"status"`
	} `json:"services"`
}

// SubscriptionStatus reports Ubuntu Pro and Livepatch state.
//
// Applicable is always true on Ubuntu, even when the pro tool is absent. That distinction matters: an
// Ubuntu host without ubuntu-advantage-tools *could* be attached and is not, which is worth showing,
// whereas a Debian host could not be and showing it an ESM badge only teaches its operator to ignore
// the dashboard.
func (u *Ubuntu) SubscriptionStatus(ctx context.Context) (*collect.Subscription, error) {
	sub := &collect.Subscription{Applicable: true, Services: map[string]string{}}

	if _, err := os.Stat(string(run.Pro)); errors.Is(err, os.ErrNotExist) {
		sub.Note = "ubuntu-advantage-tools is not installed"
		return sub, nil
	}

	res, err := run.Command(ctx, run.Pro, "status", "--format", "json")
	if err != nil {
		// Deliberately not propagated. "The pro tool failed" is a subscription state, not a collection
		// failure: returning an error here would make Gather replace this specific note with a generic
		// one, and the specific note is the whole value of the field.
		sub.Note = "pro status could not be read: " + err.Error()
		return sub, nil //nolint:nilerr // the failure is reported in Note, which is the answer
	}

	var status proStatus
	if err := json.Unmarshal(res.Stdout, &status); err != nil {
		sub.Note = "pro status returned output this build could not parse"
		return sub, nil //nolint:nilerr // as above: an unreadable status is a state, not a failure
	}
	sub.Attached = status.Attached
	for _, s := range status.Services {
		sub.Services[s.Name] = s.Status
	}
	return sub, nil
}

//go:build linux

package platform

import (
	"context"
	"fmt"
	"strings"

	"github.com/pascalgross/hostseal/internal/collect"
)

// DetectFrom identifies a host from an explicit os-release path.
func DetectFrom(path string) (collect.Platform, collect.Distribution, error) {
	fields, err := collect.ParseOSRelease(path)
	if err != nil {
		return nil, collect.Distribution{}, err
	}
	dist, err := collect.DistributionFromOSRelease(fields)
	if err != nil {
		return nil, dist, err
	}
	p, err := newFor(dist)
	return p, dist, err
}

// newFor returns the implementation for a distribution family.
//
// This is the one switch in the seam, and it is here rather than spread through the collectors on
// purpose: adding a family edits this function and nothing else.
func newFor(dist collect.Distribution) (collect.Platform, error) {
	switch dist.Family {
	case collect.FamilyUbuntu:
		return &Ubuntu{dist: dist}, nil
	case collect.FamilyDebian:
		return &Debian{dist: dist}, nil
	default:
		return nil, fmt.Errorf("platform: no implementation for family %q", dist.Family)
	}
}

// splitRelease splits an apt release string into its label and archive parts.
//
// apt-get prints releases as "Label:Version/Archive", for example "Ubuntu:24.04/noble-updates" or
// "Debian-Security:12/stable-security". Both halves matter: Ubuntu marks security by the archive
// suffix, Debian by a distinct label, and a matcher that looked at only one of them would be quietly
// wrong on one of the two families.
func splitRelease(release string) (label, archive string) {
	if before, after, found := strings.Cut(release, "/"); found {
		label = before
		archive = after
		if l, _, ok := strings.Cut(label, ":"); ok {
			label = l
		}
		return label, archive
	}
	// Some repositories publish a Release file with no Version field, and apt then prints
	// "Label:Archive" with no slash at all. Falling back to the colon rather than treating the whole
	// string as a label is what keeps the Ubuntu ESM archives — whose security marker lives entirely in
	// the archive name — from being classified as ordinary updates.
	if before, after, found := strings.Cut(release, ":"); found {
		return before, after
	}
	return release, ""
}

// Services reports systemd unit state, and whether the list was truncated.
//
// Both Linux families answer this identically, so it is one method on a shared type rather than two
// copies: systemd is systemd on Ubuntu and on Debian, and a per-family override would be a seam where
// there is no difference to express. It is on the seam at all because Windows answers the same question
// from the SCM, which shares nothing with D-Bus but the shape of the result.
func (systemdServices) Services(ctx context.Context) ([]collect.Unit, bool, error) {
	return collect.ListUnits(ctx)
}

// KernelRelease returns the running kernel release, or "unknown".
//
// Shared for the same reason Services is: /proc/sys/kernel/osrelease is the answer on both families.
func (systemdServices) KernelRelease() string { return collect.KernelRelease() }

// systemdServices supplies the two seam methods that are identical on every systemd host.
//
// It is embedded by Ubuntu and Debian rather than duplicated into each, because a copy is a place for
// the two to drift and there is no per-family difference here to justify one. It carries no state: it
// exists to hold methods, which is the whole reason Go allows an empty struct to have them.
type systemdServices struct{}

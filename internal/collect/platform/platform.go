// Package platform holds one Farrier collect.Platform implementation per distribution family.
//
// Detect chooses between them from /etc/os-release. Adding a family means adding a file here and a case
// in newFor; nothing else in the codebase learns about it, which is the property docs/EXTENDING.md
// promises about this seam.
//
// Every implementation must state in its own doc comment what it does about each of the four
// silent-wrong-answer traps listed in the collect package documentation. All four produce a plausible
// number rather than an error, so a reviewer cannot check them by reading the code for correctness —
// only by reading what the author says they thought about.
package platform

import (
	"fmt"
	"strings"

	"github.com/pegasusnetworks/farrier/internal/collect"
)

// Detect identifies the host and returns the matching platform implementation.
//
// It reads the real /etc/os-release. DetectFrom takes a path, for tests and for inspecting a chroot.
func Detect() (collect.Platform, collect.Distribution, error) {
	return DetectFrom(collect.OSReleasePath)
}

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

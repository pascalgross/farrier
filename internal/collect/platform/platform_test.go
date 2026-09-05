//go:build linux

package platform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pascalgross/hostseal/internal/collect"
)

// fixture reads captured command output from the collect package's testdata.
//
// The fixtures live one directory up because they are inputs to the shared parser, and copying them
// here would let the two copies drift — at which point one of the families would be tested against
// output apt no longer produces.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return raw
}

// TestSplitReleaseHandlesBothPrintedForms covers the two shapes apt uses.
func TestSplitReleaseHandlesBothPrintedForms(t *testing.T) {
	cases := map[string][2]string{
		"Ubuntu:24.04/noble-security":             {"Ubuntu", "noble-security"},
		"Debian-Security:12/stable-security":      {"Debian-Security", "stable-security"},
		"UbuntuESMApps:22.04/jammy-apps-security": {"UbuntuESMApps", "jammy-apps-security"},
		"UbuntuESM:jammy-infra-security":          {"UbuntuESM", "jammy-infra-security"},
		"Debian:12.8/stable":                      {"Debian", "stable"},
		"local":                                   {"local", ""},
	}
	for release, want := range cases {
		label, archive := splitRelease(release)
		if label != want[0] || archive != want[1] {
			t.Errorf("%q split to (%q, %q), want (%q, %q)", release, label, archive, want[0], want[1])
		}
	}
}

// TestSecurityClassificationDiffersBetweenFamilies is the first silent-wrong-answer trap, stated.
//
// Ubuntu marks security by archive suffix; Debian's authoritative signal is the "Debian-Security" origin
// label. This asserts each family's rule against the other family's real output, so that a future
// "simplification" collapsing the two into one predicate fails here rather than producing a plausible
// number in production — and the security/regular split is the one number this product exists to show.
func TestSecurityClassificationDiffersBetweenFamilies(t *testing.T) {
	ubuntu := &Ubuntu{dist: collect.Distribution{Family: collect.FamilyUbuntu, Codename: "noble"}}
	debian := &Debian{dist: collect.Distribution{Family: collect.FamilyDebian, Codename: "bookworm"}}

	// Debian's real output, classified by each family's rule.
	debianOutput := fixture(t, "debian-bookworm-dist-upgrade.txt")

	byDebianRule := collect.Summarise(collect.ParseSimulation(debianOutput, debian.isSecurityRelease))
	if byDebianRule.UpgradableTotal != 4 || byDebianRule.UpgradableSecurity != 3 {
		t.Errorf("Debian's own rule found %d security of %d, want 3 of 4",
			byDebianRule.UpgradableSecurity, byDebianRule.UpgradableTotal)
	}

	// Ubuntu's suffix rule happens to catch Debian's "-security" archives too. What it must not do is
	// be the only rule: a Debian mirror that names its archive after the suite rather than with the
	// suffix is caught by the label and not by the suffix.
	if !debian.isSecurityRelease("Debian-Security:12/updates") {
		t.Error("a Debian-Security label with a non-suffixed archive was not classified as security")
	}
	if ubuntu.isSecurityRelease("Debian-Security:12/updates") {
		t.Error("Ubuntu's rule matched a Debian label; the two rules are meant to be different")
	}

	// And Ubuntu's ESM archives, which carry no Debian-style label at all.
	if !ubuntu.isSecurityRelease("UbuntuESM:jammy-infra-security") {
		t.Error("an ESM Infra archive was not classified as security by Ubuntu's rule")
	}
	if ubuntu.isSecurityRelease("Ubuntu:24.04/noble-updates") {
		t.Error("an ordinary updates archive was classified as security")
	}
}

// TestSecurityOriginPatternsAreFamilySpecific is the same trap in the other direction.
//
// unattended-upgrades takes different syntax on the two families: Ubuntu's ${distro_id} shorthand and
// Debian's Origins-Pattern keys. Rendering the Ubuntu form into a Debian host's configuration produces
// a file that parses and matches nothing, so the host applies no updates at all and reports no error.
func TestSecurityOriginPatternsAreFamilySpecific(t *testing.T) {
	ubuntu := (&Ubuntu{}).SecurityOrigins()
	debian := (&Debian{}).SecurityOrigins()

	if len(ubuntu) < 3 {
		t.Errorf("Ubuntu lists %d origins; the two ESM archives must be included or a Pro host "+
			"silently stops applying the updates it is paying for", len(ubuntu))
	}
	for _, pattern := range debian {
		if pattern == ubuntu[0] {
			t.Error("the two families returned the same pattern; they take different syntax")
		}
	}
	if len(debian) == 0 {
		t.Error("Debian lists no origins")
	}
}

// TestDebianReportsSubscriptionAsNotApplicable is the third silent-wrong-answer trap.
//
// nil means "not applicable" and must be rendered as such. Returning a zero-valued struct would make a
// Debian host indistinguishable from an Ubuntu host whose status could not be read, and a Debian host
// wearing a permanent amber ESM badge teaches its operator to ignore the dashboard.
func TestDebianReportsSubscriptionAsNotApplicable(t *testing.T) {
	sub, err := (&Debian{}).SubscriptionStatus(context.Background())
	if err != nil {
		t.Fatalf("SubscriptionStatus: %v", err)
	}
	if sub != nil {
		t.Errorf("Debian returned a subscription value %+v; nil means not applicable", sub)
	}
}

// TestUbuntuReportsSubscriptionAsApplicableEvenWithoutTheProTool covers the distinction.
//
// An Ubuntu host without ubuntu-advantage-tools *could* be attached and is not, which is worth showing.
// A Debian host could not be. Both are "no subscription" and they are not the same fact.
func TestUbuntuReportsSubscriptionAsApplicableEvenWithoutTheProTool(t *testing.T) {
	// proInstalled=false explicitly, rather than relying on this machine not having the tool. GitHub's
	// runners do have it, so the version of this test that called SubscriptionStatus asserted the
	// absent-tool behaviour everywhere except where it mattered.
	sub, err := (&Ubuntu{}).subscription(context.Background(), false)
	if err != nil {
		t.Fatalf("subscription: %v", err)
	}
	if sub == nil {
		t.Fatal("Ubuntu returned nil, which means not applicable")
	}
	if !sub.Applicable {
		t.Error("Ubuntu reported Ubuntu Pro as not applicable")
	}
	if sub.Attached {
		t.Error("a host with no pro tool reported itself attached")
	}
	if sub.Note == "" {
		t.Error("an unattached host with no pro tool gave no explanation")
	}
}

// TestUbuntuSubscriptionNeverFails covers the whole entry point on whatever machine runs the tests.
//
// The specific branches are tested deterministically above; what this adds is that the real
// SubscriptionStatus — including the path that shells out to a pro tool that may or may not be here —
// answers rather than erroring. "The pro tool failed" is a subscription state, not a collection
// failure, and a host must never drop out of the fleet view because of it.
func TestUbuntuSubscriptionNeverFails(t *testing.T) {
	sub, err := (&Ubuntu{}).SubscriptionStatus(context.Background())
	if err != nil {
		t.Fatalf("SubscriptionStatus returned an error rather than a state: %v", err)
	}
	if sub == nil || !sub.Applicable {
		t.Error("Ubuntu reported Ubuntu Pro as not applicable")
	}
}

// TestDetectFromChoosesTheRightImplementation covers the seam's one switch.
func TestDetectFromChoosesTheRightImplementation(t *testing.T) {
	cases := map[string]string{
		"os-release-noble":    "*platform.Ubuntu",
		"os-release-bookworm": "*platform.Debian",
	}
	for file, want := range cases {
		p, dist, err := DetectFrom(filepath.Join("..", "testdata", file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if got := typeName(p); got != want {
			t.Errorf("%s selected %s, want %s", file, got, want)
		}
		if d, err := p.Identify(); err != nil || d != dist {
			t.Errorf("%s: Identify returned %+v (%v), want %+v", file, d, err, dist)
		}
	}

	if _, _, err := DetectFrom(filepath.Join("..", "testdata", "os-release-fedora")); err == nil {
		t.Error("a Fedora host selected a platform")
	}
}

// typeName renders a value's dynamic type for a test failure message.
func typeName(v any) string {
	switch v.(type) {
	case *Ubuntu:
		return "*platform.Ubuntu"
	case *Debian:
		return "*platform.Debian"
	default:
		return "unknown"
	}
}

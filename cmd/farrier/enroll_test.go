package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEnrolUsesTheInstalledCertificateWithoutBeingToldTwice is the bug this file exists for.
//
// The installation instructions, and the "Add a host" panel that renders the same three commands, tell
// an administrator to install the control plane's CA at DefaultServerCABundle and then run
// `farrier enroll --server … --token …`. That path was read by nothing, so the second command failed
// with "certificate signed by unknown authority" for every control plane serving its own certificate —
// which is every one that has not been given a public certificate, and the documented deployment behind
// TLS passthrough in particular. Following the instructions exactly is the case that has to work.
func TestEnrolUsesTheInstalledCertificateWithoutBeingToldTwice(t *testing.T) {
	installed := filepath.Join(t.TempDir(), "server-ca.crt")
	if err := os.WriteFile(installed, []byte("certificate bytes"), 0o644); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	got, err := resolveCABundle("", installed)
	if err != nil {
		t.Fatalf("resolving with no --ca: %v", err)
	}
	if got != installed {
		t.Errorf("enrolment would verify against %q, want the installed certificate at %q", got, installed)
	}
}

// TestEnrolFallsBackToTheSystemRootsWhenNothingWasInstalled keeps the public-certificate case working.
//
// A control plane behind a browser-trusted certificate needs no bundle, and the instructions say to skip
// that step. An empty result is how the agent asks for the system roots, so this asserts the default is
// a convention rather than a requirement.
func TestEnrolFallsBackToTheSystemRootsWhenNothingWasInstalled(t *testing.T) {
	got, err := resolveCABundle("", filepath.Join(t.TempDir(), "never-installed.crt"))
	if err != nil {
		t.Fatalf("resolving with nothing installed: %v", err)
	}
	if got != "" {
		t.Errorf("resolved to %q, want the system roots", got)
	}
}

// TestEnrolRefusesACABundleTheOperatorNamedAndDoesNotHave is the asymmetry that makes the default safe.
//
// A convention may be absent; a path somebody typed may not. Verifying against the system roots because
// --ca held a typo would accept a chain the operator did not ask for, at the one moment they were being
// explicit about which authority to trust — and it would look like a successful enrolment.
func TestEnrolRefusesACABundleTheOperatorNamedAndDoesNotHave(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "typo.crt")

	got, err := resolveCABundle(missing, filepath.Join(t.TempDir(), "installed.crt"))
	if err == nil {
		t.Fatalf("a --ca that does not exist resolved to %q instead of failing", got)
	}
}

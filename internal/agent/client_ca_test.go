package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCAFile puts a PEM certificate on disk and returns its path.
//
// The tests below care only that the bytes parse as a certificate, so the cheapest real one will do —
// a fixture that faked the PEM would prove nothing about AppendCertsFromPEM, which is the function
// whose false return the silent fallback used to swallow.
func writeCAFile(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("signing the certificate: %v", err)
	}
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("writing the certificate: %v", err)
	}
	return path
}

// TestGuaranteeAnUnusableCABundleIsRefusedRatherThanIgnored is the property that makes --ca mean
// something.
//
// A named bundle exists to refuse chains the system roots would accept. Falling back to those roots
// when the file cannot be used therefore inverts the request precisely when it matters, and does it
// silently: enrolment succeeds, the host is managed, and nobody learns that the authority the operator
// chose was never consulted. Both constructors are checked because enrolment uses one and every
// request after it uses the other, and a downgrade in either is a host verifying the wrong chain.
func TestGuaranteeAnUnusableCABundleIsRefusedRatherThanIgnored(t *testing.T) {
	dir := t.TempDir()

	notPEM := filepath.Join(dir, "not-a-certificate.crt")
	if err := os.WriteFile(notPEM, []byte("<!doctype html>\nthis is a login page, not a certificate\n"), 0o644); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	empty := filepath.Join(dir, "empty.crt")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{"a body that is not a certificate", notPEM},
		{"an empty file", empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewUnauthenticatedClient("https://control.example.org", tc.path); err == nil {
				t.Error("NewUnauthenticatedClient accepted an unusable CA bundle; it must refuse rather than " +
					"verify against the system roots")
			}
			if _, err := NewClient("https://control.example.org", dir, tc.path); err == nil {
				t.Error("NewClient accepted an unusable CA bundle; it must refuse rather than verify " +
					"against the system roots")
			}
		})
	}
}

// TestAbsentCABundleMeansTheSystemRoots keeps the publicly trusted deployment working.
//
// The agent passes its state directory's ca.crt on every start, and a control plane with a public
// certificate hands out no bundle to write there. Making an absent file an error would turn that
// ordinary deployment into an agent that refuses to start, so absence is the one case that stays quiet
// — and it is quiet because nobody asked for an authority, not because one was asked for and dropped.
func TestAbsentCABundleMeansTheSystemRoots(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nothing-here.crt")

	if _, err := NewUnauthenticatedClient("https://control.example.org", missing); err != nil {
		t.Errorf("an absent bundle should mean the system roots: %v", err)
	}
	if _, err := NewClient("https://control.example.org", t.TempDir(), missing); err != nil {
		t.Errorf("an absent bundle should mean the system roots: %v", err)
	}
	if _, err := NewUnauthenticatedClient("https://control.example.org", ""); err != nil {
		t.Errorf("no bundle at all should mean the system roots: %v", err)
	}
}

// TestAUsableCABundleBecomesTheRootPool asserts the pool is actually installed.
//
// Without this the test above passes for a constructor that reads the file, parses it and then throws
// the pool away — which is the shape of the bug being fixed, one step further along.
func TestAUsableCABundleBecomesTheRootPool(t *testing.T) {
	path := writeCAFile(t, t.TempDir())

	pool, err := loadRootCAs(path)
	if err != nil {
		t.Fatalf("loading a usable bundle: %v", err)
	}
	if pool == nil {
		t.Fatal("a usable bundle produced no root pool, so the connection would use the system roots")
	}
	if got := len(pool.Subjects()); got != 1 { //nolint:staticcheck // SA1019: the pool is built here, so Subjects is exact rather than incomplete.
		t.Errorf("root pool holds %d certificates, want 1", got)
	}
}

// TestUnreadableCABundleIsRefused covers the mode an operator hits by installing the file 0600.
//
// The installation instructions spell out the mode for exactly this reason, and a bundle that root
// wrote where the agent cannot read it must not become a silent fall back to the system roots. Skipped
// as root, which can read anything and would see the file succeed.
func TestUnreadableCABundleIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits this test depends on")
	}
	path := writeCAFile(t, t.TempDir())
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("removing the permissions: %v", err)
	}

	_, err := loadRootCAs(path)
	if err == nil {
		t.Fatal("an unreadable bundle was ignored rather than refused")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error should name the file the operator has to fix, got %q", err)
	}
}

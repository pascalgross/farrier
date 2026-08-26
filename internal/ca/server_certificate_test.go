package ca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// TestEnsureServerCertificateReissuesWhenDNSNamesChange proves that a configured public agent name
// becomes part of the private server certificate without turning every container restart into a key
// rotation. It also covers the configuration-change path: keeping a certificate that lacks a newly
// requested name would leave every agent behind the TLS-passthrough router unable to connect.
func TestEnsureServerCertificateReissuesWhenDNSNamesChange(t *testing.T) {
	dir := t.TempDir()
	authority, err := Init(dir, "test authority")
	if err != nil {
		t.Fatal(err)
	}

	certPath, _, err := authority.EnsureServerCertificate(dir, []string{"agents.one.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := readServerCertificate(t, certPath)
	if err := first.VerifyHostname("agents.one.example"); err != nil {
		t.Fatalf("first certificate does not contain its requested DNS name: %v", err)
	}

	if _, _, err := authority.EnsureServerCertificate(dir, []string{"agents.one.example"}, nil); err != nil {
		t.Fatal(err)
	}
	reused := readServerCertificate(t, certPath)
	if first.SerialNumber.Cmp(reused.SerialNumber) != 0 {
		t.Fatal("certificate with the same DNS names was unexpectedly reissued")
	}

	if _, _, err := authority.EnsureServerCertificate(dir, []string{"agents.two.example"}, nil); err != nil {
		t.Fatal(err)
	}
	reissued := readServerCertificate(t, certPath)
	if first.SerialNumber.Cmp(reissued.SerialNumber) == 0 {
		t.Fatal("certificate was reused after the requested DNS name changed")
	}
	for _, name := range []string{"localhost", "agents.two.example"} {
		if err := reissued.VerifyHostname(name); err != nil {
			t.Errorf("reissued certificate does not contain %q: %v", name, err)
		}
	}
}

// readServerCertificate parses the certificate written by EnsureServerCertificate. Keeping the parsing
// in one test helper makes the assertions above describe reuse and replacement rather than PEM plumbing.
func readServerCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatal("server certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

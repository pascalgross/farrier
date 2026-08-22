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
	"testing"
	"time"
)

// newSelfSignedPair produces a certificate and its matching key, both PEM encoded.
//
// Renewal only cares that the certificate and the key belong together; whether a CA signed it is the
// server's question, not the credential file's. A self-signed pair is therefore the right fixture, and
// avoids dragging the whole authority into a test about writing two files as one.
func newSelfSignedPair(t *testing.T, commonName string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encoding the key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// TestCredentialPromotesTheNewPairInOneStep is the renewal durability property.
//
// A renewal that wrote the certificate and the key as separate files had a window in which the two on
// disk belonged to different key pairs, and a crash inside it left a host that could neither
// authenticate nor renew. One file promoted by one rename has no such window, so this asserts the only
// observable consequence: after a promotion the pair on disk loads, and it is the new one.
func TestCredentialPromotesTheNewPairInOneStep(t *testing.T) {
	dir := t.TempDir()

	firstCert, firstKey := newSelfSignedPair(t, "first", time.Now().Add(24*time.Hour))
	if err := WriteCredential(dir, firstCert, firstKey); err != nil {
		t.Fatalf("writing the first credential: %v", err)
	}
	secondCert, secondKey := newSelfSignedPair(t, "second", time.Now().Add(48*time.Hour))
	if err := WriteCredential(dir, secondCert, secondKey); err != nil {
		t.Fatalf("promoting the second credential: %v", err)
	}

	leaf, err := CredentialLeaf(dir)
	if err != nil {
		t.Fatalf("loading the promoted credential: %v", err)
	}
	if leaf.Subject.CommonName != "second" {
		t.Errorf("the credential in use is %q, not the promoted one", leaf.Subject.CommonName)
	}

	// The superseded pair is kept, and it is still a usable pair rather than half of one.
	previous, err := os.ReadFile(filepath.Join(dir, PreviousCredentialFile))
	if err != nil {
		t.Fatalf("the superseded credential was not kept: %v", err)
	}
	if string(previous) != string(combineCredential(firstCert, firstKey)) {
		t.Error("the superseded credential is not the pair that was in use before")
	}
}

// TestCredentialFallsBackToTheSupersededPair covers the failure an atomic rename cannot prevent.
//
// A credential can be well-formed when it is written and unusable when it is read: a filesystem that
// lied about the fsync, an operator editing the file, or a control plane that issued against the wrong
// key. Without a fallback the host is off the fleet until somebody logs into it, which for a machine in
// a datacentre nobody visits is the expensive kind of outage.
func TestCredentialFallsBackToTheSupersededPair(t *testing.T) {
	dir := t.TempDir()

	firstCert, firstKey := newSelfSignedPair(t, "first", time.Now().Add(24*time.Hour))
	if err := WriteCredential(dir, firstCert, firstKey); err != nil {
		t.Fatalf("writing the first credential: %v", err)
	}
	secondCert, secondKey := newSelfSignedPair(t, "second", time.Now().Add(48*time.Hour))
	if err := WriteCredential(dir, secondCert, secondKey); err != nil {
		t.Fatalf("promoting the second credential: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, CredentialFile), []byte("-----BEGIN NONSENSE-----\n"), 0o600); err != nil {
		t.Fatalf("corrupting the credential: %v", err)
	}
	leaf, err := CredentialLeaf(dir)
	if err != nil {
		t.Fatalf("the agent did not fall back to the superseded credential: %v", err)
	}
	if leaf.Subject.CommonName != "first" {
		t.Errorf("fell back to %q rather than to the superseded pair", leaf.Subject.CommonName)
	}
}

// TestCredentialRefusesAPairThatDoesNotMatch is the check that keeps a bad renewal from landing.
//
// A control plane the guarantee assumes hostile can return a certificate issued against somebody else's
// key. Persisting it would replace a working credential with one that authenticates nothing, so the
// mismatch is refused before either file is touched and the host keeps talking.
func TestCredentialRefusesAPairThatDoesNotMatch(t *testing.T) {
	dir := t.TempDir()

	goodCert, goodKey := newSelfSignedPair(t, "good", time.Now().Add(24*time.Hour))
	if err := WriteCredential(dir, goodCert, goodKey); err != nil {
		t.Fatalf("writing the credential: %v", err)
	}
	otherCert, _ := newSelfSignedPair(t, "other", time.Now().Add(48*time.Hour))

	if err := WriteCredential(dir, otherCert, goodKey); err == nil {
		t.Fatal("a certificate that does not match the key was accepted")
	}
	leaf, err := CredentialLeaf(dir)
	if err != nil {
		t.Fatalf("the refused write damaged the working credential: %v", err)
	}
	if leaf.Subject.CommonName != "good" {
		t.Errorf("the credential in use is %q; the refused write should have changed nothing",
			leaf.Subject.CommonName)
	}
}

// TestCredentialIsNotWorldReadable pins the permissions on the file that now holds the private key.
//
// Merging the certificate into the key's file is only safe if the merged file keeps the key's
// permissions. A 0644 credential would publish the host's private key to every local account, which is
// exactly the mistake a combined file invites.
func TestCredentialIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()

	certPEM, keyPEM := newSelfSignedPair(t, "host", time.Now().Add(24*time.Hour))
	if err := WriteCredential(dir, certPEM, keyPEM); err != nil {
		t.Fatalf("writing the credential: %v", err)
	}
	if err := WriteCredential(dir, certPEM, keyPEM); err != nil {
		t.Fatalf("promoting the credential: %v", err)
	}

	for _, name := range []string{CredentialFile, PreviousCredentialFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s is mode %o, not 0600", name, perm)
		}
	}
}

// TestCredentialReportsAnAbsentPair rather than returning an empty certificate.
//
// A missing credential must fail loudly at the point of use. An empty tls.Certificate handed to the TLS
// stack produces a handshake failure with no explanation, and "the host stopped talking" is the hardest
// class of bug to diagnose from a datacentre away.
func TestCredentialReportsAnAbsentPair(t *testing.T) {
	if _, err := LoadCredential(t.TempDir()); err == nil {
		t.Fatal("loading a credential from an empty directory succeeded")
	}
}

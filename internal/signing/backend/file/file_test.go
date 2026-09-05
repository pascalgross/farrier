package file

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pascalgross/hostseal/internal/signing"
)

// newSigner generates a key file in a temporary directory and returns the unlocked signer.
//
// Every case starts from a freshly generated key rather than a fixture, so that no constant in this
// file could ever be mistaken for a real one.
func newSigner(t *testing.T, keyID string, alg signing.Algorithm) (*Signer, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing.key")
	passphrase := []byte("correct horse battery staple")
	s, err := Generate(path, keyID, alg, passphrase)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path, passphrase
}

// TestGenerateAndOpenRoundTrip covers the basic lifecycle for both algorithms.
func TestGenerateAndOpenRoundTrip(t *testing.T) {
	for _, alg := range []signing.Algorithm{signing.Ed25519, signing.ECDSAP256} {
		signer, path, passphrase := newSigner(t, "ops-laptop", alg)
		payload := []byte(`{"intent":"host.reboot"}`)

		sig, err := signer.Sign(context.Background(), payload)
		if err != nil {
			t.Fatalf("%s: Sign: %v", alg, err)
		}

		reopened, err := Open(path, passphrase)
		if err != nil {
			t.Fatalf("%s: Open: %v", alg, err)
		}
		defer reopened.Close()

		if reopened.KeyID() != "ops-laptop" || reopened.Algorithm() != alg {
			t.Errorf("%s: reopened as %q/%s", alg, reopened.KeyID(), reopened.Algorithm())
		}

		line, err := signing.TrustedSignerLine(reopened)
		if err != nil {
			t.Fatalf("%s: TrustedSignerLine: %v", alg, err)
		}
		set, err := signing.ParseSigners(strings.NewReader(line+"\n"), "test")
		if err != nil {
			t.Fatalf("%s: the generated trusted-signers line does not parse: %v", alg, err)
		}
		key, err := set.Verify(payload, sig)
		if err != nil {
			t.Fatalf("%s: a signature did not verify against the key's own line: %v", alg, err)
		}
		if key.String() != "ops-laptop (file)" {
			t.Errorf("%s: verified as %q", alg, key)
		}
	}
}

// TestOpenRefusesTheWrongPassphrase asserts the envelope is actually protecting something.
//
// The error is deliberately the same for a wrong passphrase and a tampered file, because the two are
// indistinguishable to secretbox and claiming to tell them apart would be guessing.
func TestOpenRefusesTheWrongPassphrase(t *testing.T) {
	_, path, _ := newSigner(t, "ops-laptop", signing.Ed25519)

	if _, err := Open(path, []byte("wrong")); err == nil {
		t.Fatal("the wrong passphrase unlocked the key")
	}
	if _, err := Open(path, nil); err == nil {
		t.Fatal("an empty passphrase unlocked the key")
	}
}

// TestOpenDetectsTamperedCiphertext asserts the envelope is authenticated, not merely encrypted.
//
// A file an attacker can modify undetectably is a file whose contents they partly control, and the
// contents here are a signing key.
func TestOpenDetectsTamperedCiphertext(t *testing.T) {
	_, path, passphrase := newSigner(t, "ops-laptop", signing.Ed25519)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}
	// Flip one base64 character of the ciphertext. The JSON stays valid; the seal does not.
	tampered := strings.Replace(string(raw), `"ciphertext": "`, `"ciphertext": "A`, 1)
	if tampered == string(raw) {
		t.Fatal("could not find the ciphertext field to tamper with")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("writing tampered file: %v", err)
	}
	if _, err := Open(path, passphrase); err == nil {
		t.Error("a tampered key file was accepted")
	}
}

// TestGenerateRequiresAKeyIDAndAPassphrase covers the two refusals at creation time.
//
// The key id is required because it is what the audit log records: "signed by a key" is not an audit
// trail. The passphrase is required because this backend's whole claim is that a stolen laptop does
// not hand over the fleet.
func TestGenerateRequiresAKeyIDAndAPassphrase(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(filepath.Join(dir, "a.key"), "", signing.Ed25519, []byte("pw")); err == nil {
		t.Error("a key with no id was generated")
	}
	if _, err := Generate(filepath.Join(dir, "b.key"), "ops", signing.Ed25519, nil); err == nil {
		t.Error("a key with no passphrase was generated")
	}
	if _, err := Generate(filepath.Join(dir, "c.key"), "ops", "rsa", []byte("pw")); err == nil {
		t.Error("a key with an unsupported algorithm was generated")
	}
}

// TestKeyFileIsNotWorldReadable asserts the permissions on a file that holds a signing key.
func TestKeyFileIsNotWorldReadable(t *testing.T) {
	_, path, _ := newSigner(t, "ops-laptop", signing.Ed25519)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode is %o, want 600", perm)
	}
}

// TestInspectReadsThePublicHalfWithoutThePassphrase covers the setup-time convenience.
//
// It exists so `hostseal key show` can print a trusted-signers line for a key the operator cannot
// currently unlock — which is the situation somebody is in while setting up a host with the token
// somewhere else.
func TestInspectReadsThePublicHalfWithoutThePassphrase(t *testing.T) {
	signer, path, _ := newSigner(t, "ops-laptop", signing.Ed25519)

	pub, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if pub.KeyID != "ops-laptop" || pub.Backend != "file" {
		t.Errorf("Inspect returned %q", pub)
	}

	payload := []byte(`{"intent":"host.reboot"}`)
	sig, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !pub.Verify(payload, sig) {
		t.Error("the inspected public key did not verify the signer's own signature")
	}
}

// TestSignHonoursACancelledContext covers the behaviour hardware backends need.
//
// A touch-required token blocks on a human finger, and an operator who changes their mind should be
// able to press Ctrl-C. The file backend never blocks, but it honours the contract so that callers can
// be written once against the interface rather than once per backend.
func TestSignHonoursACancelledContext(t *testing.T) {
	signer, _, _ := newSigner(t, "ops-laptop", signing.Ed25519)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.Sign(ctx, []byte("payload")); err == nil {
		t.Error("Sign ignored a cancelled context")
	}
}

// TestCloseDropsTheKey asserts a closed signer cannot sign.
//
// Go gives no way to guarantee key material is gone from memory, so Close does not pretend to scrub it
// and this does not test that it did. What can honestly be asserted is that the signer stops working,
// which is what a caller relies on after handing one to something else.
func TestCloseDropsTheKey(t *testing.T) {
	signer, _, _ := newSigner(t, "ops-laptop", signing.Ed25519)
	if err := signer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("a closed signer produced a signature")
		}
	}()
	_, _ = signer.Sign(context.Background(), []byte("payload"))
}

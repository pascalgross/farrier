package seal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestSealRoundTrips proves that what was sealed is what comes back.
func TestSealRoundTrips(t *testing.T) {
	key, err := Ensure(t.TempDir())
	if err != nil {
		t.Fatalf("ensuring a key: %v", err)
	}
	body := []byte("#cloud-config\nhostname: web-01\n")
	sealed, err := key.Seal(body)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if bytes.Contains(sealed, []byte("web-01")) {
		t.Fatal("the sealed form contains the plaintext")
	}
	opened, err := key.Open(sealed)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if !bytes.Equal(opened, body) {
		t.Fatalf("round trip changed the body: %q", opened)
	}
}

// TestSealIsFreshPerCall proves two seals of the same body differ, which is the nonce doing its job.
func TestSealIsFreshPerCall(t *testing.T) {
	key, err := Ensure(t.TempDir())
	if err != nil {
		t.Fatalf("ensuring a key: %v", err)
	}
	a, _ := key.Seal([]byte("same"))
	b, _ := key.Seal([]byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are identical; the nonce is not fresh")
	}
}

// TestEnsureIsStableAcrossRestarts proves the key file survives and keeps opening old ciphertext.
//
// This is the property an operator restore depends on: a database backup is only recoverable together
// with the key that sealed it, and a control plane restart must not rotate that key silently.
func TestEnsureIsStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	first, err := Ensure(dir)
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	sealed, err := first.Seal([]byte("survives"))
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	second, err := Ensure(dir)
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	opened, err := second.Open(sealed)
	if err != nil || string(opened) != "survives" {
		t.Fatalf("the reloaded key cannot open what the first sealed: %q, %v", opened, err)
	}

	info, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatalf("statting the key file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("the key file is %v, want 0600", mode)
	}
}

// TestTheWrongKeyOpensNothing proves a second key refuses the first key's output.
//
// This is what makes "encrypted at rest" a statement about the backup rather than about the schema: a
// database dump without the key beside the CA yields ErrSealed, not template bodies.
func TestTheWrongKeyOpensNothing(t *testing.T) {
	alpha, err := Ensure(t.TempDir())
	if err != nil {
		t.Fatalf("ensuring alpha: %v", err)
	}
	beta, err := Ensure(t.TempDir())
	if err != nil {
		t.Fatalf("ensuring beta: %v", err)
	}
	sealed, err := alpha.Seal([]byte("secret"))
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	for _, mangled := range [][]byte{sealed, sealed[:8], nil} {
		if _, err := beta.Open(mangled); !errors.Is(err, ErrSealed) {
			t.Fatalf("the wrong key opened %d bytes: %v", len(mangled), err)
		}
	}
}

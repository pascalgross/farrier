package seal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
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

// TestConcurrentEnsureAgreesOnOneKey is the property a second control-plane replica depends on.
//
// The failure it rules out is worse here than for the online signing key, which has the same race and
// the same fix. A clobbered signing key leaves agents unable to verify the *next* routine job, and
// re-enrolment repairs it. A clobbered sealing key leaves every template already stored as ciphertext
// nobody holds the key for, and nothing repairs it — the symptom is a templates page that worked an
// hour ago and now cannot decrypt its own rows.
//
// Rounds, because a race that reproduces in one attempt in three would otherwise pass this suite most
// of the time and fail in somebody's cluster.
func TestConcurrentEnsureAgreesOnOneKey(t *testing.T) {
	for round := range 8 {
		dir := t.TempDir()

		const starters = 16
		var wg sync.WaitGroup
		keys := make([]*Key, starters)
		errs := make([]error, starters)
		start := make(chan struct{})
		for i := range starters {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				keys[i], errs[i] = Ensure(dir)
			}()
		}
		close(start)
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d: starter %d: %v", round, i, err)
			}
		}

		// Every starter holds the same key, asserted through the operation that matters rather than
		// by comparing material: what must hold is that a template sealed by one replica opens on
		// another, which is the thing an operator notices when it stops being true.
		sealed, err := keys[0].Seal([]byte("#cloud-config\nhostname: web-01\n"))
		if err != nil {
			t.Fatalf("round %d: sealing: %v", round, err)
		}
		for i, key := range keys {
			if _, err := key.Open(sealed); err != nil {
				t.Fatalf("round %d: starter %d cannot open what starter 0 sealed: %v — a generator "+
					"clobbered a key that was already in place", round, i, err)
			}
		}
	}
}

// TestEnsureNeverLeavesAPartialFileBehind checks the property the concurrency test infers.
//
// Stated separately because a reader outside this package — an operator, a backup, a second process
// mid-start — sees only the file. If the only assertion were "concurrent callers agree", an
// implementation could satisfy it by locking while still exposing a half-written key to everything
// else, and a half-written sealing key is one that parses and decrypts nothing.
func TestEnsureNeverLeavesAPartialFileBehind(t *testing.T) {
	dir := t.TempDir()
	if _, err := Ensure(dir); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the key directory: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != KeyFile {
			t.Errorf("%s was left in the key directory; the temporary file is not cleaned up",
				entry.Name())
		}
	}

	info, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the sealing key is mode %o, not 0600", perm)
	}
}

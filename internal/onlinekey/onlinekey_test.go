package onlinekey

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pascalgross/hostseal/internal/signing"
)

// TestEnsureSurvivesASecondControlPlaneStartingAtTheSameMoment is why the key is linked into place.
//
// Creating the file and writing it are two syscalls, and between them the file exists and is empty. A
// second control plane reading it there gets zero bytes and refuses to start, naming a corrupt key file
// rather than the race that produced it. The count is high on purpose: the window is wide enough that a
// handful of iterations would pass on a fast disk and hide the defect again.
func TestEnsureSurvivesASecondControlPlaneStartingAtTheSameMoment(t *testing.T) {
	for round := range 200 {
		dir := t.TempDir()
		start := make(chan struct{})
		var wg sync.WaitGroup
		keys := make([]*Key, 16)
		errs := make([]error, 16)
		for i := range keys {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				keys[i], errs[i] = Ensure(dir)
			}(i)
		}
		close(start)
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d, starter %d: Ensure failed: %v", round, i, err)
			}
		}
		// And every one of them ended up with the SAME key. A starter that generated its own and wrote
		// it over the winner's would leave agents holding a public half that verifies nothing, which is
		// the failure the exclusive create existed to prevent and which must survive this fix.
		for i, key := range keys {
			if key.KeyID() != keys[0].KeyID() {
				t.Fatalf("round %d: starter %d holds key %s, starter 0 holds %s: a generator clobbered "+
					"a key that was already in place", round, i, key.KeyID(), keys[0].KeyID())
			}
		}
	}
}

// TestEnsureNeverLeavesAPartialFileBehind checks the property the concurrency test infers.
//
// Stated separately because a reader outside this package — an operator, a backup, a second process
// mid-start — sees only the file. If the only assertion were "concurrent callers agree", a future
// implementation could satisfy it by locking while still exposing a half-written key to everything else.
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
		t.Errorf("the private key is mode %o, not 0600", perm)
	}
}

// TestEnsureReturnsTheKeyAlreadyOnDisk is the ordinary restart.
//
// A control plane that generated a new key on every start would silently break the routine tier across
// a whole fleet, because agents verify against the public half they cached at enrolment.
func TestEnsureReturnsTheKeyAlreadyOnDisk(t *testing.T) {
	dir := t.TempDir()
	first, err := Ensure(dir)
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	second, err := Ensure(dir)
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if first.KeyID() != second.KeyID() {
		t.Errorf("a restart produced key %s, having stored %s", second.KeyID(), first.KeyID())
	}
}

// TestThePublicLineParsesAsATrustedSigner closes the loop this key exists inside.
//
// The line the server sends and the parser the agent uses are written from different ends, and a
// mismatch would surface as "routine jobs are refused" on every host rather than as a format error here.
func TestThePublicLineParsesAsATrustedSigner(t *testing.T) {
	key, err := Ensure(t.TempDir())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	line, err := key.PublicLine()
	if err != nil {
		t.Fatalf("PublicLine: %v", err)
	}
	set, err := signing.ParseSigners(newReader(line), "test")
	if err != nil {
		t.Fatalf("the agent's parser rejected the line the server sends: %v", err)
	}
	if set.Len() == 0 {
		t.Error("the line parsed to an empty signer set")
	}
}

// newReader adapts a string for signing.ParseSigners.
//
// A named helper rather than strings.NewReader inline, so the assertion above reads as "the agent's
// parser accepts the server's line" instead of as plumbing.
func newReader(s string) *strings.Reader { return strings.NewReader(s) }

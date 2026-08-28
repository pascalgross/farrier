package agent

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// TestGuaranteeEnrolmentStateIsReadableByTheServiceAccount is the bug this file exists for.
//
// `sudo farrier enroll` writes the credential as root; the unit runs it as an unprivileged account. The
// files therefore landed root-owned at mode 0600, the service could not open agent.json, and it logged
// "not enrolled" on a host the control plane was already listing — an enrolled host that reports
// nothing, with every visible signal saying the installation is fine.
//
// Root-only, because changing a file's owner is a privileged operation and there is no way to stage the
// mismatch without it. It runs in CI, where tests are root, which is the environment that matters: this
// is a guarantee about what an operator's `sudo` leaves behind.
func TestGuaranteeEnrolmentStateIsReadableByTheServiceAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("staging a root-owned file in a directory owned by somebody else needs root")
	}
	uid, gid := unprivilegedIDs(t)

	dir := t.TempDir()
	// The directory as the package creates it: owned by the service account, group-readable, 0750.
	if err := os.Chown(dir, uid, gid); err != nil {
		t.Fatalf("giving the state directory to the service account: %v", err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatalf("setting the directory mode: %v", err)
	}
	// The files as `sudo farrier enroll` writes them: root-owned, and 0600 for the two that matter.
	for name, perm := range map[string]os.FileMode{
		StateFile:      0o600,
		CABundleFile:   0o644,
		CredentialFile: 0o600,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("written by root\n"), perm); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	if err := AdoptStateDir(dir); err != nil {
		t.Fatalf("adopting the state directory: %v", err)
	}

	for _, name := range []string{StateFile, CABundleFile, CredentialFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("no ownership information for %s", name)
		}
		if int(owner.Uid) != uid || int(owner.Gid) != gid {
			t.Errorf("%s is owned by %d:%d, want %d:%d — the agent would report \"not enrolled\" "+
				"on an enrolled host", name, owner.Uid, owner.Gid, uid, gid)
		}
	}
}

// TestAdoptingIsANoOpWhenTheOwnerAlreadyMatches keeps the unpackaged install unaffected.
//
// Enrolling into a directory root owns — a container, a test, an installation that runs the agent as
// root — must not become an error just because there is nothing to hand over.
func TestAdoptingIsANoOpWhenTheOwnerAlreadyMatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, StateFile)
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	if err := AdoptStateDir(dir); err != nil {
		t.Fatalf("adopting a directory this user already owns: %v", err)
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Errorf("the file should be untouched: %v", err)
	}
}

// TestAdoptingAMissingDirectoryIsAnError keeps a typo in --state-dir from looking like success.
func TestAdoptingAMissingDirectoryIsAnError(t *testing.T) {
	if err := AdoptStateDir(filepath.Join(t.TempDir(), "not-created")); err == nil {
		t.Error("adopting a directory that does not exist should fail")
	}
}

// unprivilegedIDs finds an account that is not root to hand the directory to.
//
// It prefers the account the package creates, so the test stages exactly the production mismatch, and
// falls back to nobody where the package has not been installed — which is every developer's machine.
func unprivilegedIDs(t *testing.T) (uid, gid int) {
	t.Helper()
	for _, name := range []string{"farrier", "nobody", "daemon"} {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		parsedUID, err := strconv.Atoi(u.Uid)
		if err != nil || parsedUID == 0 {
			continue
		}
		parsedGID, err := strconv.Atoi(u.Gid)
		if err != nil {
			continue
		}
		return parsedUID, parsedGID
	}
	t.Skip("no unprivileged account to hand the state directory to")
	return 0, 0
}

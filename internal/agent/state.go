package agent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pascalgross/farrier/internal/canonical"
)

// DefaultStateDir is where the agent keeps everything it writes.
//
// It is the only writable path the hardened systemd unit grants, which is deliberate: an agent that can
// write nowhere else cannot be talked into leaving something behind in a directory that matters.
const DefaultStateDir = "/var/lib/farrier"

// DefaultServerCABundle is where an administrator puts the control plane's CA before enrolling.
//
// It exists because enrolment is the one request an agent makes with nothing on disk to verify against.
// Every request after it uses the bundle the enrolment response carried, written to CABundleFile — but
// that response is itself fetched over TLS, so the first connection needs an authority chosen locally
// and in advance. `farrier enroll` reads this path when --ca is not given, which is what makes the
// documented ordering — install the certificate, then enrol — mean something rather than being a step
// that writes a file nothing opens.
//
// /etc/farrier rather than the state directory: this is administrator-supplied configuration, chosen
// before the agent exists, and the state directory is the agent's to rewrite.
const DefaultServerCABundle = "/etc/farrier/server-ca.crt"

// File names inside the agent's state directory.
const (
	// StateFile records what the agent learned at enrolment.
	StateFile = "agent.json"

	// CABundleFile is the control plane's CA chain, for verifying agent certificates on renewal.
	CABundleFile = "ca.crt"

	// SaltFile holds the per-host salt used to hash /etc/machine-id.
	//
	// It is generated at package installation and never leaves the machine. Without it, the same
	// machine-id hashed by two different fleets would produce the same value, and anybody who saw both
	// could correlate them.
	SaltFile = "machine-id-salt"

	// PendingResultsDir holds job results that have not been delivered yet.
	PendingResultsDir = "pending-results"

	// MachineIDPath is systemd's machine identifier, which is documented as confidential.
	MachineIDPath = "/etc/machine-id"
)

// State is what the agent knows about its enrolment.
//
// It is deliberately small: the server URL, the host id, and nothing that could be reconstructed. Any
// state that matters and can be lost — job results — lives in its own spool directory with its own
// durability rules, rather than here.
type State struct {
	// ServerURL is the control plane's base URL.
	ServerURL string `json:"serverUrl"`

	// HostID is the identifier the control plane assigned at enrolment.
	HostID string `json:"hostId"`

	// EnrolledAt is when enrolment completed.
	EnrolledAt time.Time `json:"enrolledAt"`

	// dir is where this state was loaded from, and where its siblings live.
	dir string
}

// LoadState reads the agent's enrolment state from a directory.
func LoadState(dir string) (*State, error) {
	raw, err := os.ReadFile(filepath.Join(dir, StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("agent: this host is not enrolled; run `farrier enroll`: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("agent: reading enrolment state: %w", err)
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("agent: enrolment state is unreadable: %w", err)
	}
	s.dir = dir
	if s.ServerURL == "" || s.HostID == "" {
		return nil, errors.New("agent: enrolment state is incomplete")
	}
	return &s, nil
}

// Save writes the enrolment state atomically.
func (s *State) Save(dir string) error {
	s.dir = dir
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encoding enrolment state: %w", err)
	}
	return WriteFileAtomic(filepath.Join(dir, StateFile), raw, 0o600)
}

// Dir returns the state directory this state was loaded from.
func (s *State) Dir() string { return s.dir }

// Path returns a path inside the state directory.
func (s *State) Path(name string) string { return filepath.Join(s.dir, name) }

// WriteFileAtomic writes a file through a temporary file in the same directory and renames it.
//
// An interrupted write must never be able to leave a truncated file where a valid one used to be. For
// the certificate and key that would mean a host that cannot authenticate and cannot renew, recoverable
// only by re-enrolling it by hand — which for a fleet member in a datacentre nobody visits is a real
// cost. The directory is fsynced as well as the file, because a rename is not durable until its parent
// is.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".farrier-*")
	if err != nil {
		return fmt.Errorf("agent: creating a temporary file in %s: %w", dir, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: setting permissions on %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: writing %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: syncing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agent: closing %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("agent: renaming into place at %s: %w", path, err)
	}
	return SyncDir(dir)
}

// WriteFileExclusive writes a file that must not already exist, and fails if it does.
//
// The difference from WriteFileAtomic is the whole point and is one syscall: rename overwrites, link
// does not. Where a file *is* the record that something has already happened, an overwrite is that
// record being silently replaced by a second claim to be the first — so the bootstrap interlock, which
// says a template has been applied to this machine, is written with this rather than with a rename.
//
// It is a temporary file linked into place rather than O_CREATE|O_EXCL followed by a write, for the
// reason internal/onlinekey and internal/seal both give at length: O_EXCL makes *creation* exclusive,
// but creation and content are two syscalls, and between them the file exists and is empty. A
// concurrent reader in that window sees zero bytes and reports a corrupt record rather than a race.
// link(2) is atomic, fails with EEXIST, and never exposes a partial file.
//
// os.ErrExist is returned unwrapped enough for errors.Is, because "somebody got here first" is a
// distinct outcome a caller has to be able to recognise rather than a failure.
func WriteFileExclusive(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".farrier-*")
	if err != nil {
		return fmt.Errorf("agent: creating a temporary file in %s: %w", dir, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: setting permissions on %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: writing %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: syncing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agent: closing %s: %w", path, err)
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("agent: %s already exists: %w", path, os.ErrExist)
		}
		return fmt.Errorf("agent: linking into place at %s: %w", path, err)
	}
	return SyncDir(dir)
}

// SyncDir fsyncs a directory, making a rename inside it durable.
//
// Without this, a crash immediately after writing a pending job result can lose the rename even though
// the file's own contents were synced — and a lost result for host.reboot is a job that completes by
// the host disappearing and is never reported at all.
func SyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("agent: opening %s to sync: %w", dir, err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("agent: syncing %s: %w", dir, err)
	}
	return nil
}

// MachineIDHash returns the salted hash of /etc/machine-id.
//
// The raw value is documented by systemd as confidential and is never transmitted. If no salt exists
// yet — a source build rather than a package install — one is generated and stored, so that the hash is
// stable across restarts. A hash that changed on every start would enrol the same machine repeatedly.
func MachineIDHash(dir string) (string, error) {
	id, err := os.ReadFile(MachineIDPath)
	if err != nil {
		return "", fmt.Errorf("agent: reading %s: %w", MachineIDPath, err)
	}
	salt, err := loadOrCreateSalt(filepath.Join(dir, SaltFile))
	if err != nil {
		return "", err
	}
	return canonical.SaltedDigest(salt, []byte(strings.TrimSpace(string(id)))), nil
}

// loadOrCreateSalt reads the per-host salt, creating it if absent.
func loadOrCreateSalt(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil && len(raw) > 0:
		return raw, nil
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("agent: reading the machine-id salt: %w", err)
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("agent: generating a machine-id salt: %w", err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(salt))
	if err := WriteFileAtomic(path, encoded, 0o600); err != nil {
		return nil, err
	}
	return encoded, nil
}

// AdoptStateDir gives the state directory's contents to whoever owns the directory.
//
// It exists because enrolment and the agent are two different users. `farrier enroll` is run with sudo,
// as the documentation and the interface both instruct, and everything it writes — the credential, the
// CA bundle, the cached online key, agent.json at 0600 — therefore lands owned by root. The service
// runs as the unprivileged account the package created, with User=farrier and no capabilities, so it
// opens agent.json, gets EACCES, and reports "not enrolled" on a host that enrolled successfully
// seconds earlier.
//
// That failure is the worst shape this project has: everything looks right. The control plane shows the
// host, because the enrolment request did succeed and the row exists. The unit is active, because an
// unenrolled agent idles rather than exiting. Only the absence of facts says anything is wrong, and it
// says it in the place an operator is least likely to read it as a permissions problem on their own
// machine.
//
// The directory's own owner is the target rather than a compiled-in "farrier", because that is what the
// package established with `install -d -o farrier -g farrier` and it stays right for an installation
// that runs the agent as something else. Where the owner already matches — an unpackaged install where
// both are root, or a test in a temporary directory — every chown is a no-op, so this costs nothing and
// needs no guard for the ordinary case.
//
// Errors are returned rather than logged. A credential the service cannot read is not a partial success
// worth continuing past: enrolment consumed a single-use token, and the operator has to know now, while
// they are still at the terminal, rather than by reading journal lines an hour later.
func AdoptStateDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("agent: reading the state directory %s: %w", dir, err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Not Linux, which the agent is not built for. Nothing to do rather than a failure, because a
		// state directory with no uid behind it is not a state directory anybody can be locked out of.
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("agent: reading the state directory %s: %w", dir, err)
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		// Lchown rather than Chown: a symlink in here should have its own ownership changed, never the
		// thing it points at, which is how a writable state directory would otherwise become a way to
		// chown a file elsewhere on the system.
		if err := os.Lchown(path, int(owner.Uid), int(owner.Gid)); err != nil {
			return fmt.Errorf("agent: giving %s to uid %d: %w", path, owner.Uid, err)
		}
	}
	return nil
}

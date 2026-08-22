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
	"time"

	"github.com/pascalgross/farrier/internal/canonical"
)

// DefaultStateDir is where the agent keeps everything it writes.
//
// It is the only writable path the hardened systemd unit grants, which is deliberate: an agent that can
// write nowhere else cannot be talked into leaving something behind in a directory that matters.
const DefaultStateDir = "/var/lib/farrier"

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

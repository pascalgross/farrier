package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NonceFile is where seen job nonces are recorded.
const NonceFile = "nonces.json"

// NonceStore remembers the nonces of jobs this host has already seen.
//
// It exists to refuse replay. A signature is valid for a window, and without a nonce store a control
// plane — or anyone who captured one signed job — could deliver the same authorised reboot repeatedly
// until the window closed. Persisting it matters as much as having it: a nonce store held only in
// memory is defeated by restarting the agent, which for a reboot job is the very next thing that
// happens.
type NonceStore struct {
	// mu guards seen and the file.
	mu sync.Mutex

	// path is where the store is persisted.
	path string

	// seen maps a nonce to the moment it may be forgotten.
	//
	// Entries expire at the signature's notAfter rather than on a fixed schedule, because a nonce whose
	// signature has expired cannot be replayed anyway: the validity check refuses it first.
	seen map[string]time.Time
}

// LoadNonceStore reads the persisted nonces, pruning expired entries.
func LoadNonceStore(stateDir string) (*NonceStore, error) {
	path := filepath.Join(stateDir, NonceFile)
	store := &NonceStore{path: path, seen: map[string]time.Time{}}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agent: reading %s: %w", path, err)
	}

	var persisted map[string]time.Time
	if err := json.Unmarshal(raw, &persisted); err != nil {
		// A corrupt nonce store is refused rather than reset. Silently starting from empty would
		// silently re-open the replay window, and a host that refuses privileged jobs until somebody
		// looks at it is the safer failure.
		return nil, fmt.Errorf("agent: %s is unreadable; refusing to start with an empty replay "+
			"defence: %w", path, err)
	}

	now := time.Now()
	for nonce, expiry := range persisted {
		if expiry.After(now) {
			store.seen[nonce] = expiry
		}
	}
	return store, nil
}

// Check records a nonce and reports whether it had already been seen.
//
// The record is persisted before the caller acts on the answer, so that a crash between accepting a job
// and executing it cannot leave the nonce unrecorded and the job replayable.
func (n *NonceStore) Check(nonce string, expiresAt time.Time) (seen bool, err error) {
	if nonce == "" {
		return false, errors.New("agent: a signed job must carry a nonce")
	}
	// A zero expiry is an error rather than a default, and the difference is the whole value of this
	// store. The record exists to outlive the authorisation it guards, so its lifetime has to come from
	// the signed window; a default would forget the nonce on a schedule of the agent's own choosing and
	// make the job replayable from then on. The only caller reaches here for a signed privileged job,
	// and accept() has already refused one whose window is not a window — so this is the second of two
	// statements of the same rule, in the place that would silently paper over the first.
	if expiresAt.IsZero() {
		return false, errors.New("agent: a signed job's nonce needs the expiry its signature covers")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if _, exists := n.seen[nonce]; exists {
		return true, nil
	}

	now := time.Now()
	for existing, expiry := range n.seen {
		if !expiry.After(now) {
			delete(n.seen, existing)
		}
	}
	n.seen[nonce] = expiresAt

	raw, err := json.Marshal(n.seen)
	if err != nil {
		return false, fmt.Errorf("agent: encoding the nonce store: %w", err)
	}
	if err := WriteFileAtomic(n.path, raw, 0o600); err != nil {
		delete(n.seen, nonce)
		return false, err
	}
	return false, nil
}

// Len reports how many nonces are remembered, for logs and tests.
func (n *NonceStore) Len() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.seen)
}

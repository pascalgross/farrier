package agent

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/pascalgross/farrier/internal/signing"
)

// OnlineKeyFile is where the control plane's own public key is kept on the host.
//
// In the state directory and not in /etc/farrier, and the difference is the whole point. /etc/farrier
// holds what the *operator* decided: policy.toml, and trusted-signers, which is the anchor for every
// destructive operation and which the control plane can neither read nor write. This is a value the
// control plane sent, cached so a host can act on a routine job while offline. Filing it beside the
// trust anchor would invite exactly the confusion this separation exists to prevent — that these two
// keys are the same kind of thing.
const OnlineKeyFile = "online-key"

// LoadOnlineKey reads the cached online key as a one-key set.
//
// A set rather than a single key because that is what the verifier takes, and because it makes the
// empty case — no key cached, so nothing verifies — the same shape as an empty trusted-signers file.
// The routine tier is then refused with the message it had before there was an online key at all.
//
// A missing file is not an error. A fresh agent has not heard from a control plane yet, and one talking
// to a control plane with no online key never will.
func LoadOnlineKey(stateDir string) (*signing.SignerSet, error) {
	path := filepath.Join(stateDir, OnlineKeyFile)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &signing.SignerSet{}, nil
	}
	if err != nil {
		return &signing.SignerSet{}, fmt.Errorf("agent: reading %s: %w", path, err)
	}
	set, err := signing.ParseSigners(strings.NewReader(string(raw)), path)
	if err != nil {
		return &signing.SignerSet{}, fmt.Errorf("agent: parsing %s: %w", path, err)
	}
	return set, nil
}

// StoreOnlineKey caches the control plane's public key, if it has changed.
//
// Written only on a change, so that an ordinary heartbeat does not touch the disk sixty times an hour
// on every host in a fleet. The comparison is on the line as sent, which is also what makes rotation
// visible: a new key is a new line, and the log records the moment a host started trusting it for
// routine work.
//
// An empty line is ignored rather than treated as a deletion. An absent field means the control plane
// had nothing to say — it may have been restarted without its key directory, or be an older build — and
// reading that as "forget your key" would disable a fleet's routine tier in a way that looks like the
// agents failing rather than the server being misconfigured.
func StoreOnlineKey(stateDir, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	// Parsed before it is stored. A control plane that sent something unparseable would otherwise leave
	// a file that fails to load on every subsequent start, and the failure would surface as "routine
	// jobs are refused" long after the response that caused it.
	if _, err := signing.ParseSigners(strings.NewReader(line), "the control plane"); err != nil {
		return fmt.Errorf("agent: the control plane sent an unusable online key: %w", err)
	}

	path := filepath.Join(stateDir, OnlineKeyFile)
	if existing, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(existing)) == line {
		return nil
	}

	if err := WriteFileAtomic(path, []byte(line+"\n"), 0o640); err != nil {
		return err
	}
	slog.Info("the control plane's online key changed; routine jobs will be verified against the new one",
		"path", path)
	return nil
}

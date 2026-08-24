// Package seal encrypts provisioning template bodies at rest.
//
// docs/SECURITY.md §7 requires template bodies to be encrypted in the database, and this package is the
// whole of the mechanism. The threat it addresses is a database backup, not a compromised control
// plane: a control plane that is running holds the key and can decrypt, and §1 never claimed otherwise.
// What it buys is that a dump, a misplaced backup or a read replica somebody forgot about does not
// yield every enrolment token and break-glass credential operators put into their templates — and they
// will, whatever the warnings in internal/provision say.
//
// The key lives beside the CA, like the online signing key, because both are things a compromised
// database must not yield and both are backed up by the same operator with the same care.
// docs/INSTALL.md documents its home next to the CA's.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyFile is the file the sealing key lives in, inside the CA directory.
//
// Beside the CA rather than in the database, because a key stored next to the ciphertext it protects
// protects nothing. This placement is what makes "encrypted at rest" mean something against the threat
// it names: a database backup travels without the CA directory.
const KeyFile = "template.key"

// keySize is the AES-256 key length in bytes.
//
// A constant rather than a parameter because there is exactly one right answer and a configuration
// knob for it would only create installations with the wrong one.
const keySize = 32

// Key seals and opens template bodies.
//
// It is a value handed to the server at construction rather than a package-level singleton, so that
// tests can hold two different keys and prove that one cannot open the other's output.
type Key struct {
	// aead is the AES-256-GCM instance derived from the key material.
	aead cipher.AEAD
}

// ErrSealed reports ciphertext this key cannot open.
//
// It deliberately covers truncation, corruption and a wrong key alike: distinguishing them tells a
// caller nothing actionable, and the operator-facing answer to all three is the same — the key beside
// the CA is not the key that sealed this database.
var ErrSealed = errors.New("seal: the stored body cannot be decrypted with this key")

// Ensure loads the sealing key from a directory, generating one if it is not there.
//
// Generated on first start rather than by a separate command, for the same reason the online signing
// key is: a control plane that came up unable to store templates, and said so only in a log line
// nobody read, would be reported as a bug about the templates page rather than as the missing setup
// step it is. The file is 0600 and the directory is the CA's, so it inherits the protection the CA key
// already has.
func Ensure(dir string) (*Key, error) {
	path := filepath.Join(dir, KeyFile)

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parse(raw, path)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("seal: reading %s: %w", path, err)
	}

	material := make([]byte, keySize)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("seal: generating a key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(material) + "\n"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("seal: creating %s: %w", dir, err)
	}

	// Written to a temporary file and linked into place, which is the pattern onlinekey.Ensure
	// already argues for at length — and this key needs it more than that one does.
	//
	// A plain os.WriteFile lets two control planes starting against one fresh CA directory each
	// generate different material and each overwrite the other. The online key survives that badly;
	// this one survives it worse. Every template already sealed by the losing replica becomes
	// permanently unopenable, and the symptom is a decryption failure on a page that worked an hour
	// ago rather than anything pointing at a startup race.
	//
	// link(2) and not rename(2): rename overwrites, which is the behaviour being avoided. link is
	// atomic and fails with EEXIST, so the loser reads the winner's key instead of clobbering it, and
	// a concurrent reader sees either no file or a complete one — never the empty window that
	// O_CREATE|O_EXCL followed by a write would leave.
	tmp, err := os.CreateTemp(dir, ".template.key-*")
	if err != nil {
		return nil, fmt.Errorf("seal: creating a temporary file in %s: %w", dir, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("seal: setting permissions on the new key: %w", err)
	}
	if _, err := tmp.Write([]byte(encoded)); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("seal: writing the new key: %w", err)
	}
	// Synced before it is linked, and the directory synced after. Losing this file to a crash is not
	// recoverable by generating another: every template already stored is ciphertext under the key
	// that went missing.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("seal: syncing the new key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("seal: closing the new key: %w", err)
	}

	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil, fmt.Errorf("seal: reading %s after a concurrent create: %w", path, readErr)
			}
			return parse(existing, path)
		}
		return nil, fmt.Errorf("seal: linking %s into place: %w", path, err)
	}
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	return New(material)
}

// syncDir fsyncs a directory, making a link inside it durable.
//
// Its own function because the failure it prevents is invisible in testing: without it the key file's
// directory entry can be lost to a power cut the file's own contents survived, and the control plane
// would come back up generating a second key — under which every stored template is unreadable.
func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("seal: opening %s to sync it: %w", dir, err)
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("seal: syncing %s: %w", dir, err)
	}
	return nil
}

// parse decodes a stored key file.
//
// The format is one base64 line, chosen over raw bytes so that a key can be copied through a terminal
// during a restore without anything mangling it.
func parse(raw []byte, path string) (*Key, error) {
	material, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("seal: %s is not a base64 key: %w", path, err)
	}
	key, err := New(material)
	if err != nil {
		return nil, fmt.Errorf("seal: %s: %w", path, err)
	}
	return key, nil
}

// New builds a key from raw material, for Ensure and for tests.
func New(material []byte) (*Key, error) {
	if len(material) != keySize {
		return nil, fmt.Errorf("seal: a key is %d bytes, not %d", keySize, len(material))
	}
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, fmt.Errorf("seal: building the cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: building the AEAD: %w", err)
	}
	return &Key{aead: aead}, nil
}

// Seal encrypts a template body for storage.
//
// The nonce is generated fresh per call and prefixed to the ciphertext, so the stored value is
// self-contained and the schema needs no second column that could be updated independently of the
// bytes it belongs to.
func (k *Key) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: generating a nonce: %w", err)
	}
	return k.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a stored template body.
func (k *Key) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < k.aead.NonceSize() {
		return nil, ErrSealed
	}
	nonce, ciphertext := sealed[:k.aead.NonceSize()], sealed[k.aead.NonceSize():]
	plaintext, err := k.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// The AEAD's own error is deliberately not wrapped: it says "message authentication failed",
		// which reads as a signature problem to somebody debugging templates, and the actionable fact —
		// this key did not seal these bytes — is the sentinel's to state.
		return nil, ErrSealed
	}
	return plaintext, nil
}

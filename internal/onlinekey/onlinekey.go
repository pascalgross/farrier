// Package onlinekey holds the control plane's own signing key, the one it may use unattended.
//
// It exists to keep a distinction that matters from collapsing. A destructive job is signed offline by
// a key in the host's own trusted-signers, which this control plane does not hold and cannot obtain —
// that is what docs/SECURITY.md §1 rests on. A routine job is signed by *this* key, which lives on the
// control plane and is used without a human present. The two are different authorities and the agent
// verifies them separately; the whole reason this is its own package is so that nothing can reach for
// one where the other belongs.
//
// What that means for the threat model is worth stating rather than implying. An attacker who owns the
// control plane owns this key, so it defends against nothing in §1's scenario. docs/SECURITY.md §3 is
// explicit about what protects the routine tier instead: the host's own local policy, which bounds a
// routine intent to "sooner than it would have happened anyway, and only if the host already permits it
// unattended". A host with `allow = "none"` refuses one however it was signed.
//
// So why sign at all? Because the alternative is a privileged operation authorised by mTLS alone, and
// because it keeps one mechanism rather than two: every privileged job carries a signature over the
// same canonical payload, checked in the same place, with the same replay store. An agent that had a
// second code path for "privileged but unsigned" would have a second place to get it wrong.
package onlinekey

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pascalgross/farrier/internal/signing"
)

// KeyFile is the file the private key lives in, inside the CA directory.
//
// Beside the CA rather than in the database, because both are things a compromised database must not
// yield and both are backed up by the same operator with the same care. docs/INSTALL.md already tells
// people to back that directory up separately.
const KeyFile = "online.key"

// Key is the control plane's online signing key.
//
// It implements signing.Signer, so it composes with the canonical payload, the trusted-signers line
// format and the audit log without any of those learning that this key is different.
type Key struct {
	// private is the Ed25519 private key.
	private ed25519.PrivateKey

	// id is the identity recorded in the audit log and in a job's signerKeyId.
	id string
}

// Ensure loads the online key from a directory, generating one if it is not there.
//
// Generated on first start rather than by a separate command, for the same reason the server issues
// itself a TLS certificate when none is configured: a control plane that came up unable to authorise
// the one routine intent, and said so only in a log line nobody read, would be reported as a bug about
// packages.applySecurity rather than as the missing setup step it is.
//
// The file is 0600 and the directory is the CA's, so it inherits the protection the CA key already has.
func Ensure(dir string) (*Key, error) {
	path := filepath.Join(dir, KeyFile)

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parse(raw, path)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("onlinekey: reading %s: %w", path, err)
	}

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("onlinekey: generating a key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("onlinekey: encoding the key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("onlinekey: creating %s: %w", dir, err)
	}
	// 0600, and written with O_EXCL so that two control planes starting together on shared storage
	// cannot both generate a key and have one silently overwrite the other's — which would leave every
	// agent holding a public key that no longer verifies anything.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil, fmt.Errorf("onlinekey: reading %s after a concurrent create: %w", path, readErr)
			}
			return parse(existing, path)
		}
		return nil, fmt.Errorf("onlinekey: creating %s: %w", path, err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("onlinekey: writing %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("onlinekey: closing %s: %w", path, err)
	}
	return parse(encoded, path)
}

// parse reads a PEM private key into a Key.
func parse(raw []byte, path string) (*Key, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("onlinekey: %s does not contain a PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("onlinekey: parsing %s: %w", path, err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("onlinekey: %s holds a %T, expected an Ed25519 key", path, parsed)
	}
	return &Key{private: private, id: identityFor(private.Public())}, nil
}

// identityFor derives the key id from the public key.
//
// Derived rather than configured, so that rotating the key changes the name it signs under. An audit
// log in which two different keys both said "farrier-online-1" would answer "which key authorised
// this" with a name that had been true of two things, which is worse than answering with a fingerprint.
func identityFor(public crypto.PublicKey) string {
	encoded, ok := public.(ed25519.PublicKey)
	if !ok {
		return "farrier-online"
	}
	sum := sha256.Sum256(encoded)
	return "farrier-online-" + hex.EncodeToString(sum[:4])
}

// KeyID returns the identity recorded in the audit log and in a job's signerKeyId.
func (k *Key) KeyID() string { return k.id }

// Algorithm reports which signature algorithm this key produces.
func (k *Key) Algorithm() signing.Algorithm { return signing.Ed25519 }

// Public returns the public key, for the line an agent stores.
func (k *Key) Public() crypto.PublicKey { return k.private.Public() }

// Backend names how the private key is held, for display.
//
// "control-plane" rather than "file", even though it is a file, because that is the fact worth seeing
// in an audit log: this signature was made by the control plane itself, unattended, and not by a person
// holding a key the control plane does not have.
func (k *Key) Backend() string { return "control-plane" }

// Sign produces a detached signature over the canonical payload.
//
// The context is accepted and unused: Ed25519 signing does not block, and the signature is the
// interface's rather than this implementation's. A hardware-backed online key would need it.
func (k *Key) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(k.private, payload), nil
}

// Close releases what the key holds, which is nothing.
func (k *Key) Close() error { return nil }

// PublicLine renders the public half in the trusted-signers line format.
//
// The same format as a host's own trust anchor, deliberately: one parser, one encoder, and an operator
// who has read one file can read the other. What differs is where the line comes from and what it is
// allowed to authorise, and neither of those is a property of the format.
func (k *Key) PublicLine() (string, error) {
	line, err := signing.TrustedSignerLine(k)
	if err != nil {
		return "", fmt.Errorf("onlinekey: rendering the public line: %w", err)
	}
	return line, nil
}

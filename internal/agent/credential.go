package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Credential file names inside the agent's state directory.
const (
	// CredentialFile holds the agent's private key and client certificate in one PEM file.
	//
	// One file rather than two is a durability decision, not a tidiness one. A renewal that wrote a
	// certificate and a key separately would have a window — however short — in which the two on disk
	// belonged to different key pairs, and a crash inside that window leaves a host that cannot
	// authenticate and cannot renew, recoverable only by a person visiting it. Writing both halves as
	// one atomically renamed file removes the window entirely: the pair on disk is always a pair.
	CredentialFile = "agent.pem"

	// PreviousCredentialFile is the pair that was in use before the most recent renewal.
	//
	// It is the fallback for the case an atomic rename cannot cover: a control plane that returns a
	// certificate which is well-formed, matches the key, and is nonetheless not one this host can use.
	// Keeping the superseded pair costs one file and turns that from a site visit into a restart.
	//nolint:gosec // G101: a file name, not a credential. gosec matches the identifier, not the value.
	PreviousCredentialFile = "agent.pem.prev"
)

// ErrNoCredential reports that a host has no usable client credential on disk.
var ErrNoCredential = errors.New("agent: no usable client credential")

// WriteCredential promotes a key and certificate as a single file, keeping the superseded pair.
//
// The order matters and is the opposite of the obvious one: the outgoing pair is copied aside first, so
// that a crash between the two writes leaves either the old pair twice or the old pair and the new one
// — never a new pair with no way back. The pair is verified before either write, because a certificate
// that does not match its key is a control-plane bug the agent should refuse rather than persist.
func WriteCredential(dir string, certPEM, keyPEM []byte) error {
	combined := combineCredential(certPEM, keyPEM)
	if _, err := tls.X509KeyPair(combined, combined); err != nil {
		return fmt.Errorf("agent: the issued certificate does not match the key it was requested for: %w", err)
	}

	current := filepath.Join(dir, CredentialFile)
	if existing, err := os.ReadFile(current); err == nil && len(existing) > 0 {
		if err := WriteFileAtomic(filepath.Join(dir, PreviousCredentialFile), existing, 0o600); err != nil {
			// Not fatal. Losing the fallback is worse than not having written it, but refusing the
			// renewal over it would strand a host whose certificate is running out.
			return fmt.Errorf("agent: keeping the superseded credential: %w", err)
		}
	}
	return WriteFileAtomic(current, combined, 0o600)
}

// LoadCredential reads the client credential, falling back to the superseded pair.
//
// The fallback exists for the one failure an atomic write cannot prevent: a credential that is
// syntactically fine and still unusable — truncated by a filesystem that lied about the fsync, edited
// by hand, or issued against the wrong key by a control plane. A host that could not fall back would be
// off the fleet until somebody logged into it.
func LoadCredential(dir string) (tls.Certificate, error) {
	var firstErr error
	for _, name := range []string{CredentialFile, PreviousCredentialFile} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		cert, err := tls.X509KeyPair(raw, raw)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return cert, nil
	}
	if firstErr == nil {
		firstErr = ErrNoCredential
	}
	return tls.Certificate{}, fmt.Errorf("agent: loading %s: %w", filepath.Join(dir, CredentialFile), firstErr)
}

// CredentialLeaf returns the parsed client certificate currently in use.
//
// Renewal timing is decided from this rather than from anything the server said, because the only
// deadline that matters is the one the host's own certificate carries.
func CredentialLeaf(dir string) (*x509.Certificate, error) {
	pair, err := LoadCredential(dir)
	if err != nil {
		return nil, err
	}
	if pair.Leaf != nil {
		return pair.Leaf, nil
	}
	if len(pair.Certificate) == 0 {
		return nil, ErrNoCredential
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("agent: parsing the client certificate: %w", err)
	}
	return leaf, nil
}

// combineCredential joins a key and a certificate chain into one PEM document.
//
// The key comes first so that a reader who opens the file sees immediately that it is secret, and a
// trailing newline is enforced because a certificate written without one would run into the key's
// header and make the whole file unparseable.
func combineCredential(certPEM, keyPEM []byte) []byte {
	var buf bytes.Buffer
	for _, part := range [][]byte{keyPEM, certPEM} {
		buf.Write(part)
		if len(part) > 0 && part[len(part)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

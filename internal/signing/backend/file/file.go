// Package file implements the passphrase-protected key-file signing backend.
//
// It exists as a backend separate from the hardware ones because most operators start with a key file
// and only move to a token once the fleet justifies the ceremony. Refusing that path would not make
// anyone buy a YubiKey; it would push them to keep the key on the control plane instead, which is
// strictly worse than a passphrase-protected file on a laptop. What Farrier does instead is make the
// difference visible: the audit log records "ops-laptop (file)" differently from "ops-yubikey-1
// (PKCS#11)", and an operator reviewing a destructive job can see which one authorised it.
//
// The on-disk format is a small JSON envelope: scrypt over the passphrase, NaCl secretbox over a PKCS#8
// private key. It is deliberately not an encrypted PEM — Go's x509.EncryptPEMBlock is deprecated
// because the format it produces is weak, and rolling this envelope is both stronger and easier to
// reason about than the alternatives.
package file

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"

	"github.com/pascalgross/farrier/internal/signing"
)

// envelopeVersion is the format version written into every key file.
//
// It is present from the first release because a key file outlives the tool that wrote it. Adding a
// version later means guessing at the format of files already on operators' laptops.
const envelopeVersion = 1

// scrypt parameters. These are the interactive-login parameters from the scrypt paper, which take
// roughly a tenth of a second on a laptop — the right trade for a key unlocked by hand a few times a
// week, and enough to make an offline attack on a stolen file expensive.
const (
	scryptN      = 1 << 15
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 16
	nonceLen     = 24
)

// envelope is the on-disk representation of an encrypted signing key.
type envelope struct {
	// Version is the format version.
	Version int `json:"version"`

	// KeyID is the identity that must appear in a host's trusted-signers file.
	KeyID string `json:"keyId"`

	// Algorithm is the signature algorithm this key produces.
	Algorithm signing.Algorithm `json:"algorithm"`

	// PublicKey is the base64 DER SubjectPublicKeyInfo, stored in the clear.
	//
	// Keeping the public half readable without the passphrase means `farrier key show` can print the
	// trusted-signers line for a key the operator cannot currently unlock, which is exactly the
	// situation somebody is in when they are setting up a host and the token is at the office.
	PublicKey string `json:"publicKey"`

	// KDF names the key-derivation function, currently always scrypt.
	KDF string `json:"kdf"`

	// N, R, P are the scrypt cost parameters, stored so that raising them later does not orphan
	// existing files.
	N int `json:"n"`
	R int `json:"r"`
	P int `json:"p"`

	// Salt is the base64 scrypt salt.
	Salt []byte `json:"salt"`

	// Nonce is the base64 secretbox nonce.
	Nonce []byte `json:"nonce"`

	// Ciphertext is the sealed PKCS#8 private key.
	Ciphertext []byte `json:"ciphertext"`
}

// Signer is a signing.Signer backed by a passphrase-protected key file.
type Signer struct {
	// keyID is the identity recorded in the audit log.
	keyID string

	// algorithm is the signature algorithm.
	algorithm signing.Algorithm

	// private is the unlocked private key. It lives only as long as the Signer.
	private crypto.Signer
}

// Generate creates a new key, writes it encrypted to path, and returns a Signer for it.
//
// The file is written 0600 through a temporary file in the same directory and renamed, so that an
// interrupted write cannot leave a truncated key file where a valid one used to be. That matters more
// here than almost anywhere else: an operator who overwrites their signing key at the wrong moment
// loses the ability to authorise anything on every host that trusts it.
func Generate(path, keyID string, alg signing.Algorithm, passphrase []byte) (*Signer, error) {
	if keyID == "" {
		return nil, errors.New("file: a key id is required; it is what the audit log records")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("file: a passphrase is required for a file-backed key")
	}
	// Refused rather than overwritten. Losing a signing key means losing the ability to authorise
	// anything on every host that trusts it, and the recovery is editing trusted-signers on each of
	// them by hand. A tool that destroys that on a mistyped path is not a tool anybody should have to
	// be careful with.
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("file: %s already exists; refusing to replace a signing key. "+
			"Move it aside if you mean to generate a new one — every host trusting the old key would "+
			"need its trusted-signers edited by hand", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("file: checking %s: %w", path, err)
	}

	var priv crypto.Signer
	var err error
	switch alg {
	case signing.Ed25519:
		_, key, genErr := ed25519.GenerateKey(rand.Reader)
		priv, err = key, genErr
	case signing.ECDSAP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("file: %w: %q", signing.ErrUnknownAlgorithm, alg)
	}
	if err != nil {
		return nil, fmt.Errorf("file: generating key: %w", err)
	}

	env, err := seal(keyID, alg, priv, passphrase)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(path, env); err != nil {
		return nil, err
	}
	return &Signer{keyID: keyID, algorithm: alg, private: priv}, nil
}

// Open unlocks a key file and returns a Signer for it.
func Open(path string, passphrase []byte) (*Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("file: reading %s: %w", path, err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("file: %s is not a Farrier key file: %w", path, err)
	}
	if env.Version != envelopeVersion {
		return nil, fmt.Errorf("file: %s is version %d, this build understands %d",
			path, env.Version, envelopeVersion)
	}

	key, err := derive(passphrase, env.Salt, env.N, env.R, env.P)
	if err != nil {
		return nil, err
	}
	var nonce [nonceLen]byte
	if len(env.Nonce) != nonceLen {
		return nil, fmt.Errorf("file: %s has a %d-byte nonce, expected %d", path, len(env.Nonce), nonceLen)
	}
	copy(nonce[:], env.Nonce)

	plain, ok := secretbox.Open(nil, env.Ciphertext, &nonce, key)
	if !ok {
		// One message for a wrong passphrase and for a tampered file, because the two are
		// indistinguishable to secretbox and pretending otherwise would be guessing.
		return nil, fmt.Errorf("file: cannot unlock %s: wrong passphrase, or the file has been altered", path)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("file: %s holds an unreadable private key: %w", path, err)
	}
	priv, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("file: %s holds a %T, which cannot sign", path, parsed)
	}
	return &Signer{keyID: env.KeyID, algorithm: env.Algorithm, private: priv}, nil
}

// Inspect reads a key file's public half without needing the passphrase.
//
// It exists so that `farrier key show` can print a trusted-signers line for a key the operator cannot
// currently unlock, which is the situation somebody is in while setting up a host with the token
// somewhere else.
func Inspect(path string) (signing.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return signing.PublicKey{}, fmt.Errorf("file: reading %s: %w", path, err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return signing.PublicKey{}, fmt.Errorf("file: %s is not a Farrier key file: %w", path, err)
	}
	key, err := signing.ParsePublicKey(env.Algorithm, env.PublicKey)
	if err != nil {
		return signing.PublicKey{}, err
	}
	return signing.PublicKey{
		Algorithm: env.Algorithm,
		KeyID:     env.KeyID,
		Backend:   "file",
		Key:       key,
		Encoded:   env.PublicKey,
	}, nil
}

// KeyID returns the identity that must appear in a host's trusted-signers file.
func (s *Signer) KeyID() string { return s.keyID }

// Algorithm reports which signature algorithm this signer produces.
func (s *Signer) Algorithm() signing.Algorithm { return s.algorithm }

// Public returns the public key, for writing a trusted-signers line.
func (s *Signer) Public() crypto.PublicKey { return s.private.Public() }

// Backend names how the private key is held, for display in the audit log.
func (s *Signer) Backend() string { return "file" }

// Sign produces a detached signature over the canonical payload.
//
// Ed25519 signs the payload directly, because it hashes internally; ECDSA signs a SHA-256 digest of it,
// which is what PKCS#11 tokens and cloud KMS offerings also produce, so the resulting signature is
// interchangeable with theirs. The verifier does the corresponding thing and never has to know which
// backend it came from.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch s.algorithm {
	case signing.Ed25519:
		return s.private.Sign(rand.Reader, payload, crypto.Hash(0))
	case signing.ECDSAP256:
		sum := sha256.Sum256(payload)
		return s.private.Sign(rand.Reader, sum[:], crypto.SHA256)
	default:
		return nil, fmt.Errorf("file: %w: %q", signing.ErrUnknownAlgorithm, s.algorithm)
	}
}

// Close drops the unlocked private key.
//
// Go gives no way to guarantee the key material is gone from memory, so this does not pretend to
// scrub it. Dropping the reference is what can honestly be done, and claiming more would be worse than
// claiming nothing.
func (s *Signer) Close() error {
	s.private = nil
	return nil
}

// seal encrypts a private key into an envelope.
func seal(keyID string, alg signing.Algorithm, priv crypto.Signer, passphrase []byte) (*envelope, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("file: encoding private key: %w", err)
	}
	_, encodedPub, err := signing.EncodePublicKey(priv.Public())
	if err != nil {
		return nil, err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("file: reading randomness: %w", err)
	}
	key, err := derive(passphrase, salt, scryptN, scryptR, scryptP)
	if err != nil {
		return nil, err
	}

	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("file: reading randomness: %w", err)
	}

	return &envelope{
		Version:    envelopeVersion,
		KeyID:      keyID,
		Algorithm:  alg,
		PublicKey:  encodedPub,
		KDF:        "scrypt",
		N:          scryptN,
		R:          scryptR,
		P:          scryptP,
		Salt:       salt,
		Nonce:      nonce[:],
		Ciphertext: secretbox.Seal(nil, pkcs8, &nonce, key),
	}, nil
}

// derive runs scrypt over the passphrase with the envelope's stored parameters.
func derive(passphrase, salt []byte, n, r, p int) (*[scryptKeyLen]byte, error) {
	if n <= 1 || r <= 0 || p <= 0 {
		return nil, fmt.Errorf("file: implausible scrypt parameters N=%d r=%d p=%d", n, r, p)
	}
	out, err := scrypt.Key(passphrase, salt, n, r, p, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("file: deriving key: %w", err)
	}
	var key [scryptKeyLen]byte
	copy(key[:], out)
	return &key, nil
}

// writeAtomic writes the envelope 0600 via a temporary file in the same directory.
//
// An interrupted write must not be able to leave a truncated key file where a valid one used to be:
// an operator who loses their signing key loses the ability to authorise anything on every host that
// trusts it.
func writeAtomic(path string, env *envelope) error {
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("file: encoding key file: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("file: creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".farrier-key-*")
	if err != nil {
		return fmt.Errorf("file: creating a temporary file in %s: %w", dir, err)
	}
	// The rename below makes this a no-op on success; on any failure path it removes the partial file.
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("file: setting permissions: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("file: writing key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("file: syncing key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("file: closing key: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}

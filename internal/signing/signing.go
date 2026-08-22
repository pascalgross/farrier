// Package signing verifies detached signatures over Farrier job payloads, and produces them.
//
// It is the third of the three mechanisms behind docs/SECURITY.md §1: every destructive operation
// requires a signature from a key the control plane does not hold, listed in that host's own
// /etc/farrier/trusted-signers.
//
// The package is deliberately lopsided. Verification is small, fixed and shared by the agent and the
// server; signing is an open-ended set of backends that runs only on an operator's machine. That shape
// is what makes an open-ended list of backends safe: the agent only ever sees a public key and a
// signature over a canonical payload, and cannot learn which backend produced it. Adding a backend is
// purely client-side and cannot widen the agent's attack surface by even one branch.
//
// Two algorithms exist on the wire. Ed25519 is the default and should be used unless something in the
// chain cannot. ECDSA P-256 exists because YubiKey PIV before firmware 5.7.0 and several cloud KMS
// offerings cannot do Ed25519 at all — carrying one algorithm tag now is very much cheaper than
// rewriting every host's trusted-signers later.
package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Algorithm names a signature algorithm as it appears on the wire and in trusted-signers.
//
// It is tagged explicitly rather than inferred from the key length because inference is what forces a
// fleet-wide file rewrite the first time a third algorithm is needed. One tag now, no migration later.
type Algorithm string

// The supported signature algorithms.
const (
	// Ed25519 is the default. Signatures are the raw 64-byte form.
	Ed25519 Algorithm = "ed25519"

	// ECDSAP256 is for hardware and cloud key stores that cannot do Ed25519.
	//
	// Signatures are ASN.1 DER SEQUENCE{r,s}, which is what crypto/ecdsa's SignASN1, PKCS#11 tokens
	// and every major cloud KMS produce. Accepting only the fixed-width concatenated form would
	// exclude exactly the hardware this algorithm exists to support.
	ECDSAP256 Algorithm = "ecdsa-p256"
)

// Valid reports whether the algorithm is one this build understands.
//
// Every path that takes an algorithm from a file or from the network calls this first, so that an
// unrecognised value fails closed rather than falling through to a default verifier.
func (a Algorithm) Valid() bool { return a == Ed25519 || a == ECDSAP256 }

// ErrUnknownAlgorithm reports an algorithm tag this build does not implement.
var ErrUnknownAlgorithm = errors.New("signing: unknown algorithm")

// ErrNoTrustedSigner reports that no key in the set produced the signature.
//
// It is deliberately one error rather than one per key. Telling a caller which of several keys nearly
// matched is information they cannot act on and an attacker can.
var ErrNoTrustedSigner = errors.New("signing: no trusted signer produced this signature")

// PublicKey is one entry from a trusted-signers file.
//
// KeyID is the identity that ends up in the audit log, which is why it is required rather than
// optional: "signed by a key" is not an audit trail, and reconstructing which key it was from a
// fingerprint six months later is exactly the work an audit trail exists to avoid.
type PublicKey struct {
	// Algorithm is the tag from the file.
	Algorithm Algorithm

	// KeyID is the human-readable identity, the third field on the line.
	KeyID string

	// Backend is the optional fourth field, naming how the private key is held.
	//
	// It is advisory and local: the host records what the administrator wrote down, so that
	// "ops-laptop (file)" reads differently from "ops-yubikey-1 (PKCS#11)" in the audit log. Nothing
	// verifies it, because nothing can — a signature carries no evidence of where it was produced.
	// Recording the administrator's own annotation is honest; asking the signing tool and believing
	// the answer would not be.
	Backend string

	// Key is the parsed public key.
	Key crypto.PublicKey

	// Encoded is the base64 field exactly as it appeared, for round-tripping and display.
	Encoded string
}

// String renders the key for logs and the UI as "key-id (backend)".
func (k PublicKey) String() string {
	if k.Backend == "" {
		return k.KeyID
	}
	return k.KeyID + " (" + k.Backend + ")"
}

// Verify reports whether this key produced sig over payload.
//
// payload is the canonical JSON of the job, not a digest of it. That is a requirement on the wire
// format rather than a preference: if the operator's signing tool signed an opaque digest supplied by
// the server, a compromised control plane could display one operation in the browser and have a
// different one signed. See docs/PROTOCOL.md §8.
func (k PublicKey) Verify(payload, sig []byte) bool {
	switch key := k.Key.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(key, payload, sig)
	case *ecdsa.PublicKey:
		// ECDSA signs a digest, unlike Ed25519, which hashes internally. Doing it here rather than at
		// the call site keeps the caller from having to know which algorithm it is holding.
		sum := sha256.Sum256(payload)
		return ecdsa.VerifyASN1(key, sum[:], sig)
	default:
		return false
	}
}

// ParsePublicKey decodes a base64 public key of the given algorithm.
//
// Three encodings are accepted for each algorithm: the OpenSSH wire format, DER SubjectPublicKeyInfo,
// and — for Ed25519 — the bare 32-byte key. Being permissive here is deliberate and costs nothing,
// because all three decode to the same key or to an error. An administrator pasting a line should not
// have to know which of the two obvious formats their tool emitted, and the alternative is a fleet
// where half the hosts have a subtly different file.
func ParsePublicKey(alg Algorithm, encoded string) (crypto.PublicKey, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, alg)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("signing: key is not valid base64: %w", err)
	}

	if key, err := parseSSHWireFormat(raw); err == nil {
		return matchAlgorithm(alg, key)
	}
	if key, err := x509.ParsePKIXPublicKey(raw); err == nil {
		return matchAlgorithm(alg, key)
	}
	if alg == Ed25519 && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("signing: %s key is not in OpenSSH, DER SubjectPublicKeyInfo or raw form", alg)
}

// parseSSHWireFormat decodes an OpenSSH public key blob into a crypto key.
//
// The OpenSSH format is accepted because trusted-signers is deliberately close to authorized_keys, and
// because operators already have tooling that emits it — ssh-keygen, ssh-add -L, every cloud console's
// key page. Refusing it would make the first step of adopting Farrier a format conversion.
func parseSSHWireFormat(blob []byte) (crypto.PublicKey, error) {
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, err
	}
	cryptoKey, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("signing: OpenSSH key does not expose an underlying crypto key")
	}
	return cryptoKey.CryptoPublicKey(), nil
}

// matchAlgorithm checks that a decoded key is the type its algorithm tag claims.
//
// A mismatch is rejected rather than corrected. The tag is what the verifier dispatches on, so a line
// tagged ed25519 carrying a P-256 key is a file whose meaning depends on which of the two the reader
// believes, and that ambiguity is worth an error.
func matchAlgorithm(alg Algorithm, key crypto.PublicKey) (crypto.PublicKey, error) {
	switch alg {
	case Ed25519:
		k, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("signing: key is tagged %s but is a %T", alg, key)
		}
		return k, nil
	case ECDSAP256:
		k, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("signing: key is tagged %s but is a %T", alg, key)
		}
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("signing: key is tagged %s but uses curve %s", alg, k.Curve.Params().Name)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, alg)
	}
}

// EncodePublicKey renders a public key in the base64 form trusted-signers uses.
//
// It emits DER SubjectPublicKeyInfo for both algorithms, which is the form every backend can produce
// and every language can read. The parser accepts the OpenSSH form too, but what this project writes
// out is the one that does not depend on an SSH library being available.
func EncodePublicKey(key crypto.PublicKey) (Algorithm, string, error) {
	var alg Algorithm
	switch k := key.(type) {
	case ed25519.PublicKey:
		alg = Ed25519
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", "", fmt.Errorf("signing: unsupported curve %s", k.Curve.Params().Name)
		}
		alg = ECDSAP256
	default:
		return "", "", fmt.Errorf("signing: unsupported key type %T", key)
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", "", fmt.Errorf("signing: encoding public key: %w", err)
	}
	return alg, base64.StdEncoding.EncodeToString(der), nil
}

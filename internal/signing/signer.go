package signing

import (
	"context"
	"crypto"
	"fmt"
)

// Signer produces a detached signature over the canonical job payload.
//
// It is an interface with an open-ended set of implementations, and that openness is safe for one
// specific reason: the verifier never changes. The agent only ever sees a public key and a signature
// over a canonical payload, and cannot learn — or care — which backend produced it. Adding a backend is
// therefore purely client-side and cannot widen the agent's attack surface by a single branch.
//
// This is the one place in Farrier where an open-ended plugin-shaped list is acceptable, and the reason
// is worth stating next to the interface rather than only in docs/EXTENDING.md: everything that runs on
// a managed host is compile-time closed, and this runs on the operator's own machine.
//
// Backends: file is implemented. sshagent, pkcs11, gpgagent and kms are specified in
// docs/EXTENDING.md and not yet written. The path a signature travels is complete — the control plane
// accepts one on POST /api/v1/jobs, an agent verifies it against the host's own trusted-signers, and a
// root helper acts on it — so what these backends lack is not somewhere to go but `farrier sign`, the
// command that would drive them. They arrive with it, because shipping a backend that cannot be
// exercised end to end would be shipping untested code into the one path where being wrong is
// unrecoverable. No token vendor is hard-coded
// anywhere — pkcs11 will cover YubiKey PIV, Nitrokey and SoftHSM alike, and kms will cover AWS, GCP
// and Azure.
type Signer interface {
	// KeyID returns the identity that must appear in the host's trusted-signers file.
	//
	// It is what the audit log records, which is why the signer supplies it rather than having the
	// server infer it from the key: an operator should be able to see "ops-yubikey-1" in the log
	// without anyone having to reverse a fingerprint six months later.
	KeyID() string

	// Algorithm reports which signature algorithm this signer produces.
	Algorithm() Algorithm

	// Public returns the public key, for writing a trusted-signers line.
	Public() crypto.PublicKey

	// Backend names how the private key is held, for display: "file", "pkcs11", "kms".
	//
	// It exists because "signed by ops-laptop (file)" must read differently from "signed by
	// ops-yubikey-1 (PKCS#11)". File-based keys are supported without a lecture — refusing them would
	// not make anyone buy a token, it would push them to keep the key on the control plane instead,
	// which is strictly worse — but the difference should be visible to whoever reviews the log.
	Backend() string

	// Sign produces a detached signature over the canonical payload.
	//
	// The payload is the full canonical JSON of the job, never a digest supplied by the server. A
	// signer that signed an opaque digest would let a compromised control plane display one operation
	// in the browser and have a different one signed, which is why this is a requirement on the wire
	// format and not a convention of the CLI.
	//
	// The context is honoured because hardware backends block: a touch-required token waits for a
	// human finger, and an operator who changes their mind should be able to press Ctrl-C.
	Sign(ctx context.Context, payload []byte) ([]byte, error)

	// Close releases whatever the backend holds open — a token session, an agent connection, a key in
	// memory.
	Close() error
}

// TrustedSignerLine renders the trusted-signers file line for a signer's public key.
//
// It exists so that an operator setting up a host runs one command and pastes one line, rather than
// deriving the encoding themselves. Getting that wrong produces a host that refuses every job for a
// reason the error message cannot explain.
func TrustedSignerLine(s Signer) (string, error) {
	alg, encoded, err := EncodePublicKey(s.Public())
	if err != nil {
		return "", err
	}
	line := string(alg) + " " + encoded + " " + s.KeyID()
	if b := s.Backend(); b != "" {
		line += " " + b
	}
	return line, nil
}

// SelfCheck verifies a signature a backend has just produced, against that backend's own public key.
//
// It exists because of one failure mode, and it is the one every remote key store walks into. A
// PKCS#11 token returns ECDSA as a raw r‖s pair and Azure Key Vault returns it base64url-encoded, and
// the wire format is ASN.1 DER; a digest sent where the payload was meant produces a signature over
// the wrong bytes. None of that fails at the signer. It fails on every host in the fleet, as
// ErrNoTrustedSigner — "no key produced this signature" — which reads to an operator as a broken key
// or a wrong trust anchor, days after the fact, on machines they cannot easily inspect.
//
// Checking locally costs a verification and turns the whole class into an error at the terminal of the
// person who ran the command. Both issue #22 and issue #23 ask for exactly this in words: the failure
// when a backend cannot produce what is needed must say so, rather than surfacing as a signature that
// does not verify.
//
// It proves the encoding, not the key custody. A backend that signed with the wrong key would pass
// this and fail on a host, which is correct: what a host trusts is its own trusted-signers file and
// nothing here can or should second-guess it.
func SelfCheck(s Signer, payload, signature []byte) error {
	key := PublicKey{Algorithm: s.Algorithm(), KeyID: s.KeyID(), Key: s.Public()}
	if key.Verify(payload, signature) {
		return nil
	}
	return fmt.Errorf("signing: the %s backend produced a signature that does not verify against its "+
		"own public key for %s. It has not been used, because a host would have refused it as coming "+
		"from no trusted signer — which would have looked like a broken trust anchor rather than an "+
		"encoding fault here", s.Backend(), s.KeyID())
}

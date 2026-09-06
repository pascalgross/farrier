// Package kms implements the cloud key-store signing backend, for AWS KMS, Google Cloud KMS and Azure
// Key Vault.
//
// It exists for the organisation that already runs its signing through a key store: the key custody,
// the audit trail and the access review are the ones they already have, which is a better answer than
// "put a file on a laptop" for anybody with a compliance story, and the only answer at all for a fleet
// with no laptop to put a key on.
//
// # The caveat, stated where the code is rather than only in a document
//
// A KMS key is reachable by whoever holds the cloud credentials. If the control plane runs in the same
// account and can assume a role that reaches the signing key, then an attacker who owns the control
// plane owns the destructive tier, and the guarantee in docs/SECURITY.md §1 is false for that
// installation. That is not something this code can check or enforce: a hardware token (issue #22)
// keeps the control plane away from the key by physics, and a KMS does it by IAM policy, which is a
// weaker thing that people misconfigure. docs/SECURITY.md §9 and §10 say so in the sections that exist
// for exactly that kind of statement.
//
// # No vendor SDK
//
// Three providers, three stdlib HTTP clients, no new module. That is a deliberate trade and the reason
// is proportion: the SDKs would take this binary's dependency graph from six external modules to
// fifty-seven, to make three HTTPS POSTs. What they would buy is credential chains — SSO, federation,
// the several shapes of managed identity — and the escape hatch for all of those is one command that
// exports a credential into the environment, documented in docs/INSTALL.md rather than implemented
// here. For a tool whose whole argument is about how little it contains, and which holds the authority
// the first paragraph of the guarantee rests on, that is the right way round.
package kms

import (
	"context"
	"crypto"
	"fmt"

	"github.com/pascalgross/hostseal/internal/signing"
	"github.com/pascalgross/hostseal/internal/signing/backend"
)

// BearerTokenEnv supplies a bearer token directly, bypassing credential discovery.
//
// The escape hatch for the credential flows this package deliberately does not implement — workload
// identity federation, SSO, an impersonation chain, a corporate token broker. An operator runs their
// cloud's own CLI, exports what it prints, and signs. It is honoured by the two providers that
// authenticate with a bearer token; AWS needs no equivalent because its three environment variables
// already are one.
//
// The token's audience has to match the provider being used. Only one provider is active per
// invocation, so a single variable is unambiguous.
//
// the *name of an environment variable*; the credential is whatever an operator puts in it.
//
//nolint:gosec // G101 sees a constant whose name ends in "TOKEN" and assumes a credential. This is
const BearerTokenEnv = "HOSTSEAL_KMS_BEARER_TOKEN"

// provider is one cloud's key store, reduced to the two questions a signer asks.
//
// An interface rather than a switch, because the three differ in every detail that matters — who
// hashes, which base64 alphabet, whether a signature comes back as DER or as a raw pair, whether the
// public key arrives as DER, as PEM or as a JWK — and a shape general enough to cover that by
// configuration would be a templating language with a field-path extractor in front of it. That is the
// thing docs/EXTENDING.md names as the pattern this project declines.
type provider interface {
	// name is the cloud, for error messages and for the confirmation screen.
	name() string

	// publicKey fetches the key a host will verify against, and the algorithm it implies.
	//
	// The algorithm comes from the key rather than from the reference, so a reference cannot claim
	// ed25519 for a P-256 key — and a key this build cannot carry is refused here, before anything is
	// signed, with a message naming what it actually is.
	publicKey(ctx context.Context) (crypto.PublicKey, signing.Algorithm, error)

	// sign produces a signature over the canonical payload, in the encoding the wire format wants.
	sign(ctx context.Context, alg signing.Algorithm, payload []byte) ([]byte, error)

	// reference renders the key's resource name, for the confirmation screen.
	//
	// An operator about to authorise a reboot should see which account's key is about to sign it,
	// because that — not the algorithm, not the backend — is the thing this backend's caveat is about.
	reference() string
}

// init registers the three provider schemes.
//
// Three schemes rather than one "kms:" with a provider inside it, because awskms:, gcpkms: and
// azurekms: are what cosign already uses and an operator who has signed a container image has seen
// them. A single scheme would put five colons in an AWS reference and make the reader count them.
func init() {
	for _, scheme := range []string{awsScheme, gcpScheme, azureScheme} {
		backend.Register(backend.Backend{
			Scheme:  scheme,
			Open:    openWith(scheme),
			Inspect: inspectWith(scheme),
		})
	}
}

// Signer is a signing.Signer backed by a key in a cloud key store.
type Signer struct {
	// prov is the cloud this key lives in.
	prov provider

	// keyID is the identity recorded in the audit log and listed in trusted-signers.
	keyID string

	// algorithm is resolved from the key when it is opened, because Algorithm cannot report a failure.
	algorithm signing.Algorithm

	// public is the key a host will verify against.
	public crypto.PublicKey
}

// openWith builds the Open function for one provider scheme.
func openWith(scheme string) func(context.Context, string, backend.PassphraseFunc) (signing.Signer, error) {
	return func(ctx context.Context, ref string, _ backend.PassphraseFunc) (signing.Signer, error) {
		return Open(ctx, scheme, ref)
	}
}

// inspectWith builds the Inspect function for one provider scheme.
func inspectWith(scheme string) func(context.Context, string, backend.PassphraseFunc) (signing.PublicKey, error) {
	return func(ctx context.Context, ref string, _ backend.PassphraseFunc) (signing.PublicKey, error) {
		signer, err := Open(ctx, scheme, ref)
		if err != nil {
			return signing.PublicKey{}, err
		}
		alg, encoded, err := signing.EncodePublicKey(signer.Public())
		if err != nil {
			return signing.PublicKey{}, err
		}
		return signing.PublicKey{
			Algorithm: alg,
			KeyID:     signer.KeyID(),
			Backend:   Backend,
			Key:       signer.Public(),
			Encoded:   encoded,
		}, nil
	}
}

// Backend is what this backend calls itself in a trusted-signers line and in the audit log.
//
// One word for all three clouds. The line's fourth field is the administrator's own annotation about
// how a key is held — nothing verifies it, because nothing can — and "kms" is the true answer to that
// question for every provider here. Which cloud is a property of the reference, and the reference is
// on the operator's screen when they sign.
const Backend = "kms"

// Open resolves a reference to a signer, fetching the key's public half on the way.
//
// Everything that can fail does so here: the reference is parsed, the credential found, the public key
// fetched and the algorithm settled. That is what lets Algorithm and Public have no error return, and
// it is what turns "this key is RSA" into a message before the operator is asked to confirm anything
// rather than into a signature no host accepts.
func Open(ctx context.Context, scheme, ref string) (*Signer, error) {
	resource, keyID := backend.SplitKeyID(ref)
	if keyID == "" {
		return nil, fmt.Errorf("kms: the reference needs a #key-id — the identity this key is listed "+
			"under in every host's trusted-signers and recorded under in the audit log. A resource name "+
			"is not one: write %s:%s#ops-kms-1", scheme, resource)
	}
	if err := backend.ValidateKeyID(keyID); err != nil {
		return nil, err
	}

	prov, err := newProvider(scheme, resource)
	if err != nil {
		return nil, err
	}
	public, algorithm, err := prov.publicKey(ctx)
	if err != nil {
		return nil, err
	}
	return &Signer{prov: prov, keyID: keyID, algorithm: algorithm, public: public}, nil
}

// newProvider builds the client for one scheme.
func newProvider(scheme, resource string) (provider, error) {
	switch scheme {
	case awsScheme:
		return newAWS(resource)
	case gcpScheme:
		return newGCP(resource)
	case azureScheme:
		return newAzure(resource)
	default:
		return nil, fmt.Errorf("kms: %q is not a key-store scheme", scheme)
	}
}

// KeyID returns the identity that must appear in a host's trusted-signers file.
func (s *Signer) KeyID() string { return s.keyID }

// Algorithm reports which signature algorithm this signer produces.
func (s *Signer) Algorithm() signing.Algorithm { return s.algorithm }

// Public returns the public key, for writing a trusted-signers line.
func (s *Signer) Public() crypto.PublicKey { return s.public }

// Backend names how the private key is held, for display in the audit log.
func (s *Signer) Backend() string { return Backend }

// Reference renders the key's resource name, for the confirmation the operator reads before signing.
func (s *Signer) Reference() string { return s.prov.name() + " " + s.prov.reference() }

// Sign produces a detached signature over the canonical payload.
//
// The context is honoured for a reason that is not hypothetical here: this is a network call, and a
// key store having a bad afternoon must not leave `hostseal sign` hanging with no way out.
//
// The result is verified against this signer's own public key before it is returned, and that check
// earns its place three times over in this package. Azure returns ECDSA as a raw r‖s pair where the
// wire format is DER; AWS wants a digest for one algorithm and the whole payload for another; every
// provider has its own base64 alphabet. Each of those mistakes produces a well-formed signature that
// no host will accept, reported days later as a trust anchor that has stopped working. Checking here
// costs microseconds and puts the error in front of the person who can fix it.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	signature, err := s.prov.sign(ctx, s.algorithm, payload)
	if err != nil {
		return nil, err
	}
	if err := signing.SelfCheck(s, payload, signature); err != nil {
		return nil, err
	}
	return signature, nil
}

// Close releases nothing.
//
// There is no session to end and no key material held: every call is a fresh HTTPS request against a
// key that never leaves the provider. The method exists because signing.Signer has it, and saying so
// is better than an empty body a reader has to wonder about.
func (s *Signer) Close() error { return nil }

// unsupportedAlgorithm reports a key this build cannot carry, naming what it is.
//
// One function so every provider refuses in the same words. Issue #23 asks for exactly this: fail with
// a message naming the mismatch rather than producing something that will not verify on a host.
func unsupportedAlgorithm(provider, what string) error {
	return fmt.Errorf("kms: %s reports this key as %s, and HostSeal's wire format carries ed25519 and "+
		"ecdsa-p256 only. Create a key of one of those types; docs/EXTENDING.md explains why ecdsa-p256 "+
		"exists, and it is the one every provider here can do", provider, what)
}

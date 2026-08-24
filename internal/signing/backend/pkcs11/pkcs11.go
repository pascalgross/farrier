// Package pkcs11 implements the hardware-token signing backend, over any PKCS#11 module.
//
// It exists because the file backend keeps the destructive key in a passphrase-protected file on an
// operator's laptop. That is a real improvement over a shared credential and it is still a file: it
// can be copied, and neither the operator nor anybody else would know. A key on a token cannot be, and
// that changes what a stolen laptop means — which matters most in this tier, because the first
// paragraph of docs/SECURITY.md §1 rests on a key the control plane does not hold.
//
// No vendor is hard-coded. One implementation covers YubiKey PIV, Nitrokey and SoftHSM, because all
// three are PKCS#11 modules and the key is named with an RFC 7512 URI, which is what every other tool
// that talks to a token already speaks.
//
// The agent learns nothing from any of this. It verifies a signature against a key in its own
// trusted-signers and cannot tell which backend produced it, which is why an open-ended set of
// backends is safe here and nowhere else in Farrier.
package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"

	"github.com/pascalgross/farrier/internal/signing"
	"github.com/pascalgross/farrier/internal/signing/backend"
)

// maxMatches bounds an object search.
//
// Two, not one, so that an ambiguous reference is discovered and reported rather than silently
// resolved to whichever key the module happened to return first. A tool that authorises reboots must
// not guess which key an operator meant.
const maxMatches = 2

// p256Params is the DER encoding of the prime256v1 object identifier, as CKA_EC_PARAMS carries it.
//
// Compared as bytes rather than parsed, because that is what a token returns and because the
// comparison is exact either way. 1.2.840.10045.3.1.7.
var p256Params = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

// edwards25519Params are the two spellings of Ed25519's CKA_EC_PARAMS.
//
// Both are seen in the wild and both are legitimate: PKCS#11 v3.0 permits the OID 1.3.101.112, and
// SoftHSM 2.6 returns a DER PrintableString "edwards25519" instead. Accepting one would refuse the
// module the CI tests run against, or every module that follows the newer specification.
var edwards25519Params = [][]byte{
	{0x06, 0x03, 0x2b, 0x65, 0x70},
	append([]byte{0x13, 0x0c}, []byte("edwards25519")...),
}

// init registers this backend under the "pkcs11" scheme.
func init() {
	backend.Register(backend.Backend{
		Scheme:  Scheme,
		Open:    open,
		Inspect: inspect,
	})
}

// Signer is a signing.Signer backed by a key on a PKCS#11 token.
type Signer struct {
	// mu serialises token use. A PKCS#11 session is a single conversation, and Close must not be able
	// to pull one out from under a signature that is still in progress.
	mu sync.Mutex

	// mod is the loaded module.
	mod *module

	// session is the open, logged-in session.
	session ckULong

	// private is the handle of the key that signs.
	private ckULong

	// keyID is the identity recorded in the audit log.
	keyID string

	// algorithm is resolved when the token is opened, because Algorithm cannot report a failure.
	algorithm signing.Algorithm

	// public is the key a host will verify against.
	public crypto.PublicKey

	// closed reports whether Close has run, so that a signature after it fails with a sentence rather
	// than by calling into a finalised module.
	closed bool
}

// open resolves a PKCS#11 URI to a logged-in signer.
//
// Everything that can fail does so here rather than at signing time: the module is loaded, the token
// found, the PIN taken, the key located and its algorithm resolved. That ordering is what lets
// Algorithm and Public have no error return, and it is also the better experience — an operator learns
// that their reference is wrong before they are asked to touch the token, not after.
func open(_ context.Context, ref string, prompt backend.PassphraseFunc) (signing.Signer, error) {
	parsed, err := parseURI(ref)
	if err != nil {
		return nil, err
	}

	mod, err := openModule(parsed.modulePath)
	if err != nil {
		return nil, err
	}
	args := ckInitializeArgs{flags: ckfOSLockingOK}
	if err := check("C_Initialize", mod.initialize(pointerTo(&args))); err != nil {
		mod.close()
		return nil, err
	}

	slot, err := findSlot(mod, parsed)
	if err != nil {
		finalize(mod)
		return nil, err
	}
	session, err := mod.openSessionOn(slot)
	if err != nil {
		finalize(mod)
		return nil, err
	}

	pin, err := readPIN(parsed, prompt)
	if err != nil {
		closeSession(mod, session)
		return nil, err
	}
	if err := mod.loginUser(session, pin); err != nil {
		closeSession(mod, session)
		return nil, err
	}

	signer, err := resolveKey(mod, session, parsed)
	if err != nil {
		closeSession(mod, session)
		return nil, err
	}
	return signer, nil
}

// inspect reads a token's public key and renders its trusted-signers entry.
//
// It opens the token exactly as signing does and then signs nothing. That is more ceremony than the
// file backend needs for the same question, and it is what a token requires: the public object is
// often readable without a login and often is not, and a `farrier key show` that worked on one vendor
// and silently returned nothing on another would send an operator looking for a fault in their key.
func inspect(ctx context.Context, ref string, prompt backend.PassphraseFunc) (signing.PublicKey, error) {
	signer, err := open(ctx, ref, prompt)
	if err != nil {
		return signing.PublicKey{}, err
	}
	defer func() { _ = signer.Close() }()

	alg, encoded, err := signing.EncodePublicKey(signer.Public())
	if err != nil {
		return signing.PublicKey{}, err
	}
	return signing.PublicKey{
		Algorithm: alg,
		KeyID:     signer.KeyID(),
		Backend:   Scheme,
		Key:       signer.Public(),
		Encoded:   encoded,
	}, nil
}

// findSlot picks the slot the reference names.
//
// An unqualified reference is accepted only when exactly one token is present. Choosing the first of
// several would make the same command sign with a different key depending on what else was plugged
// in, which is not a property a tool that authorises reboots should have.
func findSlot(mod *module, parsed uri) (ckULong, error) {
	slots, err := mod.slots()
	if err != nil {
		return 0, err
	}
	if len(slots) == 0 {
		return 0, fmt.Errorf("pkcs11: %s reports no slot with a token in it", parsed.modulePath)
	}

	if parsed.slotID >= 0 {
		for _, slot := range slots {
			if slot == ckULong(parsed.slotID) {
				return slot, nil
			}
		}
		return 0, fmt.Errorf("pkcs11: slot %d holds no token; the slots with one are %v",
			parsed.slotID, slots)
	}

	if parsed.token == "" {
		if len(slots) == 1 {
			return slots[0], nil
		}
		return 0, fmt.Errorf("pkcs11: %d tokens are present and the reference names none; "+
			"add token=<label> or slot-id=<n>", len(slots))
	}

	var labels []string
	for _, slot := range slots {
		label, labelErr := mod.tokenLabel(slot)
		if labelErr != nil {
			return 0, labelErr
		}
		if label == parsed.token {
			return slot, nil
		}
		labels = append(labels, label)
	}
	return 0, fmt.Errorf("pkcs11: no token is labelled %q; the tokens present are %q",
		parsed.token, labels)
}

// readPIN takes the token's PIN from a file or from the operator.
func readPIN(parsed uri, prompt backend.PassphraseFunc) ([]byte, error) {
	if parsed.pinSource != "" {
		raw, err := os.ReadFile(parsed.pinSource)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: reading pin-source %s: %w", parsed.pinSource, err)
		}
		// Trailing whitespace only: a PIN may legitimately contain spaces, and a file written with a
		// heredoc or an editor ends in a newline that is not part of it.
		return []byte(strings.TrimRight(string(raw), " \t\r\n")), nil
	}
	if prompt == nil {
		return nil, fmt.Errorf("pkcs11: no PIN and no way to ask for one; " +
			"add pin-source=/path/to/file to the reference")
	}
	return prompt("PIN for " + describeToken(parsed) + ": ")
}

// describeToken names a token for a prompt, in the words the operator wrote.
func describeToken(parsed uri) string {
	switch {
	case parsed.token != "":
		return "token " + parsed.token
	case parsed.slotID >= 0:
		return fmt.Sprintf("slot %d", parsed.slotID)
	default:
		return "the token"
	}
}

// resolveKey finds the private key, reads its public half, and settles the algorithm.
func resolveKey(mod *module, session ckULong, parsed uri) (*Signer, error) {
	private, err := findOne(mod, session, ckoPrivateKey, parsed)
	if err != nil {
		return nil, err
	}
	public, err := findOne(mod, session, ckoPublicKey, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w\nThe private key was found; its public half is what a host verifies "+
			"against, so it has to be readable too", err)
	}

	keyType, err := mod.attributeULong(session, public, ckaKeyType)
	if err != nil {
		return nil, err
	}
	params, err := mod.attribute(session, public, ckaECParams)
	if err != nil {
		return nil, err
	}
	point, err := mod.attribute(session, public, ckaECPoint)
	if err != nil {
		return nil, err
	}

	algorithm, key, err := decodeKey(keyType, params, point)
	if err != nil {
		return nil, err
	}
	return &Signer{
		mod: mod, session: session, private: private,
		keyID: parsed.keyID(), algorithm: algorithm, public: key,
	}, nil
}

// findOne locates exactly one object of a class matching the reference.
func findOne(mod *module, session, class ckULong, parsed uri) (ckULong, error) {
	classValue := class
	template := []ckAttribute{{
		kind: ckaClass, value: pointerTo(&classValue), valueLen: ckULong(sizeOfULong),
	}}
	if parsed.object != "" {
		label := []byte(parsed.object)
		template = append(template, ckAttribute{
			kind: ckaLabel, value: pointerTo(&label[0]), valueLen: ckULong(len(label)),
		})
	}
	if len(parsed.id) > 0 {
		id := parsed.id
		template = append(template, ckAttribute{
			kind: ckaID, value: pointerTo(&id[0]), valueLen: ckULong(len(id)),
		})
	}

	handles, err := mod.find(session, template, maxMatches)
	if err != nil {
		return 0, err
	}
	switch len(handles) {
	case 0:
		return 0, fmt.Errorf("pkcs11: the token holds no %s matching this reference", className(class))
	case 1:
		return handles[0], nil
	default:
		return 0, fmt.Errorf("pkcs11: more than one %s matches this reference; "+
			"narrow it with object=<label> or id=<hex>", className(class))
	}
}

// className renders an object class for an error message.
func className(class ckULong) string {
	if class == ckoPrivateKey {
		return "private key"
	}
	return "public key"
}

// decodeKey turns a token's attributes into one of the two algorithms the wire carries.
//
// The refusal is the part worth care. A key this build cannot carry has to fail here, naming what it
// is, rather than producing a signature no host will verify: docs/PROTOCOL.md fixes the wire format at
// ed25519 and ecdsa-p256, and the agent dispatches on the key type it parsed rather than on any
// algorithm tag it was sent — so an RSA key would sign happily and then be reported by every host as
// a key that does not verify, which reads as a broken trust anchor.
func decodeKey(keyType ckULong, params, point []byte) (signing.Algorithm, crypto.PublicKey, error) {
	raw, err := unwrapECPoint(point)
	if err != nil {
		return "", nil, err
	}

	switch keyType {
	case ckkEC:
		if !bytesEqual(params, p256Params) {
			return "", nil, fmt.Errorf("pkcs11: this key is on an elliptic curve Farrier does not "+
				"carry (CKA_EC_PARAMS %x). The wire format is ed25519 and ecdsa-p256; generate a "+
				"P-256 key on the token, or use an Ed25519 one", params)
		}
		key, parseErr := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
		if parseErr != nil {
			return "", nil, fmt.Errorf("pkcs11: the token's CKA_EC_POINT is not a P-256 point: %w", parseErr)
		}
		return signing.ECDSAP256, key, nil

	case ckkECEdwards:
		known := false
		for _, candidate := range edwards25519Params {
			if bytesEqual(params, candidate) {
				known = true
			}
		}
		if !known {
			return "", nil, fmt.Errorf("pkcs11: this Edwards key names a curve Farrier does not carry "+
				"(CKA_EC_PARAMS %x); only Ed25519 is on the wire", params)
		}
		if len(raw) != ed25519.PublicKeySize {
			return "", nil, fmt.Errorf("pkcs11: the token's Ed25519 point is %d bytes, expected %d",
				len(raw), ed25519.PublicKeySize)
		}
		return signing.Ed25519, ed25519.PublicKey(raw), nil

	case ckkRSA:
		return "", nil, fmt.Errorf("pkcs11: this key is RSA, and Farrier's wire format carries " +
			"ed25519 and ecdsa-p256 only. A YubiKey PIV slot holding an RSA key needs a new key pair " +
			"generated as ECCP256 before it can authorise anything here")

	default:
		return "", nil, fmt.Errorf("pkcs11: this key's CKA_KEY_TYPE is 0x%X, which is neither "+
			"CKK_EC nor CKK_EC_EDWARDS; Farrier carries ed25519 and ecdsa-p256 only", keyType)
	}
}

// unwrapECPoint takes the elliptic-curve point out of the DER OCTET STRING a token wraps it in.
//
// The specification says CKA_EC_POINT is a DER-encoded OCTET STRING around the X9.62 point, and most
// modules do that. A few return the bare point. Trying the wrapper first and falling back keeps both
// working, and neither reading can be mistaken for the other: a bare uncompressed P-256 point starts
// 0x04 0x04… only if it is 65 bytes long and its second byte is 0x04, which the DER form is not.
func unwrapECPoint(point []byte) ([]byte, error) {
	if len(point) == 0 {
		return nil, errors.New("pkcs11: the token returned no CKA_EC_POINT for this key")
	}
	var wrapped []byte
	if rest, err := asn1.Unmarshal(point, &wrapped); err == nil && len(rest) == 0 {
		return wrapped, nil
	}
	return point, nil
}

// bytesEqual compares two byte slices.
//
// Its own function rather than bytes.Equal so that this file imports nothing whose name could be
// confused with the constant-time comparisons elsewhere in the signing path: these are public
// parameters and there is nothing here to leak.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// KeyID returns the identity that must appear in a host's trusted-signers file.
func (s *Signer) KeyID() string { return s.keyID }

// Algorithm reports which signature algorithm this signer produces.
func (s *Signer) Algorithm() signing.Algorithm { return s.algorithm }

// Public returns the public key, for writing a trusted-signers line.
func (s *Signer) Public() crypto.PublicKey { return s.public }

// Backend names how the private key is held, for display in the audit log.
func (s *Signer) Backend() string { return Scheme }

// Sign produces a detached signature over the canonical payload.
//
// Two things happen here that the file backend does not need.
//
// The token call runs on its own goroutine and the context is watched beside it, because PKCS#11 has
// no cancellation: C_Sign on a touch-required token blocks until somebody puts a finger on it. What
// this gives an operator is honest and worth stating plainly — Ctrl-C returns control to them; the
// token may still complete the operation. The signature that results is discarded and never leaves
// this machine, so a cancelled signature authorises nothing.
//
// And the signature is verified against this signer's own public key before it is returned. A token
// returns ECDSA as a raw r‖s pair while the wire format is ASN.1 DER, and an unconverted signature
// would be reported by every host as a key that does not verify — which reads as a broken trust
// anchor rather than as an encoding bug in this file. Checking costs microseconds and turns the whole
// class into an error at the operator's terminal.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	type outcome struct {
		// signature is what the token produced, already in the wire's encoding.
		signature []byte

		// err is why it did not.
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		signature, err := s.signOnToken(payload)
		done <- outcome{signature: signature, err: err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			return nil, result.err
		}
		if err := signing.SelfCheck(s, payload, result.signature); err != nil {
			return nil, err
		}
		return result.signature, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// signOnToken is the part that talks to the token, under the session lock.
func (s *Signer) signOnToken(payload []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errors.New("pkcs11: this signer has been closed")
	}
	switch s.algorithm {
	case signing.Ed25519:
		// The payload itself: Ed25519 hashes internally, and CKM_EDDSA in its default mode is pure
		// Ed25519 over what it is given.
		return s.mod.signData(s.session, s.private, ckmEDDSA, payload)

	case signing.ECDSAP256:
		digest := sha256.Sum256(payload)
		raw, err := s.mod.signData(s.session, s.private, ckmECDSA, digest[:])
		if err != nil {
			return nil, err
		}
		return derFromRS(raw)

	default:
		return nil, fmt.Errorf("pkcs11: %w: %q", signing.ErrUnknownAlgorithm, s.algorithm)
	}
}

// derFromRS re-encodes a token's raw ECDSA signature as the ASN.1 DER the wire format carries.
//
// CKM_ECDSA returns r and s as two fixed-width big-endian halves, each the curve's byte length;
// crypto/ecdsa's VerifyASN1 — which is what a host runs — expects a DER SEQUENCE of two INTEGERs.
// This is the single most likely bug in a PKCS#11 backend and the one that would surface on a fleet
// rather than here, so the length is checked exactly rather than accommodated: a token that returned
// something else is a fault worth naming, not a shape to guess at.
func derFromRS(raw []byte) ([]byte, error) {
	const half = 32
	if len(raw) != 2*half {
		return nil, fmt.Errorf("pkcs11: the token returned a %d-byte ECDSA signature, expected %d "+
			"(a P-256 r‖s pair)", len(raw), 2*half)
	}
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, errors.New("pkcs11: the token returned an ECDSA signature with a zero component")
	}
	der, err := asn1.Marshal(struct {
		// R and S are the signature's two halves, DER INTEGERs.
		R, S *big.Int
	}{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: re-encoding the token's signature: %w", err)
	}
	return der, nil
}

// Close logs out, closes the session and unloads the module.
//
// It takes the session lock first, so a signature the operator interrupted cannot have the token
// pulled out from under it: the call is still running on the token, and finalising the module
// underneath it is how a process crashes in a vendor library rather than in Go.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	closeSession(s.mod, s.session)
	return nil
}

// closeSession logs out and tears down a module, in the order the specification wants.
func closeSession(mod *module, session ckULong) {
	// Every step is best effort. This runs on failure paths, where the module may already be in a
	// state that refuses one of them, and a teardown that stopped at the first error would leave the
	// library loaded and the session open — which is worse than the error it reported.
	_ = mod.logout(session)
	_ = mod.closeSession(session)
	finalize(mod)
}

// finalize shuts down and unloads a module.
func finalize(mod *module) {
	_ = mod.finalize(nil)
	mod.close()
}

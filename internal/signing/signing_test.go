package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testKey is a generated key pair with everything the tests need to build fixtures from it.
//
// It exists so that each test states what it is asserting rather than restating key generation, and so
// that every case runs against a freshly generated key rather than a constant somebody might later be
// tempted to reuse as a real one.
type testKey struct {
	// algorithm is the wire tag.
	algorithm Algorithm

	// public is the verifying half.
	public any

	// signRaw produces a signature over a payload in the form this algorithm uses on the wire.
	signRaw func(payload []byte) []byte

	// derBase64 is the DER SubjectPublicKeyInfo encoding, base64.
	derBase64 string

	// sshBase64 is the OpenSSH wire encoding, base64, or "" where not applicable.
	sshBase64 string
}

// newEd25519Key generates an Ed25519 test key in every encoding the parser accepts.
func newEd25519Key(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("encoding Ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("encoding Ed25519 key for SSH: %v", err)
	}
	return testKey{
		algorithm: Ed25519,
		public:    pub,
		signRaw:   func(payload []byte) []byte { return ed25519.Sign(priv, payload) },
		derBase64: base64.StdEncoding.EncodeToString(der),
		sshBase64: base64.StdEncoding.EncodeToString(sshPub.Marshal()),
	}
}

// newECDSAKey generates a P-256 test key in every encoding the parser accepts.
func newECDSAKey(t *testing.T) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating P-256 key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("encoding P-256 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("encoding P-256 key for SSH: %v", err)
	}
	return testKey{
		algorithm: ECDSAP256,
		public:    &priv.PublicKey,
		signRaw: func(payload []byte) []byte {
			sum := sha256.Sum256(payload)
			sig, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
			if err != nil {
				t.Fatalf("signing with P-256: %v", err)
			}
			return sig
		},
		derBase64: base64.StdEncoding.EncodeToString(der),
		sshBase64: base64.StdEncoding.EncodeToString(sshPub.Marshal()),
	}
}

// TestParsePublicKeyAcceptsEveryDocumentedEncoding covers the permissiveness the format promises.
//
// trusted-signers is deliberately close to authorized_keys, so an administrator should be able to
// paste what their tooling produced without knowing whether it emitted OpenSSH or DER. All three forms
// must decode to a key that verifies the same signature.
func TestParsePublicKeyAcceptsEveryDocumentedEncoding(t *testing.T) {
	payload := []byte(`{"intent":"host.reboot"}`)

	for _, k := range []testKey{newEd25519Key(t), newECDSAKey(t)} {
		sig := k.signRaw(payload)
		encodings := map[string]string{"DER": k.derBase64, "OpenSSH": k.sshBase64}
		if k.algorithm == Ed25519 {
			encodings["raw"] = base64.StdEncoding.EncodeToString(k.public.(ed25519.PublicKey))
		}
		for name, encoded := range encodings {
			parsed, err := ParsePublicKey(k.algorithm, encoded)
			if err != nil {
				t.Errorf("%s %s: %v", k.algorithm, name, err)
				continue
			}
			pk := PublicKey{Algorithm: k.algorithm, KeyID: "test", Key: parsed, Encoded: encoded}
			if !pk.Verify(payload, sig) {
				t.Errorf("%s %s: a valid signature did not verify", k.algorithm, name)
			}
			if pk.Verify([]byte(`{"intent":"facts.collect"}`), sig) {
				t.Errorf("%s %s: a signature verified over the wrong payload", k.algorithm, name)
			}
		}
	}
}

// TestParsePublicKeyRejectsMismatchedAlgorithmTags asserts the tag and the key must agree.
//
// The tag is what the verifier dispatches on, so a line tagged ed25519 carrying a P-256 key is a file
// whose meaning depends on which of the two the reader believes. That ambiguity is worth an error.
func TestParsePublicKeyRejectsMismatchedAlgorithmTags(t *testing.T) {
	ed := newEd25519Key(t)
	ec := newECDSAKey(t)

	if _, err := ParsePublicKey(Ed25519, ec.derBase64); err == nil {
		t.Error("a P-256 key tagged ed25519 was accepted")
	}
	if _, err := ParsePublicKey(ECDSAP256, ed.derBase64); err == nil {
		t.Error("an Ed25519 key tagged ecdsa-p256 was accepted")
	}
	if _, err := ParsePublicKey("ed448", ed.derBase64); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("an unknown algorithm produced %v, which does not wrap ErrUnknownAlgorithm", err)
	}
	if _, err := ParsePublicKey(Ed25519, "not base64 at all!"); err == nil {
		t.Error("invalid base64 was accepted")
	}
	if _, err := ParsePublicKey(Ed25519, base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("a five-byte key was accepted")
	}
}

// signersFile builds a trusted-signers file body from lines.
func signersFile(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

// TestParseSignersReadsTheDocumentedFormat covers a well-formed file.
func TestParseSignersReadsTheDocumentedFormat(t *testing.T) {
	ed := newEd25519Key(t)
	ec := newECDSAKey(t)
	body := signersFile(
		"# a comment",
		"",
		"ed25519    "+ed.derBase64+"   ops-laptop        file",
		"ecdsa-p256 "+ec.derBase64+"   ops-yubikey-1     pkcs11",
	)

	set, err := ParseSigners(strings.NewReader(body), "test")
	if err != nil {
		t.Fatalf("ParseSigners: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("parsed %d keys, want 2", set.Len())
	}
	keys := set.Keys()
	if keys[0].String() != "ops-laptop (file)" {
		t.Errorf("first key renders as %q", keys[0].String())
	}
	if keys[1].String() != "ops-yubikey-1 (pkcs11)" {
		t.Errorf("second key renders as %q", keys[1].String())
	}
}

// TestParseSignersRejectsMalformedLines asserts a bad line is an error rather than a skipped line.
//
// Silently ignoring a key an administrator believed they had installed produces a host that refuses
// every job for a reason nobody can see — discovered during the incident the job was meant to fix.
func TestParseSignersRejectsMalformedLines(t *testing.T) {
	ed := newEd25519Key(t)
	cases := map[string]string{
		"missing key id":  "ed25519 " + ed.derBase64,
		"missing key":     "ed25519",
		"too many fields": "ed25519 " + ed.derBase64 + " ops file extra",
		"bad algorithm":   "rsa " + ed.derBase64 + " ops",
		"bad base64":      "ed25519 @@@@ ops",
		"duplicate id": signersFile(
			"ed25519 "+ed.derBase64+" ops",
			"ed25519 "+newEd25519Key(t).derBase64+" ops",
		),
	}
	for name, body := range cases {
		if _, err := ParseSigners(strings.NewReader(body), "test"); err == nil {
			t.Errorf("%s: accepted %q", name, body)
		}
	}
}

// TestGuaranteeAnEmptySignerSetVerifiesNothing is the property a fresh install depends on.
//
// The shipped trusted-signers file is empty, so this is the state every host is in until an
// administrator changes it. No key means no destructive work, no exceptions, and no fallback to
// trusting whoever sent the job.
func TestGuaranteeAnEmptySignerSetVerifiesNothing(t *testing.T) {
	ed := newEd25519Key(t)
	payload := []byte(`{"intent":"host.reboot"}`)
	sig := ed.signRaw(payload)

	for name, set := range map[string]*SignerSet{
		"nil":            nil,
		"empty":          {source: "test"},
		"comments only":  mustParse(t, signersFile("# nothing here", "")),
		"absent on disk": mustLoad(t, t.TempDir()+"/absent"),
	} {
		if !set.Empty() {
			t.Errorf("%s: reported itself non-empty", name)
		}
		if _, err := set.Verify(payload, sig); err == nil {
			t.Errorf("%s: verified a signature with no trusted keys", name)
		} else if !errors.Is(err, ErrNoTrustedSigners) {
			t.Errorf("%s: error %v does not wrap ErrNoTrustedSigners", name, err)
		}
	}
}

// mustParse parses a trusted-signers body or fails the test.
func mustParse(t *testing.T, body string) *SignerSet {
	t.Helper()
	set, err := ParseSigners(strings.NewReader(body), "test")
	if err != nil {
		t.Fatalf("ParseSigners: %v", err)
	}
	return set
}

// mustLoad loads a trusted-signers file from a path or fails the test.
func mustLoad(t *testing.T, path string) *SignerSet {
	t.Helper()
	set, err := LoadSignersFrom(path)
	if err != nil {
		t.Fatalf("LoadSignersFrom(%s): %v", path, err)
	}
	return set
}

// TestVerifyRejectsSignaturesFromUntrustedKeys is the core of the third mechanism.
//
// A key the administrator did not list must not be able to authorise anything, however well-formed its
// signature is. This is what "a key the control plane does not hold" reduces to in code.
func TestVerifyRejectsSignaturesFromUntrustedKeys(t *testing.T) {
	trusted := newEd25519Key(t)
	attacker := newEd25519Key(t)
	payload := []byte(`{"intent":"host.reboot"}`)

	set := mustParse(t, signersFile("ed25519 "+trusted.derBase64+" ops-laptop file"))

	if got, err := set.Verify(payload, trusted.signRaw(payload)); err != nil {
		t.Errorf("a trusted key's signature was rejected: %v", err)
	} else if got.KeyID != "ops-laptop" {
		t.Errorf("Verify attributed the signature to %q", got.KeyID)
	}

	if _, err := set.Verify(payload, attacker.signRaw(payload)); err == nil {
		t.Fatal("a signature from an untrusted key was accepted")
	} else if !errors.Is(err, ErrNoTrustedSigner) {
		t.Errorf("error %v does not wrap ErrNoTrustedSigner", err)
	}

	// A valid signature over a different payload must not verify this one. This is the check that
	// would matter if a compromised control plane replayed a signature onto a different job.
	otherPayload := []byte(`{"intent":"packages.applyAll"}`)
	if _, err := set.Verify(payload, trusted.signRaw(otherPayload)); err == nil {
		t.Error("a signature over a different payload was accepted")
	}
}

// TestDigestIsOrderIndependent covers the field the heartbeat carries.
//
// The digest exists so an operator can see that two hosts which should have the same signers do,
// without any host transmitting its trust anchor. If it depended on the order the lines happened to be
// written in, it would report differences that do not exist and hide the ones that do.
func TestDigestIsOrderIndependent(t *testing.T) {
	a := newEd25519Key(t)
	b := newEd25519Key(t)

	one := mustParse(t, signersFile("ed25519 "+a.derBase64+" alpha", "ed25519 "+b.derBase64+" beta"))
	two := mustParse(t, signersFile("ed25519 "+b.derBase64+" beta", "ed25519 "+a.derBase64+" alpha"))

	d1, err := one.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	d2, err := two.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if d1 != d2 {
		t.Errorf("the same keys in a different order digested differently:\n%s\n%s", d1, d2)
	}

	three := mustParse(t, signersFile("ed25519 "+a.derBase64+" alpha"))
	d3, err := three.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if d3 == d1 {
		t.Error("removing a key did not change the digest")
	}
}

// TestVerifyIsUnaffectedByWhichBackendProducedTheSignature is the property that keeps backends safe.
//
// The agent sees a public key and a signature and nothing else. It cannot learn which backend signed,
// which is exactly why an open-ended list of backends cannot widen its attack surface. Signing the
// same payload two different ways and verifying both against the same key states that directly.
func TestVerifyIsUnaffectedByWhichBackendProducedTheSignature(t *testing.T) {
	k := newECDSAKey(t)
	payload := []byte(`{"intent":"service.restart","params":{"unit":"nginx.service"}}`)
	set := mustParse(t, signersFile("ecdsa-p256 "+k.derBase64+" ops-token pkcs11"))

	// ECDSA is randomised, so two signatures over the same payload differ byte for byte. Both must
	// verify: a verifier that had somehow become sensitive to signature encoding would pass a test
	// using only one.
	first, second := k.signRaw(payload), k.signRaw(payload)
	if string(first) == string(second) {
		t.Fatal("two ECDSA signatures over the same payload were identical; the test is not testing what it thinks")
	}
	for i, sig := range [][]byte{first, second} {
		if _, err := set.Verify(payload, sig); err != nil {
			t.Errorf("signature %d did not verify: %v", i, err)
		}
	}
}

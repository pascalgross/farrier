package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/signing"
)

// Every test here drives a provider against an httptest server rather than a cloud account. The
// endpoint is a field on the provider struct and is never a setting, an environment variable or a
// reference attribute: an endpoint an operator could redirect is a signing oracle pointed somewhere
// else, and a test that needed one would be asking for that to exist in shipped code. Tests live in
// this package so they can construct the provider directly instead.

// testKey is a P-256 key pair the fake providers sign with, and the tests verify against.
type testKey struct {
	// private is what the fake service signs with.
	private *ecdsa.PrivateKey

	// spkiDER and spkiPEM are the two encodings the three providers hand a public key back in.
	spkiDER []byte
	spkiPEM string
}

// newTestKey generates a key pair for one test.
//
// Generated rather than a fixture, so no constant in this file could ever be mistaken for a real key —
// the same reasoning the file backend's tests state.
func newTestKey(t *testing.T) testKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatalf("encoding the public key: %v", err)
	}
	return testKey{
		private: private,
		spkiDER: der,
		spkiPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}
}

// signDER signs a digest and returns the DER form, which is what AWS and Google produce.
func (k testKey) signDER(t *testing.T, digest []byte) []byte {
	t.Helper()
	signature, err := ecdsa.SignASN1(rand.Reader, k.private, digest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return signature
}

// signJOSE signs a digest and returns the raw r‖s form, which is what Azure produces.
func (k testKey) signJOSE(t *testing.T, digest []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

// readRequest decodes a JSON request body in a fake handler.
func readRequest(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading the request: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("the request is not JSON: %v", err)
	}
	return body
}

// staticCredential is the AWS credential the fakes expect.
var staticCredential = awsCredential{
	accessKeyID:     "AKIDEXAMPLE",
	secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
}

// TestGuaranteeSigV4MatchesTheSpecificationsWorkedExample checks the arithmetic against AWS's own.
//
// It is the only test here that checks this implementation against something other than itself. The
// inputs and the expected signature are AWS's published Signature Version 4 example — the ListUsers
// request, the example credentials, and the fixed timestamp — and it exercises the path and
// query-string parts of a canonical request that KMS itself never uses, which is precisely why it is
// worth having: a signing implementation nobody checks against the specification is one that agrees
// only with itself.
func TestGuaranteeSigV4MatchesTheSpecificationsWorkedExample(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	signV4(req, nil, staticCredential, "us-east-1", "iam", at)

	const expected = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != expected {
		t.Fatalf("the signature does not match AWS's published example\n got: %s\nwant: %s", got, expected)
	}
}

// awsFake stands in for the KMS endpoint, and re-derives the signature over what it received.
//
// Re-deriving rather than comparing against a golden string is what makes it a real check: it catches
// a header left out of SignedHeaders, a body serialised twice, a session token that was set but not
// signed, and a clock format — none of which a fixed expected value over a fixed input would notice,
// because a fixed input never exercises them.
func awsFake(t *testing.T, key testKey, onSign func(map[string]any)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the request: %v", err)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-amz-json-1.1" {
			t.Errorf("the content type is %q", got)
		}

		// The request the client signed, rebuilt here from the headers it said it signed, and signed
		// again with the same secret. Only those headers: SigV4 covers the set a request names, and
		// Go's transport adds Content-Length and User-Agent on the wire that no client signs.
		check := r.Clone(r.Context())
		check.Header = http.Header{}
		for _, name := range signedHeadersOf(t, r) {
			if value := r.Header.Get(name); value != "" {
				check.Header.Set(name, value)
			}
		}
		check.URL.Scheme, check.URL.Host = "http", r.Host
		signV4(check, raw, staticCredential, "eu-central-1", "kms", mustParseAmzDate(t, r))
		if check.Header.Get("Authorization") != r.Header.Get("Authorization") {
			t.Errorf("the request is not signed over what arrived\n got: %s\nwant: %s",
				r.Header.Get("Authorization"), check.Header.Get("Authorization"))
		}

		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("the request is not JSON: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")

		switch target := r.Header.Get("X-Amz-Target"); target {
		case "TrentService.GetPublicKey":
			writeJSON(t, w, map[string]any{
				"PublicKey": base64.StdEncoding.EncodeToString(key.spkiDER),
				"KeySpec":   "ECC_NIST_P256",
			})
		case "TrentService.Sign":
			if onSign != nil {
				onSign(body)
			}
			message, _ := base64.StdEncoding.DecodeString(body["Message"].(string))
			digest := message
			if body["MessageType"] == "RAW" {
				sum := sha256.Sum256(message)
				digest = sum[:]
			}
			writeJSON(t, w, map[string]any{
				"Signature": base64.StdEncoding.EncodeToString(key.signDER(t, digest)),
			})
		default:
			t.Errorf("unexpected target %q", target)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// signedHeadersOf reads the header names a request's Authorization says are covered.
func signedHeadersOf(t *testing.T, r *http.Request) []string {
	t.Helper()
	for _, part := range strings.Split(r.Header.Get("Authorization"), " ") {
		part = strings.TrimSuffix(part, ",")
		if names, ok := strings.CutPrefix(part, "SignedHeaders="); ok {
			return strings.Split(names, ";")
		}
	}
	t.Fatalf("the request carries no SignedHeaders: %q", r.Header.Get("Authorization"))
	return nil
}

// mustParseAmzDate reads back the timestamp the client signed with.
func mustParseAmzDate(t *testing.T, r *http.Request) time.Time {
	t.Helper()
	at, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		t.Fatalf("the request carries no usable X-Amz-Date: %v", err)
	}
	return at
}

// writeJSON answers a fake request.
func writeJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("writing the response: %v", err)
	}
}

// newAWSAgainst builds an AWS provider pointed at a fake.
func newAWSAgainst(srv *httptest.Server) *awsProvider {
	return &awsProvider{
		arn:         "arn:aws:kms:eu-central-1:123456789012:key/abcd",
		region:      "eu-central-1",
		endpoint:    srv.URL + "/",
		credentials: func(context.Context) (awsCredential, error) { return staticCredential, nil },
		now:         time.Now,
	}
}

// TestAWSSignsAndTheResultVerifies is the whole AWS path.
func TestAWSSignsAndTheResultVerifies(t *testing.T) {
	key := newTestKey(t)
	var sent map[string]any
	prov := newAWSAgainst(awsFake(t, key, func(body map[string]any) { sent = body }))

	public, alg, err := prov.publicKey(context.Background())
	if err != nil {
		t.Fatalf("fetching the public key: %v", err)
	}
	if alg != signing.ECDSAP256 {
		t.Fatalf("the algorithm is %s", alg)
	}

	payload := []byte(`{"intent":"host.reboot"}`)
	signature, err := prov.sign(context.Background(), alg, payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// The digest travelled, not the payload: a DIGEST message keeps the request small and is what the
	// service signs.
	if sent["MessageType"] != "DIGEST" || sent["SigningAlgorithm"] != "ECDSA_SHA_256" {
		t.Fatalf("the request asked for %v / %v", sent["MessageType"], sent["SigningAlgorithm"])
	}
	digest := sha256.Sum256(payload)
	if sent["Message"] != base64.StdEncoding.EncodeToString(digest[:]) {
		t.Fatal("the message is not the payload's digest")
	}

	verifier := signing.PublicKey{Algorithm: alg, Key: public}
	if !verifier.Verify(payload, signature) {
		t.Fatal("a host would refuse this signature")
	}
}

// TestAWSSendsTheWholePayloadForEd25519 covers the other half of the digest decision.
//
// Pure Ed25519 needs MessageType RAW, because ED25519_PH_SHA_512 prehashes on top of what it is given
// and produces something crypto/ed25519 will not accept. Asserting the algorithm name is asserting
// that this build never asks for the prehashed one.
func TestAWSSendsTheWholePayloadForEd25519(t *testing.T) {
	key := newTestKey(t)
	var sent map[string]any
	prov := newAWSAgainst(awsFake(t, key, func(body map[string]any) { sent = body }))

	payload := []byte("the canonical payload")
	if _, err := prov.sign(context.Background(), signing.Ed25519, payload); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if sent["MessageType"] != "RAW" || sent["SigningAlgorithm"] != "ED25519_SHA_512" {
		t.Fatalf("the request asked for %v / %v", sent["MessageType"], sent["SigningAlgorithm"])
	}
	if sent["Message"] != base64.StdEncoding.EncodeToString(payload) {
		t.Fatal("the whole payload did not travel")
	}
}

// TestAWSRefusesAnEd25519PayloadOverTheRawLimit keeps a service-side 400 from being the first anybody
// hears of a real limit.
//
// The parameter object HostSeal signs is bounded at 8 KiB, so a payload over KMS's 4096-byte RAW limit
// is reachable rather than theoretical, and the useful answer names the limit and the alternative.
func TestAWSRefusesAnEd25519PayloadOverTheRawLimit(t *testing.T) {
	prov := newAWSAgainst(awsFake(t, newTestKey(t), nil))

	_, err := prov.sign(context.Background(), signing.Ed25519, make([]byte, awsMaxRawMessage+1))
	if err == nil {
		t.Fatal("an over-size Ed25519 payload was sent")
	}
	if !strings.Contains(err.Error(), "4096") || !strings.Contains(err.Error(), "ecdsa-p256") {
		t.Fatalf("the refusal names neither the limit nor the way round it: %v", err)
	}
}

// TestAWSRefusesAKeyHostSealCannotCarry is the capability report issue #23 asks for.
func TestAWSRefusesAKeyHostSealCannotCarry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An RSA key, in the DER a real GetPublicKey would return for one.
		rsaDER, err := base64.StdEncoding.DecodeString(rsaSPKIBase64)
		if err != nil {
			t.Fatalf("decoding the fixture: %v", err)
		}
		writeJSON(t, w, map[string]any{
			"PublicKey": base64.StdEncoding.EncodeToString(rsaDER),
			"KeySpec":   "RSA_4096",
		})
	}))
	t.Cleanup(srv.Close)

	_, _, err := newAWSAgainst(srv).publicKey(context.Background())
	if err == nil {
		t.Fatal("an RSA key was accepted")
	}
	if !strings.Contains(err.Error(), "RSA_4096") || !strings.Contains(err.Error(), "ecdsa-p256") {
		t.Fatalf("the refusal does not name the key or the way round it: %v", err)
	}
}

// gcpFake stands in for Cloud KMS.
func gcpFake(t *testing.T, key testKey, onSign func(map[string]any)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("the request carries %q", got)
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/publicKey"):
			writeJSON(t, w, map[string]any{
				"pem":       key.spkiPEM,
				"algorithm": "EC_SIGN_P256_SHA256",
				"pemCrc32c": crc32Value([]byte(key.spkiPEM)),
			})
		case strings.HasSuffix(r.URL.Path, ":asymmetricSign"):
			body := readRequest(t, r)
			if onSign != nil {
				onSign(body)
			}
			var digest []byte
			if raw, ok := body["digest"].(map[string]any); ok {
				digest, _ = base64.StdEncoding.DecodeString(raw["sha256"].(string))
			} else {
				data, _ := base64.StdEncoding.DecodeString(body["data"].(string))
				sum := sha256.Sum256(data)
				digest = sum[:]
			}
			signature := key.signDER(t, digest)
			writeJSON(t, w, map[string]any{
				"signature":            base64.StdEncoding.EncodeToString(signature),
				"signatureCrc32c":      crc32Value(signature),
				"verifiedDigestCrc32c": true,
			})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newGCPAgainst builds a Cloud KMS provider pointed at a fake.
func newGCPAgainst(srv *httptest.Server) *gcpProvider {
	return &gcpProvider{
		resource: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
		endpoint: srv.URL,
		token:    func(context.Context) (string, error) { return "test-token", nil },
	}
}

// TestGCPSignsWithADigestAndChecksItsChecksums is the whole Cloud KMS path.
func TestGCPSignsWithADigestAndChecksItsChecksums(t *testing.T) {
	key := newTestKey(t)
	var sent map[string]any
	prov := newGCPAgainst(gcpFake(t, key, func(body map[string]any) { sent = body }))

	public, alg, err := prov.publicKey(context.Background())
	if err != nil {
		t.Fatalf("fetching the public key: %v", err)
	}

	payload := []byte("what the operator approved")
	signature, err := prov.sign(context.Background(), alg, payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Exactly one of digest and data, and the checksum beside it.
	if _, ok := sent["data"]; ok {
		t.Error("an ECDSA request carried data as well as a digest")
	}
	digest := sha256.Sum256(payload)
	if sent["digestCrc32c"] != crc32Value(digest[:]) {
		t.Errorf("the digest checksum is %v", sent["digestCrc32c"])
	}

	verifier := signing.PublicKey{Algorithm: alg, Key: public}
	if !verifier.Verify(payload, signature) {
		t.Fatal("a host would refuse this signature")
	}
}

// TestGCPRefusesASignatureWhoseChecksumDoesNotMatch proves the integrity fields are checked.
//
// They exist because corruption on this path looks exactly like a broken key: one flipped bit and
// every host refuses the signature, and the operator spends a day on their trust anchor.
func TestGCPRefusesASignatureWhoseChecksumDoesNotMatch(t *testing.T) {
	key := newTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/publicKey") {
			writeJSON(t, w, map[string]any{"pem": key.spkiPEM, "algorithm": "EC_SIGN_P256_SHA256"})
			return
		}
		writeJSON(t, w, map[string]any{
			"signature":            base64.StdEncoding.EncodeToString(key.signDER(t, make([]byte, 32))),
			"signatureCrc32c":      "1",
			"verifiedDigestCrc32c": true,
		})
	}))
	t.Cleanup(srv.Close)

	_, err := newGCPAgainst(srv).sign(context.Background(), signing.ECDSAP256, []byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("a corrupted signature was accepted: %v", err)
	}
}

// azureFake stands in for Key Vault, answering in the JOSE encodings it really uses.
func azureFake(t *testing.T, key testKey, kty string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("the request carries %q", got)
		}
		if r.URL.Query().Get("api-version") == "" {
			t.Error("the request names no api-version")
		}

		if strings.HasSuffix(r.URL.Path, "/sign") {
			body := readRequest(t, r)
			if body["alg"] != "ES256" {
				t.Errorf("the request asked for %v", body["alg"])
			}
			digest, err := base64.RawURLEncoding.DecodeString(body["value"].(string))
			if err != nil || len(digest) != 32 {
				t.Errorf("the value is not a base64url 32-byte digest: %v", err)
			}
			// Raw r‖s, base64url — the shape Key Vault really answers with, which is the whole
			// reason this provider has a conversion at all.
			writeJSON(t, w, map[string]any{
				"value": base64.RawURLEncoding.EncodeToString(key.signJOSE(t, digest)),
			})
			return
		}

		point, err := key.private.PublicKey.Bytes()
		if err != nil {
			t.Errorf("encoding the point: %v", err)
			return
		}
		x, y := point[1:33], point[33:]
		writeJSON(t, w, map[string]any{
			"key": map[string]any{
				"kty": kty,
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(x),
				"y":   base64.RawURLEncoding.EncodeToString(y),
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newAzureAgainst builds a Key Vault provider pointed at a fake.
func newAzureAgainst(srv *httptest.Server) *azureProvider {
	return &azureProvider{
		keyURL: srv.URL + "/keys/hostseal-signing/9885aa55",
		scope:  "https://vault.azure.net/.default",
		token:  func(context.Context, string) (string, error) { return "test-token", nil },
	}
}

// TestGuaranteeAzureSignaturesAreReencodedToDER is the conversion this provider exists to get right.
//
// Key Vault defines ES256 as RFC 7518 does — the raw r‖s concatenation — and HostSeal's verifier is
// crypto/ecdsa's VerifyASN1. Handing the raw pair over would produce a signature every host refuses as
// coming from no trusted signer, which reads as a broken trust anchor days later. Both halves are
// asserted: what the provider returns is DER, and it verifies.
func TestGuaranteeAzureSignaturesAreReencodedToDER(t *testing.T) {
	key := newTestKey(t)
	prov := newAzureAgainst(azureFake(t, key, "EC-HSM"))

	public, alg, err := prov.publicKey(context.Background())
	if err != nil {
		t.Fatalf("fetching the public key: %v", err)
	}
	if alg != signing.ECDSAP256 {
		t.Fatalf("the algorithm is %s", alg)
	}

	payload := []byte("reboot web-01")
	signature, err := prov.sign(context.Background(), alg, payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	var parsed struct {
		// R and S are the signature's two halves.
		R, S *big.Int
	}
	if rest, err := asn1.Unmarshal(signature, &parsed); err != nil || len(rest) != 0 {
		t.Fatalf("the signature is not a DER SEQUENCE of two INTEGERs: %v", err)
	}
	verifier := signing.PublicKey{Algorithm: alg, Key: public}
	if !verifier.Verify(payload, signature) {
		t.Fatal("the converted signature does not verify")
	}

	// And the raw form would not have. Without this the test would pass against a provider that
	// happened to return DER from the fake, proving nothing about the conversion.
	raw := make([]byte, 64)
	parsed.R.FillBytes(raw[:32])
	parsed.S.FillBytes(raw[32:])
	if verifier.Verify(payload, raw) {
		t.Fatal("a raw r‖s signature verified, so this test proves nothing")
	}
}

// TestAzureRefusesEd25519WithAMessageNamingTheMismatch is issue #23's explicit requirement.
//
// Key Vault has no EdDSA algorithm and no OKP key type, so this is not a gap to work around but a
// property of the service. The message says so and names what to do instead; it never falls back.
func TestAzureRefusesEd25519WithAMessageNamingTheMismatch(t *testing.T) {
	prov := newAzureAgainst(azureFake(t, newTestKey(t), "EC"))

	_, err := prov.sign(context.Background(), signing.Ed25519, []byte("payload"))
	if err == nil {
		t.Fatal("Key Vault was asked for an Ed25519 signature")
	}
	if !strings.Contains(err.Error(), "ed25519") || !strings.Contains(err.Error(), "ecdsa-p256") {
		t.Fatalf("the refusal does not name the mismatch: %v", err)
	}
}

// TestAzureRefusesANonECKey covers the other capability refusal.
func TestAzureRefusesANonECKey(t *testing.T) {
	_, _, err := newAzureAgainst(azureFake(t, newTestKey(t), "RSA")).publicKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("an RSA key was accepted: %v", err)
	}
}

// TestGuaranteeASignatureIsVerifiedBeforeItIsReturned is the check that catches every encoding bug.
//
// The fake returns a structurally valid signature over a different payload — which is what an
// unconverted r‖s, a digest sent where the payload was meant, or the wrong base64 alphabet all look
// like from here. Sign must refuse it rather than hand back something every host in the fleet will
// reject days later as a broken trust anchor.
func TestGuaranteeASignatureIsVerifiedBeforeItIsReturned(t *testing.T) {
	key := newTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/publicKey") {
			writeJSON(t, w, map[string]any{"pem": key.spkiPEM, "algorithm": "EC_SIGN_P256_SHA256"})
			return
		}
		wrong := sha256.Sum256([]byte("a different document entirely"))
		signature := key.signDER(t, wrong[:])
		writeJSON(t, w, map[string]any{
			"signature":            base64.StdEncoding.EncodeToString(signature),
			"signatureCrc32c":      crc32Value(signature),
			"verifiedDigestCrc32c": true,
		})
	}))
	t.Cleanup(srv.Close)

	prov := newGCPAgainst(srv)
	public, alg, err := prov.publicKey(context.Background())
	if err != nil {
		t.Fatalf("fetching the public key: %v", err)
	}
	signer := &Signer{prov: prov, keyID: "ops-kms-1", algorithm: alg, public: public}

	if _, err := signer.Sign(context.Background(), []byte("what the operator approved")); err == nil {
		t.Fatal("a signature over a different payload was returned")
	} else if !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("the refusal does not say what happened: %v", err)
	}
}

// TestSignHonoursACancelledContext proves the deadline reaches the network call.
func TestSignHonoursACancelledContext(t *testing.T) {
	key := newTestKey(t)
	prov := newGCPAgainst(gcpFake(t, key, nil))
	signer := &Signer{prov: prov, keyID: "ops-kms-1", algorithm: signing.ECDSAP256,
		public: key.private.Public()}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.Sign(ctx, []byte("payload")); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context produced %v", err)
	}
}

// TestOpenRefusesAReferenceWithoutAKeyID keeps the audit log's identity from being an ARN.
func TestOpenRefusesAReferenceWithoutAKeyID(t *testing.T) {
	_, err := Open(context.Background(), awsScheme, "arn:aws:kms:eu-central-1:1:key/abcd")
	if err == nil || !strings.Contains(err.Error(), "#") {
		t.Fatalf("a reference with no identity was accepted: %v", err)
	}
	_, err = Open(context.Background(), awsScheme, "arn:aws:kms:eu-central-1:1:key/abcd#ops kms")
	if err == nil || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("a key id with a space was accepted: %v", err)
	}
}

// TestReferencesAreValidatedBeforeAnythingIsSent covers each provider's reference rules.
//
// Every one of these is a refusal that has to happen locally: a reference this build cannot make sense
// of must not become a request to a service chosen by the part of it that was misread.
func TestReferencesAreValidatedBeforeAnythingIsSent(t *testing.T) {
	for _, c := range []struct {
		// scheme is the provider.
		scheme string

		// resource is what an operator wrote.
		resource string

		// because is a fragment of the reason it is refused.
		because string
	}{
		{awsScheme, "abcd-1234", "ARN"},
		{awsScheme, "arn:aws:s3:::bucket/key", "ARN"},
		{gcpScheme, "projects/p/locations/l/keyRings/r/cryptoKeys/k", "version"},
		{azureScheme, "ops.vault.azure.net", "vault host and the key version"},
		{azureScheme, "evil.example.com/keys/k/v", "Azure vault host"},
		{azureScheme, "https://ops.vault.azure.net/keys/k/v", "bare vault host"},
		{azureScheme, "ops.vault.azure.net/keys/k", "key version"},
	} {
		if _, err := newProvider(c.scheme, c.resource); err == nil {
			t.Errorf("%s:%s was accepted", c.scheme, c.resource)
		} else if !strings.Contains(err.Error(), c.because) {
			t.Errorf("%s:%s was refused for the wrong reason: %v", c.scheme, c.resource, err)
		}
	}

	// And the well-formed ones are accepted, so the rules above are not simply refusing everything.
	for _, c := range []struct {
		// scheme is the provider.
		scheme string

		// resource is a reference that must work.
		resource string
	}{
		{awsScheme, "arn:aws:kms:eu-central-1:123456789012:key/abcd-1234"},
		{gcpScheme, "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"},
		{azureScheme, "ops.vault.azure.net/keys/hostseal-signing/9885aa55"},
		{azureScheme, "ops.managedhsm.azure.net/keys/hostseal-signing/9885aa55"},
	} {
		if _, err := newProvider(c.scheme, c.resource); err != nil {
			t.Errorf("%s:%s was refused: %v", c.scheme, c.resource, err)
		}
	}
}

// TestDERFromJOSERefusesWhatItCannotConvert keeps the Azure conversion strict.
func TestDERFromJOSERefusesWhatItCannotConvert(t *testing.T) {
	for _, raw := range [][]byte{make([]byte, 63), make([]byte, 65), make([]byte, 64), nil} {
		if _, err := derFromJOSE(raw); err == nil {
			t.Errorf("a %d-byte signature was converted", len(raw))
		}
	}
}

// rsaSPKIBase64 is a 2048-bit RSA public key in DER SubjectPublicKeyInfo, base64.
//
// A public key, and a fixture: it exists so a test can ask what happens when a provider reports a key
// type HostSeal's wire format does not carry, which is a question about this code rather than about the
// key. Nothing signs with it and its private half was never kept.
const rsaSPKIBase64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3ZKN0hVJ6dLtiJ8sTUJ2" +
	"cvNBBZH6WKTS0qBqBcbdyrBBqZYRIvSBFPqZKcuUB3IjLnQVOoNQpKMxpbEeRtQP" +
	"F1IPTNfTAKWuSMyPWNKz1yhrfUdBBjbNSFTdDUpN0Y4LxIqBpAlLjHYFLZQZlBWY" +
	"5cKRJdJDl0NoiEnQlkxeUwrJHnJqTNjOZBqI3EqGUxjEZeJqZLNzUuqXQIWtdMcN" +
	"y5MZUFrWsxHXVZLdlYCJWiOsBHqPHUyFHXpQlvKUFDbmZBRQpBUcHyPQzUuKPZLl" +
	"3jgLKVsGpVEQKJVCFXQnZfhCPMLLZ1EYPxOYlJUPPQoHrHNKmzCJhFmuXVvLpVGa" +
	"cwIDAQAB"

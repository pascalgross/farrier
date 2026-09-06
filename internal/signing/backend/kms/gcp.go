package kms

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"net/http"
	"strconv"
	"strings"

	"github.com/pascalgross/hostseal/internal/signing"
)

// gcpScheme selects this provider.
const gcpScheme = "gcpkms"

// gcpEndpoint is Cloud KMS's base URL.
//
// Derived, never configured, for the same reason AWS's is: a base URL an operator could set is a way
// to point a signing tool at somebody else's service.
const gcpEndpoint = "https://cloudkms.googleapis.com"

// castagnoli is the CRC-32C table Cloud KMS's integrity fields use.
//
// Castagnoli, not the IEEE polynomial that hash/crc32's default table uses. Getting that wrong makes
// every request fail its own integrity check, which is at least loud.
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// gcpProvider signs with a key version in Google Cloud KMS.
type gcpProvider struct {
	// resource is the full cryptoKeyVersions resource name.
	resource string

	// endpoint is the service's base URL, a field only so a test can stand in for it.
	endpoint string

	// token finds a bearer token. A field for the same reason.
	token func(ctx context.Context) (string, error)
}

// newGCP builds a provider from a cryptoKeyVersions resource name.
//
// The version is required rather than defaulted to the primary. A key's primary version changes when
// somebody rotates it, and a signature that silently moved to a new key would be a fleet-wide outage
// on the day of a rotation: every host would refuse jobs from a key id its trusted-signers still lists
// against the old public key.
func newGCP(resource string) (provider, error) {
	if !strings.HasPrefix(resource, "projects/") || !strings.Contains(resource, "/cryptoKeyVersions/") {
		return nil, fmt.Errorf("kms: %q is not a Cloud KMS key version. Name the version, not the key: "+
			"gcpkms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1#ops-kms-1 — "+
			"a reference to the key alone would follow a rotation onto a public key no host trusts",
			resource)
	}
	return &gcpProvider{resource: resource, endpoint: gcpEndpoint, token: gcpToken}, nil
}

// name is the cloud, for messages.
func (p *gcpProvider) name() string { return "Google Cloud KMS" }

// reference renders the key version, for the confirmation screen.
func (p *gcpProvider) reference() string { return p.resource }

// gcpPublicKeyResponse is what the publicKey endpoint answers.
type gcpPublicKeyResponse struct {
	// Pem is an RFC 7468 SubjectPublicKeyInfo.
	Pem string `json:"pem"`

	// Algorithm names the key's purpose, and is what a refusal quotes back.
	Algorithm string `json:"algorithm"`

	// PemCrc32c is the provider's own integrity check over the PEM.
	PemCrc32c string `json:"pemCrc32c"`
}

// publicKey fetches the key version's public half.
func (p *gcpProvider) publicKey(ctx context.Context) (crypto.PublicKey, signing.Algorithm, error) {
	var res gcpPublicKeyResponse
	url := p.endpoint + "/v1/" + p.resource + "/publicKey"
	if err := getJSON(ctx, p.name(), url, &res, p.authorise); err != nil {
		return nil, "", err
	}
	if err := checkCRC32C("the public key", res.Pem, res.PemCrc32c); err != nil {
		return nil, "", err
	}

	block, _ := pem.Decode([]byte(res.Pem))
	if block == nil {
		return nil, "", fmt.Errorf("kms: Cloud KMS returned a public key that is not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("kms: Cloud KMS returned a public key this build cannot parse: %w", err)
	}
	alg, _, err := signing.EncodePublicKey(key)
	if err != nil {
		purpose := res.Algorithm
		if purpose == "" {
			purpose = "a key type this build does not recognise"
		}
		return nil, "", unsupportedAlgorithm("Cloud KMS", purpose)
	}
	return key, alg, nil
}

// gcpSignResponse is what asymmetricSign answers.
type gcpSignResponse struct {
	// Signature is base64, ASN.1 DER for ECDSA and raw for Ed25519 — both what the wire wants.
	Signature string `json:"signature"`

	// SignatureCrc32c is the provider's integrity check over the signature.
	SignatureCrc32c string `json:"signatureCrc32c"`

	// VerifiedDigestCrc32c and VerifiedDataCrc32c report that the service checked what we sent.
	//
	// Asserted rather than ignored: they are the half of the integrity story that says the request
	// arrived intact, and a false here means the service signed something other than what was meant.
	VerifiedDigestCrc32c bool `json:"verifiedDigestCrc32c"`
	VerifiedDataCrc32c   bool `json:"verifiedDataCrc32c"`
}

// sign asks Cloud KMS for a signature.
//
// Exactly one of digest and data may be sent, and which one is a property of the algorithm rather than
// a choice: EC_SIGN_ED25519 is pure EdDSA and takes raw data, and the P-256 purposes take a digest.
func (p *gcpProvider) sign(ctx context.Context, alg signing.Algorithm, payload []byte) ([]byte, error) {
	request := map[string]any{}
	switch alg {
	case signing.ECDSAP256:
		digest := sha256.Sum256(payload)
		request["digest"] = map[string]any{"sha256": base64.StdEncoding.EncodeToString(digest[:])}
		request["digestCrc32c"] = crc32Value(digest[:])

	case signing.Ed25519:
		request["data"] = base64.StdEncoding.EncodeToString(payload)
		request["dataCrc32c"] = crc32Value(payload)

	default:
		return nil, fmt.Errorf("kms: %w: %q", signing.ErrUnknownAlgorithm, alg)
	}

	var res gcpSignResponse
	url := p.endpoint + "/v1/" + p.resource + ":asymmetricSign"
	if err := postJSON(ctx, p.name(), url, request, &res, p.authorise); err != nil {
		return nil, err
	}
	if !res.VerifiedDigestCrc32c && !res.VerifiedDataCrc32c {
		return nil, fmt.Errorf("kms: Cloud KMS did not confirm the checksum of what it signed, so what " +
			"it signed cannot be shown to be what was sent")
	}

	signature, err := base64.StdEncoding.DecodeString(res.Signature)
	if err != nil {
		return nil, fmt.Errorf("kms: Cloud KMS returned a signature that is not base64: %w", err)
	}
	if err := checkCRC32C("the signature", string(signature), res.SignatureCrc32c); err != nil {
		return nil, err
	}
	return signature, nil
}

// authorise attaches the bearer token to a request.
func (p *gcpProvider) authorise(req *http.Request, _ []byte) error {
	tokenCtx, done := context.WithTimeout(req.Context(), credentialBudget)
	token, err := p.token(tokenCtx)
	done()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// crc32Value renders a CRC-32C the way the API carries it: a decimal string.
func crc32Value(data []byte) string {
	return strconv.FormatUint(uint64(crc32.Checksum(data, castagnoli)), 10)
}

// checkCRC32C verifies one of the provider's integrity fields.
//
// Checked rather than ignored, because Cloud KMS provides them for a path where corruption looks
// exactly like a broken key: a signature with one bit flipped in transit is refused by every host, and
// the operator spends a day looking at their trust anchor. An absent field is accepted — the API
// documents them as best effort — and a present, wrong one is not.
func checkCRC32C(what, value, expected string) error {
	if expected == "" {
		return nil
	}
	if got := crc32Value([]byte(value)); got != expected {
		return fmt.Errorf("kms: Cloud KMS's checksum for %s does not match what arrived (%s against %s); "+
			"something altered it in transit", what, got, expected)
	}
	return nil
}

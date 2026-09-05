package kms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/pascalgross/hostseal/internal/signing"
)

// azureScheme selects this provider.
const azureScheme = "azurekms"

// azureAPIVersion is the Key Vault data-plane version this speaks.
const azureAPIVersion = "7.4"

// azureVaultSuffixes are the hosts a reference may name.
//
// The vault host is the one place an operator-supplied string decides where a payload goes and whose
// public key is written into a fleet's trusted-signers. Constraining it to Azure's own suffixes costs
// one comparison and closes the only endpoint-injection surface the three providers have; AWS's and
// Google's endpoints are derived and cannot be supplied at all.
var azureVaultSuffixes = []string{".vault.azure.net", ".managedhsm.azure.net"}

// azureProvider signs with a key in Azure Key Vault or Managed HSM.
type azureProvider struct {
	// keyURL is the full https URL of the key version, without a trailing operation.
	keyURL string

	// scope is the token audience, derived from the host rather than configured.
	scope string

	// token finds a bearer token. A field so a test can supply one.
	token func(ctx context.Context, scope string) (string, error)
}

// newAzure builds a provider from a vault host and key path.
//
// The reference carries no scheme of its own — the client always builds https — so there is no
// spelling of it that downgrades the transport.
func newAzure(resource string) (provider, error) {
	host, path, ok := strings.Cut(resource, "/")
	if !ok {
		return nil, fmt.Errorf("kms: %q is not a Key Vault key. Name the vault host and the key "+
			"version: azurekms:ops.vault.azure.net/keys/hostseal-signing/9885aa55…#ops-kms-1", resource)
	}
	if strings.Contains(host, ":") || strings.Contains(host, "@") {
		return nil, fmt.Errorf("kms: %q is not a bare vault host; the transport is always https and "+
			"is not part of the reference", host)
	}

	suffix := ""
	for _, candidate := range azureVaultSuffixes {
		if strings.HasSuffix(host, candidate) && len(host) > len(candidate) {
			suffix = candidate
		}
	}
	if suffix == "" {
		return nil, fmt.Errorf("kms: %q is not an Azure vault host; it must end in %s. That is checked "+
			"because this host decides where the payload is sent and whose public key ends up in a "+
			"fleet's trusted-signers", host, strings.Join(azureVaultSuffixes, " or "))
	}

	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) != 3 || segments[0] != "keys" || segments[1] == "" || segments[2] == "" {
		return nil, fmt.Errorf("kms: %q does not name a key version. Name the version explicitly: "+
			"keys/<name>/<version> — a reference without one follows a rotation onto a public key no "+
			"host trusts", path)
	}

	scope := "https://vault.azure.net/.default"
	if suffix == ".managedhsm.azure.net" {
		scope = "https://managedhsm.azure.net/.default"
	}
	return &azureProvider{
		keyURL: "https://" + host + "/" + strings.Join(segments, "/"),
		scope:  scope,
		token:  azureToken,
	}, nil
}

// name is the cloud, for messages.
func (p *azureProvider) name() string { return "Azure Key Vault" }

// reference renders the key URL, for the confirmation screen.
func (p *azureProvider) reference() string { return p.keyURL }

// azureKeyResponse is what a get-key request answers.
type azureKeyResponse struct {
	// Key is the JWK. Not a SubjectPublicKeyInfo — Key Vault speaks JOSE throughout — so the point
	// has to be reassembled from its coordinates.
	Key struct {
		// Kty is the key type: EC or EC-HSM here, and RSA for a key this build cannot carry.
		Kty string `json:"kty"`

		// Crv is the curve name.
		Crv string `json:"crv"`

		// X and Y are the coordinates, base64url and possibly stripped of leading zeros.
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"key"`
}

// publicKey fetches the key version's public half and reassembles it from its JWK coordinates.
//
// This is where Azure's one categorical limitation is reported. Key Vault's algorithm enumeration has
// no EdDSA member and its key-type enumeration has no OKP, so an Ed25519 key cannot exist there at
// all — which is the concrete instance of the sentence docs/EXTENDING.md already carries about why
// ecdsa-p256 is on the wire.
func (p *azureProvider) publicKey(ctx context.Context) (crypto.PublicKey, signing.Algorithm, error) {
	var res azureKeyResponse
	if err := getJSON(ctx, p.name(), p.keyURL+"?api-version="+azureAPIVersion, &res, p.authorise); err != nil {
		return nil, "", err
	}

	switch res.Key.Kty {
	case "EC", "EC-HSM":
	case "":
		return nil, "", fmt.Errorf("kms: Azure Key Vault returned a key with no type")
	default:
		return nil, "", unsupportedAlgorithm("Azure Key Vault",
			"a "+res.Key.Kty+" key. Key Vault has no EdDSA algorithm and no OKP key type, so an "+
				"ed25519 key cannot exist there: create a P-256 key and use the ecdsa-p256 line")
	}
	if res.Key.Crv != "P-256" {
		return nil, "", unsupportedAlgorithm("Azure Key Vault", "a key on curve "+res.Key.Crv)
	}

	x, err := base64.RawURLEncoding.DecodeString(res.Key.X)
	if err != nil {
		return nil, "", fmt.Errorf("kms: the key's x coordinate is not base64url: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(res.Key.Y)
	if err != nil {
		return nil, "", fmt.Errorf("kms: the key's y coordinate is not base64url: %w", err)
	}

	// Left-padded to the curve's width before they are reassembled: a JWK coordinate may legitimately
	// arrive with its leading zero bytes stripped, and a point built from a short coordinate is a
	// point on no curve.
	point := make([]byte, 1+2*32)
	point[0] = 4
	copy(point[1+32-min(len(x), 32):1+32], x)
	copy(point[1+64-min(len(y), 32):], y)

	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, "", fmt.Errorf("kms: Azure Key Vault returned coordinates that are not a P-256 "+
			"point: %w", err)
	}
	return key, signing.ECDSAP256, nil
}

// azureSignResponse is what the sign endpoint answers.
type azureSignResponse struct {
	// Value is base64url — and, for ES256, a raw r‖s pair rather than DER.
	Value string `json:"value"`
}

// sign asks Key Vault for a signature over the payload's digest.
//
// Key Vault never hashes: the endpoint is documented as creating a signature from a digest, so the
// caller computes it, always. And the answer needs converting, which is the single most consequential
// fact about this provider — see derFromJOSE.
func (p *azureProvider) sign(ctx context.Context, alg signing.Algorithm, payload []byte) ([]byte, error) {
	if alg != signing.ECDSAP256 {
		return nil, unsupportedAlgorithm("Azure Key Vault", "asked for "+string(alg))
	}
	digest := sha256.Sum256(payload)
	request := map[string]any{
		"alg":   "ES256",
		"value": base64.RawURLEncoding.EncodeToString(digest[:]),
	}

	var res azureSignResponse
	url := p.keyURL + "/sign?api-version=" + azureAPIVersion
	if err := postJSON(ctx, p.name(), url, request, &res, p.authorise); err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(res.Value)
	if err != nil {
		return nil, fmt.Errorf("kms: Azure Key Vault returned a signature that is not base64url: %w", err)
	}
	return derFromJOSE(raw)
}

// authorise attaches the bearer token to a request.
func (p *azureProvider) authorise(req *http.Request, _ []byte) error {
	tokenCtx, done := context.WithTimeout(req.Context(), credentialBudget)
	token, err := p.token(tokenCtx, p.scope)
	done()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// derFromJOSE re-encodes Key Vault's ECDSA signature as the ASN.1 DER the wire format carries.
//
// Key Vault defines ES256 as RFC 7518 does — the JWS form, which is the concatenation of R and S each
// left-padded to the curve's size. HostSeal's verifier is crypto/ecdsa's VerifyASN1, which expects a
// DER SEQUENCE of two INTEGERs. An unconverted Azure signature therefore verifies nowhere: every host
// in the fleet reports the key as producing signatures from no trusted signer, which reads as a broken
// trust anchor rather than as sixty bytes in the wrong shape.
//
// This is the reason Sign verifies its own output before returning it.
func derFromJOSE(raw []byte) ([]byte, error) {
	const half = 32
	if len(raw) != 2*half {
		return nil, fmt.Errorf("kms: Azure Key Vault returned a %d-byte ES256 signature, expected %d "+
			"(a P-256 r‖s pair)", len(raw), 2*half)
	}
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, fmt.Errorf("kms: Azure Key Vault returned an ECDSA signature with a zero component")
	}
	der, err := asn1.Marshal(struct {
		// R and S are the signature's two halves, DER INTEGERs.
		R, S *big.Int
	}{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("kms: re-encoding Key Vault's signature: %w", err)
	}
	return der, nil
}

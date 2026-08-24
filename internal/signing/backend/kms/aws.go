package kms

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pascalgross/farrier/internal/signing"
)

// awsScheme selects this provider.
const awsScheme = "awskms"

// awsMaxRawMessage is the largest payload AWS KMS will sign with MessageType RAW.
//
// Four kilobytes, and it matters: pure Ed25519 needs RAW, because the alternative — ED25519_PH_SHA_512
// — is Ed25519ph, which prehashes on top of what it is given and produces a signature crypto/ed25519
// will not accept. So an Ed25519 key in AWS KMS cannot sign a payload above this, and Farrier's own
// parameter object is bounded at 8 KiB, which means the case is reachable. It is refused here, by
// name, rather than as a 400 from a service.
const awsMaxRawMessage = 4096

// awsProvider signs with a key in AWS KMS.
type awsProvider struct {
	// arn is the full key ARN, which is also where the region comes from.
	arn string

	// region is parsed out of the ARN, so the endpoint and the key can never disagree.
	region string

	// endpoint is the service's base URL. Derived, never configured: an endpoint an operator could
	// set is a way to point a signing tool at somebody else's service.
	endpoint string

	// credentials finds a credential to sign the request with. A field so a test can supply one.
	credentials func(ctx context.Context) (awsCredential, error)

	// now reads the clock, for the date in the signature. A field for the same reason.
	now func() time.Time
}

// newAWS builds a provider from a key ARN.
//
// The full ARN is required rather than a key id or an alias, and that is not pedantry: the ARN carries
// the region, so there is no region flag, no AWS_REGION fallback, and no way for the endpoint to
// disagree with the key it is being asked about.
func newAWS(resource string) (provider, error) {
	// arn:aws:kms:<region>:<account>:key/<id>
	parts := strings.SplitN(resource, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "kms" || parts[3] == "" {
		return nil, fmt.Errorf("kms: %q is not a KMS key ARN. Paste the full ARN — it carries the "+
			"region, which is where the endpoint comes from: "+
			"awskms:arn:aws:kms:eu-central-1:123456789012:key/abcd-…#ops-kms-1", resource)
	}
	region := parts[3]
	return &awsProvider{
		arn:         resource,
		region:      region,
		endpoint:    "https://kms." + region + ".amazonaws.com/",
		credentials: awsCredentials,
		now:         time.Now,
	}, nil
}

// name is the cloud, for messages.
func (p *awsProvider) name() string { return "AWS KMS" }

// reference renders the key ARN, for the confirmation screen.
func (p *awsProvider) reference() string { return p.arn }

// awsPublicKeyResponse is what GetPublicKey answers.
type awsPublicKeyResponse struct {
	// PublicKey is base64 DER SubjectPublicKeyInfo, which is the form trusted-signers already carries.
	PublicKey string `json:"PublicKey"`

	// KeySpec names the key's type, and is what a refusal quotes back.
	KeySpec string `json:"KeySpec"`

	// SigningAlgorithms is what the key may be used for, reported rather than assumed.
	SigningAlgorithms []string `json:"SigningAlgorithms"`
}

// publicKey fetches the key and settles the algorithm from what AWS says it is.
func (p *awsProvider) publicKey(ctx context.Context) (crypto.PublicKey, signing.Algorithm, error) {
	var res awsPublicKeyResponse
	if err := p.call(ctx, "GetPublicKey", map[string]any{"KeyId": p.arn}, &res); err != nil {
		return nil, "", err
	}

	der, err := base64.StdEncoding.DecodeString(res.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("kms: AWS KMS returned a public key that is not base64: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, "", fmt.Errorf("kms: AWS KMS returned a public key this build cannot parse: %w", err)
	}
	alg, _, err := signing.EncodePublicKey(key)
	if err != nil {
		spec := res.KeySpec
		if spec == "" {
			spec = "a key type this build does not recognise"
		}
		return nil, "", unsupportedAlgorithm("AWS KMS", spec)
	}
	return key, alg, nil
}

// awsSignResponse is what Sign answers.
type awsSignResponse struct {
	// Signature is base64. ECDSA comes back as ASN.1 DER, which is what the wire format wants;
	// Ed25519 comes back as the raw 64 bytes, which is also what it wants. Neither needs converting,
	// which makes AWS the easy one of the three.
	Signature string `json:"Signature"`
}

// sign asks KMS for a signature over the payload.
//
// Which of the payload and its digest travels is the whole of the difference between the two
// algorithms. ECDSA sends a digest, because that is what the service signs and it keeps the request
// small. Ed25519 must send the payload itself: EdDSA hashes internally as part of the algorithm, and
// the only KMS mechanism that does pure Ed25519 is ED25519_SHA_512 over MessageType RAW.
func (p *awsProvider) sign(ctx context.Context, alg signing.Algorithm, payload []byte) ([]byte, error) {
	request := map[string]any{"KeyId": p.arn}
	switch alg {
	case signing.ECDSAP256:
		digest := sha256.Sum256(payload)
		request["Message"] = base64.StdEncoding.EncodeToString(digest[:])
		request["MessageType"] = "DIGEST"
		request["SigningAlgorithm"] = "ECDSA_SHA_256"

	case signing.Ed25519:
		if len(payload) > awsMaxRawMessage {
			return nil, fmt.Errorf("kms: this payload is %d bytes and AWS KMS accepts at most %d for "+
				"an Ed25519 signature. The limit is on MessageType RAW, which pure Ed25519 requires — "+
				"ED25519_PH_SHA_512 would prehash on top of it and produce a signature no host accepts. "+
				"An ecdsa-p256 key has no such limit, because it signs a digest",
				len(payload), awsMaxRawMessage)
		}
		request["Message"] = base64.StdEncoding.EncodeToString(payload)
		request["MessageType"] = "RAW"
		request["SigningAlgorithm"] = "ED25519_SHA_512"

	default:
		return nil, fmt.Errorf("kms: %w: %q", signing.ErrUnknownAlgorithm, alg)
	}

	var res awsSignResponse
	if err := p.call(ctx, "Sign", request, &res); err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(res.Signature)
	if err != nil {
		return nil, fmt.Errorf("kms: AWS KMS returned a signature that is not base64: %w", err)
	}
	return signature, nil
}

// call makes one signed KMS API request.
func (p *awsProvider) call(ctx context.Context, action string, request, out any) error {
	credentialCtx, done := context.WithTimeout(ctx, credentialBudget)
	cred, err := p.credentials(credentialCtx)
	done()
	if err != nil {
		return err
	}

	return postJSON(ctx, p.name(), p.endpoint, request, out, func(req *http.Request, body []byte) error {
		// The two headers the JSON-1.1 protocol needs, set before signing because the signature covers
		// every header it lists.
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "TrentService."+action)
		signV4(req, body, cred, p.region, "kms", p.now())
		return nil
	})
}

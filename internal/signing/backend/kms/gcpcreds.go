package kms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// gcpMetadataBase is the Compute Engine metadata server.
//
// A constant for the same reason AWS's is: an address a caller could change is a way to hand a signing
// tool a token issued by somebody else.
const gcpMetadataBase = "http://metadata.google.internal"

// gcpAudience is what a self-signed service-account JWT is addressed to.
//
// The API's own endpoint. A service account calling a Google API may present a JWT it signed itself,
// with the API as the audience, and skip the token exchange entirely — which is one fewer network
// dependency on a path that already has one, and it works when oauth2.googleapis.com is unreachable
// but Cloud KMS is not.
const gcpAudience = "https://cloudkms.googleapis.com/"

// gcpTokenLifetime is how long a self-signed assertion is good for.
//
// An hour, which is Google's maximum and irrelevant in practice: the token is minted for one command
// and discarded when it exits.
const gcpTokenLifetime = time.Hour

// gcpServiceAccount is the part of a service-account key file this package reads.
type gcpServiceAccount struct {
	// Type distinguishes a service account from user credentials in the same file shape.
	Type string `json:"type"`

	// ClientEmail is the account's identity, and both the issuer and the subject of its assertion.
	ClientEmail string `json:"client_email"`

	// PrivateKey is a PEM PKCS#8 RSA key.
	PrivateKey string `json:"private_key"`

	// PrivateKeyID goes in the assertion's header so Google can pick the right key to verify it.
	PrivateKeyID string `json:"private_key_id"`

	// ClientID, ClientSecret and RefreshToken are the authorized_user shape instead — what
	// `gcloud auth application-default login` writes on a laptop, which is what an operator will
	// actually have.
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

// gcpToken finds a bearer token for Cloud KMS.
//
// Environment override first, then application default credentials, then the metadata server — the
// same ordering as AWS's chain and for the same reason: on a laptop the metadata address black-holes
// rather than refusing, so asking the network first spends the whole budget learning nothing.
func gcpToken(ctx context.Context) (string, error) {
	if token := os.Getenv(BearerTokenEnv); token != "" {
		return token, nil
	}

	account, path, err := loadApplicationDefaultCredentials()
	if err != nil {
		return "", err
	}
	switch {
	case account == nil:
		return gcpMetadataToken(ctx)
	case account.Type == "service_account":
		return selfSignedJWT(account)
	case account.RefreshToken != "":
		return gcpRefreshedToken(ctx, account)
	default:
		return "", fmt.Errorf("kms: %s is neither a service account nor a refreshable user "+
			"credential. Run `gcloud auth application-default login`, or set %s to a token from "+
			"`gcloud auth print-access-token`", path, BearerTokenEnv)
	}
}

// loadApplicationDefaultCredentials reads the well-known credential file, if there is one.
//
// A missing file is not an error: it is the ordinary state of a Compute Engine instance, where the
// metadata server is the answer. GOOGLE_APPLICATION_CREDENTIALS pointing at a file that does not exist
// *is* an error, because somebody meant something by setting it.
func loadApplicationDefaultCredentials() (*gcpServiceAccount, string, error) {
	path := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	explicit := path != ""
	if !explicit {
		home, err := os.UserHomeDir()
		if err != nil {
			//nolint:nilerr // A machine with no home directory has no application default credentials
			// file, which is the ordinary state of a Compute Engine instance. The chain continues to
			// the metadata server, which is where such a machine's token comes from.
			return nil, "", nil
		}
		path = filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
	}

	//nolint:gosec // G703 flags a path from the environment, which is GOOGLE_APPLICATION_CREDENTIALS
	// read on behalf of the operator who set it, in a command they ran themselves — the same reason
	// the repository already excludes this finding's older spelling.
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist) && explicit:
		return nil, path, fmt.Errorf("kms: GOOGLE_APPLICATION_CREDENTIALS names %s, which does not exist", path)
	case errors.Is(err, os.ErrNotExist):
		return nil, "", nil
	case err != nil:
		return nil, path, fmt.Errorf("kms: reading %s: %w", path, err)
	}

	var account gcpServiceAccount
	if err := json.Unmarshal(raw, &account); err != nil {
		return nil, path, fmt.Errorf("kms: %s is not a Google credential file: %w", path, err)
	}
	return &account, path, nil
}

// selfSignedJWT mints the assertion a service account presents as its own bearer token.
//
// No token exchange at all: Google accepts a JWT a service account signed itself, addressed to the API
// it is calling. That is one fewer round trip and one fewer service that has to be reachable, on a
// path whose whole job is to produce one signature.
func selfSignedJWT(account *gcpServiceAccount) (string, error) {
	if account.ClientEmail == "" || account.PrivateKey == "" {
		return "", errors.New("kms: the service-account file has no client_email or no private_key")
	}
	key, err := parseRSAPrivateKey(account.PrivateKey)
	if err != nil {
		return "", err
	}

	now := time.Now()
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	if account.PrivateKeyID != "" {
		header["kid"] = account.PrivateKeyID
	}
	claims := map[string]any{
		"iss": account.ClientEmail,
		"sub": account.ClientEmail,
		"aud": gcpAudience,
		"iat": now.Unix(),
		"exp": now.Add(gcpTokenLifetime).Unix(),
	}

	encodedHeader, err := jsonBase64URL(header)
	if err != nil {
		return "", err
	}
	encodedClaims, err := jsonBase64URL(claims)
	if err != nil {
		return "", err
	}
	signingInput := encodedHeader + "." + encodedClaims

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("kms: signing the service-account assertion: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// parseRSAPrivateKey reads the PEM key out of a service-account file.
func parseRSAPrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("kms: the service account's private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("kms: the service account's private_key is not a PKCS#8 key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("kms: the service account's private_key is a %T, and Google issues RSA", parsed)
	}
	return key, nil
}

// jsonBase64URL renders one JWT segment.
func jsonBase64URL(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("kms: encoding a token segment: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// gcpTokenResponse is what an OAuth token endpoint answers.
type gcpTokenResponse struct {
	// AccessToken is the bearer token.
	AccessToken string `json:"access_token"`
}

// gcpRefreshedToken exchanges a user refresh token for an access token.
//
// The laptop case, and the one an operator most often has: `gcloud auth application-default login`
// writes a refresh token, and this is what turns it into something a request can carry.
func gcpRefreshedToken(ctx context.Context, account *gcpServiceAccount) (string, error) {
	form := url.Values{
		"client_id":     {account.ClientID},
		"client_secret": {account.ClientSecret},
		"refresh_token": {account.RefreshToken},
		"grant_type":    {"refresh_token"},
	}
	var res gcpTokenResponse
	if err := formPost(ctx, "Google's token endpoint",
		"https://oauth2.googleapis.com/token", form.Encode(), &res); err != nil {
		return "", err
	}
	if res.AccessToken == "" {
		return "", errors.New("kms: Google's token endpoint returned no access token")
	}
	return res.AccessToken, nil
}

// gcpMetadataToken asks the instance's metadata server for the default service account's token.
func gcpMetadataToken(ctx context.Context) (string, error) {
	const path = "/computeMetadata/v1/instance/service-accounts/default/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gcpMetadataBase+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	res, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("kms: no Google credentials in %s, none in the application default "+
			"credentials file, and the metadata server did not answer: %w", BearerTokenEnv, err)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := readBounded(res)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kms: the metadata server answered %d for an access token", res.StatusCode)
	}
	var parsed gcpTokenResponse
	if err := decodeJSONString(body, &parsed); err != nil || parsed.AccessToken == "" {
		return "", fmt.Errorf("kms: the metadata server returned no usable access token")
	}
	return parsed.AccessToken, nil
}

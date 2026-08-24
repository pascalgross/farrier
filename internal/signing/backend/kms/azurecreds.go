package kms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// azureIMDSBase is the Azure instance metadata service.
const azureIMDSBase = "http://169.254.169.254"

// azureLoginBase is the identity platform's token endpoint host.
const azureLoginBase = "https://login.microsoftonline.com"

// azureTokenResponse is what either token endpoint answers.
type azureTokenResponse struct {
	// AccessToken is the bearer token.
	AccessToken string `json:"access_token"`
}

// azureToken finds a bearer token for one Key Vault scope.
//
// Environment override, then a client secret, then managed identity. Two flows are deliberately
// absent — client-certificate authentication and workload identity federation — and their escape
// hatch is the same one command every provider here has:
//
//	FARRIER_KMS_BEARER_TOKEN="$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)"
//
// which is documented in docs/INSTALL.md rather than implemented as a third credential chain.
func azureToken(ctx context.Context, scope string) (string, error) {
	if token := os.Getenv(BearerTokenEnv); token != "" {
		return token, nil
	}

	tenant := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	secret := os.Getenv("AZURE_CLIENT_SECRET")
	if tenant != "" && clientID != "" && secret != "" {
		return azureClientCredentialsToken(ctx, tenant, clientID, secret, scope)
	}
	if tenant != "" || secret != "" {
		return "", errors.New("kms: AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are set " +
			"in part. A client credential needs all three; set the rest, or unset them all to use a " +
			"managed identity")
	}
	return azureManagedIdentityToken(ctx, scope, clientID)
}

// azureClientCredentialsToken exchanges a client secret for a token.
func azureClientCredentialsToken(ctx context.Context, tenant, clientID, secret, scope string) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"scope":         {scope},
	}
	var res azureTokenResponse
	endpoint := azureLoginBase + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	if err := formPost(ctx, "the Microsoft identity platform", endpoint, form.Encode(), &res); err != nil {
		return "", err
	}
	if res.AccessToken == "" {
		return "", errors.New("kms: the Microsoft identity platform returned no access token")
	}
	return res.AccessToken, nil
}

// azureManagedIdentityToken asks the instance metadata service for a managed identity's token.
//
// The IMDS endpoint takes a resource rather than a scope, so the ".default" suffix the OAuth flow
// wants is trimmed here. Two spellings of one audience is exactly the kind of detail that produces a
// 401 nobody can explain, so it is converted in one place with the reason beside it.
func azureManagedIdentityToken(ctx context.Context, scope, clientID string) (string, error) {
	resource := strings.TrimSuffix(scope, "/.default")

	query := url.Values{
		"api-version": {"2018-02-01"},
		"resource":    {resource},
	}
	if clientID != "" {
		// A user-assigned identity, where the instance has more than one and the caller says which.
		query.Set("client_id", clientID)
	}

	endpoint := azureIMDSBase + "/metadata/identity/oauth2/token?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata", "true")

	res, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("kms: no Azure credentials in %s, none in AZURE_TENANT_ID/"+
			"AZURE_CLIENT_ID/AZURE_CLIENT_SECRET, and the managed identity endpoint did not "+
			"answer: %w", BearerTokenEnv, err)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := readBounded(res)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kms: the managed identity endpoint answered %d: %s", res.StatusCode, body)
	}
	var parsed azureTokenResponse
	if err := decodeJSONString(body, &parsed); err != nil || parsed.AccessToken == "" {
		return "", errors.New("kms: the managed identity endpoint returned no usable access token")
	}
	return parsed.AccessToken, nil
}

package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxResponseBytes bounds what a provider's answer may be.
//
// A signature and a public key are both small; a megabyte is three orders of magnitude of headroom and
// still a bound. It exists because this is the one part of `hostseal sign` that reads bytes from
// somewhere else, and an unbounded read from a service that is having a bad day is a signing tool that
// stops responding rather than one that reports an error.
const maxResponseBytes = 1 << 20

// credentialBudget bounds the whole business of finding a credential.
//
// Separate from, and much shorter than, the deadline on the signing call. On a laptop the metadata
// endpoints — 169.254.169.254, metadata.google.internal — black-hole rather than refuse, so without a
// budget of its own a misconfigured credential chain spends the entire signing deadline discovering
// nothing and then reports the KMS as slow. Two seconds is long enough for a real metadata server on a
// real instance and short enough that "no credentials configured" arrives as itself.
const credentialBudget = 2 * time.Second

// httpClient is the client every provider uses.
//
// One shared client so connections are reused across the two calls one signature makes, and so there
// is a single place where the transport is stated. No timeout is set on the client itself: every call
// carries a context, which is the deadline that matters and the one a caller can shorten.
var httpClient = &http.Client{}

// apiError is a provider's non-2xx answer.
//
// It carries the status and the body because cloud KMS errors are the part an operator can act on: a
// 403 from AWS names the missing IAM action, and a 404 from Key Vault names the key. Discarding that
// in favour of "the request failed" would leave the person at the terminal with nothing.
type apiError struct {
	// provider names the cloud, so the message is unambiguous in a shell history.
	provider string

	// status is the HTTP status code.
	status int

	// body is what the service said, bounded.
	body string
}

// Error renders the failure with what the service said.
func (e apiError) Error() string {
	body := strings.TrimSpace(e.body)
	if body == "" {
		body = "(no body)"
	}
	if len(body) > 2000 {
		body = body[:2000] + "…"
	}
	return fmt.Sprintf("kms: %s answered %d: %s", e.provider, e.status, body)
}

// postJSON sends a JSON request and decodes a JSON response.
//
// The request is built before it is signed, because AWS's SigV4 covers a hash of the body: a caller
// that serialised twice would sign one document and send another, which fails as a signature mismatch
// rather than as the bug it is. So the body is marshalled once here and handed to the signer as bytes.
func postJSON(ctx context.Context, provider, url string, body any, out any,
	decorate func(req *http.Request, body []byte) error) error {

	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("kms: encoding the %s request: %w", provider, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("kms: building the %s request: %w", provider, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if decorate != nil {
		if err := decorate(req, encoded); err != nil {
			return err
		}
	}
	return do(provider, req, out)
}

// getJSON sends a GET and decodes a JSON response.
func getJSON(ctx context.Context, provider, url string, out any,
	decorate func(req *http.Request, body []byte) error) error {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("kms: building the %s request: %w", provider, err)
	}
	if decorate != nil {
		if err := decorate(req, nil); err != nil {
			return err
		}
	}
	return do(provider, req, out)
}

// do runs one request and decodes its answer.
func do(provider string, req *http.Request, out any) error {
	//nolint:gosec // G704 flags a request whose URL is not a literal, which is unavoidable for a
	// client of three services and is bounded rather than unbounded: AWS's and Google's endpoints are
	// derived from the key reference and cannot be supplied at all, and Azure's host is checked
	// against the two Azure suffixes before it is used, in newAzure, for exactly this reason. There
	// is deliberately no endpoint setting anywhere in this package — one would be a signing oracle
	// pointed somewhere else — and the tests reach a fake by constructing a provider directly.
	res, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("kms: reaching %s: %w", provider, err)
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("kms: reading the %s response: %w", provider, err)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return apiError{provider: provider, status: res.StatusCode, body: string(raw)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("kms: the %s response is not the JSON this expects: %w", provider, err)
	}
	return nil
}

// formPost sends an application/x-www-form-urlencoded request, for the two OAuth token endpoints.
func formPost(ctx context.Context, provider, url, form string, out any) error {
	//nolint:gosec // G704 again, and with less to say than at the call in do: every URL that reaches
	// here is built from a package constant plus a tenant identifier that is percent-escaped into a
	// path segment. There is no reference field an operator can put a host in.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(form))
	if err != nil {
		return fmt.Errorf("kms: building the %s token request: %w", provider, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(provider, req, out)
}

// readBounded reads a response body under the same bound every other read here uses.
func readBounded(res *http.Response) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("kms: reading a response: %w", err)
	}
	return string(raw), nil
}

// decodeJSONString decodes a JSON document already read into a string.
//
// A tiny wrapper so that the metadata paths, which read a body and then decide whether it is JSON, do
// not each grow their own unmarshal-and-wrap.
func decodeJSONString(body string, out any) error {
	return json.Unmarshal([]byte(body), out)
}

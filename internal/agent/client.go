package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pegasusnetworks/farrier/internal/buildinfo"
	"github.com/pegasusnetworks/farrier/internal/protocol"
)

// maxResponseBytes bounds what the agent will read from the control plane.
//
// The agent trusts the control plane for availability and for nothing else. A server that returned an
// unbounded body could exhaust a managed host's memory, and "the control plane is compromised" is the
// scenario this whole product is designed around.
const maxResponseBytes = 8 << 20

// HTTPError is a non-2xx response from the control plane.
//
// The status code is carried separately from the message because the agent's behaviour is decided by
// the code — 401 stops, 429 honours Retry-After, 5xx retries forever — and never by parsing the text.
type HTTPError struct {
	// Status is the HTTP status code.
	Status int

	// Code is the machine-readable error from the problem document, if there was one.
	Code string

	// Message is the human-readable text, for the journal.
	Message string

	// RetryAfter is the parsed Retry-After header, zero if absent.
	RetryAfter time.Duration
}

// Error renders the failure for logs.
func (e *HTTPError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("control plane returned %d (%s): %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("control plane returned %d", e.Status)
}

// Client speaks the agent protocol to one control plane.
type Client struct {
	// baseURL is the control plane's base URL, without a trailing slash.
	baseURL string

	// http carries the mTLS configuration and the timeouts.
	http *http.Client
}

// NewClient builds a client that authenticates with a certificate.
//
// The certificate is loaded through a callback rather than fixed at construction so that a renewal
// takes effect on the next request without restarting the process — and, more importantly, so that a
// renewal that fails leaves the previous certificate in use rather than none.
func NewClient(baseURL string, certPath, keyPath, caPath string) (*Client, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, fmt.Errorf("agent: loading the client certificate: %w", err)
			}
			return &cert, nil
		},
	}

	// A CA bundle is honoured when one is present so that a private control-plane certificate works
	// without touching the system trust store. When it is absent the system roots are used, which is
	// the ordinary case for a control plane with a publicly trusted certificate.
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err == nil && len(pem) > 0 {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				tlsCfg.RootCAs = pool
			}
		}
	}

	return &Client{
		baseURL: trimSlash(baseURL),
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
				DialContext: (&net.Dialer{
					Timeout:   15 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout: 15 * time.Second,
				// Idle connections are kept because the agent talks to exactly one host, repeatedly,
				// and a fresh TLS handshake every sixty seconds is pure waste on both ends.
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
			// No client-level timeout. The job long-poll legitimately holds a connection for up to a
			// minute, and a global timeout would cut exactly the request the protocol is built around.
			// Every call carries its own context deadline instead.
		},
	}, nil
}

// NewUnauthenticatedClient builds a client for enrolment, which has no certificate yet.
func NewUnauthenticatedClient(baseURL, caPath string) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err == nil && len(pem) > 0 {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				tlsCfg.RootCAs = pool
			}
		}
	}
	return &Client{
		baseURL: trimSlash(baseURL),
		http: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// trimSlash removes a trailing slash so paths concatenate cleanly.
func trimSlash(url string) string {
	for len(url) > 0 && url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	return url
}

// BaseURL returns the control plane this client talks to.
func (c *Client) BaseURL() string { return c.baseURL }

// do performs one request and decodes the response.
//
// Every call in the agent goes through this, which is where the two things that must never be forgotten
// live: the response body is bounded before it is decoded, and a non-2xx becomes an HTTPError carrying
// the status rather than a generic failure the caller would have to parse.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("agent: encoding a request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("agent: building a request: %w", err)
	}
	req.Header.Set("User-Agent", buildinfo.UserAgent("agent"))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("agent: %s %s: %w", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()

	limited := io.LimitReader(res.Body, maxResponseBytes)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("agent: reading the response to %s %s: %w", method, path, err)
	}

	if res.StatusCode >= 300 {
		httpErr := &HTTPError{Status: res.StatusCode}
		var problem protocol.ErrorBody
		if json.Unmarshal(raw, &problem) == nil {
			httpErr.Code = problem.Error
			httpErr.Message = problem.Message
		}
		if after := res.Header.Get("Retry-After"); after != "" {
			if seconds, convErr := time.ParseDuration(after + "s"); convErr == nil {
				httpErr.RetryAfter = seconds
			}
		}
		return httpErr
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("agent: decoding the response to %s %s: %w", method, path, err)
		}
	}
	return nil
}

// Enroll exchanges a bootstrap token and a CSR for a certificate.
func (c *Client) Enroll(ctx context.Context, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var res protocol.EnrollResponse
	err := c.do(ctx, http.MethodPost, protocol.PathEnroll, req, &res)
	return res, err
}

// Heartbeat reports host state and returns the control plane's pacing and requests.
func (c *Client) Heartbeat(ctx context.Context, req protocol.HeartbeatRequest) (protocol.HeartbeatResponse, error) {
	var res protocol.HeartbeatResponse
	err := c.do(ctx, http.MethodPost, protocol.PathHeartbeat, req, &res)
	return res, err
}

// PollJobs long-polls for work, holding for up to wait seconds.
func (c *Client) PollJobs(ctx context.Context, wait int) ([]protocol.Job, error) {
	var res protocol.JobsResponse
	path := fmt.Sprintf("%s?wait=%d", protocol.PathJobs, wait)
	err := c.do(ctx, http.MethodGet, path, nil, &res)
	return res.Jobs, err
}

// ReportResult delivers a job result. It is safe to call repeatedly for the same job.
func (c *Client) ReportResult(ctx context.Context, result protocol.ResultRequest) error {
	path := protocol.PathResults + result.JobID + "/result"
	return c.do(ctx, http.MethodPost, path, result, nil)
}

// Renew exchanges a CSR for a fresh certificate, authenticated by the current one.
func (c *Client) Renew(ctx context.Context, csr string) (protocol.RenewResponse, error) {
	var res protocol.RenewResponse
	err := c.do(ctx, http.MethodPost, protocol.PathRenew, protocol.RenewRequest{CSR: csr}, &res)
	return res, err
}

// IsUnauthorised reports whether an error is a 401.
//
// It exists because 401 is the one status the agent must not retry: a host that re-enrolled itself
// whenever its certificate was rejected would be a host an attacker could cause to re-enrol. The agent
// stops and logs loudly instead, and an operator decides.
func IsUnauthorised(err error) bool {
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && httpErr.Status == http.StatusUnauthorized
}

// RetryAfter returns the server-requested delay from a 429, or zero.
func RetryAfter(err error) time.Duration {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.RetryAfter
	}
	return 0
}

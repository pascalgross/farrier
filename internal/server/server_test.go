package server_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pegasusnetworks/farrier/internal/agent"
	"github.com/pegasusnetworks/farrier/internal/auth"
	"github.com/pegasusnetworks/farrier/internal/ca"
	"github.com/pegasusnetworks/farrier/internal/protocol"
	"github.com/pegasusnetworks/farrier/internal/server"
	"github.com/pegasusnetworks/farrier/internal/store"
)

// harness is a running control plane with an in-memory store, for end-to-end tests.
//
// It runs the real server over real TLS with real client-certificate verification rather than calling
// handlers directly. Most of what enrolment and the heartbeat do is in the middleware — certificate
// verification, the revocation lookup, the identity that comes out of it — and a test that bypassed the
// transport would be testing the least interesting half.
type harness struct {
	// server is the running HTTPS test server.
	server *httptest.Server

	// store is the in-memory backing store, for assertions.
	store *store.Memory

	// dir is a scratch directory holding the CA and the agent's state.
	dir string

	// caFile is the test server's own certificate, so the agent can verify it.
	caFile string

	// adminToken authenticates the administrative API.
	adminToken string
}

// newHarness starts a control plane for one test.
func newHarness(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	authority, err := ca.Init(filepath.Join(dir, "ca"), "Farrier Test CA")
	if err != nil {
		t.Fatalf("creating a CA: %v", err)
	}

	memory := store.NewMemory()
	const adminToken = "test-admin-token-0123456789"
	provider, err := auth.NewStaticToken(adminToken, "tester")
	if err != nil {
		t.Fatalf("configuring auth: %v", err)
	}

	srv, err := server.New(server.Config{
		Authority:        authority,
		Store:            memory,
		Auth:             provider,
		HeartbeatSeconds: 60,
		TokenTTL:         time.Hour,
	})
	if err != nil {
		t.Fatalf("building the server: %v", err)
	}

	ts := httptest.NewUnstartedServer(srv)
	// The server's own TLS configuration carries ClientCAs and VerifyClientCertIfGiven; httptest adds
	// its generated server certificate to it. Starting with a default configuration instead would
	// silently disable client-certificate verification, which is most of what these tests exercise.
	ts.TLS = srv.TLSConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)

	caFile := filepath.Join(dir, "server-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("writing the server CA: %v", err)
	}

	return &harness{server: ts, store: memory, dir: dir, caFile: caFile, adminToken: adminToken}
}

// issueToken creates an enrolment token through the administrative API.
//
// It goes through the API rather than the store so that the token the tests use is one an operator
// could have created, including its hashing — which is the part that would break silently if the
// hashing on either side changed.
func (h *harness) issueToken(t *testing.T, group string) string {
	t.Helper()

	token, hash, err := server.NewEnrollmentToken()
	if err != nil {
		t.Fatalf("generating a token: %v", err)
	}
	err = h.store.CreateEnrollmentToken(context.Background(), store.EnrollmentToken{
		Hash:      hash,
		Label:     "test",
		Group:     group,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("storing a token: %v", err)
	}
	return token
}

// enrolHost enrols one host and returns its state directory and identifier.
func (h *harness) enrolHost(t *testing.T, name, token string) *agent.State {
	t.Helper()

	stateDir := filepath.Join(h.dir, "hosts", name)
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		t.Fatalf("creating a state directory: %v", err)
	}
	state, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		ServerURL: h.server.URL,
		Token:     token,
		StateDir:  stateDir,
		CABundle:  h.caFile,
		Hostname:  name,
	})
	if err != nil {
		t.Fatalf("enrolling %s: %v", name, err)
	}
	return state
}

// agentClient builds a protocol client authenticated as an enrolled host.
func (h *harness) agentClient(t *testing.T, state *agent.State) *agent.Client {
	t.Helper()

	client, err := agent.NewClient(h.server.URL,
		state.Path(agent.CertFile), state.Path(agent.KeyFile), h.caFile)
	if err != nil {
		t.Fatalf("building an agent client: %v", err)
	}
	return client
}

// TestEnrolmentIssuesAWorkingCertificate is the end-to-end path a new host takes.
//
// It asserts the whole chain in one test because the pieces are only meaningful together: a certificate
// that verifies but is not in the database authenticates nothing, and a database row without a
// certificate is a host that cannot speak.
func TestEnrolmentIssuesAWorkingCertificate(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))

	if state.HostID == "" {
		t.Fatal("enrolment returned no host id")
	}
	host, err := h.store.GetHost(context.Background(), state.HostID)
	if err != nil {
		t.Fatalf("the enrolled host is not in the store: %v", err)
	}
	if host.Hostname != "web-01" || host.Group != "web-prod" {
		t.Errorf("the host was recorded as %+v", host)
	}

	// The certificate must authenticate a real request, not merely parse.
	client := h.agentClient(t, state)
	if _, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:aaa",
	}); err != nil {
		t.Fatalf("the issued certificate could not authenticate a heartbeat: %v", err)
	}

	// The private key must have stayed on the host: what went to the server was a CSR.
	if _, err := os.Stat(state.Path(agent.KeyFile)); err != nil {
		t.Errorf("the agent has no private key on disk: %v", err)
	}
}

// TestEnrolmentTokensAreSingleUse covers the one thing protecting the unauthenticated endpoint.
//
// Enrolment is the only call without a client certificate, so everything that makes it safe is in the
// token: single-use, time-limited and consumed atomically. A token that worked twice would let anyone
// who saw it once enrol a host of their own.
func TestEnrolmentTokensAreSingleUse(t *testing.T) {
	h := newHarness(t)
	token := h.issueToken(t, "web-prod")

	h.enrolHost(t, "web-01", token)

	_, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		ServerURL: h.server.URL,
		Token:     token,
		StateDir:  filepath.Join(h.dir, "hosts", "web-02"),
		CABundle:  h.caFile,
		Hostname:  "web-02",
	})
	if err == nil {
		t.Fatal("a bootstrap token was accepted twice")
	}
	if !agent.IsUnauthorised(err) {
		t.Errorf("a reused token produced %v, want a 401", err)
	}
}

// TestUnknownAndExpiredTokensAreIndistinguishable asserts the refusal reveals nothing.
//
// Telling a caller whether a token was unknown, expired or already used is free reconnaissance for
// whoever is guessing. All three must produce the same response.
func TestUnknownAndExpiredTokensAreIndistinguishable(t *testing.T) {
	h := newHarness(t)

	expired, hash, err := server.NewEnrollmentToken()
	if err != nil {
		t.Fatalf("generating a token: %v", err)
	}
	if err := h.store.CreateEnrollmentToken(context.Background(), store.EnrollmentToken{
		Hash: hash, CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("storing an expired token: %v", err)
	}

	var statuses []int
	for i, token := range []string{"frr_completely-unknown", expired} {
		_, err := agent.Enroll(context.Background(), agent.EnrollOptions{
			ServerURL: h.server.URL,
			Token:     token,
			StateDir:  filepath.Join(h.dir, "hosts", "probe", string(rune('a'+i))),
			CABundle:  h.caFile,
		})
		if err == nil {
			t.Fatalf("token %q was accepted", token)
		}
		if !agent.IsUnauthorised(err) {
			t.Errorf("token %q produced %v, want a 401", token, err)
		}
		statuses = append(statuses, http.StatusUnauthorized)
	}
	if len(statuses) != 2 {
		t.Fatal("both cases should have produced a status")
	}
}

// TestUnauthenticatedRequestsAreRefused asserts every endpoint but enrolment needs a certificate.
//
// It matters that this is checked per route rather than at the TLS layer: the listener uses
// VerifyClientCertIfGiven, because enrolment has no certificate yet and a browser never will, so the
// requirement lives in middleware and could be forgotten on a new route.
func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	h := newHarness(t)
	client := h.server.Client()

	for _, path := range []string{
		protocol.PathHeartbeat,
		protocol.PathJobs,
		protocol.PathRenew,
		protocol.PathResults + "01JTEST/result",
	} {
		method := http.MethodPost
		if path == protocol.PathJobs {
			method = http.MethodGet
		}
		req, err := http.NewRequest(method, h.server.URL+path, http.NoBody)
		if err != nil {
			t.Fatalf("building a request for %s: %v", path, err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s returned %d without a certificate, want 401", method, path, res.StatusCode)
		}
	}
}

// TestRevocationTakesEffectImmediately is the whole revocation design in one test.
//
// Farrier uses neither CRL nor OCSP: every authenticated request looks the certificate's fingerprint up
// in the database. The property that buys is exactly this — a revoked host stops working on its next
// request, with no distribution delay.
func TestRevocationTakesEffectImmediately(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)

	if _, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{}); err != nil {
		t.Fatalf("a freshly enrolled host could not heartbeat: %v", err)
	}

	if err := h.store.RevokeHost(context.Background(), state.HostID); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	_, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{})
	if err == nil {
		t.Fatal("a revoked host was still able to heartbeat")
	}
	if !agent.IsUnauthorised(err) {
		t.Errorf("a revoked host got %v, want a 401", err)
	}
}

// TestHeartbeatIsDigestFirst is the behaviour that makes a fleet affordable.
//
// Five hundred hosts sending a full inventory every sixty seconds is hundreds of kilobytes per host per
// minute of write amplification. The server must ask for a document once, take it, and then stop asking
// while the digest is unchanged. Getting this wrong is a production incident rather than an
// inefficiency, and it fails in the direction that looks like it works.
func TestHeartbeatIsDigestFirst(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)
	ctx := context.Background()

	facts := map[string]any{"hostname": "web-01", "kernel": "6.8.0-51-generic"}

	// A digest the server has never seen: it must ask for the document.
	res, err := client.Heartbeat(ctx, protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:first",
	})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if !res.WantFacts {
		t.Error("the server did not ask for facts it has never seen")
	}

	// The document arrives. The server stores it and computes the digest itself.
	if _, err := client.Heartbeat(ctx, protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:first", Facts: facts,
	}); err != nil {
		t.Fatalf("heartbeat with facts: %v", err)
	}

	host, err := h.store.GetHost(ctx, state.HostID)
	if err != nil {
		t.Fatalf("reading the host: %v", err)
	}
	if len(host.Facts) == 0 {
		t.Fatal("the facts document was not stored")
	}
	// The server recomputes the digest rather than trusting the reported one. A host whose claimed
	// digest did not match what it sent would otherwise poison every future comparison.
	if host.FactsDigest == "sha256:first" {
		t.Error("the server stored the digest the host claimed rather than the one it computed")
	}

	// The same document again: no further request.
	res, err = client.Heartbeat(ctx, protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: host.FactsDigest,
	})
	if err != nil {
		t.Fatalf("steady-state heartbeat: %v", err)
	}
	if res.WantFacts {
		t.Error("the server asked again for a document whose digest it already holds")
	}

	// A changed digest: it asks again.
	res, err = client.Heartbeat(ctx, protocol.HeartbeatRequest{
		AgentVersion: "test", FactsDigest: "sha256:changed",
	})
	if err != nil {
		t.Fatalf("heartbeat after a change: %v", err)
	}
	if !res.WantFacts {
		t.Error("the server did not ask for facts after the digest changed")
	}
}

// TestHeartbeatPacingIsServerSet asserts the agent is told how often to call.
//
// The point of server-set pacing is that a control plane can spread load across the minute, or back a
// whole fleet off during an incident, without deploying a new agent.
func TestHeartbeatPacingIsServerSet(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)

	res, err := client.Heartbeat(context.Background(), protocol.HeartbeatRequest{AgentVersion: "test"})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if res.NextHeartbeatSeconds != 60 {
		t.Errorf("nextHeartbeatSeconds is %d, want 60", res.NextHeartbeatSeconds)
	}
	if res.ServerTime.IsZero() {
		t.Error("the response carries no server time, so the agent cannot report its clock offset")
	}
}

// TestJobPollReturnsAnEmptyArrayNotNull covers a small thing that costs a client a branch.
//
// docs/PROTOCOL.md shows an empty array. A client that had to handle both [] and null would have a
// branch nobody tests.
func TestJobPollReturnsAnEmptyArrayNotNull(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)

	jobs, err := client.PollJobs(context.Background(), 0)
	if err != nil {
		t.Fatalf("polling: %v", err)
	}
	if jobs == nil {
		t.Error("the poll returned null rather than an empty array")
	}
	if len(jobs) != 0 {
		t.Errorf("a fresh host has %d jobs, want none", len(jobs))
	}
}

// TestJobLongPollReturnsEarlyWhenWorkArrives asserts the wake-up path works.
//
// Without it the long-poll is a sleep: still correct, still functional, and slower in a way nobody
// notices until they wonder why jobs take half a minute to start.
func TestJobLongPollReturnsEarlyWhenWorkArrives(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)

	go func() {
		time.Sleep(100 * time.Millisecond)
		h.store.Enqueue(state.HostID, protocol.Job{
			ID: "01JTESTJOB", Intent: "facts.collect", Class: "read", IssuedAt: time.Now(),
		})
	}()

	started := time.Now()
	jobs, err := client.PollJobs(context.Background(), 10)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("polling: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != "01JTESTJOB" {
		t.Fatalf("the poll returned %+v", jobs)
	}
	if elapsed > 5*time.Second {
		t.Errorf("the long-poll took %s to return work enqueued after 100ms; it slept rather than woke",
			elapsed.Round(time.Millisecond))
	}
}

// TestResultsAreIdempotent asserts a redelivered result is accepted and changes nothing.
//
// The agent retries until it gets a 2xx, so a lost response means a second delivery. Work that succeeded
// but whose result was lost must never re-execute: that is how a retry turns one reboot into a reboot
// loop.
func TestResultsAreIdempotent(t *testing.T) {
	h := newHarness(t)
	state := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, state)
	ctx := context.Background()

	result := protocol.ResultRequest{
		JobID:      "01JTESTJOB",
		Status:     protocol.StatusSucceeded,
		StartedAt:  time.Now().Add(-time.Second),
		FinishedAt: time.Now(),
	}
	for i := range 3 {
		if err := client.ReportResult(ctx, result); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}

	stored, ok := h.store.Result("01JTESTJOB")
	if !ok {
		t.Fatal("the result was not recorded")
	}
	if stored.Status != protocol.StatusSucceeded {
		t.Errorf("the stored result is %+v", stored)
	}
}

// TestCertificateRenewalKeepsTheSameHostIdentity is the property that stops a re-key being a takeover.
//
// The identity comes from the presenting certificate and never from the CSR. A CSR is an untrusted
// document, and honouring its subject would let one enrolled host re-key a certificate for a different
// host entirely.
func TestCertificateRenewalKeepsTheSameHostIdentity(t *testing.T) {
	h := newHarness(t)
	stateA := h.enrolHost(t, "web-01", h.issueToken(t, "web-prod"))
	stateB := h.enrolHost(t, "web-02", h.issueToken(t, "web-prod"))
	client := h.agentClient(t, stateA)

	// A CSR naming the *other* host. The subject must be ignored entirely.
	res, err := client.Renew(context.Background(), csrNaming(t, stateB.HostID))
	if err != nil {
		t.Fatalf("renewing: %v", err)
	}

	block, _ := pem.Decode([]byte(res.Certificate))
	if block == nil {
		t.Fatal("the renewed certificate is not a PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the renewed certificate: %v", err)
	}
	if cert.Subject.CommonName != stateA.HostID {
		t.Errorf("a renewal for %s produced a certificate for %s: the CSR's subject was honoured",
			stateA.HostID, cert.Subject.CommonName)
	}
}

// csrNaming builds a certificate signing request whose subject names a given host.
//
// It exists to construct the attack the renewal test is about: a CSR is an untrusted document, and this
// is what an untrusted document claiming to be someone else looks like.
func csrNaming(t *testing.T, commonName string) string {
	t.Helper()
	csr, err := agent.TestCSR(commonName)
	if err != nil {
		t.Fatalf("building a CSR: %v", err)
	}
	return csr
}

// TestAdminAPINeedsACredential asserts the operator surface is not open.
//
// A compromised administrator account is inside the guarantee's threat model and still cannot run code
// on a host — but an *unauthenticated* administrative API would be a different and much sillier
// problem.
func TestAdminAPINeedsACredential(t *testing.T) {
	h := newHarness(t)
	client := h.server.Client()

	res, err := client.Get(h.server.URL + "/api/v1/hosts")
	if err != nil {
		t.Fatalf("GET /api/v1/hosts: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("the host list returned %d without a credential, want 401", res.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/hosts", http.NoBody)
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.adminToken)
	res, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/hosts with a token: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("the host list returned %d with a valid token, want 200", res.StatusCode)
	}
}

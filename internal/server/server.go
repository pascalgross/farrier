// Package server is the Farrier control plane's HTTP surface.
//
// It serves three things from one listener and one binary: the agent protocol under /agent/v1, an
// administrative API under /api/v1, and the Angular application embedded via embed.FS. One binary plus
// PostgreSQL is the entire deployment, because open-source software is installed by strangers who close
// the tab on friction and a four-service Compose stack is friction.
//
// The listener uses mutual TLS with VerifyClientCertIfGiven rather than RequireAndVerifyClientCert.
// That is not a weakening: enrolment must work before a host has a certificate, and an operator's
// browser has none at all. Every route that needs a certificate checks for one itself, and does so in
// the same middleware that performs the revocation lookup, so there is one place where "is this a
// legitimate agent" is answered rather than several.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/pegasusnetworks/farrier/internal/auth"
	"github.com/pegasusnetworks/farrier/internal/buildinfo"
	"github.com/pegasusnetworks/farrier/internal/ca"
	"github.com/pegasusnetworks/farrier/internal/notify"
	"github.com/pegasusnetworks/farrier/internal/protocol"
	"github.com/pegasusnetworks/farrier/internal/store"
)

// webAssets holds the built Angular application.
//
//go:embed all:assets
var webAssets embed.FS

// Config is everything the server needs to run.
type Config struct {
	// Addr is the listen address, such as ":8443".
	Addr string

	// TLSCert and TLSKey are the server's own certificate and key, PEM files on disk.
	//
	// They are the *server's* identity, separate from the agent CA: agents verify the control plane
	// like any HTTPS client, so this is usually a publicly trusted certificate while agent
	// certificates come from Farrier's private CA.
	TLSCert string
	TLSKey  string

	// Authority issues and verifies agent certificates.
	Authority *ca.Authority

	// Store is the persistence layer.
	Store store.Store

	// Auth authenticates human operators.
	Auth auth.Provider

	// Sinks receive outbound event notifications.
	Sinks []notify.Sink

	// HeartbeatSeconds is the pacing handed to agents.
	//
	// It is server-set so that a control plane can spread load across the minute, or back a whole
	// fleet off during an incident, without deploying a new agent.
	HeartbeatSeconds int

	// TokenTTL is how long a newly issued enrolment token remains usable.
	TokenTTL time.Duration
}

// Server is the running control plane.
type Server struct {
	// cfg is the configuration this server was built with.
	cfg Config

	// mux routes every request.
	mux *http.ServeMux

	// assets is the embedded web application rooted at its own directory.
	assets fs.FS

	// hasUI reports whether a built application is actually present.
	hasUI bool

	// enrolLimiter bounds attempts against the one endpoint that needs no client certificate.
	enrolLimiter *rateLimiter
}

// New builds a server from a configuration.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("server: a store is required")
	}
	if cfg.Authority == nil {
		return nil, errors.New("server: a certificate authority is required")
	}
	if cfg.Auth == nil {
		return nil, errors.New("server: an authentication provider is required")
	}
	if cfg.HeartbeatSeconds == 0 {
		cfg.HeartbeatSeconds = protocol.DefaultHeartbeatSeconds
	}
	if cfg.TokenTTL == 0 {
		// Long enough to provision a machine at a leisurely pace, short enough that a token pasted into
		// a ticket and forgotten is not still valid next month.
		cfg.TokenTTL = 24 * time.Hour
	}

	assets, err := fs.Sub(webAssets, "assets")
	if err != nil {
		return nil, fmt.Errorf("server: reading embedded assets: %w", err)
	}
	_, statErr := fs.Stat(assets, "index.html")

	s := &Server{
		cfg:          cfg,
		mux:          http.NewServeMux(),
		assets:       assets,
		hasUI:        statErr == nil,
		enrolLimiter: newRateLimiter(enrollBurst, enrollRefill),
	}
	s.routes()
	return s, nil
}

// routes registers every handler.
//
// The complete surface is visible in one function on purpose. "What can this server be asked to do" is
// a question an operator evaluating Farrier should be able to answer by reading one screen, in the same
// way the intent catalogue answers it for hosts.
func (s *Server) routes() {
	// The agent protocol. Five endpoints, no more.
	s.mux.HandleFunc("POST "+protocol.PathEnroll, s.handleEnroll)
	s.mux.Handle("POST "+protocol.PathHeartbeat, s.requireAgent(s.handleHeartbeat))
	s.mux.Handle("GET "+protocol.PathJobs, s.requireAgent(s.handleJobs))
	s.mux.Handle("POST "+protocol.PathResults+"{id}/result", s.requireAgent(s.handleResult))
	s.mux.Handle("POST "+protocol.PathRenew, s.requireAgent(s.handleRenew))

	// The administrative API, for the UI and for scripting.
	s.mux.Handle("GET /api/v1/hosts", s.requireOperator(s.handleListHosts))
	s.mux.Handle("GET /api/v1/hosts/{id}", s.requireOperator(s.handleGetHost))
	s.mux.Handle("POST /api/v1/hosts/{id}/revoke", s.requireOperator(s.handleRevokeHost))
	s.mux.Handle("DELETE /api/v1/hosts/{id}", s.requireOperator(s.handleDeleteHost))
	s.mux.Handle("GET /api/v1/tokens", s.requireOperator(s.handleListTokens))
	s.mux.Handle("POST /api/v1/tokens", s.requireOperator(s.handleCreateToken))
	s.mux.Handle("GET /api/v1/catalogue", s.requireOperator(s.handleCatalogue))

	// Unauthenticated, and deliberately so: a health check that needs a credential is a health check
	// the load balancer cannot perform.
	s.mux.HandleFunc("GET /healthz", s.handleHealth)

	s.mux.HandleFunc("/", s.handleUI)
}

// ServeHTTP routes a request, so the server can be used directly in tests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// TLSConfig builds the listener's TLS configuration.
//
// ClientAuth is VerifyClientCertIfGiven rather than RequireAndVerifyClientCert because three different
// kinds of client reach this port: an agent enrolling, which has no certificate yet; an enrolled agent,
// which has one; and an operator's browser, which never will. Requiring one at the TLS layer would make
// enrolment impossible and the UI unreachable, so the requirement lives in the middleware that also
// performs the revocation lookup.
//
// Client certificates are verified against Farrier's own CA only. Using the system roots would mean any
// publicly trusted certificate could authenticate as an agent.
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    s.cfg.Authority.ClientCAPool(),
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: nil, // filled in by ListenAndServe from the configured files
	}
}

// ListenAndServe runs the server until the context ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	tlsCfg := s.TLSConfig()
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("server: loading the TLS certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	srv := &http.Server{
		Addr:      s.cfg.Addr,
		Handler:   s.mux,
		TLSConfig: tlsCfg,
		// ReadHeaderTimeout bounds a slowloris; the read timeout is deliberately absent because the
		// job long-poll legitimately holds a connection open for up to a minute, and a global read
		// timeout would cut exactly the request the protocol is built around.
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown was not clean", "error", err)
		}
	}()

	slog.Info("farrier control plane listening",
		"addr", s.cfg.Addr,
		"version", buildinfo.String(),
		"tls", len(tlsCfg.Certificates) > 0,
		"ui", s.hasUI,
		"ca_expires", s.cfg.Authority.NotAfter().Format(time.RFC3339),
	)

	if len(tlsCfg.Certificates) == 0 {
		// Refused rather than degraded. Client certificates require TLS, so a control plane serving
		// plain HTTP does not merely serve agent traffic insecurely — it cannot serve it at all, and
		// every agent would get a 401 that no amount of debugging on the agent side would explain.
		return errors.New("server: no TLS certificate. Pass --tls-cert and --tls-key, or let " +
			"`farrier-server serve` issue one from the agent CA. The agent protocol authenticates hosts " +
			"with client certificates, which do not exist without TLS")
	}
	err := srv.ListenAndServeTLS("", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// agentContextKey is the type of the context key carrying an authenticated host.
//
// A private named type rather than a string so that nothing outside this package can read or overwrite
// the value, which is the difference between a context key and a global variable.
type agentContextKey struct{}

// operatorContextKey is the type of the context key carrying an authenticated operator.
type operatorContextKey struct{}

// requireAgent authenticates an agent by client certificate and revocation lookup.
//
// The revocation lookup is the point: verifying the chain proves the certificate was issued, and the
// database lookup proves it has not been withdrawn since. Farrier uses neither CRL nor OCSP, so a
// handler that skipped this would accept a revoked host indefinitely — which is exactly the failure a
// revocation mechanism exists to prevent.
func (s *Server) requireAgent(next func(http.ResponseWriter, *http.Request, store.Host)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeError(w, http.StatusUnauthorized, "no_client_certificate",
				"this endpoint requires an agent client certificate")
			return
		}
		peer := r.TLS.PeerCertificates[0]
		fingerprint := Fingerprint(peer)

		cert, err := s.cfg.Store.LookupCertificate(r.Context(), fingerprint)
		switch {
		case errors.Is(err, store.ErrNotFound):
			// A certificate this CA issued but the database does not know is one that was revoked and
			// purged, or one issued by a CA key that is no longer the database's. Both are refusals.
			writeError(w, http.StatusUnauthorized, "unknown_certificate", "certificate is not recognised")
			return
		case err != nil:
			slog.Error("certificate lookup failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "could not verify the certificate")
			return
		case cert.Revoked:
			writeError(w, http.StatusUnauthorized, "revoked", "certificate has been revoked")
			return
		}

		host, err := s.cfg.Store.GetHost(r.Context(), cert.HostID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusUnauthorized, "unknown_host", "host is not recognised")
			return
		case err != nil:
			slog.Error("host lookup failed", "error", err, "host", cert.HostID)
			writeError(w, http.StatusInternalServerError, "internal", "could not load the host")
			return
		case host.Revoked:
			writeError(w, http.StatusUnauthorized, "revoked", "host has been revoked")
			return
		}

		ctx := context.WithValue(r.Context(), agentContextKey{}, host)
		next(w, r.WithContext(ctx), host)
	})
}

// requireOperator authenticates a human operator.
func (s *Server) requireOperator(next func(http.ResponseWriter, *http.Request, auth.Identity)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := s.cfg.Auth.Authenticate(r.Context(), r)
		if err != nil || identity == nil {
			// One response for missing, malformed and wrong. Telling the caller which half of their
			// guess was right is free reconnaissance.
			w.Header().Set("WWW-Authenticate", `Bearer realm="farrier"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "a valid operator credential is required")
			return
		}
		ctx := context.WithValue(r.Context(), operatorContextKey{}, *identity)
		next(w, r.WithContext(ctx), *identity)
	})
}

// Fingerprint returns the SHA-256 fingerprint of a certificate, lower-case hex.
//
// This one value is the revocation key, so it is computed in one exported function rather than at each
// call site: two places computing it differently — over the PEM rather than the DER, say — would
// produce a lookup that never matches and a fleet that could not authenticate.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// handleHealth reports that the process is up and can reach its database.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if _, err := s.cfg.Store.ListEnrollmentTokens(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database", "the database is not reachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": buildinfo.Version,
		"commit":  buildinfo.Revision(),
	})
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("could not write a response body", "error", err)
	}
}

// writeError writes a problem document.
//
// Agents must not require the body and must never parse Message for control flow, but a human reading
// a curl output during an incident reads exactly this, so it is worth writing properly.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, protocol.ErrorBody{Error: code, Message: message})
}

// decodeJSON reads a bounded JSON request body.
//
// The bound is applied here rather than trusted to well-behaved agents. In multi-tenant hosting one
// host filling the database fills it for other customers, and the first place to stop that is before
// the bytes are in memory.
func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

// isTooLarge reports whether a decode failed because the body exceeded its bound.
//
// The two failures want different statuses and different agent behaviour: docs/PROTOCOL.md §11 says an
// agent drops a 400 without retrying and truncates-and-retries a 413. Returning one status for both
// would make a malformed body look like an over-size one, and an agent would keep retrying something
// that will never parse.
func isTooLarge(err error) bool {
	var maxBytes *http.MaxBytesError
	return errors.As(err, &maxBytes)
}

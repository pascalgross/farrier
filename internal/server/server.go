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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pascalgross/farrier/internal/auth"
	"github.com/pascalgross/farrier/internal/buildinfo"
	"github.com/pascalgross/farrier/internal/ca"
	"github.com/pascalgross/farrier/internal/notify"
	"github.com/pascalgross/farrier/internal/onlinekey"
	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/seal"
	"github.com/pascalgross/farrier/internal/store"
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

	// Accounts is the local-accounts provider, nil when this installation has none.
	//
	// It is here as well as inside Auth, and the duplication is the point: Auth answers "who is this
	// request", which is all any handler needs, while signing in and signing out are operations on a
	// particular kind of credential and have to reach the implementation that owns its format. A nil
	// value means the two session routes answer 404, which is the honest response for a control plane
	// authenticated by bearer token alone.
	Accounts *auth.Accounts

	// OnlineKey signs routine jobs, and is nil when this control plane has none.
	//
	// Nil is a supported configuration rather than a broken one: without it the routine tier is
	// refused, which is exactly where the agent was before an online key existed. It is not a
	// substitute for the destructive tier's authority and cannot be used as one — the agent verifies
	// the two against different anchors and will not accept this key for a destructive intent.
	OnlineKey *onlinekey.Key

	// TemplateKey seals provisioning template bodies at rest, and is required.
	//
	// Required rather than optional, unlike OnlineKey, because its absence would not disable a feature
	// — it would ship the same feature storing plaintext, and docs/SECURITY.md §7 promises encrypted
	// bodies unconditionally. `farrier-server serve` generates one beside the CA on first start, so
	// requiring it costs an operator nothing.
	TemplateKey *seal.Key

	// HeartbeatSeconds is the pacing handed to agents.
	//
	// It is server-set so that a control plane can spread load across the minute, or back a whole
	// fleet off during an incident, without deploying a new agent.
	HeartbeatSeconds int

	// SMTP is how alert mail leaves the control plane, zero-valued for not at all.
	//
	// Process configuration rather than tenant data: which relay this control plane may speak to is
	// the installation operator's decision. Tenants choose recipients, per alert rule, and a rule
	// with recipients on an installation with no relay is delivered everywhere except mail — with
	// the gap named in the log rather than silent.
	SMTP notify.SMTPConfig

	// TokenTTL is how long a newly issued enrolment token remains usable.
	TokenTTL time.Duration
}

// Server is the running control plane.
type Server struct {
	// cfg is the configuration this server was built with.
	cfg Config

	// mux routes every request.
	mux *http.ServeMux

	// paths matches a request path against the API and agent routes while ignoring the method.
	//
	// It exists so that a request under /api or /agent that matched no route can tell an unknown path
	// from a known path asked for with the wrong method, and answer 404 or 405 accordingly. Deriving it
	// from the same route() calls that build mux is what keeps the two from drifting: a hand-kept second
	// table would answer 405 for a route somebody had already deleted.
	paths *http.ServeMux

	// allow accumulates, per route pattern, the methods that pattern is registered with.
	//
	// It is a build-time scratch table rather than state: routes() fills it and sealRoutes() turns it
	// into handlers on paths. A ServeMux panics on a duplicated pattern, and three of these routes
	// share a path with a different method, so the methods have to be collected before they are
	// registered.
	allow map[string][]string

	// assets is the embedded web application rooted at its own directory.
	assets fs.FS

	// hasUI reports whether a built application is actually present.
	hasUI bool

	// enrolLimiter bounds attempts against the one endpoint that needs no client certificate.
	enrolLimiter *rateLimiter

	// signInLimiter bounds attempts against the other endpoint that needs no credential at all.
	//
	// A separate limiter rather than a shared one, because the two defend different things and want
	// different numbers: enrolment is a fleet being built and should tolerate a burst, and a sign-in
	// costs this process 64 MiB of Argon2id per attempt.
	signInLimiter *rateLimiter

	// accounts is the local-accounts provider, nil when this installation has none.
	accounts *auth.Accounts

	// events fans live events out to subscribed browser tabs; the durable copy is the store's inbox.
	events eventStream

	// outbound counts the deliveries running detached from the request that produced them, so a
	// shutdown drains them rather than abandoning an alert mail mid-conversation.
	outbound sync.WaitGroup

	// background counts the long-lived goroutines the server owns — today, the alert evaluator.
	//
	// Separate from outbound and waited on first: the evaluator *produces* detached deliveries, so
	// closing the outbound set before its last pass finished would refuse exactly the notifications
	// a stopping control plane most needs to have sent.
	background sync.WaitGroup

	// outboundMu guards draining and inFlight, and serialises them against outbound.Add.
	outboundMu sync.Mutex

	// draining reports that the shutdown drain has begun, after which no new delivery starts.
	draining bool

	// inFlight is how many detached deliveries are running, for the cap in detach.
	inFlight int

	// outboundCtx is the parent of every detached delivery.
	//
	// It exists so that a shutdown ends them at a moment this process chooses, rather than whenever
	// the supervisor loses patience: the listener stops, the drain waits, and anything still going
	// after the grace period is cancelled with a log line saying so.
	outboundCtx context.Context

	// outboundStop cancels outboundCtx.
	outboundStop context.CancelFunc
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
	if cfg.TemplateKey == nil {
		return nil, errors.New("server: a template sealing key is required; " +
			"seal.Ensure generates one beside the CA")
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
		cfg:           cfg,
		mux:           http.NewServeMux(),
		assets:        assets,
		hasUI:         statErr == nil,
		enrolLimiter:  newRateLimiter(enrollBurst, enrollRefill),
		signInLimiter: newRateLimiter(signInBurst, signInRefill),
		accounts:      cfg.Accounts,
		paths:         http.NewServeMux(),
		allow:         map[string][]string{},
	}
	// Background rather than derived from a request or from ListenAndServe's context: a detached
	// delivery must outlive the request that caused it, and must still be cancellable as a group.
	s.outboundCtx, s.outboundStop = context.WithCancel(context.Background())
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
	s.route(http.MethodPost, protocol.PathEnroll, http.HandlerFunc(s.handleEnroll))
	s.route(http.MethodPost, protocol.PathHeartbeat, s.requireAgent(s.handleHeartbeat))
	s.route(http.MethodGet, protocol.PathJobs, s.requireAgent(s.handleJobs))
	s.route(http.MethodPost, protocol.PathResults+"{id}/result", s.requireAgent(s.handleResult))
	s.route(http.MethodPost, protocol.PathRenew, s.requireAgent(s.handleRenew))

	// The administrative API, for the UI and for scripting.
	s.route(http.MethodGet, "/api/v1/hosts", s.requireOperator(s.handleListHosts))
	s.route(http.MethodGet, "/api/v1/hosts/{id}", s.requireOperator(s.handleGetHost))
	s.route(http.MethodPost, "/api/v1/hosts/{id}/revoke", s.requireOperator(s.handleRevokeHost))
	s.route(http.MethodDelete, "/api/v1/hosts/{id}", s.requireOperator(s.handleDeleteHost))
	s.route(http.MethodGet, "/api/v1/tokens", s.requireOperator(s.handleListTokens))
	s.route(http.MethodPost, "/api/v1/tokens", s.requireOperator(s.handleCreateToken))
	s.route(http.MethodGet, "/api/v1/catalogue", s.requireOperator(s.handleCatalogue))
	s.route(http.MethodGet, "/api/v1/jobs", s.requireOperator(s.handleListJobs))
	s.route(http.MethodPost, "/api/v1/jobs", s.requireOperator(s.handleCreateJob))
	s.route(http.MethodGet, "/api/v1/jobs/{id}", s.requireOperator(s.handleGetJob))
	s.route(http.MethodPost, "/api/v1/jobs/{id}/approve", s.requireOperator(s.handleApproveJob))
	s.route(http.MethodGet, "/api/v1/whoami", s.requireIdentity(s.handleWhoami))

	// Signing in and signing out. Both are unauthenticated on purpose: the first is where a credential
	// comes from, and the second has to work for a session that has already stopped authenticating —
	// otherwise the cookie and its row both stay behind.
	s.route(http.MethodPost, "/api/v1/session", http.HandlerFunc(s.handleSignIn))
	s.route(http.MethodDelete, "/api/v1/session", http.HandlerFunc(s.handleSignOut))
	s.route(http.MethodGet, "/api/v1/templates", s.requireOperator(s.handleListTemplates))
	s.route(http.MethodPost, "/api/v1/templates", s.requireOperator(s.handleCreateTemplate))
	s.route(http.MethodGet, "/api/v1/templates/{name}", s.requireOperator(s.handleGetTemplate))
	s.route(http.MethodGet, "/api/v1/templates/{name}/versions",
		s.requireOperator(s.handleListTemplateVersions))
	s.route(http.MethodPost, "/api/v1/templates/{name}/render", s.requireOperator(s.handleRenderTemplate))
	s.route(http.MethodGet, "/api/v1/events", s.requireOperator(s.handleListEvents))
	s.route(http.MethodGet, "/api/v1/events/stream", s.requireOperator(s.handleEventStream))
	s.route(http.MethodGet, "/api/v1/services/failed", s.requireOperator(s.handleFailedServices))
	s.route(http.MethodGet, "/api/v1/hosts/{id}/services/history", s.requireOperator(s.handleServiceHistory))
	s.route(http.MethodGet, "/api/v1/alerts", s.requireOperator(s.handleListAlertRules))
	s.route(http.MethodPost, "/api/v1/alerts", s.requireOperator(s.handleCreateAlertRule))
	s.route(http.MethodPatch, "/api/v1/alerts/{id}", s.requireOperator(s.handleUpdateAlertRule))
	s.route(http.MethodDelete, "/api/v1/alerts/{id}", s.requireOperator(s.handleDeleteAlertRule))

	// Tenant administration, for whoever runs the installation rather than a fleet in it. These are the
	// only routes a platform credential can reach, and the only routes an operator credential cannot.
	s.route(http.MethodGet, "/api/v1/tenants", s.requirePlatform(s.handleListTenants))
	s.route(http.MethodPost, "/api/v1/tenants", s.requirePlatform(s.handleCreateTenant))
	s.route(http.MethodGet, "/api/v1/tenants/{id}", s.requirePlatform(s.handleGetTenant))
	s.route(http.MethodPatch, "/api/v1/tenants/{id}", s.requirePlatform(s.handleUpdateTenant))
	s.route(http.MethodDelete, "/api/v1/tenants/{id}", s.requirePlatform(s.handleDeleteTenant))

	// Unauthenticated, and deliberately so: a health check that needs a credential is a health check
	// the load balancer cannot perform.
	s.mux.HandleFunc("GET /healthz", s.handleHealth)

	// Everything else under the two API prefixes is a client error and is answered as one. Without
	// these two the "/" fallback below would match instead and return 200 and an HTML page: a mistyped
	// approve call would look like an approval, and — the sharper edge — an agent posting a result to a
	// path that does not route would see 2xx, treat the result as delivered and drop it, which quietly
	// converts the protocol's at-least-once delivery into at-most-once.
	s.mux.HandleFunc("/api/", s.handleAPIMiss)
	s.mux.HandleFunc("/agent/", s.handleAPIMiss)

	s.mux.HandleFunc("/", s.handleUI)
	s.sealRoutes()
}

// route registers one API or agent route and records the method its path accepts.
//
// Every such route goes through here rather than through mux directly, so that the method table cannot
// be left behind by an edit to the route list above.
func (s *Server) route(method, pattern string, h http.Handler) {
	s.mux.Handle(method+" "+pattern, h)
	s.allow[pattern] = append(s.allow[pattern], method)
}

// sealRoutes turns the collected methods into the path-only mux the miss handler consults.
func (s *Server) sealRoutes() {
	for pattern, methods := range s.allow {
		slices.Sort(methods)
		s.paths.Handle(pattern, allowedMethods(strings.Join(methods, ", ")))
	}
}

// allowedMethods answers a request whose path is a real route but whose method is not.
//
// It is a distinct type rather than a closure so that the miss handler can recognise its own handler by
// type assertion: http.ServeMux also returns synthesised redirect handlers, and a 405 for one of those
// would be a lie about a path that does not exist.
type allowedMethods string

// ServeHTTP reports that the path exists but not for this method.
func (a allowedMethods) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", string(a))
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed",
		"this path does not accept "+r.Method+"; it accepts "+string(a))
}

// handleAPIMiss answers a request under /api or /agent that matched no route.
//
// The distinction it draws is worth the machinery: 405 tells a client its path is right and its verb is
// wrong, and 404 tells it the path is wrong. Answering 404 for both would send somebody hunting for a
// typo in a path that is correct.
func (s *Server) handleAPIMiss(w http.ResponseWriter, r *http.Request) {
	if h, _ := s.paths.Handler(r); h != nil {
		if allow, ok := h.(allowedMethods); ok {
			allow.ServeHTTP(w, r)
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
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

	// context.Background below is correct here and the linter's usual advice is not: this goroutine runs
	// *because* ctx was cancelled, so deriving the shutdown deadline from it would produce a context
	// that is already done and a Shutdown that abandons every in-flight request instead of draining it.
	// The fifteen seconds are what a long-poll needs to finish.
	// Closed once Shutdown has returned, which is what the drain below waits for. ListenAndServeTLS
	// returns the moment Shutdown is *invoked*, so draining on that alone would race the connection
	// drain and abandon deliveries detached by requests that were still being served.
	shutdownDone := make(chan struct{})
	go func() { //nolint:gosec // G118: the request-scoped context is the cancelled one; see above.
		defer close(shutdownDone)
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
		// A deliberate stop: the handlers are still finishing, and some of them are still detaching
		// deliveries. Wait for that to be over before deciding what is outstanding.
		<-shutdownDone
		s.drainOutbound(ctx)
		return nil
	}

	// Any other error means the listener never ran or died under us, so nothing is waiting on
	// Shutdown to return. Drain anyway: the evaluator may have detached work already.
	s.drainOutbound(ctx)
	return err
}

// outboundDrainGrace is how long a stopping control plane waits, once for the evaluator and once for
// the deliveries.
//
// Deliveries beyond the inbox run detached from the request that produced them, so the process must
// not simply exit while one is in flight: an alert mail abandoned mid-SMTP is precisely the delivery
// whose absence somebody would trust. It must not wait indefinitely either — a full retry sequence
// against a hanging relay outlasts every reasonable stop timeout, and a service killed by its
// supervisor is a service that logged nothing about why.
//
// The arithmetic that picks it, against systemd's default 90-second TimeoutStopSec: fifteen seconds
// for the connection drain, then two of these graces, then a tail of at most three uncancellable
// delivery records at deliveryRecordTimeout each. Ten seconds keeps the total near fifty, which
// leaves room for a supervisor configured tighter than the default.
const outboundDrainGrace = 10 * time.Second

// drainOutbound waits for the detached deliveries, then cancels the ones that are still going.
//
// The second wait is bounded by the work itself rather than by another timer. Cancelling the group
// makes the webhook return at once, makes the retry loop stop between attempts, and makes the rule
// loop stop starting mail; an SMTP conversation already in progress finishes inside the deadline it
// set on its own connection. What is left after that is at most three delivery records — the attempt
// that was cancelled, the claim that could not be made, and the rules that were never started — each
// on a deadline of its own, deliberately surviving the cancellation: the delivery a stopping control
// plane abandoned is exactly the one whose absence somebody would otherwise trust. Fifteen seconds
// past the grace, in the worst case, bought with an honest answer.
func (s *Server) drainOutbound(ctx context.Context) {
	// The evaluator first: it is a producer, and closing the outbound set while it is still mid-pass
	// would refuse the very notifications this drain exists to let finish. It returns on the same
	// cancelled context the listener stopped on, and every store call in a pass is bounded, so this
	// wait is short.
	//
	// Only when that context is actually done, though. A listener that failed to *start* — a port
	// already bound — leaves the evaluator legitimately ticking, and waiting for it there would hang
	// the process on the one error it most needs to report and exit on.
	//
	// Bounded like the wait below it, and for a sharper reason than symmetry: the calls in a pass
	// that survive cancellation are the *reporting* ones — the inbox write, the delivery record —
	// and against a database that hangs rather than refuses, an unbounded wait here would spend the
	// supervisor's whole patience before the grace below had even started, and the process would be
	// killed still holding the records this drain exists to preserve.
	if ctx.Err() != nil && !waitBounded(&s.background, outboundDrainGrace) {
		slog.Warn("the alert evaluator did not finish its pass in time; closing deliveries anyway",
			"waited", outboundDrainGrace)
	}

	// Then closed to new work, under the same lock detach takes. A WaitGroup whose counter goes from
	// zero back up while somebody waits on it is a documented misuse.
	s.outboundMu.Lock()
	s.draining = true
	s.outboundMu.Unlock()

	if waitBounded(&s.outbound, outboundDrainGrace) {
		return
	}

	slog.Warn("event deliveries are still running at shutdown; cancelling them",
		"waited", outboundDrainGrace)
	s.outboundStop()
	s.outbound.Wait()
}

// waitBounded waits for a group and reports whether it finished within the grace.
//
// A WaitGroup has no deadline of its own, and every wait in a shutdown path needs one: the difference
// between a process that exits late with a log line and one the supervisor kills is exactly this.
func waitBounded(wg *sync.WaitGroup, grace time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(grace):
		return false
	}
}

// agentContextKey is the type of the context key carrying an authenticated host.
//
// A private named type rather than a string so that nothing outside this package can read or overwrite
// the value, which is the difference between a context key and a global variable.
type agentContextKey struct{}

// operatorContextKey is the type of the context key carrying an authenticated operator.
type operatorContextKey struct{}

// operator is an authenticated human operator together with the store handle that reaches their tenant.
//
// The two travel together on purpose. A handler is handed the scoped store rather than the whole one,
// so "which tenant is this request allowed to touch" is answered once, in the middleware, and a handler
// that forgot to ask has no way to reach anything it should not — there is no unscoped store in reach
// to forget with.
type operator struct {
	// Identity is who they are.
	auth.Identity

	// Store reaches this operator's tenant and nothing else.
	Store store.Scoped
}

// caller is an authenticated agent together with the store handle for its tenant.
//
// The host is resolved from the certificate and the tenant is resolved from the same row, so an agent
// never names its own tenant and could not name a different one. That is why the agent protocol needed
// no wire change for any of this: the tenant is a property of the credential, and the credential is a
// certificate this control plane issued.
type caller struct {
	// Host is the machine that authenticated.
	Host store.Host

	// Store reaches that host's tenant and nothing else.
	Store store.Scoped
}

// requireAgent authenticates an agent by client certificate and revocation lookup.
//
// The revocation lookup is the point: verifying the chain proves the certificate was issued, and the
// database lookup proves it has not been withdrawn since. Farrier uses neither CRL nor OCSP, so a
// handler that skipped this would accept a revoked host indefinitely — which is exactly the failure a
// revocation mechanism exists to prevent.
//
// It is also where an agent request acquires its tenant. The certificate row carries it, so the lookup
// that was already happening on every request answers both questions at once, and there is exactly one
// place to get it wrong rather than one per handler.
func (s *Server) requireAgent(next func(http.ResponseWriter, *http.Request, caller)) http.Handler {
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

		scoped := s.cfg.Store.In(cert.TenantID)
		host, err := scoped.GetHost(r.Context(), cert.HostID)
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

		who := caller{Host: host, Store: scoped}
		ctx := context.WithValue(r.Context(), agentContextKey{}, who)
		next(w, r.WithContext(ctx), who)
	})
}

// requireOperator authenticates a human operator and scopes the request to their tenant.
//
// The tenant comes from the credential and from nowhere else — not a path segment, not a header, not a
// query parameter. There is therefore no field of the request an operator could edit to reach another
// fleet, which is a stronger statement than "every handler checks", because it does not depend on every
// handler.
//
// A platform administrator is refused here rather than given an empty tenant. Running an installation
// for other people is a different job from reading what they run, and the credential that does the
// first must not silently be able to do the second.
func (s *Server) requireOperator(next func(http.ResponseWriter, *http.Request, operator)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := s.cfg.Auth.Authenticate(r.Context(), r)
		if err != nil || identity == nil {
			// One response for missing, malformed and wrong. Telling the caller which half of their
			// guess was right is free reconnaissance.
			w.Header().Set("WWW-Authenticate", `Bearer realm="farrier"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "a valid operator credential is required")
			return
		}
		if identity.Platform || identity.Tenant == "" {
			writeError(w, http.StatusForbidden, "not_an_operator",
				"this is a platform credential, which administers tenants and reaches no tenant's "+
					"hosts or jobs. Use an operator credential for this fleet.")
			return
		}

		who := operator{Identity: *identity, Store: s.cfg.Store.In(store.TenantID(identity.Tenant))}
		ctx := context.WithValue(r.Context(), operatorContextKey{}, who)
		next(w, r.WithContext(ctx), who)
	})
}

// requireIdentity authenticates any operator credential without deciding which kind it is.
//
// It exists for exactly one route — GET /api/v1/whoami — and the reason is worth stating, because a
// middleware that accepts both credentials is otherwise the shape of a mistake. Every other route
// belongs to one of the two roles and refuses the other, which is the whole of the separation
// docs/SECURITY.md §5.3 describes. "Who am I" belongs to neither: it is the question a browser asks
// before it knows which interface to render, and answering a platform credential with 403 meant the
// application could only report that the credential it had just been given was unusable, without
// being able to say what it was for.
//
// It hands over the identity and no store handle at all. A handler behind it therefore has nothing in
// reach that could read a tenant's data, which is the property requirePlatform relies on too.
func (s *Server) requireIdentity(next func(http.ResponseWriter, *http.Request, auth.Identity)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := s.cfg.Auth.Authenticate(r.Context(), r)
		if err != nil || identity == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="farrier"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "a valid credential is required")
			return
		}
		next(w, r, *identity)
	})
}

// requirePlatform authenticates the installation's own administrator.
//
// It guards the tenant routes and nothing else. The identity it produces carries no tenant and is given
// no scoped store, so a handler behind it has nothing in reach that could read a customer's fleet even
// if it tried.
func (s *Server) requirePlatform(next func(http.ResponseWriter, *http.Request, auth.Identity)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := s.cfg.Auth.Authenticate(r.Context(), r)
		if err != nil || identity == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="farrier"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "a valid credential is required")
			return
		}
		if !identity.Platform {
			// Deliberately the same shape of refusal an operator gets for a platform route: a tenant's
			// operator learns that this is not for them, and not whether the installation has any
			// tenants beyond their own.
			writeError(w, http.StatusForbidden, "not_a_platform_administrator",
				"tenant administration requires the installation's platform credential")
			return
		}
		next(w, r, *identity)
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

	// The tenant list rather than a tenant's data, because this endpoint is unauthenticated and
	// therefore belongs to no tenant. Only the error is looked at; nothing about any tenant leaves here.
	if _, err := s.cfg.Store.ListTenants(ctx); err != nil {
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
	// One object, and nothing after it. encoding/json stops at the end of the first value and would
	// otherwise discard whatever follows in silence, so a caller that concatenated two job requests —
	// a `jq -c` stream piped into curl, a loop missing its separator — would be told 201 for the first
	// and never told anything at all about the second. internal/intent/params.go refuses exactly this
	// one layer down, for the same reason.
	if dec.More() {
		return errTrailingData
	}
	return nil
}

// errTrailingData is returned for a body that holds more than the one value it should.
//
// It is a sentinel rather than a formatted error so that a handler can tell this failure from a syntax
// error and say which it was. Both are a 400, but they are different mistakes: one body is malformed
// and the other is two well-formed requests where the endpoint takes one, and only the second leaves
// the caller believing something was queued that was not.
var errTrailingData = errors.New("server: the request body holds more than one JSON value")

// writeDecodeError answers a failed decodeJSON with the status and the message that failure deserves.
//
// Three failures arrive as one error and want three answers, and every handler that collapsed them
// taught its caller something untrue: an over-size body answered as malformed sends an agent into a
// retry loop over something that will never parse (docs/PROTOCOL.md §11), and two concatenated JSON
// values answered as malformed leaves a caller believing the first request was refused when in fact
// only the first was ever read. The trailing-data message is per-endpoint because what was *not* done
// is per-endpoint, and that is the half the caller needs.
func writeDecodeError(w http.ResponseWriter, err error, trailing string) {
	switch {
	case isTooLarge(err):
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the request body is too large")
	case errors.Is(err, errTrailingData):
		writeError(w, http.StatusBadRequest, "malformed", trailing)
	default:
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
	}
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

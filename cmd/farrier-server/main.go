// Command farrier-server is the Farrier control plane.
//
// It is a single binary with the Angular application embedded, plus PostgreSQL. That is a deliberate
// packaging decision rather than a limitation: open-source software is installed by strangers who close
// the tab on friction, and a four-service Compose stack is friction. Sharing Go with the agent also
// means the intent catalogue and the signature verifier are literally the same code on both sides,
// rather than two implementations that agree until they do not.
//
// The server can ask a host for work. It cannot make a host do anything that host's own
// /etc/farrier/policy.toml forbids, and it holds no key that authorises a destructive operation. See
// docs/SECURITY.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pascalgross/farrier/internal/auth"
	"github.com/pascalgross/farrier/internal/buildinfo"
	"github.com/pascalgross/farrier/internal/ca"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/onlinekey"
	"github.com/pascalgross/farrier/internal/server"
	"github.com/pascalgross/farrier/internal/store"
)

// usage prints the command list.
func usage() {
	fmt.Fprintf(os.Stderr, `farrier-server %s

usage:
  farrier-server serve       run the control plane
  farrier-server ca init     create the private CA that issues agent certificates
  farrier-server catalogue   print the intent catalogue this build knows
  farrier-server version     print the version

Run "farrier-server serve --help" for its options.
`, buildinfo.String())
}

// main dispatches to a subcommand.
func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "serve":
		os.Exit(serve(args[1:]))
	case "ca":
		os.Exit(caCommand(args[1:]))
	case "catalogue":
		printCatalogue()
	case "version":
		fmt.Println("farrier-server " + buildinfo.String())
	default:
		fmt.Fprintf(os.Stderr, "farrier-server: unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
}

// setupLogging configures structured logging to stderr, which systemd routes to the journal.
func setupLogging() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "server", "version", buildinfo.Version))
}

// serve runs the control plane until it is signalled to stop.
func serve(argv []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8443", "listen address")
	caDir := fs.String("ca-dir", "/var/lib/farrier-server/ca", "directory holding the agent CA")
	dsn := fs.String("database", envOr("FARRIER_DATABASE_URL", ""),
		"PostgreSQL connection URL, or the literal \"memory\" for a throwaway in-process store")
	tlsCert := fs.String("tls-cert", "", "PEM certificate for this server's own HTTPS identity")
	tlsKey := fs.String("tls-key", "", "PEM key for this server's own HTTPS identity")
	adminToken := fs.String("admin-token", envOr("FARRIER_ADMIN_TOKEN", ""),
		"bearer token for one tenant's operators; one is generated and printed if omitted")
	tenantSlug := fs.String("tenant", envOr("FARRIER_TENANT", "default"),
		"the tenant --admin-token acts in; created on first start if it does not exist")
	platformToken := fs.String("platform-token", envOr("FARRIER_PLATFORM_TOKEN", ""),
		"bearer token for tenant administration; reaches no tenant's hosts or jobs. Omit on a "+
			"single-fleet installation")
	webhook := fs.String("webhook", "",
		"URL to POST this tenant's events to; sinks send data out and nothing sends code in")
	heartbeat := fs.Int("heartbeat-seconds", 60, "pacing handed to agents, which they clamp to 15..3600")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	setupLogging()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	authority, err := ca.Load(*caDir)
	if errors.Is(err, ca.ErrNotInitialised) {
		fmt.Fprintf(os.Stderr, "farrier-server: no certificate authority in %s.\n"+
			"Run: farrier-server ca init --ca-dir %s\n", *caDir, *caDir)
		return 1
	}
	if err != nil {
		slog.Error("could not load the certificate authority", "error", err)
		return 1
	}

	backing, err := openStore(ctx, *dsn)
	if err != nil {
		slog.Error("could not open the store", "error", err)
		return 1
	}
	defer func() { _ = backing.Close() }()

	if err := backing.Migrate(ctx); err != nil {
		slog.Error("could not migrate the database", "error", err)
		return 1
	}

	// Whether the boundary this installation claims is actually there.
	//
	// Tenant isolation is PostgreSQL row-level security, and a connection made as a superuser or as a
	// role with BYPASSRLS ignores every policy in the schema. That is not a degraded mode, it is no
	// isolation at all, and nothing about the running system would look different — so this refuses to
	// start rather than serving many customers out of one database with the wall switched off.
	if err := requireRowLevelSecurity(ctx, backing, *dsn); err != nil {
		slog.Error("refusing to start", "error", err)
		return 1
	}

	tenant, err := ensureTenant(ctx, backing, *tenantSlug, *webhook)
	if err != nil {
		slog.Error("could not prepare the tenant", "error", err)
		return 1
	}

	token := *adminToken
	if token == "" {
		// Generating one rather than starting without authentication. A control plane that came up open
		// because nobody set a flag is a control plane somebody eventually leaves open.
		token, err = auth.GenerateToken()
		if err != nil {
			slog.Error("could not generate an admin token", "error", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "\nNo --admin-token was given, so one has been generated for this run.\n"+
			"It is not stored and will be different next time; set FARRIER_ADMIN_TOKEN to keep it.\n\n"+
			"  export FARRIER_ADMIN_TOKEN=%s\n\n", token)
	}
	operators, err := auth.NewStaticToken(token, "operator", string(tenant.ID))
	if err != nil {
		slog.Error("could not configure operator authentication", "error", err)
		return 1
	}
	provider := auth.Provider(operators)

	// The platform credential is optional, and its absence is the single-fleet case rather than a
	// misconfiguration. Without one there is nothing that can create a second tenant, which is exactly
	// right for somebody running Farrier for themselves: the tenancy is there, and it is one.
	if *platformToken != "" {
		platform, platformErr := auth.NewPlatformToken(*platformToken, "platform")
		if platformErr != nil {
			slog.Error("could not configure platform authentication", "error", platformErr)
			return 1
		}
		provider = auth.Chain(operators, platform)
		slog.Info("tenant administration is enabled", "route", "/api/v1/tenants")
	}

	// The key that signs routine jobs. Beside the CA, generated on first start, and its public half is
	// handed to every agent at enrolment and on every heartbeat. It authorises one tier and cannot
	// authorise the destructive one: an agent verifies those against its own trusted-signers, which
	// this process cannot write. See docs/SECURITY.md §3.
	online, err := onlinekey.Ensure(*caDir)
	if err != nil {
		slog.Error("could not prepare the online signing key", "error", err)
		return 1
	}
	slog.Info("routine jobs will be signed by this control plane", "key", online.KeyID())

	// Client certificates require TLS, so a control plane with no certificate cannot serve the agent
	// protocol at all. Rather than starting something that refuses every agent with a 401, one is
	// issued from the same private CA — which means an enrolled agent, holding the CA bundle it was
	// given, verifies the control plane with no further configuration.
	if *tlsCert == "" || *tlsKey == "" {
		issuedCert, issuedKey, certErr := authority.EnsureServerCertificate(*caDir, tlsNames(*addr), nil)
		if certErr != nil {
			slog.Error("could not issue a server certificate", "error", certErr)
			return 1
		}
		*tlsCert, *tlsKey = issuedCert, issuedKey
		slog.Warn("serving with a certificate issued by Farrier's own CA. Enrolled agents trust it "+
			"automatically; browsers will not. Pass --tls-cert and --tls-key from whatever issues your "+
			"public certificates before operators use this in earnest.",
			"certificate", issuedCert,
			"enrol_with", "farrier enroll --ca "+filepath.Join(*caDir, "ca.crt"))
	}

	srv, err := server.New(server.Config{
		Addr:             *addr,
		TLSCert:          *tlsCert,
		TLSKey:           *tlsKey,
		Authority:        authority,
		Store:            backing,
		Auth:             provider,
		OnlineKey:        online,
		HeartbeatSeconds: *heartbeat,
		TokenTTL:         24 * time.Hour,
	})
	if err != nil {
		slog.Error("could not build the server", "error", err)
		return 1
	}

	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("the server stopped with an error", "error", err)
		return 1
	}
	return 0
}

// requireRowLevelSecurity refuses to start when the database role can see through the tenant boundary.
//
// Isolation between tenants is row-level security, and PostgreSQL exempts two kinds of role from every
// policy: a superuser, and a role with BYPASSRLS. Connecting as either does not weaken the boundary,
// it removes it — every query returns every tenant's rows — and nothing about the running system would
// look wrong. A control plane that served several customers from one database in that state would be
// discovered by a customer, so this is a refusal rather than a warning.
//
// The in-memory store has no roles and enforces the same scoping in Go, so it is exempt from the check
// rather than from the rule.
func requireRowLevelSecurity(ctx context.Context, backing store.Store, dsn string) error {
	pg, ok := backing.(*store.Postgres)
	if !ok {
		return nil
	}
	role, superuser, bypass, err := pg.ConnectionRole(ctx)
	if err != nil {
		return fmt.Errorf("could not check the database role's privileges: %w", err)
	}
	if !superuser && !bypass {
		slog.Info("tenant isolation is enforced by the database", "role", role)
		return nil
	}

	why := "is a superuser"
	if !superuser {
		why = "has BYPASSRLS"
	}
	return fmt.Errorf(
		"the database role %q %s, so PostgreSQL applies no row-level security policy to it and "+
			"tenants are not isolated from one another. Connect as an ordinary role that owns the "+
			"schema: CREATE ROLE farrier LOGIN PASSWORD '…'; GRANT ALL ON DATABASE … TO farrier; "+
			"and point --database at it (currently %s)",
		role, why, redactDSN(dsn))
}

// redactDSN removes the password from a connection URL so it can go in an error message.
//
// The message this appears in is one somebody will paste into an issue, and a connection string is the
// single most likely secret in a control plane's configuration.
func redactDSN(dsn string) string {
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.User == nil {
		return dsn
	}
	if _, hasPassword := parsed.User.Password(); hasPassword {
		parsed.User = url.UserPassword(parsed.User.Username(), "…")
	}
	return parsed.String()
}

// ensureTenant finds the tenant this server's operator credential acts in, creating it if it is new.
//
// A single-fleet installation should not have to know that tenants exist: it starts the binary, gets a
// token, and has a fleet. So the named tenant is created on first start and found on every start after
// that, and an installation that never passes --tenant simply always uses "default" — which is also the
// tenant migration 0004 assigns every pre-existing row to, so upgrading changes nothing.
func ensureTenant(ctx context.Context, backing store.Store, slug, webhook string) (store.Tenant, error) {
	tenants, err := backing.ListTenants(ctx)
	if err != nil {
		return store.Tenant{}, fmt.Errorf("reading the tenant list: %w", err)
	}
	for _, t := range tenants {
		if t.Slug != slug {
			continue
		}
		// The webhook flag is applied on every start, because it is how a single-fleet installation
		// configures one at all. On a hosted installation the flag is left unset and the platform API
		// is where a tenant's endpoint is set, so an unset flag must not clear what is stored.
		if webhook != "" && webhook != t.WebhookURL {
			t.WebhookURL = webhook
			if err := backing.UpdateTenant(ctx, t); err != nil {
				return store.Tenant{}, fmt.Errorf("recording the tenant's webhook: %w", err)
			}
		}
		return t, nil
	}

	id, err := server.NewID()
	if err != nil {
		return store.Tenant{}, fmt.Errorf("allocating a tenant id: %w", err)
	}
	tenant := store.Tenant{
		ID:          store.TenantID(id),
		Slug:        slug,
		DisplayName: slug,
		CreatedAt:   time.Now().UTC(),
		// A new fleet releases destructive jobs on the strength of their offline signature alone. That
		// signature is what docs/SECURITY.md §1 rests on; approval is a control-plane control on top of
		// it, and defaulting to one that a single operator cannot satisfy would ship a tier nobody
		// could reach. Turn it on per tenant when there is a second person to turn it on for.
		ApprovalMode: store.ApprovalNone,
		WebhookURL:   webhook,
	}
	if err := backing.CreateTenant(ctx, tenant); err != nil {
		return store.Tenant{}, fmt.Errorf("creating tenant %q: %w", slug, err)
	}
	slog.Info("created a tenant", "tenant", tenant.ID, "slug", slug)
	return tenant, nil
}

// openStore connects to the configured backing store.
//
// PostgreSQL is the only supported backend. The memory option exists for a demonstration and for the
// integration harness, and it says so loudly every time, because a control plane that silently lost its
// fleet on restart would be discovered at the worst possible moment.
func openStore(ctx context.Context, dsn string) (store.Store, error) {
	switch dsn {
	case "":
		return nil, errors.New("a database URL is required: pass --database or set FARRIER_DATABASE_URL")
	case "memory":
		slog.Warn("using the in-memory store. This is for demonstrations and tests only: " +
			"every host, token and job result is lost when this process exits, nothing is shared " +
			"between replicas, and none of the PostgreSQL behaviour the real store depends on is " +
			"being exercised.")
		return store.NewMemory(), nil
	default:
		return store.OpenPostgres(ctx, dsn)
	}
}

// caCommand implements `farrier-server ca init`.
func caCommand(argv []string) int {
	if len(argv) == 0 || argv[0] != "init" {
		fmt.Fprintln(os.Stderr, "usage: farrier-server ca init [--ca-dir DIR] [--common-name NAME]")
		return 2
	}
	fs := flag.NewFlagSet("ca init", flag.ExitOnError)
	dir := fs.String("ca-dir", "/var/lib/farrier-server/ca", "directory to create the CA in")
	commonName := fs.String("common-name", "Farrier Agent CA", "subject common name")
	if err := fs.Parse(argv[1:]); err != nil {
		return 2
	}
	setupLogging()

	authority, err := ca.Init(*dir, *commonName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: %v\n", err)
		return 1
	}
	fmt.Printf("Created a certificate authority in %s.\n", *dir)
	fmt.Printf("It expires %s.\n\n", authority.NotAfter().Format("2006-01-02"))
	fmt.Println("Back up ca.key separately from the database. An attacker with both can impersonate")
	fmt.Println("hosts to this control plane; an attacker with the database alone cannot. Neither")
	fmt.Println("lets them run code on a host: an agent authorises a job by its class and its")
	fmt.Println("signature, not by who asked.")
	return 0
}

// printCatalogue writes the complete intent catalogue to stdout.
//
// It exists so that an operator evaluating Farrier can see the entire set of things the control plane
// is able to ask for, from the binary they are about to run, without reading the source or trusting a
// web page. The claim this project makes is about that set being small and closed, so it should be
// possible to check it in one command.
func printCatalogue() {
	fmt.Printf("%-26s %-12s %-6s %-8s %s\n", "INTENT", "CLASS", "EXEC", "SIGNED", "SUMMARY")
	for _, s := range intent.All() {
		executor := "no"
		if s.Implemented {
			executor = "yes"
		}
		signed := "-"
		switch {
		case s.Class.RequiresOfflineSignature():
			signed = "offline"
		case s.Class.Privileged():
			signed = "online"
		}
		fmt.Printf("%-26s %-12s %-6s %-8s %s\n", s.Name, s.Class, executor, signed, s.Summary)
	}
	fmt.Printf("\n%d intents. This set is closed: a compile-time map with no registry and no\n",
		len(intent.Names()))
	fmt.Println("configuration that adds to it. Permanently refused, with reasons in docs/SECURITY.md:")
	for _, n := range intent.Refused {
		fmt.Printf("  %s\n", n)
	}
}

// tlsNames returns the DNS names a self-issued server certificate should carry.
//
// The listen address is parsed for a hostname because "--addr farrier.internal:8443" is a reasonable
// thing to write and a certificate that omitted it would fail verification for exactly the name the
// operator chose. A bare port yields nothing extra, and the caller always adds localhost.
func tlsNames(addr string) []string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" || net.ParseIP(host) != nil {
		return nil
	}
	return []string{host}
}

// envOr returns an environment variable, or a fallback.
//
// Credentials come from the environment as well as from flags because a flag value is visible in the
// process list to every user on the machine, and a database URL usually contains a password.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

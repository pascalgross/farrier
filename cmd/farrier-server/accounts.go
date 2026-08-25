package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/pascalgross/farrier/internal/auth"
	"github.com/pascalgross/farrier/internal/prompt"
	"github.com/pascalgross/farrier/internal/server"
	"github.com/pascalgross/farrier/internal/store"
)

// accountsCommand implements `farrier-server accounts`.
//
// Accounts are created here, on the machine, and not through the API — which is the answer to a
// question docs/SECURITY.md §5.3 already decides. A platform credential administers fleets and
// deliberately cannot mint an operator's credential, because a tenant API that handed out credentials
// would make whoever runs the installation able to authenticate as any customer. Doing it from the
// command line adds no power to that role: §5.3's closing paragraph says outright that a platform
// administrator has the database and the process. What it adds is that the power they already had is
// findable, rather than something they have to write SQL for.
//
// The practical consequence is worth stating for whoever runs a fleet for themselves: creating the
// first account is a shell command on the control plane, once, and everything after it is a browser.
func accountsCommand(argv []string) int {
	if len(argv) == 0 {
		accountsUsage()
		return 2
	}
	switch argv[0] {
	case "add":
		return accountsAdd(argv[1:])
	case "list":
		return accountsList(argv[1:])
	case "passwd":
		return accountsPasswd(argv[1:])
	case "remove":
		return accountsRemove(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "farrier-server: unknown accounts command %q\n\n", argv[0])
		accountsUsage()
		return 2
	}
}

// accountsUsage prints the account subcommand list.
func accountsUsage() {
	fmt.Fprint(os.Stderr, `usage:
  farrier-server accounts add    --tenant SLUG --email ADDRESS [--name NAME]
  farrier-server accounts list   [--tenant SLUG]
  farrier-server accounts passwd --tenant SLUG --email ADDRESS
  farrier-server accounts remove --tenant SLUG --email ADDRESS

The password is asked for on the terminal, never taken as a flag: argv is world-readable in ps.
Every command needs --database, or FARRIER_DATABASE_URL.
`)
}

// accountFlags are the flags every account subcommand shares.
//
// A struct rather than four copies, because the database URL and the tenant are the two things it is
// easy to get subtly wrong — pointing at the wrong database creates an account nobody can use, and
// omitting the tenant would create one in a fleet the operator did not mean.
type accountFlags struct {
	// dsn is the PostgreSQL connection URL.
	dsn *string

	// tenant is the fleet slug the account belongs to.
	tenant *string

	// email is the address the account signs in with.
	email *string

	// name is the display name, empty for the address.
	name *string
}

// bindAccountFlags declares the shared flags on a flag set.
func bindAccountFlags(fs *flag.FlagSet) accountFlags {
	return accountFlags{
		dsn: fs.String("database", envOr("FARRIER_DATABASE_URL", ""),
			"PostgreSQL connection URL"),
		tenant: fs.String("tenant", envOr("FARRIER_TENANT", "default"),
			"the fleet this account signs in to, by slug"),
		email: fs.String("email", "", "the address this account signs in with"),
		name:  fs.String("name", "", "display name, defaulting to the address"),
	}
}

// openAccountStore connects to the database and finds the tenant a slug names.
//
// The tenant is resolved to an id here rather than passed through as a slug, because Store.In takes an
// id and a slug that matched nothing would otherwise produce a handle that silently reaches an empty
// fleet — an account created into nowhere, discovered at the first failed sign-in.
func openAccountStore(ctx context.Context, dsn, slug string) (store.Store, store.Tenant, error) {
	if dsn == "" {
		return nil, store.Tenant{}, errors.New("a database URL is required: pass --database or set FARRIER_DATABASE_URL")
	}
	backing, err := store.OpenPostgres(ctx, dsn)
	if err != nil {
		return nil, store.Tenant{}, err
	}
	tenants, err := backing.ListTenants(ctx)
	if err != nil {
		_ = backing.Close()
		return nil, store.Tenant{}, fmt.Errorf("reading the tenant list: %w", err)
	}
	for _, t := range tenants {
		if t.Slug == slug {
			return backing, t, nil
		}
	}
	_ = backing.Close()
	return nil, store.Tenant{}, fmt.Errorf("no fleet with the slug %q; run `farrier-server serve` once to "+
		"create it, or pass --tenant", slug)
}

// accountsAdd creates one operator account.
func accountsAdd(argv []string) int {
	fs := flag.NewFlagSet("accounts add", flag.ExitOnError)
	flags := bindAccountFlags(fs)
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *flags.email == "" {
		fmt.Fprintln(os.Stderr, "farrier-server: --email is required")
		return 2
	}
	setupLogging()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	backing, tenant, err := openAccountStore(ctx, *flags.dsn, *flags.tenant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: %v\n", err)
		return 1
	}
	defer func() { _ = backing.Close() }()

	hash, code := readNewPassword()
	if code != 0 {
		return code
	}

	id, err := server.NewID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: allocating an account id: %v\n", err)
		return 1
	}
	address := auth.NormaliseEmail(*flags.email)
	err = backing.In(tenant.ID).CreateAccount(ctx, store.Account{
		ID:           id,
		Email:        address,
		EmailKey:     auth.EmailKey(address),
		DisplayName:  *flags.name,
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	})
	if errors.Is(err, store.ErrConflict) {
		// Across the installation rather than within the fleet, because the address is what a sign-in
		// form names and it has to resolve to one account. Migration 0009 says why.
		fmt.Fprintf(os.Stderr, "farrier-server: %s already has an account on this control plane\n", address)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: creating the account: %v\n", err)
		return 1
	}

	fmt.Printf("Created %s in the fleet %q.\n\n", address, tenant.Slug)
	fmt.Println("They can sign in at this control plane's web interface now. Nothing was mailed and")
	fmt.Println("nothing was printed: the password is the one you just typed, and only its hash is")
	fmt.Println("stored, so it cannot be recovered from here or from a database dump.")
	return 0
}

// accountsList prints one fleet's accounts.
//
// It prints the address, the name and the last sign-in and nothing else. There is no column for the
// hash and there will not be one: a listing that could show it is a listing somebody screenshots.
func accountsList(argv []string) int {
	fs := flag.NewFlagSet("accounts list", flag.ExitOnError)
	flags := bindAccountFlags(fs)
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	setupLogging()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	backing, tenant, err := openAccountStore(ctx, *flags.dsn, *flags.tenant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: %v\n", err)
		return 1
	}
	defer func() { _ = backing.Close() }()

	accounts, err := backing.In(tenant.ID).ListAccounts(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: listing accounts: %v\n", err)
		return 1
	}
	if len(accounts) == 0 {
		fmt.Printf("The fleet %q has no accounts. Everyone signs in with its bearer token.\n", tenant.Slug)
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ADDRESS\tNAME\tCREATED\tLAST SIGN-IN")
	for _, a := range accounts {
		last := "never"
		if !a.LastSignedInAt.IsZero() {
			last = a.LastSignedInAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			a.Email, a.DisplayName, a.CreatedAt.UTC().Format("2006-01-02"), last)
	}
	return flushOrFail(w)
}

// accountsPasswd sets an existing account's password.
//
// It is how somebody who has forgotten theirs gets back in, and it is deliberately the same act as
// creating one: whoever runs the control plane types a new password and tells the person what it is.
// There is no reset link, because a reset link needs a mail relay this installation may not have and a
// token that would be a second credential to get wrong.
func accountsPasswd(argv []string) int {
	fs := flag.NewFlagSet("accounts passwd", flag.ExitOnError)
	flags := bindAccountFlags(fs)
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *flags.email == "" {
		fmt.Fprintln(os.Stderr, "farrier-server: --email is required")
		return 2
	}
	setupLogging()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	backing, tenant, err := openAccountStore(ctx, *flags.dsn, *flags.tenant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: %v\n", err)
		return 1
	}
	defer func() { _ = backing.Close() }()

	account, code := findAccount(ctx, backing, tenant, *flags.email)
	if code != 0 {
		return code
	}
	hash, code := readNewPassword()
	if code != 0 {
		return code
	}
	if err := backing.In(tenant.ID).UpdateAccountPassword(ctx, account.ID, hash); err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: changing the password: %v\n", err)
		return 1
	}

	fmt.Printf("Changed the password for %s.\n\n", account.Email)
	fmt.Println("Their existing sessions still work: a session is a credential of its own, and ending")
	fmt.Println("them here would sign somebody out mid-incident for a change they asked for. Use")
	fmt.Println("`accounts remove` if the account itself should stop working.")
	return 0
}

// accountsRemove deletes an account and every session it holds.
func accountsRemove(argv []string) int {
	fs := flag.NewFlagSet("accounts remove", flag.ExitOnError)
	flags := bindAccountFlags(fs)
	assumeYes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *flags.email == "" {
		fmt.Fprintln(os.Stderr, "farrier-server: --email is required")
		return 2
	}
	setupLogging()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	backing, tenant, err := openAccountStore(ctx, *flags.dsn, *flags.tenant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: %v\n", err)
		return 1
	}
	defer func() { _ = backing.Close() }()

	account, code := findAccount(ctx, backing, tenant, *flags.email)
	if code != 0 {
		return code
	}
	if !*assumeYes {
		ok, confirmErr := prompt.Confirm(fmt.Sprintf(
			"Remove %s from the fleet %q, and end their sessions? [y/N] ", account.Email, tenant.Slug))
		if confirmErr != nil {
			fmt.Fprintf(os.Stderr, "farrier-server: %v\n", confirmErr)
			return 1
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "farrier-server: not removed.")
			return 3
		}
	}
	if err := backing.In(tenant.ID).DeleteAccount(ctx, account.ID); err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: removing the account: %v\n", err)
		return 1
	}

	fmt.Printf("Removed %s. Their sessions went with the account.\n\n", account.Email)
	fmt.Println("The jobs they queued keep naming them, because an audit trail that forgot who did")
	fmt.Println("something when they left would be an audit trail for exactly the wrong period.")
	return 0
}

// findAccount resolves an address to one of a fleet's accounts, or reports why it could not.
//
// It goes through the unscoped resolver and then checks the tenant, rather than listing the fleet and
// searching: that is the same path a sign-in takes, so a mismatch between the two — an address that
// signs in but that this command cannot find — is impossible rather than merely unlikely.
func findAccount(ctx context.Context, backing store.Store, tenant store.Tenant, email string) (store.Account, int) {
	account, err := backing.AccountByEmail(ctx, auth.EmailKey(email))
	if errors.Is(err, store.ErrNotFound) {
		fmt.Fprintf(os.Stderr, "farrier-server: no account for %s\n", auth.NormaliseEmail(email))
		return store.Account{}, 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: reading the account: %v\n", err)
		return store.Account{}, 1
	}
	if account.TenantID != tenant.ID {
		// Named rather than silently operated on. The address resolves across the installation, so a
		// typo in --tenant would otherwise change an account in a fleet the operator did not name.
		fmt.Fprintf(os.Stderr, "farrier-server: %s belongs to a different fleet than %q\n",
			account.Email, tenant.Slug)
		return store.Account{}, 1
	}
	return account, 0
}

// readNewPassword prompts twice and returns the hash to store.
//
// Twice because a password nobody can reproduce is an account nobody can use, and the person typing it
// cannot see what they typed. The comparison is a plain string equality rather than a constant-time
// one: both sides are the same local operator's own input, thirty microseconds apart, and dressing it
// up as a timing-sensitive comparison would suggest a threat that is not there.
func readNewPassword() (string, int) {
	password, err := prompt.Secret("Password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: %v\n", err)
		return "", 1
	}
	confirmation, err := prompt.Secret("Confirm: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: %v\n", err)
		return "", 1
	}
	if string(password) != string(confirmation) {
		fmt.Fprintln(os.Stderr, "farrier-server: the passwords do not match")
		return "", 1
	}
	hash, err := auth.HashPassword(string(password))
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: %v\n", err)
		return "", 1
	}
	return hash, 0
}

// flushOrFail writes out a tabwriter and turns a write failure into an exit code.
//
// Its own function because a listing that failed to reach the terminal must not exit 0: a truncated
// account list read as "these are all the accounts" is exactly the wrong thing to be quiet about.
func flushOrFail(w *tabwriter.Writer) int {
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "farrier-server: writing the listing: %v\n", err)
		return 1
	}
	return 0
}

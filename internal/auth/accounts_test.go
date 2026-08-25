package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/pascalgross/farrier/internal/store"
)

// accountFixture is one operator account in one fleet, with the provider that authenticates it.
type accountFixture struct {
	// provider is what the tests call.
	provider *Accounts

	// backing is the store, so a test can look at what a sign-in wrote.
	backing *store.Memory

	// tenant is the fleet the account belongs to.
	tenant store.TenantID

	// email and password are the credential.
	email    string
	password string
}

// newAccountFixture builds a store holding one account, and a provider over it.
//
// The tenant is the in-memory store's own default rather than a second one, because these tests are
// about the credential rather than about isolation — internal/store's tenancy suite is where a leak
// between fleets would be caught, and duplicating it here would only make it look covered twice.
func newAccountFixture(t *testing.T) *accountFixture {
	t.Helper()

	const email = "alice@example.org"
	const password = "a password long enough"

	backing := store.NewMemory()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hashing the fixture password: %v", err)
	}
	if err := backing.In(store.DefaultTenant).CreateAccount(context.Background(), store.Account{
		ID:           "01JACCOUNT",
		Email:        email,
		EmailKey:     EmailKey(email),
		DisplayName:  "Alice",
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("creating the fixture account: %v", err)
	}

	return &accountFixture{
		provider: NewAccounts(backing, time.Hour, 24*time.Hour),
		backing:  backing,
		tenant:   store.DefaultTenant,
		email:    email,
		password: password,
	}
}

// signIn performs a sign-in and returns the cookie it set.
func (f *accountFixture) signIn(t *testing.T, email, password string) (*Identity, *http.Cookie) {
	t.Helper()

	w := httptest.NewRecorder()
	identity, err := f.provider.SignIn(context.Background(), w, signInRequest(), email, password)
	if err != nil {
		return nil, nil
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == SessionCookieName {
			return identity, cookie
		}
	}
	t.Fatal("a successful sign-in set no session cookie")
	return nil, nil
}

// signInRequest builds the request a sign-in arrives on.
//
// It carries a user agent and a peer address because the session row records both, and a fixture that
// left them empty would let a change that stopped recording them pass unnoticed.
func signInRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/session", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("User-Agent", "Mozilla/5.0 (fixture)")
	return r
}

// authenticated builds a request carrying a session cookie and the header that goes with it.
func authenticated(cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	r.AddCookie(cookie)
	r.Header.Set(SessionHeader, "1")
	return r
}

// TestSigningInWithAnAddressAndAPasswordProducesASessionThatAuthenticates is the happy path end to end.
//
// It asserts the two things everything else rests on: the identity carries the fleet the account
// belongs to — from the account row and from nothing in the request — and the cookie it set is a
// credential the provider will accept on the next request.
func TestSigningInWithAnAddressAndAPasswordProducesASessionThatAuthenticates(t *testing.T) {
	f := newAccountFixture(t)

	identity, cookie := f.signIn(t, f.email, f.password)
	if identity == nil {
		t.Fatal("the correct credential was refused")
	}
	if identity.Tenant != string(f.tenant) {
		t.Errorf("the identity acts in %q, want %q", identity.Tenant, f.tenant)
	}
	if identity.Principal() != "local-account:"+f.email {
		t.Errorf("the principal is %q; it is what every job this operator queues will record",
			identity.Principal())
	}
	if identity.Platform {
		t.Error("an operator account produced a platform identity")
	}

	back, err := f.provider.Authenticate(context.Background(), authenticated(cookie))
	if err != nil {
		t.Fatalf("the session the sign-in issued does not authenticate: %v", err)
	}
	if back.Principal() != identity.Principal() {
		t.Errorf("the session authenticates as %q, want %q", back.Principal(), identity.Principal())
	}
}

// TestTheSessionCookieCannotBeReadOrSentByAnotherSite pins the attributes that make it a session.
//
// Three of the four are the difference between a session and a liability, and none of them is visible
// in any behaviour a test could otherwise assert: a missing HttpOnly is a credential any script on the
// page can read, a missing Secure is one a downgrade can take, and SameSite=None is one another site
// can spend.
func TestTheSessionCookieCannotBeReadOrSentByAnotherSite(t *testing.T) {
	f := newAccountFixture(t)
	_, cookie := f.signIn(t, f.email, f.password)

	if !cookie.HttpOnly {
		t.Error("the session cookie is readable by any script on the page")
	}
	if !cookie.Secure {
		t.Error("the session cookie is not marked Secure")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("the session cookie is SameSite=%v; Lax is what blocks a cross-site form post",
			cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("the session cookie is scoped to %q, so signing out would not clear it", cookie.Path)
	}
	if cookie.Value == "" {
		t.Error("the session cookie carries no token")
	}
}

// TestACookieWithoutTheHeaderIsNotAuthenticated is the cross-site request forgery defence.
//
// The cookie alone is what another origin can cause a browser to send. The header is what it cannot
// set without a preflight this server does not answer, so a request carrying one and not the other is
// exactly the request that must not be authenticated — and this is the only place that is enforced.
func TestACookieWithoutTheHeaderIsNotAuthenticated(t *testing.T) {
	f := newAccountFixture(t)
	_, cookie := f.signIn(t, f.email, f.password)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", nil)
	r.AddCookie(cookie)
	if _, err := f.provider.Authenticate(context.Background(), r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a cookie with no %s header authenticated: %v", SessionHeader, err)
	}

	// And the same request with the header does, so the test above is about the header rather than
	// about something else having gone wrong.
	if _, err := f.provider.Authenticate(context.Background(), authenticated(cookie)); err != nil {
		t.Fatalf("the same cookie with the header did not authenticate: %v", err)
	}
}

// TestEveryWayToPresentTheWrongCredentialIsTheSameRefusal is the reconnaissance rule.
//
// A wrong password, an address nobody holds and an address that is nearly right all answer
// ErrUnauthenticated with nothing else attached. What this cannot assert is the other half — that they
// cost the same — which is why internal/auth verifies against a decoy hash on the unknown-address path
// rather than returning early.
func TestEveryWayToPresentTheWrongCredentialIsTheSameRefusal(t *testing.T) {
	f := newAccountFixture(t)

	cases := []struct {
		// name says which half of the credential is wrong.
		name string

		// email and password are what is presented.
		email    string
		password string
	}{
		{"a wrong password", "alice@example.org", "a different password"},
		{"an address nobody holds", "nobody@example.org", "a password long enough"},
		{"an empty address", "", "a password long enough"},
		{"an empty password", "alice@example.org", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, err := f.provider.SignIn(context.Background(), w, signInRequest(), c.email, c.password)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("SignIn returned %v, want ErrUnauthenticated", err)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("a refused sign-in set a cookie")
			}
		})
	}
}

// TestAnAddressIsMatchedWithoutRegardToCaseOrSurroundingSpace is the normalisation.
//
// An operator who typed their address with a capital on Monday must not be a different person on
// Tuesday, and an address pasted with a trailing space out of a chat message must not be a fourth
// person. The subject recorded on the identity is the normalised form for the same reason: the audit
// trail must not hold three spellings of one operator.
func TestAnAddressIsMatchedWithoutRegardToCaseOrSurroundingSpace(t *testing.T) {
	f := newAccountFixture(t)

	for _, presented := range []string{"Alice@Example.ORG", "  alice@example.org  ", "ALICE@EXAMPLE.ORG"} {
		identity, _ := f.signIn(t, presented, f.password)
		if identity == nil {
			t.Fatalf("signing in as %q was refused", presented)
		}
		if identity.Subject != "alice@example.org" {
			t.Errorf("signing in as %q recorded the subject %q", presented, identity.Subject)
		}
	}
}

// TestAnExpiredSessionAuthenticatesNobody is the window, checked against this process's clock.
//
// The store deliberately does not check expiry — it returns the row and lets the caller judge — so if
// this check were dropped the session would work for ever and nothing else would notice. The clock is
// moved rather than slept through, which is also how the deliberate choice of the *local* clock is
// visible: the row is untouched and only this process's opinion of the time changed.
func TestAnExpiredSessionAuthenticatesNobody(t *testing.T) {
	f := newAccountFixture(t)
	_, cookie := f.signIn(t, f.email, f.password)

	f.provider.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := f.provider.Authenticate(context.Background(), authenticated(cookie)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a session past its expiry authenticated: %v", err)
	}
}

// TestSigningOutEndsTheSessionRatherThanOnlyTheCookie is what "sign out" has to mean.
//
// Clearing the cookie is what the browser sees; deleting the row is what makes the token stop working
// for whoever copied it. A test that only checked the cookie would pass against an implementation that
// left a live credential behind.
func TestSigningOutEndsTheSessionRatherThanOnlyTheCookie(t *testing.T) {
	f := newAccountFixture(t)
	_, cookie := f.signIn(t, f.email, f.password)

	w := httptest.NewRecorder()
	r := authenticated(cookie)
	if err := f.provider.SignOut(context.Background(), w, r); err != nil {
		t.Fatalf("signing out: %v", err)
	}

	if _, _, err := f.backing.SessionByToken(context.Background(), HashSessionToken(cookie.Value)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the session row survived a sign-out: %v", err)
	}
	if _, err := f.provider.Authenticate(context.Background(), authenticated(cookie)); !errors.Is(err, ErrUnauthenticated) {
		t.Error("the token still authenticates after signing out")
	}

	var cleared bool
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value == "" {
			cleared = true
		}
	}
	if !cleared {
		t.Error("signing out did not clear the cookie")
	}

	// Twice, because a browser that retried, or an operator with two tabs, must not see a failure.
	if err := f.provider.SignOut(context.Background(), httptest.NewRecorder(), r); err != nil {
		t.Errorf("signing out a second time failed: %v", err)
	}
}

// TestDeletingAnAccountEndsItsSessions is the revocation path.
//
// It is the whole answer to "an operator has left": there is no session list to walk and no logout to
// push, so removing the account has to take its live credentials with it. The store performs it — with
// an ON DELETE CASCADE in PostgreSQL and a sweep in memory — and this asserts the property from the
// side that matters, which is that the token stops authenticating.
func TestDeletingAnAccountEndsItsSessions(t *testing.T) {
	f := newAccountFixture(t)
	_, cookie := f.signIn(t, f.email, f.password)

	if err := f.backing.In(f.tenant).DeleteAccount(context.Background(), "01JACCOUNT"); err != nil {
		t.Fatalf("deleting the account: %v", err)
	}
	if _, err := f.provider.Authenticate(context.Background(), authenticated(cookie)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("a session belonging to a deleted account still authenticates")
	}
}

// TestSigningInRecordsWhenAndRewritesAWeakHash covers the two writes a sign-in makes besides the session.
//
// The stamp is what makes a stale account visible. The rewrite is what makes raising the Argon2id
// parameters possible at all: sign-in is the only moment the password is known, so a hash written under
// weaker parameters is either replaced there or never.
func TestSigningInRecordsWhenAndRewritesAWeakHash(t *testing.T) {
	f := newAccountFixture(t)
	ctx := context.Background()

	// A well-formed hash of the fixture password at a lower cost, of the kind an older build wrote.
	weaker := weakHash(t, f.password)
	if err := f.backing.In(f.tenant).UpdateAccountPassword(ctx, "01JACCOUNT", weaker); err != nil {
		t.Fatalf("planting the weaker hash: %v", err)
	}

	if identity, _ := f.signIn(t, f.email, f.password); identity == nil {
		t.Fatal("a password stored under weaker parameters was refused")
	}

	account, err := f.backing.In(f.tenant).GetAccount(ctx, "01JACCOUNT")
	if err != nil {
		t.Fatalf("reading the account back: %v", err)
	}
	if account.PasswordHash == weaker {
		t.Error("the weaker hash was not rewritten at sign-in")
	}
	if NeedsRehash(account.PasswordHash) {
		t.Error("the rewritten hash is still below this build's parameters")
	}
	if !VerifyPassword(account.PasswordHash, f.password) {
		t.Fatal("the rewritten hash does not verify the password it was made from")
	}
	if account.LastSignedInAt.IsZero() {
		t.Error("signing in did not record when")
	}
}

// weakHash returns a real Argon2id hash of a password at parameters below this build's.
//
// Produced by hashing at the current cost and rewriting the parameter field, rather than by exposing a
// second hashing entry point: the point is a value NeedsRehash recognises, and a second entry point
// would be a way to write one in production.
func weakHash(t *testing.T, password string) string {
	t.Helper()

	// The parameters have to be ones argon2 will actually reproduce, so the digest is computed here
	// with them rather than copied from a hash made with different ones.
	const memory, passes, lanes = 19456, 2, 1
	salt := []byte("sixteen-byte-slt")
	key := argon2.IDKey([]byte(password), salt, passes, memory, lanes, argonKeyLength)
	return encodePHC(memory, passes, lanes, salt, key)
}

// storeThatCannotRecordASession is the store a control plane has during a database outage.
//
// It embeds a working one and breaks the single write a sign-in makes after the password has already
// been verified, which is the case the two failure paths have to be told apart in: the credential was
// correct and the sign-in still cannot complete.
type storeThatCannotRecordASession struct {
	// Store is the working store everything else goes through.
	store.Store
}

// In returns a handle whose session write fails.
func (s storeThatCannotRecordASession) In(tenant store.TenantID) store.Scoped {
	return scopedThatCannotRecordASession{Scoped: s.Store.In(tenant)}
}

// scopedThatCannotRecordASession is the scoped half of the same fault.
type scopedThatCannotRecordASession struct {
	// Scoped is the working handle every other method goes through.
	store.Scoped
}

// CreateSession fails the way an unreachable database does.
func (s scopedThatCannotRecordASession) CreateSession(_ context.Context, _ store.Session) error {
	return errors.New("store: the database is not reachable")
}

// TestAStoreFailureIsNotReportedAsAWrongPassword separates the two ways a sign-in can fail.
//
// Every wrong credential is one refusal, deliberately. A store that cannot be reached is not a wrong
// credential, and reporting it as one would tell an operator their password was wrong during an
// outage — so they would spend the outage typing it again. The caller distinguishes them by
// ErrUnauthenticated, which is why this asserts on the error's identity rather than on its text.
func TestAStoreFailureIsNotReportedAsAWrongPassword(t *testing.T) {
	f := newAccountFixture(t)
	broken := NewAccounts(storeThatCannotRecordASession{Store: f.backing}, time.Hour, 24*time.Hour)

	w := httptest.NewRecorder()
	_, err := broken.SignIn(context.Background(), w, signInRequest(), f.email, f.password)
	if err == nil {
		t.Fatal("a sign-in succeeded against a store that cannot record a session")
	}
	if errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a store failure was reported as a refused credential: %v", err)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("a sign-in that could not be recorded still set a cookie")
	}
}

// TestASessionInUseIsExtendedAndOneLeftAloneIsNot is the whole of what sliding renewal has to do.
//
// Two properties, and they are the two halves of the trade the constants describe. A session that keeps
// being used moves its expiry forward, so an operator working through the afternoon is not signed out
// in the middle of it; a session that is not used keeps the expiry it had, so a cookie copied off a
// machine and left alone runs out on schedule.
//
// The renewal is not free and the third assertion is about the price: it happens at most once every
// SessionRenewAfter, so a page that makes six requests in a second costs one write rather than six.
func TestASessionInUseIsExtendedAndOneLeftAloneIsNot(t *testing.T) {
	f := newAccountFixture(t)

	start := time.Now().UTC()
	f.provider.now = func() time.Time { return start }
	_, cookie := f.signIn(t, f.email, f.password)

	hash := HashSessionToken(cookie.Value)
	first, _, err := f.backing.SessionByToken(context.Background(), hash)
	if err != nil {
		t.Fatalf("reading the session back: %v", err)
	}

	// A request a minute later: inside SessionRenewAfter, so nothing is written.
	f.provider.now = func() time.Time { return start.Add(time.Minute) }
	if _, err := f.provider.Authenticate(context.Background(), authenticated(cookie)); err != nil {
		t.Fatalf("the session stopped authenticating a minute after it was made: %v", err)
	}
	unchanged, _, err := f.backing.SessionByToken(context.Background(), hash)
	if err != nil {
		t.Fatalf("reading the session back: %v", err)
	}
	if !unchanged.ExpiresAt.Equal(first.ExpiresAt) {
		t.Errorf("a request %s after the sign-in rewrote the expiry; SessionRenewAfter is %s",
			time.Minute, SessionRenewAfter)
	}

	// A request half an hour later: past SessionRenewAfter, so the idle window restarts from now.
	later := start.Add(30 * time.Minute)
	f.provider.now = func() time.Time { return later }
	if _, err := f.provider.Authenticate(context.Background(), authenticated(cookie)); err != nil {
		t.Fatalf("the session stopped authenticating half an hour in: %v", err)
	}
	extended, _, err := f.backing.SessionByToken(context.Background(), hash)
	if err != nil {
		t.Fatalf("reading the session back: %v", err)
	}
	if !extended.ExpiresAt.After(first.ExpiresAt) {
		t.Errorf("a session in use was not extended: expiry stayed at %s", first.ExpiresAt)
	}
	if !extended.LastUsedAt.Equal(later) {
		t.Errorf("last use = %s, want %s", extended.LastUsedAt, later)
	}
}

// TestASessionPastItsAbsoluteWindowAuthenticatesNobody is what stops "extended on use" meaning forever.
//
// Without the absolute window, a cookie copied off a machine and used once an hour would never expire:
// every use would push the idle window out again. So the age of the session is checked too, and this
// asserts that the check is on the sign-in rather than on the last use — the session here is used
// continuously right up to the boundary and is refused the moment it is past it.
func TestASessionPastItsAbsoluteWindowAuthenticatesNobody(t *testing.T) {
	f := newAccountFixture(t)

	start := time.Now().UTC()
	f.provider.now = func() time.Time { return start }
	_, cookie := f.signIn(t, f.email, f.password)

	// The fixture's windows: an hour idle, a day absolute. Used every half hour, so the idle window
	// never lapses, right up to the day.
	for at := time.Duration(0); at < 24*time.Hour; at += 30 * time.Minute {
		f.provider.now = func() time.Time { return start.Add(at) }
		if _, err := f.provider.Authenticate(context.Background(), authenticated(cookie)); err != nil {
			t.Fatalf("the session stopped authenticating %s in, inside its absolute window: %v", at, err)
		}
	}

	f.provider.now = func() time.Time { return start.Add(24*time.Hour + time.Second) }
	if _, err := f.provider.Authenticate(context.Background(), authenticated(cookie)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a session a day and a second old still authenticated: %v", err)
	}
}

// TestASignInRecordsWhereItCameFrom covers the half of the session list that makes it usable.
//
// A list of six sessions that are all just "a session" is a list nobody signs anybody out from. Both
// values are advisory — a user agent is a string the client chooses and behind a proxy the address is
// the proxy's — and the point is that they are recorded at all.
func TestASignInRecordsWhereItCameFrom(t *testing.T) {
	f := newAccountFixture(t)
	_, cookie := f.signIn(t, f.email, f.password)

	held, _, err := f.backing.SessionByToken(context.Background(), HashSessionToken(cookie.Value))
	if err != nil {
		t.Fatalf("reading the session back: %v", err)
	}
	if held.UserAgent != "Mozilla/5.0 (fixture)" {
		t.Errorf("user agent = %q, want the one the request sent", held.UserAgent)
	}
	if held.Source != "203.0.113.7" {
		t.Errorf("source = %q, want the peer address without its port", held.Source)
	}
}

// unreachableStore is the store a control plane has when its database has gone.
//
// It fails the three unscoped lookups the two providers make and leaves everything else working, which
// is exactly the shape of the outage that matters: nothing was compared, so nothing is known about the
// credential that was presented.
type unreachableStore struct {
	// Store is the working store everything else goes through.
	store.Store
}

// errDatabaseGone is what an unreachable database looks like from here: unclassified.
//
// Not ErrNotFound and not a sentinel of its own, because that is what pgx returns — a wrapped network
// error. A test that injected a classified error would prove the code handles a case that cannot occur.
var errDatabaseGone = errors.New("store: dial tcp 127.0.0.1:5432: connect: connection refused")

// AccountByEmail fails the way an unreachable database does.
func (unreachableStore) AccountByEmail(_ context.Context, _ string) (store.Account, error) {
	return store.Account{}, errDatabaseGone
}

// SessionByToken fails the way an unreachable database does.
func (unreachableStore) SessionByToken(_ context.Context, _ string) (store.Session, store.Account, error) {
	return store.Session{}, store.Account{}, errDatabaseGone
}

// APITokenByHash fails the way an unreachable database does.
func (unreachableStore) APITokenByHash(_ context.Context, _ string) (store.APIToken, store.Account, error) {
	return store.APIToken{}, store.Account{}, errDatabaseGone
}

// TestAnOutageIsNotAWrongPassword is the distinction the whole of ErrUnavailable exists for.
//
// A provider that cannot reach its store knows *nothing* about the credential it was handed. Reporting
// that as ErrUnauthenticated makes the control plane answer 401, and a 401 is not a neutral fact: to a
// browser it is the sign-in form, and to a script it is "your token was revoked". Every operator would
// be told their credential had been taken away at the moment nobody could check whether it had — and
// the ones typing a password would spend the outage typing it again.
//
// Both paths are asserted together because they fail in the same way and would be fixed separately.
func TestAnOutageIsNotAWrongPassword(t *testing.T) {
	f := newAccountFixture(t)
	broken := NewAccounts(unreachableStore{Store: f.backing}, time.Hour, 24*time.Hour)

	t.Run("signing in", func(t *testing.T) {
		w := httptest.NewRecorder()
		_, err := broken.SignIn(context.Background(), w, signInRequest(), f.email, f.password)
		if errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("an unreachable database was reported as a wrong credential: %v", err)
		}
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
		if len(w.Result().Cookies()) != 0 {
			t.Error("a sign-in that never reached the database still set a cookie")
		}
	})

	t.Run("presenting a session", func(t *testing.T) {
		// A cookie from a working store, presented to a broken one. The value does not matter: what is
		// asserted is that failing to look it up is not the same as failing to find it.
		_, cookie := f.signIn(t, f.email, f.password)
		_, err := broken.Authenticate(context.Background(), authenticated(cookie))
		if errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("an unreachable database invalidated a live session: %v", err)
		}
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
	})

	t.Run("an address that genuinely does not exist is still a refusal", func(t *testing.T) {
		// The other half, and the one that would be broken by an over-eager fix: a working store that
		// answers ErrNotFound must still produce one refusal, indistinguishable from a wrong password.
		w := httptest.NewRecorder()
		_, err := f.provider.SignIn(context.Background(), w, signInRequest(),
			"nobody@example.org", "a password long enough")
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("an unknown address was not a refusal: %v", err)
		}
		if errors.Is(err, ErrUnavailable) {
			t.Fatal("an unknown address was reported as an outage")
		}
	})
}

// TestAnOutageInOneProviderDoesNotRefuseACredentialAnotherAccepts is the ordering inside Chain.
//
// Two providers, one broken. A browser holding a valid session must still get in while the token
// provider's store is unreachable — the alternative is that one failing dependency signs out everybody,
// including the operator trying to diagnose it. And when nobody authenticates *because* a store was
// unreachable, that must reach the caller rather than being flattened into a refusal.
func TestAnOutageInOneProviderDoesNotRefuseACredentialAnotherAccepts(t *testing.T) {
	f := newAccountFixture(t)
	_, cookie := f.signIn(t, f.email, f.password)

	working := f.provider
	broken := NewAPITokens(unreachableStore{Store: f.backing})
	composed := Chain(broken, working)

	identity, err := composed.Authenticate(context.Background(), authenticated(cookie))
	if err != nil {
		t.Fatalf("a valid session was refused because another provider's store was down: %v", err)
	}
	if identity == nil || identity.Subject != f.email {
		t.Fatalf("identity = %+v, want the fixture account", identity)
	}

	// Nobody authenticates: the request carries a bearer token the broken provider cannot check and no
	// cookie at all. The outage is what the caller is told about.
	naked := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	naked.Header.Set("Authorization", "Bearer "+APITokenPrefix+"something")
	if _, err = composed.Authenticate(context.Background(), naked); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want the outage to survive the chain", err)
	}

	// And a request with no credential at all is still a plain refusal, because nothing was consulted.
	bare := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	if _, err = composed.Authenticate(context.Background(), bare); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated for a request carrying nothing", err)
	}
}

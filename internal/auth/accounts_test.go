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
		provider: NewAccounts(backing, time.Hour),
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
	identity, err := f.provider.SignIn(context.Background(), w, email, password)
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
			_, err := f.provider.SignIn(context.Background(), w, c.email, c.password)
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

	if _, err := f.backing.SessionByToken(context.Background(), HashSessionToken(cookie.Value)); !errors.Is(err, store.ErrNotFound) {
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

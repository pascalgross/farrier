package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pascalgross/farrier/internal/store"
)

// SessionCookieName is where a signed-in browser's credential lives.
//
// A cookie rather than a value the application holds, because it is the only place a browser can keep a
// credential that a script running on the page cannot read. The interface previously kept a bearer
// token in localStorage and said in its own comment that this was a trade worth naming; this is the
// other side of that trade being taken.
const SessionCookieName = "farrier_session"

// SessionHeader is the header a cookie-authenticated request must carry.
//
// It is the cross-site request forgery defence, and it works because of what a browser will not do: a
// cross-site form post cannot set a header at all, and a cross-site fetch that sets one triggers a CORS
// preflight this server does not answer. So a request that arrives with both the cookie and this header
// was made by a page from this origin.
//
// SameSite=Lax on the cookie already blocks the form-post case. Lax rather than Strict because Strict
// also withholds the cookie from an ordinary top-level navigation — an operator following a link to a
// host page from a chat message would land on the sign-in form and have to reload — and that is a real
// cost for a case this header already covers. Two mechanisms, neither relied on alone.
//
// The value is not checked. Its presence is the proof; a value would imply a secret that has to be
// distributed, stored and compared, and would add nothing a header name does not already say.
const SessionHeader = "X-Farrier-Session"

// The three numbers that decide how long a sign-in lasts.
//
// One number cannot express what is wanted here, and trying to make it was the previous shape's mistake:
// a fixed twelve hours signs an operator out in the middle of an afternoon they spent working, and
// stretching it to a fortnight to avoid that hands a stolen cookie a fortnight. So there are two
// windows, and the credential dies at whichever comes first.
//
// DefaultSessionTTL is the *idle* window: how long a session survives without being used. It restarts
// on use, which is what makes an afternoon's work uninterrupted.
//
// DefaultSessionMaxAge is the absolute one, measured from the sign-in and never extended. It is what
// stops "idle window that restarts" from meaning "forever": a cookie copied off a machine and used
// once a day would otherwise never expire. A week means signing in on Monday, which is friction an
// operator notices once.
//
// SessionRenewAfter is neither — it is how often the extension is worth a database write. Renewing on
// every request would put an UPDATE on the path of every page load for a value nothing reads more
// precisely than this; renewing at most every quarter of an hour costs one write per session per
// quarter hour, and the only visible effect of the delay is that a session's recorded last use can be
// fifteen minutes stale.
const (
	// DefaultSessionTTL is how long a session survives without being used.
	DefaultSessionTTL = 12 * time.Hour

	// DefaultSessionMaxAge is how long a session may live however much it is used.
	DefaultSessionMaxAge = 7 * 24 * time.Hour

	// SessionRenewAfter is how often extending a session is worth a write.
	SessionRenewAfter = 15 * time.Minute
)

// Accounts authenticates operators against local accounts: an address, a password, and a session.
//
// It is the implementation docs/EXTENDING.md's `auth.Provider` section named first and the package
// comment promised — "local accounts now, OIDC and SAML later" — and it is now the only way a person
// signs in. The shared bearer token it was once added beside is gone: a credential held in a flag,
// naming nobody in the audit trail and withdrawable only by restarting the control plane, is not
// something an installation should have to be careful with. What a script needs instead is APITokens,
// beside this file, and what it issues belongs to one of these accounts.
//
// It reaches the store directly, which is the one thing about this type worth defending. The Provider
// seam is an interface so that an implementation can look wherever it needs to, and local accounts need
// somewhere to keep accounts; the alternative is a second set of record types and an adapter that
// exists only to avoid an import. Nothing on a managed host links this package.
type Accounts struct {
	// store holds the accounts, the sessions and the tokens.
	store store.Store

	// ttl is the idle window: how long a session survives without being used.
	ttl time.Duration

	// maxAge is the absolute window, measured from the sign-in and never extended.
	maxAge time.Duration

	// now is the clock, injectable so that the tests can age a session without sleeping.
	now func() time.Time
}

// NewAccounts returns a provider authenticating against the accounts in a store.
//
// Both windows are parameters rather than the constants, so that an installation with a different
// answer changes one call rather than a package constant — and so that a test can age a session without
// waiting for one. A max age below the idle window would make the idle window unreachable, which is a
// configuration nobody means, so it is raised rather than honoured.
func NewAccounts(backing store.Store, ttl, maxAge time.Duration) *Accounts {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if maxAge < ttl {
		maxAge = max(DefaultSessionMaxAge, ttl)
	}
	return &Accounts{store: backing, ttl: ttl, maxAge: maxAge, now: time.Now}
}

// scopeFor returns the handle through which one account's own rows are reached.
//
// The two sides of the tenant boundary are one interface and this is the only place that chooses
// between them. An account carries its side on the record — an empty tenant is a platform
// administrator, and that is not a missing value but the whole of what makes them one — so everything
// downstream is written against store.AccountScope and never learns which it holds.
//
// A function rather than a method, because both providers in this package need it and a second copy of
// this choice is a second place to get it wrong: a platform account reached through In("") would be a
// handle whose row-level security matches nothing, and the symptom would be an administrator whose
// sessions silently do not exist.
func scopeFor(backing store.Store, account store.Account) store.AccountScope {
	if account.TenantID == "" {
		return backing.Platform()
	}
	return backing.In(account.TenantID)
}

// Name identifies the implementation, for the audit log and the sign-in form.
//
// It becomes half of the principal recorded against every job this operator queues, so it must never
// collide with the token providers': "alice" holding an account and a shared token that happens to be
// displayed as "alice" have to be two principals, because second-person approval is a string equality
// over exactly this value.
func (a *Accounts) Name() string { return "local-account" }

// Authenticate resolves a session cookie to an identity, or returns ErrUnauthenticated.
//
// Every refusal is the same one — no cookie, no header, an unknown token, an expired session, a deleted
// account — for the reason ErrUnauthenticated exists: which half of a guess was right is not something
// this endpoint is entitled to tell anybody.
//
// Both windows are checked against this process's clock rather than the database's, matching every
// other validity window in Farrier. docs/SECURITY.md treats clock skew as a boundary, and a credential
// that outlived its window because two machines disagreed is the least visible way for that to matter.
func (a *Accounts) Authenticate(ctx context.Context, r *http.Request) (*Identity, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, ErrUnauthenticated
	}
	if r.Header.Get(SessionHeader) == "" {
		// See SessionHeader: a cookie without it is a request some other origin caused a browser to
		// make, and the only thing to do with one is not authenticate it.
		return nil, ErrUnauthenticated
	}

	// The tenant comes from the account the session names and from nowhere in the request, which is the
	// same shape the agent side has: a certificate row carries its host's tenant, and nothing an agent
	// sends names one. It is what makes "there is no field an operator could edit to reach another
	// fleet" true of the cookie as well.
	now := a.now()
	hash := HashSessionToken(cookie.Value)
	session, account, err := a.store.SessionByToken(ctx, hash)
	if err != nil || !session.Valid(now) || !a.withinMaxAge(session, now) {
		return nil, ErrUnauthenticated
	}

	a.renew(ctx, session, account, now)
	return a.identityFor(account), nil
}

// withinMaxAge reports whether a session is still inside its absolute window.
//
// Separate from Session.Valid because the two windows belong to different layers. How long a session
// may live without being used is written on the row, so the store can answer it; how long it may live
// at all is this provider's policy, and a store that enforced it would be a store with an opinion about
// authentication.
func (a *Accounts) withinMaxAge(session store.Session, now time.Time) bool {
	return now.Before(session.CreatedAt.Add(a.maxAge))
}

// renew extends a session that has been used, at most once every SessionRenewAfter.
//
// Best-effort by construction: the request has already authenticated, and a database that cannot take
// the write is a reason to log rather than to refuse somebody holding a valid credential. The worst a
// lost renewal costs is that the session expires at its original time.
//
// The cookie is not rewritten, because there is no ResponseWriter here and adding one to the Provider
// seam for this would be the tail wagging the dog. It does not need to be: SignIn sets the cookie to
// expire at the absolute window, and the row is what actually decides — a browser presenting a cookie
// whose session has gone is refused, which is the same answer it would get from a cookie the browser
// had already discarded.
func (a *Accounts) renew(ctx context.Context, session store.Session, account store.Account, now time.Time) {
	// A session that has never been used is measured from when it was made, not from the zero time.
	// Otherwise every sign-in would pay for a second write on the first page load it serves, to move an
	// expiry that is at most a moment old.
	since := session.LastUsedAt
	if since.IsZero() {
		since = session.CreatedAt
	}
	if now.Sub(since) < SessionRenewAfter {
		return
	}
	// Never past the absolute window. Without this the idle window would push the expiry beyond the
	// bound the max-age check enforces, and the row would outlive the credential it stands for.
	expires := now.Add(a.ttl)
	if cap := session.CreatedAt.Add(a.maxAge); cap.Before(expires) {
		expires = cap
	}
	if err := scopeFor(a.store, account).TouchSession(ctx, account.ID, session.TokenHash, expires, now); err != nil {
		slog.Warn("could not extend a session", "error", err, "operator", account.Email)
	}
}

// SignIn exchanges an address and a password for a session, and sets the cookie that carries it.
//
// The cookie is written here rather than by the handler because this type owns the credential's format:
// a caller that had to remember HttpOnly, Secure, SameSite and the path would be a caller that could
// forget one of them, and three of those four are the difference between a session and a liability.
//
// A wrong address and a wrong password are one refusal, and they cost the same: an address nobody holds
// still pays for a password verification against a hash generated for the purpose. Without that, the
// endpoint answers "no such account" in a millisecond and "wrong password" in a tenth of a second, and
// the difference is a list of who has an account here.
//
// The whole request is taken rather than two strings because the session row records what the browser
// called itself and where it came from. Both are advisory and both are the difference between a session
// list somebody can act on and six rows that all say "a session".
func (a *Accounts) SignIn(ctx context.Context, w http.ResponseWriter, r *http.Request, email, password string) (*Identity, error) {
	account, err := a.store.AccountByEmail(ctx, EmailKey(email))
	if err != nil {
		// Not found, and the store failing for any other reason, are the same answer to the caller. The
		// second is worth a log line, because it is an outage rather than a refusal.
		if !errors.Is(err, store.ErrNotFound) {
			slog.Error("could not read an operator account", "error", err)
		}
		VerifyPassword(decoyHash(), password)
		return nil, ErrUnauthenticated
	}
	if !VerifyPassword(account.PasswordHash, password) {
		return nil, ErrUnauthenticated
	}

	now := a.now()
	scoped := scopeFor(a.store, account)

	// The one moment the password is known and the hash can be rewritten. Doing it here is what makes
	// raising the Argon2id parameters something an installation grows into rather than a migration.
	if NeedsRehash(account.PasswordHash) {
		if rehashed, hashErr := HashPassword(password); hashErr == nil {
			if err := scoped.UpdateAccountPassword(ctx, account.ID, rehashed); err != nil {
				// Not fatal to the sign-in: the credential the operator presented was correct, and a
				// failure to improve how it is stored is not a reason to refuse them.
				slog.Warn("could not re-hash a password at sign-in", "error", err, "operator", account.Email)
			}
		}
	}

	token, err := GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("auth: generating a session token: %w", err)
	}
	if err := scoped.CreateSession(ctx, store.Session{
		TokenHash: HashSessionToken(token),
		AccountID: account.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(a.ttl),
		UserAgent: describeAgent(r),
		Source:    RequestSource(r),
	}); err != nil {
		return nil, fmt.Errorf("auth: recording a session: %w", err)
	}
	if err := scoped.RecordAccountSignIn(ctx, account.ID, now); err != nil {
		// The sign-in stands. This stamp exists so that a stale account is visible, and losing one is
		// not worth refusing a correct credential over.
		slog.Warn("could not stamp a sign-in", "error", err, "operator", account.Email)
	}

	// The cookie is dated to the absolute window rather than to the idle one, because the row decides
	// and the cookie only has to survive long enough to present it. Dating it to the idle window would
	// make a browser discard a session the server would still have honoured — a sign-out at twelve
	// hours that no policy asked for.
	http.SetCookie(w, a.cookie(token, now.Add(a.maxAge)))
	return a.identityFor(account), nil
}

// SignOut ends the session a request carries and clears the cookie.
//
// The row is deleted rather than left to expire, because "sign out" has to mean the credential stops
// working — including for whoever copied it. A request carrying no session, or one already gone, is not
// an error: signing out twice is not a failure a caller should have to tell apart from success.
func (a *Accounts) SignOut(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	http.SetCookie(w, a.cookie("", time.Unix(0, 0)))

	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		// A request with no cookie has nothing to sign out of, which is a success and not a failure —
		// see the paragraph above on signing out twice.
		//nolint:nilerr // "no cookie" is the idempotent case, not an error to report.
		return nil
	}
	hash := HashSessionToken(cookie.Value)
	session, account, err := a.store.SessionByToken(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("auth: reading the session to end it: %w", err)
	}
	return scopeFor(a.store, account).DeleteSession(ctx, account.ID, session.TokenHash)
}

// identityFor renders an account as the identity the rest of the control plane sees.
//
// The subject is the address rather than the account id, and that is a decision about the audit log:
// `local-account:alice@example.org` is what somebody reading "who queued this reboot" needs, and
// `local-account:01JABC…` is a lookup they cannot perform once the account is gone. It is also why
// there is no rename — an address is the principal recorded on every job, so changing one would leave
// the history naming somebody who no longer exists.
//
// An account with no tenant is a platform administrator, and both fields say so: the empty tenant is
// what every route reaching tenant data refuses, and Platform is what the two platform-only routes
// require. Deriving them from one field rather than storing a flag is deliberate — a row that claimed
// to be a platform administrator *and* named a fleet would be a contradiction nothing refuses.
func identityFor(provider string, account store.Account) *Identity {
	display := account.DisplayName
	if display == "" {
		display = account.Email
	}
	return &Identity{
		Subject:  NormaliseEmail(account.Email),
		Display:  display,
		Provider: provider,
		Tenant:   string(account.TenantID),
		Platform: account.TenantID == "",
	}
}

// identityFor renders one of this provider's accounts as an identity, held as a browser session.
func (a *Accounts) identityFor(account store.Account) *Identity {
	identity := identityFor(a.Name(), account)
	identity.Credential = CredentialSession
	return identity
}

// RequestSource identifies where a request came from, for a rate limiter and for a session list.
//
// The peer address is used and no forwarded header is consulted. A header is set by whoever is talking
// to the server, so trusting one would let a single client present a different source on every request
// and defeat the limiter entirely. Behind a proxy this reports the proxy, which is the honest behaviour
// for a control plane that has not been told which proxies to trust — and it is why the session list
// calls the value advisory rather than showing it as a fact.
func RequestSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// describeAgent returns the browser string to record against a session, bounded.
//
// Bounded because it is a value a client chooses and this one is stored: a request may send however
// many kilobytes it likes, and a row that grows with what an attacker sends is a row worth truncating
// before it is written. A hundred characters is longer than every real user agent's useful prefix.
func describeAgent(r *http.Request) string {
	const maxUserAgent = 100
	agent := strings.TrimSpace(r.UserAgent())
	if len(agent) > maxUserAgent {
		return agent[:maxUserAgent]
	}
	return agent
}

// cookie builds the session cookie, set and cleared through the same function.
//
// One function so the attributes cannot differ between the two: a clear that omitted Path would leave
// the original cookie in place under a different path, and the operator would be signed out until the
// next reload signed them back in.
func (a *Accounts) cookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:  SessionCookieName,
		Value: value,
		Path:  "/",
		// The control plane listens on TLS and nothing else — client certificates require it — so
		// Secure costs nothing and closes the case where a proxy in front of it does not.
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

// NormaliseEmail returns the form of an address this control plane compares and stores.
//
// Lower-cased and trimmed, and nothing more. The local part of an address is case-sensitive by the
// letter of RFC 5321 and case-insensitive at every mail provider anybody uses, and an operator who
// typed their address with a capital on Monday must not be a different person on Tuesday. Dots and
// plus-addressing are left alone: stripping them is a Gmail convention, not a rule, and applying it
// would silently merge two addresses that are two people somewhere else.
func NormaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// EmailKey returns the value an account row is found by.
//
// SHA-256 of the normalised address, unsalted and unstretched — which is right here and wrong for the
// password column beside it. This is not a secret being protected; it is a fixed-width key so that the
// sign-in lookup can name one row through the same session setting the certificate and enrolment-token
// resolvers use, instead of teaching the row-level security policy a second shape of key.
func EmailKey(email string) string {
	sum := sha256.Sum256([]byte(NormaliseEmail(email)))
	return hex.EncodeToString(sum[:])
}

// HashSessionToken returns the stored form of a session token.
//
// Unsalted SHA-256 for the same reason internal/server.HashToken uses it for an enrolment token: the
// input is 256 bits of uniform randomness this process generated, so there is no dictionary to attack
// and a work factor would only slow down every authenticated request. It is written here rather than
// imported because internal/server imports this package and not the other way round.
func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// decoyHash returns a real Argon2id hash of a value nobody knows, for the unknown-address path.
//
// Computed once and reused, because the point is to spend the same time as a real verification and not
// to be unpredictable — the password it hides is never compared against anything a caller supplies.
// Computing it lazily rather than in an init keeps the cost off the startup path of a control plane
// that never sees a failed sign-in.
var decoyHash = sync.OnceValue(func() string {
	token, err := GenerateToken()
	if err != nil {
		// A hash of a constant is worse than a hash of a random string and much better than skipping
		// the verification, which is the whole point of this value. crypto/rand failing at all is a
		// broken machine.
		token = "farrier-decoy-password"
	}
	hashed, err := HashPassword(token)
	if err != nil {
		// Unreachable: the token is 64 characters. VerifyPassword returns false for an unparseable
		// hash and still pays for the parse, which is the wrong cost — so this is worth noticing.
		slog.Error("could not build the sign-in decoy hash", "error", err)
		return ""
	}
	return hashed
})

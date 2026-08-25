package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pascalgross/farrier/internal/store"
)

// APITokenPrefix marks a Farrier API token as one.
//
// It costs nothing and buys two things. A secret scanner — GitHub's, or a pre-commit hook — matches on
// a prefix, so a token pasted into a repository can be found before somebody uses it; and a person
// looking at an environment file can tell what they are holding without trying it. The convention is
// widely copied for exactly these reasons.
const APITokenPrefix = "frr_"

// APITokenBytes is how much randomness a token carries.
//
// Thirty-two bytes, like a session token and an enrolment token, because it is the same kind of thing:
// a credential this process generates and compares by hash. It is the number that makes storing an
// unsalted SHA-256 correct, so it is stated here rather than left to the generator.
const APITokenBytes = 32

// APITokens authenticates a script or a job runner as the account whose token it presents.
//
// It is what replaces the shared bearer token, and the difference is the whole point. `FARRIER_ADMIN_
// TOKEN` was one credential for a whole fleet: it named nobody in the audit trail, made second-person
// approval unsatisfiable — that rule is a string comparison between two principals, and under one
// shared token they were always equal — never expired, and could be withdrawn only by restarting the
// control plane with a new one and telling everybody. A token issued here belongs to one account, acts
// as that account, may expire, and is revoked from a page in a second.
//
// "Acts as that account" is meant exactly: the identity this returns is the same identity that
// account's browser session returns, same provider and same subject. That is not laziness about the
// audit trail — it is what keeps the approval rule honest. If a token were its own principal, an
// operator under the two-person rule could queue a job in the browser and release it with their own
// token, and the comparison would see two people.
type APITokens struct {
	// store holds the tokens and the accounts they belong to.
	store store.Store

	// now is the clock, injectable so that a test can expire a token without waiting.
	now func() time.Time
}

// NewAPITokens returns a provider authenticating the tokens in a store.
func NewAPITokens(backing store.Store) *APITokens {
	return &APITokens{store: backing, now: time.Now}
}

// Name identifies the implementation, for the audit log and the login page.
//
// It reports "local-account" rather than something of its own, and that is the load-bearing sentence in
// this file. The name is half of the principal recorded against every job — see Identity.Principal —
// so a token that called itself something else would make one person look like two to the second-person
// approval rule, which is a comparison of exactly this string.
func (a *APITokens) Name() string { return "local-account" }

// Authenticate resolves a bearer token to the identity of the account that owns it.
//
// Every refusal is ErrUnauthenticated: no header, the wrong scheme, an unknown token, an expired one,
// an account since deleted. Which of those it was is not something this endpoint may tell whoever is
// guessing.
//
// Expiry is checked against this process's clock rather than the database's, matching every other
// validity window in Farrier — docs/SECURITY.md treats clock skew as a boundary.
func (a *APITokens) Authenticate(ctx context.Context, r *http.Request) (*Identity, error) {
	presented := bearerToken(r)
	if presented == "" {
		return nil, ErrUnauthenticated
	}

	now := a.now()
	token, account, err := a.store.APITokenByHash(ctx, HashAPIToken(presented))
	if err != nil {
		// Not found and an outage are the same answer to the caller; the second is worth a log line,
		// because it is a control plane that has stopped working rather than a credential that is wrong.
		if !errors.Is(err, store.ErrNotFound) {
			slog.Error("could not read an API token", "error", err)
		}
		return nil, ErrUnauthenticated
	}
	if !token.Usable(now) {
		return nil, ErrUnauthenticated
	}

	a.touch(ctx, token, account, now)

	// The label goes in Display and nowhere else. It is what turns "alice did this" into "alice's CI
	// runner did this" when somebody reads the interface, and it deliberately does not reach Principal:
	// a label is a string the operator can edit, and a principal that could be edited would be an audit
	// trail that could be rewritten.
	identity := identityFor(a.Name(), account)
	identity.Credential = CredentialAPIToken
	if label := strings.TrimSpace(token.Label); label != "" {
		identity.Display += " (" + label + ")"
	}
	return identity, nil
}

// touch records that a token was used, at most once every SessionRenewAfter.
//
// The same rate as a session's, for the same reason and with the same consequence: a write on every
// request would put an UPDATE in front of every scripted call for a value nothing reads more precisely
// than this. Best-effort — the request has already authenticated, and a database that cannot take the
// stamp is not a reason to refuse a valid credential.
//
// It exists so that "which of these six tokens is still in use" is answerable before somebody has to
// revoke one and wait to see what breaks.
func (a *APITokens) touch(ctx context.Context, token store.APIToken, account store.Account, now time.Time) {
	if now.Sub(token.LastUsedAt) < SessionRenewAfter {
		return
	}
	if err := scopeFor(a.store, account).TouchAPIToken(ctx, account.ID, token.Hash, now); err != nil {
		slog.Warn("could not stamp an API token's use", "error", err, "operator", account.Email)
	}
}

// GenerateAPIToken returns a new token in the form an operator copies out of the interface.
//
// The prefix and the randomness are produced together, in one place, because they travel together: a
// token generated somewhere else without the prefix would authenticate perfectly and be invisible to
// every scanner that exists to catch it.
//
// Base64 without padding rather than hex, so that 32 bytes is 43 characters instead of 64. It is
// URL-safe because a token ends up in a shell, in an environment file and occasionally — against
// advice — in a URL, and a `+` or a `/` in any of those is somebody's afternoon.
func GenerateAPIToken() (string, error) {
	raw := make([]byte, APITokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return APITokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// HashAPIToken returns the stored form of an API token.
//
// Unsalted SHA-256, exactly as for a session token and an enrolment token, and correct for the same
// reason: the input is 256 bits of uniform randomness this process generated, so there is no dictionary
// to attack and a work factor would only slow down every authenticated request. The prefix is hashed
// along with the rest, because it is part of the string the operator holds.
func HashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// bearerToken returns the credential in an Authorization header, or the empty string.
//
// The scheme is matched case-insensitively because RFC 7235 says it is case-insensitive, and a client
// that sends `bearer` is a client that would otherwise be refused for a reason nobody could see from
// either end.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

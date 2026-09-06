// Package auth authenticates human operators against the control plane.
//
// It is a seam: local accounts now, OIDC and SAML later, added by writing an implementation rather than
// by editing a switch. See docs/EXTENDING.md.
//
// Two implementations ship and they are two halves of one answer. Accounts is an address and a password
// per person, with a session in an HttpOnly cookie: it is what a browser uses, and it is what makes the
// audit trail name somebody and makes second-person approval reachable. APITokens is a revocable token
// belonging to one of those accounts, acting as that account: it is what a script uses. They compose
// through Chain, so an installation has both.
//
// There used to be a third, StaticToken: one shared bearer token per fleet, held in a flag. It is gone
// on purpose. A shared credential names nobody in the audit trail, cannot be withdrawn from one person
// without changing it for everybody, never expires, and made the second-person approval rule
// unsatisfiable by construction — that rule compares the approver's principal against the job's
// creator, and under one shared token those two strings were always equal.
//
// Accounts reaches internal/store, which is why this package does. That is a property of local accounts
// rather than of the seam — an OIDC implementation would reach an issuer instead — and nothing on a
// managed host links any of it: only cmd/hostseal-server and internal/server import this package.
//
// It is worth being explicit that this is **not** a boundary the guarantee in docs/SECURITY.md rests
// on. A compromised administrator account is inside that threat model by construction — the guarantee
// says an attacker who owns the control plane, its database *and* an administrator account still cannot
// run arbitrary code on an enrolled host. Good operator authentication protects the fleet's
// availability and its audit trail; the thing that protects the hosts is the local policy file and the
// signing key the control plane does not hold.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrUnauthenticated reports that a request carried no usable credential.
//
// It is one error for a missing, malformed and wrong credential alike. Distinguishing them tells
// whoever is guessing which half of their guess was right.
var ErrUnauthenticated = errors.New("auth: unauthenticated")

// ErrUnavailable reports that a credential could not be checked, which is not the same as wrong.
//
// The distinction is the whole point and it is easy to lose, because both end a request. A provider
// that cannot reach its store knows nothing about the credential it was given — so answering 401 tells
// every signed-in operator that their session has been invalidated and every one signing in that their
// password is wrong, at the moment none of that is true and none of them can do anything about it. An
// outage should look like an outage: the browser keeps its cookie, the operator stops retyping, and
// whoever is on call reads a 500 rather than a support request about passwords.
//
// It carries no detail about the credential and never reaches the caller as text. What the caller gets
// is a 500 and a sentence about the control plane; this exists so that the middleware can tell which
// of the two answers to give.
var ErrUnavailable = errors.New("auth: the credential could not be checked")

// Identity is an authenticated operator.
type Identity struct {
	// Subject is the stable identifier the provider knows this operator by.
	//
	// It is not the principal recorded in the audit log — see Principal. A bare subject is whatever the
	// provider chose to call somebody, and two providers can choose the same thing.
	Subject string

	// Display is a human-readable name for the UI.
	Display string

	// Provider names which implementation authenticated this request.
	//
	// It is recorded alongside the subject because "alice" from a local account and "alice" from an
	// OIDC provider are different principals, and an audit trail that conflated them would be worse
	// than one that named neither.
	Provider string

	// Tenant is the fleet this operator acts in, empty for a platform administrator.
	//
	// One credential reaches exactly one tenant. That is the whole of the operator-side isolation
	// model: there is no tenant in the URL and none in a header, so there is no request field an
	// operator could change to point at somebody else's fleet, and nothing downstream has to remember
	// to check that they were allowed to.
	Tenant string

	// Credential names the kind of credential this request presented.
	//
	// It exists because two of them resolve to the same person on purpose. An API token acts as the
	// account that owns it — same provider, same subject, therefore the same principal — so that the
	// second-person approval rule cannot be sidestepped by holding one. That is right for the audit
	// trail and wrong for exactly one class of route: the account page, where a credential must not be
	// able to mint or revoke another. A leaked token that could issue a token with no expiry would
	// outlive its own revocation.
	//
	// It is deliberately not part of Principal. Who did something and what they were holding at the
	// time are two questions, and only the first is an identity.
	Credential string

	// Platform reports a platform administrator: the installation's operator rather than a customer's.
	//
	// It carries no tenant and is refused by every route that reaches tenant data. That separation is
	// the point rather than a convenience — running HostSeal for other people should not require being
	// able to read their fleets, and a role that could do both would make "the hoster cannot see your
	// hosts" a promise about restraint instead of about routing.
	Platform bool
}

// Principal is the string recorded as the author of an action.
//
// Provider-qualified, because the bare subject is not unique and one comparison of it is load-bearing:
// a tenant using second-person approval refuses a release by whoever created the job, and that refusal
// is a string equality. Two identity sources that both call somebody "alice" would make one person look
// like two, or two people look like one, and which of those you get is a coin toss. The Provider field
// was added for exactly this and was previously persisted nowhere.
func (i Identity) Principal() string {
	if i.Provider == "" {
		return i.Subject
	}
	return i.Provider + ":" + i.Subject
}

// The kinds of credential Identity.Credential names.
//
// Two, and there is no plan for a third of this shape: an OIDC or SAML implementation would produce a
// session like any other, because what this distinguishes is not where the identity came from but
// whether a person is at the other end of the request.
const (
	// CredentialSession is a signed-in browser, holding a cookie this control plane issued.
	CredentialSession = "session"

	// CredentialAPIToken is a script, holding a token an account minted for it.
	CredentialAPIToken = "api-token"
)

// Provider authenticates a human operator against the control plane.
type Provider interface {
	// Name identifies the implementation, for the audit log and the login page.
	Name() string

	// Authenticate resolves a request to an identity, or returns ErrUnauthenticated.
	//
	// It takes the whole request rather than a credential string because the implementations differ in
	// where they look: a bearer token is in a header, a session is in a cookie, and a future SAML
	// implementation needs the form body.
	Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}

// Chain tries several providers in order and takes the first identity one of them returns.
//
// A control plane needs at least two credentials that are not the same kind of thing — what a browser
// holds and what a script holds — and the Provider seam authenticates rather than enumerates, so
// composing is the way to have both without either implementation knowing about the other. Order is the
// order given; every member is asked, so adding one cannot silently shadow another.
func Chain(providers ...Provider) Provider { return chain(providers) }

// chain is the composed provider Chain returns.
type chain []Provider

// Name identifies the implementation, for the audit log and the login page.
//
// It reports the members rather than "chain", because the name ends up in a log line explaining a
// refusal, and "chain" would tell whoever is reading it nothing they did not already know.
func (c chain) Name() string {
	names := make([]string, 0, len(c))
	for _, p := range c {
		names = append(names, p.Name())
	}
	return strings.Join(names, "+")
}

// Authenticate returns the first identity any member recognises.
//
// Every member is tried even after one fails, and the failure is not reported until all have been:
// returning early on the first ErrUnauthenticated would be correct but would also make the number of
// comparisons depend on which credential was presented, and the whole reason each member compares in
// constant time is that this should not be observable.
//
// An operational failure is kept and reported only when nobody authenticated, which is the ordering
// that matters: a browser holding a valid session must still get in while the token provider's store is
// unreachable, and a request that authenticated nowhere *because* a store was unreachable must not be
// told its credential was wrong. Refusals are discarded rather than joined — every member refusing is
// the ordinary case and says nothing worth keeping.
func (c chain) Authenticate(ctx context.Context, r *http.Request) (*Identity, error) {
	var found *Identity
	var unavailable error
	for _, p := range c {
		identity, err := p.Authenticate(ctx, r)
		if err == nil && identity != nil && found == nil {
			found = identity
			continue
		}
		if err != nil && !errors.Is(err, ErrUnauthenticated) && unavailable == nil {
			unavailable = err
		}
	}
	if found != nil {
		return found, nil
	}
	if unavailable != nil {
		return nil, unavailable
	}
	return nil, ErrUnauthenticated
}

// GenerateToken returns 32 bytes of randomness as hex, for a session token.
//
// Thirty-two bytes because that is what makes storing an unsalted SHA-256 of it correct: there is no
// dictionary to attack a value drawn uniformly from 2^256. Hex rather than base64 because a session
// token is never read or typed by a person — it lives in a cookie — so there is nothing to trade
// twenty-one characters of length for.
func GenerateToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: generating a token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// GeneratePassword returns a password for an account nobody has chosen one for yet.
//
// Deliberately shorter than a token: 18 bytes is 144 bits, which is far past anything a password has to
// resist, and 24 characters is short enough that somebody reading it off a first-start log and typing
// it into a browser does not make a mistake. A 64-character hex string would be stronger in a way that
// changes nothing and worse in a way that matters — it would get pasted into a note and left there.
//
// It is a temporary credential by intent. What produces it is the first start of a control plane whose
// database holds no accounts, and the sentence printed beside it says to change it.
func GeneratePassword() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: generating a password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

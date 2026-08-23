// Package auth authenticates human operators against the control plane.
//
// It is a seam: local accounts now, OIDC and SAML later, added by writing an implementation rather than
// by editing a switch. See docs/EXTENDING.md.
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
	"crypto/sha256"
	"crypto/subtle"
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

	// Platform reports a platform administrator: the installation's operator rather than a customer's.
	//
	// It carries no tenant and is refused by every route that reaches tenant data. That separation is
	// the point rather than a convenience — running Farrier for other people should not require being
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

// StaticToken authenticates a single bearer token, for a small installation and for the tests.
//
// It exists because the first thing anybody does with a new control plane is start it, and requiring an
// identity provider to be configured before the fleet list will render is exactly the friction that
// makes people close the tab. The token is compared in constant time and only its hash is held.
type StaticToken struct {
	// hash is the SHA-256 of the accepted token.
	hash [32]byte

	// display is the operator name recorded for this token.
	display string

	// tenant is the fleet this token reaches, empty for a platform token.
	tenant string

	// platform reports that this token administers the installation rather than a fleet.
	platform bool
}

// NewStaticToken returns a provider accepting one bearer token, acting in one tenant.
//
// The tenant is bound to the credential rather than chosen per request, which is what makes an operator
// unable to reach another fleet by editing a URL. It is required: a token with no tenant would be an
// operator credential that reaches nothing, and silently defaulting one to a tenant it happened to find
// is how a test fixture becomes a production configuration.
func NewStaticToken(token, display, tenant string) (*StaticToken, error) {
	provider, err := newToken(token, display)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(tenant) == "" {
		return nil, errors.New("auth: an operator token must name the tenant it acts in")
	}
	provider.tenant = tenant
	return provider, nil
}

// NewPlatformToken returns a provider for the installation's own administrator.
//
// It holds no tenant and every route that reaches tenant data refuses it. What it can do is create and
// configure tenants — which is the whole job of running Farrier for other people, and is deliberately a
// different job from being able to read what they run.
func NewPlatformToken(token, display string) (*StaticToken, error) {
	if display == "" {
		display = "platform"
	}
	provider, err := newToken(token, display)
	if err != nil {
		return nil, err
	}
	provider.platform = true
	return provider, nil
}

// newToken builds the half of a token provider both kinds share.
func newToken(token, display string) (*StaticToken, error) {
	token = strings.TrimSpace(token)
	if len(token) < 16 {
		return nil, errors.New("auth: an admin token must be at least 16 characters")
	}
	if display == "" {
		display = "operator"
	}
	// Trimmed on both sides. The presented token is trimmed too, so a configured token carrying a
	// trailing newline — which is what happens when it comes from a file, or from a shell that added
	// one — would otherwise be a token that can never be presented successfully.
	return &StaticToken{hash: sha256.Sum256([]byte(token)), display: display}, nil
}

// Chain tries several providers in order and takes the first identity one of them returns.
//
// A hosted control plane needs at least two credentials that are not the same kind of thing — the
// platform administrator's and each tenant's — and the Provider seam authenticates rather than
// enumerates, so composing is the way to have both without either implementation knowing about the
// other. Order is the order given; every member is asked, so adding one cannot silently shadow another.
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
func (c chain) Authenticate(ctx context.Context, r *http.Request) (*Identity, error) {
	var found *Identity
	for _, p := range c {
		identity, err := p.Authenticate(ctx, r)
		if err == nil && identity != nil && found == nil {
			found = identity
		}
	}
	if found == nil {
		return nil, ErrUnauthenticated
	}
	return found, nil
}

// GenerateToken returns a new random admin token.
//
// It is used when no token is configured, so that starting the server for the first time produces a
// working, credentialed control plane rather than an open one. The token is printed once, at startup,
// and is not recoverable afterwards.
func GenerateToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: generating a token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// Name identifies the implementation, for the audit log and the login page.
//
// The two kinds are named apart because the name becomes half of the principal recorded against every
// job, and a platform administrator and a tenant's operator must never be able to collide there.
func (s *StaticToken) Name() string {
	if s.platform {
		return "platform-token"
	}
	return "static-token"
}

// Authenticate resolves a request to an identity, or returns ErrUnauthenticated.
func (s *StaticToken) Authenticate(_ context.Context, r *http.Request) (*Identity, error) {
	header := r.Header.Get("Authorization")
	token, found := strings.CutPrefix(header, "Bearer ")
	if !found {
		return nil, ErrUnauthenticated
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(token)))
	if subtle.ConstantTimeCompare(got[:], s.hash[:]) != 1 {
		return nil, ErrUnauthenticated
	}
	return &Identity{
		Subject:  s.display,
		Display:  s.display,
		Provider: s.Name(),
		Tenant:   s.tenant,
		Platform: s.platform,
	}, nil
}

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
	// Subject is the stable identifier recorded in the audit log.
	Subject string

	// Display is a human-readable name for the UI.
	Display string

	// Provider names which implementation authenticated this request.
	//
	// It is recorded alongside the subject because "alice" from a local account and "alice" from an
	// OIDC provider are different principals, and an audit trail that conflated them would be worse
	// than one that named neither.
	Provider string
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
}

// NewStaticToken returns a provider accepting exactly one bearer token.
func NewStaticToken(token, display string) (*StaticToken, error) {
	if len(token) < 16 {
		return nil, errors.New("auth: an admin token must be at least 16 characters")
	}
	if display == "" {
		display = "operator"
	}
	return &StaticToken{hash: sha256.Sum256([]byte(token)), display: display}, nil
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
func (s *StaticToken) Name() string { return "static-token" }

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
	return &Identity{Subject: s.display, Display: s.display, Provider: s.Name()}, nil
}

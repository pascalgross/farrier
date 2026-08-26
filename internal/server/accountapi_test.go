package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/pascalgross/farrier/internal/auth"
)

// signedIn returns a cookie-keeping client that has already signed in as the harness's account.
func (h *harness) signedIn(t *testing.T) *http.Client {
	t.Helper()

	client := h.browser(t)
	status, body := sessionRequest(t, client, http.MethodPost, h.server.URL+"/api/v1/session",
		map[string]string{"email": h.accountEmail, "password": h.accountPassword})
	if status != http.StatusOK {
		t.Fatalf("signing in returned %d: %s", status, body)
	}
	return client
}

// mintToken issues an API token through the account API and returns it.
func mintToken(t *testing.T, h *harness, client *http.Client, label string) (string, string) {
	t.Helper()

	status, body := sessionRequest(t, client, http.MethodPost, h.server.URL+"/api/v1/account/tokens",
		map[string]any{"label": label})
	if status != http.StatusCreated {
		t.Fatalf("minting a token returned %d: %s", status, body)
	}
	var issued struct {
		// ID is the token's stored hash, which is what revoking one names.
		ID string `json:"id"`

		// Token is the value, returned exactly once.
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decoding the issued token: %v", err)
	}
	return issued.Token, issued.ID
}

// TestAnOperatorMintsATokenUsesItAndRevokesIt is the whole replacement for the shared bearer token.
//
// It is what a script's setup now looks like: sign in as a person, issue a token that belongs to that
// person, use it from somewhere with no browser, and take it away again. The assertion that matters
// most is the last one — a revoked token stops working immediately, with no restart, which is the
// property `FARRIER_ADMIN_TOKEN` could not have.
func TestAnOperatorMintsATokenUsesItAndRevokesIt(t *testing.T) {
	h := newHarness(t)
	client := h.signedIn(t)

	token, id := mintToken(t, h, client, "continuous integration")
	if !bytes.HasPrefix([]byte(token), []byte(auth.APITokenPrefix)) {
		t.Errorf("issued token %q does not carry the prefix a secret scanner matches on", token)
	}

	status, body := h.adminJSON(t, token, http.MethodGet, "/api/v1/hosts", nil)
	if status != http.StatusOK {
		t.Fatalf("the fleet listing returned %d for a valid API token: %s", status, body)
	}

	status, body = sessionRequest(t, client, http.MethodDelete,
		h.server.URL+"/api/v1/account/tokens/"+id, nil)
	if status != http.StatusNoContent {
		t.Fatalf("revoking the token returned %d: %s", status, body)
	}
	if status, body = h.adminJSON(t, token, http.MethodGet, "/api/v1/hosts", nil); status != http.StatusUnauthorized {
		t.Fatalf("a revoked token still reached the fleet listing: %d %s", status, body)
	}
}

// TestGuaranteeAnAPITokenCannotMintOrRevokeAnother is why the account routes read the credential kind.
//
// A token acts as the account that owns it, which is what keeps the second-person approval rule honest.
// The cost of that is that a token presented to the account routes would look exactly like the person —
// and could then issue a second token, one with no expiry, that survives the first being revoked. So
// the account routes are the one place that asks what the caller was holding as well as who they are.
//
// The 403 is deliberately distinguishable from a 401: the credential is valid, and telling somebody
// their token is fine but not for this is the difference between a fixable message and a mystery.
func TestGuaranteeAnAPITokenCannotMintOrRevokeAnother(t *testing.T) {
	h := newHarness(t)
	client := h.signedIn(t)
	token, id := mintToken(t, h, client, "continuous integration")

	for _, c := range []struct {
		// name says which account route this is.
		name string

		// method and path are the request a token must not be able to make.
		method string
		path   string

		// body is what it would send, nil for none.
		body any
	}{
		{name: "read the account", method: http.MethodGet, path: "/api/v1/account"},
		{name: "change the password", method: http.MethodPost, path: "/api/v1/account/password",
			body: map[string]string{"currentPassword": "x", "newPassword": "a longer password"}},
		{name: "list sessions", method: http.MethodGet, path: "/api/v1/account/sessions"},
		{name: "sign out everywhere", method: http.MethodPost, path: "/api/v1/account/sessions/revoke"},
		{name: "list tokens", method: http.MethodGet, path: "/api/v1/account/tokens"},
		{name: "mint another", method: http.MethodPost, path: "/api/v1/account/tokens",
			body: map[string]any{"label": "a token minted by a token"}},
		{name: "revoke one", method: http.MethodDelete, path: "/api/v1/account/tokens/" + id},
	} {
		t.Run(c.name, func(t *testing.T) {
			status, body := h.adminJSON(t, token, c.method, c.path, c.body)
			if status != http.StatusForbidden {
				t.Fatalf("%s %s returned %d for an API token, want 403: %s", c.method, c.path, status, body)
			}
		})
	}

	// And the token that tried is still exactly one token: nothing above created a second.
	status, body := sessionRequest(t, client, http.MethodGet, h.server.URL+"/api/v1/account/tokens", nil)
	if status != http.StatusOK {
		t.Fatalf("listing tokens returned %d: %s", status, body)
	}
	var listing struct {
		// Tokens is what the account holds.
		Tokens []struct {
			// Label is what the operator called it.
			Label string `json:"label"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decoding the token listing: %v", err)
	}
	if len(listing.Tokens) != 1 {
		t.Fatalf("the account holds %d tokens, want the one it minted itself", len(listing.Tokens))
	}
}

// TestChangingAPasswordNeedsTheCurrentOne is what stops a borrowed session becoming an account takeover.
//
// The request already carries a session that authenticated, so asking again looks redundant until you
// name the case: a session is a credential somebody else may be holding — an unlocked laptop, a copied
// cookie — and a password change is the one operation that locks the owner out of their own account.
func TestChangingAPasswordNeedsTheCurrentOne(t *testing.T) {
	h := newHarness(t)
	client := h.signedIn(t)

	status, body := sessionRequest(t, client, http.MethodPost, h.server.URL+"/api/v1/account/password",
		map[string]string{"currentPassword": "not the password", "newPassword": "a replacement password"})
	if status != http.StatusUnauthorized {
		t.Fatalf("a wrong current password returned %d, want 401: %s", status, body)
	}

	// Too short is refused as well, and separately: the message is different because the fix is.
	status, body = sessionRequest(t, client, http.MethodPost, h.server.URL+"/api/v1/account/password",
		map[string]string{"currentPassword": h.accountPassword, "newPassword": "short"})
	if status != http.StatusBadRequest {
		t.Fatalf("a five-character password returned %d, want 400: %s", status, body)
	}

	const replacement = "a replacement password"
	status, body = sessionRequest(t, client, http.MethodPost, h.server.URL+"/api/v1/account/password",
		map[string]string{"currentPassword": h.accountPassword, "newPassword": replacement})
	if status != http.StatusNoContent {
		t.Fatalf("changing the password returned %d: %s", status, body)
	}

	// The session survives the change, which is the deliberate half: a routine password change that
	// signed every device out is a password change people learn not to make.
	if status, _ = sessionRequest(t, client, http.MethodGet, h.server.URL+"/api/v1/hosts", nil); status != http.StatusOK {
		t.Errorf("the session stopped working after its own password change: %d", status)
	}

	// And the new password is the one that signs in.
	fresh := h.browser(t)
	if status, body = sessionRequest(t, fresh, http.MethodPost, h.server.URL+"/api/v1/session",
		map[string]string{"email": h.accountEmail, "password": replacement}); status != http.StatusOK {
		t.Fatalf("signing in with the new password returned %d: %s", status, body)
	}
	if status, _ = sessionRequest(t, h.browser(t), http.MethodPost, h.server.URL+"/api/v1/session",
		map[string]string{"email": h.accountEmail, "password": h.accountPassword}); status != http.StatusUnauthorized {
		t.Errorf("the old password still signs in: %d", status)
	}
}

// TestSigningOutEverywhereEndsEverySessionIncludingThisOne is what somebody presses after losing a laptop.
//
// Including this one, deliberately. A version that quietly kept the current session would have to be
// explained, and the explanation — "everywhere except here" — lands at the moment somebody is least
// able to reason about which "here" they mean.
func TestSigningOutEverywhereEndsEverySessionIncludingThisOne(t *testing.T) {
	h := newHarness(t)
	first := h.signedIn(t)
	second := h.signedIn(t)

	status, body := sessionRequest(t, first, http.MethodGet, h.server.URL+"/api/v1/account/sessions", nil)
	if status != http.StatusOK {
		t.Fatalf("listing sessions returned %d: %s", status, body)
	}
	var listing struct {
		// Sessions is every browser this account is signed in on.
		Sessions []struct {
			// Current marks the one that asked, computed here rather than compared by the client.
			Current bool `json:"current"`

			// UserAgent is what the browser called itself.
			UserAgent string `json:"userAgent"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decoding the session listing: %v", err)
	}
	if len(listing.Sessions) != 2 {
		t.Fatalf("the account has %d sessions listed, want 2", len(listing.Sessions))
	}
	current := 0
	for _, held := range listing.Sessions {
		if held.Current {
			current++
		}
	}
	if current != 1 {
		t.Errorf("%d sessions are marked as the current one, want exactly 1", current)
	}
	// Nothing in the listing authenticates anybody, which is what makes it safe to render on a page.
	if bytes.Contains(body, []byte("tokenHash")) || bytes.Contains(body, []byte("token")) {
		t.Errorf("the session listing carries a token: %s", body)
	}

	if status, body = sessionRequest(t, first, http.MethodPost,
		h.server.URL+"/api/v1/account/sessions/revoke", nil); status != http.StatusOK {
		t.Fatalf("signing out everywhere returned %d: %s", status, body)
	}
	for name, client := range map[string]*http.Client{"the one that asked": first, "the other": second} {
		if status, _ = sessionRequest(t, client, http.MethodGet, h.server.URL+"/api/v1/hosts", nil); status != http.StatusUnauthorized {
			t.Errorf("%s still reaches the fleet after signing out everywhere: %d", name, status)
		}
	}
}

// TestGuaranteeAnOutageIsNotAnswered401 is the middleware half of the distinction internal/auth draws.
//
// Every route behind a credential goes through one of four guards, and all four used to answer 401 for
// any error at all. That is wrong in a way nobody notices until it happens: during a database outage
// every browser is shown the sign-in form and every script is told its token was revoked, at the moment
// the control plane cannot tell whether either is true. The operators most likely to be looking are the
// ones diagnosing the outage, and the first thing they would conclude is that authentication is broken.
//
// Every guard is asserted, because they were four copies of the same clause and a fix to one is not a
// fix to the others.
func TestGuaranteeAnOutageIsNotAnswered401(t *testing.T) {
	h := newHarness(t)

	for _, c := range []struct {
		// name says which guard this route is behind.
		name string

		// method and path are the request.
		method string
		path   string
	}{
		{name: "requireOperator", method: http.MethodGet, path: "/api/v1/hosts"},
		{name: "requireIdentity", method: http.MethodGet, path: "/api/v1/whoami"},
		{name: "requirePlatform", method: http.MethodGet, path: "/api/v1/tenants"},
		{name: "requireAccount", method: http.MethodGet, path: "/api/v1/account"},
	} {
		t.Run(c.name, func(t *testing.T) {
			status, body := h.adminJSON(t, UnavailableToken, c.method, c.path, nil)
			if status != http.StatusInternalServerError {
				t.Fatalf("%s returned %d during an outage, want 500: %s", c.path, status, body)
			}
			// And it says nothing about the credential — not whether the account exists, not which
			// provider could not answer.
			if bytes.Contains(body, []byte("unauthenticated")) {
				t.Errorf("the outage response reads as a refusal: %s", body)
			}

			// The same route, with a credential that is genuinely wrong, is still one refusal.
			status, body = h.adminJSON(t, "not-a-token-anybody-issued", c.method, c.path, nil)
			if status != http.StatusUnauthorized {
				t.Fatalf("%s returned %d for a wrong credential, want 401: %s", c.path, status, body)
			}
		})
	}
}

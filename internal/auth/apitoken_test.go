package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/store"
)

// tokenFixture is one account holding one API token, and the provider that authenticates it.
type tokenFixture struct {
	// accounts is the fixture the account itself comes from, so a session can be compared against.
	accounts *accountFixture

	// provider is what the tests call.
	provider *APITokens

	// token is the value a script would present.
	token string
}

// newTokenFixture issues one token against the account fixture's operator.
func newTokenFixture(t *testing.T, expiresAt time.Time) *tokenFixture {
	t.Helper()

	f := newAccountFixture(t)
	token, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("generating a token: %v", err)
	}
	err = f.backing.In(f.tenant).CreateAPIToken(context.Background(), store.APIToken{
		Hash:      HashAPIToken(token),
		AccountID: "01JACCOUNT",
		Label:     "continuous integration",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("recording the fixture token: %v", err)
	}
	return &tokenFixture{accounts: f, provider: NewAPITokens(f.backing), token: token}
}

// presenting builds the request a script would make.
func presenting(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// TestAnAPITokenActsAsTheAccountThatIssuedIt is the property the whole design turns on.
//
// A token is the same principal as the person who minted it, because the second-person approval rule is
// a string comparison between the approver's principal and the job creator's. If a token were its own
// principal, an operator under that rule could queue a job in the browser and release it with their own
// token, and the comparison would see two people where there is one.
//
// The credential kind still differs, and that is what the account routes read to refuse a token the
// power to mint another. Two questions — who did this, and what were they holding — and only the first
// is an identity.
func TestAnAPITokenActsAsTheAccountThatIssuedIt(t *testing.T) {
	f := newTokenFixture(t, time.Time{})

	session, cookie := f.accounts.signIn(t, f.accounts.email, f.accounts.password)
	if cookie == nil {
		t.Fatal("the fixture account could not sign in")
	}
	byToken, err := f.provider.Authenticate(context.Background(), presenting(f.token))
	if err != nil {
		t.Fatalf("a valid token did not authenticate: %v", err)
	}

	if byToken.Principal() != session.Principal() {
		t.Errorf("token principal = %q, session principal = %q; they must be the same person",
			byToken.Principal(), session.Principal())
	}
	if byToken.Tenant != session.Tenant {
		t.Errorf("token tenant = %q, session tenant = %q", byToken.Tenant, session.Tenant)
	}
	if byToken.Credential != CredentialAPIToken {
		t.Errorf("credential = %q, want %q", byToken.Credential, CredentialAPIToken)
	}
	if session.Credential != CredentialSession {
		t.Errorf("session credential = %q, want %q", session.Credential, CredentialSession)
	}
	// The label reaches the display and nothing else: an operator reading the interface wants to know
	// it was the CI runner, and the audit trail must not be rewritable by renaming a token.
	if !strings.Contains(byToken.Display, "continuous integration") {
		t.Errorf("display = %q, want the token's label in it", byToken.Display)
	}
	if strings.Contains(byToken.Principal(), "continuous integration") {
		t.Errorf("principal = %q; a label must not reach the principal", byToken.Principal())
	}
}

// TestAnExpiredOrUnknownAPITokenAuthenticatesNobody is the refusal path, and it is one answer.
//
// Expiry is checked against this process's clock rather than the database's, matching every other
// validity window in HostSeal — docs/SECURITY.md treats clock skew as a boundary.
func TestAnExpiredOrUnknownAPITokenAuthenticatesNobody(t *testing.T) {
	past := time.Now().UTC().Add(-time.Minute)
	f := newTokenFixture(t, past)

	for _, c := range []struct {
		// name says which refusal this is.
		name string

		// header is the whole Authorization header, empty for none at all.
		header string
	}{
		{name: "expired", header: "Bearer " + f.token},
		{name: "unknown", header: "Bearer " + APITokenPrefix + "not-a-token-anybody-issued"},
		{name: "wrong scheme", header: "Basic " + f.token},
		{name: "no header", header: ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			if _, err := f.provider.Authenticate(context.Background(), r); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("err = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

// TestATokenThatIsUsedRecordsThatItWas is what makes an unused token visible as unused.
//
// "Which of these six can I revoke" is otherwise a question answered by revoking one and waiting to see
// what breaks. Like a session's renewal it is rate-limited to one write per SessionRenewAfter, because
// nothing reads this value more precisely than that.
func TestATokenThatIsUsedRecordsThatItWas(t *testing.T) {
	f := newTokenFixture(t, time.Time{})

	at := time.Now().UTC().Add(time.Hour)
	f.provider.now = func() time.Time { return at }
	if _, err := f.provider.Authenticate(context.Background(), presenting(f.token)); err != nil {
		t.Fatalf("a valid token did not authenticate: %v", err)
	}

	held, _, err := f.accounts.backing.APITokenByHash(context.Background(), HashAPIToken(f.token))
	if err != nil {
		t.Fatalf("reading the token back: %v", err)
	}
	if !held.LastUsedAt.Equal(at) {
		t.Errorf("last use = %s, want %s", held.LastUsedAt, at)
	}
}

// TestAGeneratedTokenIsPrefixedAndLongEnoughToStoreUnsalted covers both halves of the format.
//
// The prefix is what lets a secret scanner find one pasted into a repository before somebody uses it.
// The length is what makes storing an unsalted SHA-256 correct: there is no dictionary to attack a
// value drawn uniformly from 2^256, which is the same argument the enrolment token makes.
func TestAGeneratedTokenIsPrefixedAndLongEnoughToStoreUnsalted(t *testing.T) {
	token, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("generating a token: %v", err)
	}
	if !strings.HasPrefix(token, APITokenPrefix) {
		t.Errorf("token = %q, want the %q prefix a scanner matches on", token, APITokenPrefix)
	}
	// Base64 of 32 bytes without padding is 43 characters, so the whole is 47.
	if len(token) != len(APITokenPrefix)+43 {
		t.Errorf("token is %d characters, want %d bytes of randomness", len(token), APITokenBytes)
	}

	second, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("generating a second token: %v", err)
	}
	if token == second {
		t.Error("two generated tokens are the same")
	}
}

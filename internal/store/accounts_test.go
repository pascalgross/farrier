package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestAnAccountThatHasNeverSignedInSaysSoInBothStores is the one field the two backends can disagree on.
//
// PostgreSQL has NULL and Go has the zero time, and the obvious bridge — COALESCE to the epoch — is
// wrong in a way nothing else would catch: `IsZero()` is what every caller asks, 1970 is not zero, and
// the symptom is a listing that reports "never signed in" as a date in 1970. It was exactly that until
// somebody ran the command.
func TestAnAccountThatHasNeverSignedInSaysSoInBothStores(t *testing.T) {
	eachScoped(t, func(t *testing.T, _ Store, tenant Scoped) {
		ctx := context.Background()
		if err := tenant.CreateAccount(ctx, Account{
			ID: "01JNEVER", Email: "never@example.org", EmailKey: "email-key-never",
			DisplayName: "Never", PasswordHash: "hash", CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("creating the account: %v", err)
		}

		account, err := tenant.GetAccount(ctx, "01JNEVER")
		if err != nil {
			t.Fatalf("reading it back: %v", err)
		}
		if !account.LastSignedInAt.IsZero() {
			t.Fatalf("an account that has never signed in reports %s", account.LastSignedInAt)
		}

		stamp := time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC)
		if err := tenant.RecordAccountSignIn(ctx, "01JNEVER", stamp); err != nil {
			t.Fatalf("stamping a sign-in: %v", err)
		}
		account, err = tenant.GetAccount(ctx, "01JNEVER")
		if err != nil {
			t.Fatalf("reading it back after the stamp: %v", err)
		}
		if !account.LastSignedInAt.Equal(stamp) {
			t.Fatalf("the stamped sign-in reads back as %s, want %s", account.LastSignedInAt, stamp)
		}
	})
}

// TestASessionOutlivesNothingItShouldNot covers the two lifetimes that make a session revocable.
//
// A sign-in clears that account's expired rows, so the table does not need a sweeper; deleting the
// account takes its live sessions with it, which is the whole answer to "an operator has left". Both
// are asserted through the unscoped resolver, because that is the path a request actually takes — a
// test that looked in the tenant's own listing would prove something no authentication does.
func TestASessionOutlivesNothingItShouldNot(t *testing.T) {
	eachScoped(t, func(t *testing.T, s Store, tenant Scoped) {
		ctx := context.Background()
		now := time.Now().UTC()
		if err := tenant.CreateAccount(ctx, Account{
			ID: "01JSESSIONS", Email: "sessions@example.org", EmailKey: "email-key-sessions",
			PasswordHash: "hash", CreatedAt: now,
		}); err != nil {
			t.Fatalf("creating the account: %v", err)
		}

		// One session that has already expired, and then a fresh sign-in, which must sweep it.
		if err := tenant.CreateSession(ctx, Session{
			TokenHash: "expired", AccountID: "01JSESSIONS",
			CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("creating the expired session: %v", err)
		}
		if err := tenant.CreateSession(ctx, Session{
			TokenHash: "live", AccountID: "01JSESSIONS",
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("creating the live session: %v", err)
		}

		if _, err := s.SessionByToken(ctx, "expired"); !errors.Is(err, ErrNotFound) {
			t.Errorf("the expired session survived the next sign-in: %v", err)
		}
		live, err := s.SessionByToken(ctx, "live")
		if err != nil {
			t.Fatalf("the live session is not resolvable: %v", err)
		}
		if live.TenantID != tenant.Tenant() {
			t.Errorf("the session resolves to tenant %q, want %q", live.TenantID, tenant.Tenant())
		}
		if !live.Valid(now) || live.Valid(now.Add(2*time.Hour)) {
			t.Error("the session's validity window is not what it was created with")
		}

		if err := tenant.DeleteAccount(ctx, "01JSESSIONS"); err != nil {
			t.Fatalf("deleting the account: %v", err)
		}
		if _, err := s.SessionByToken(ctx, "live"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a session survived the account it belonged to: %v", err)
		}
	})
}

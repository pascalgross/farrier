package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// accountColumns is the projection every account read shares.
//
// One constant rather than four copies, so that adding a column is one edit and cannot leave a reader
// scanning a shape the query no longer returns.
const accountColumns = `id, tenant_id, email, email_key, display_name, password_hash, created_at,
	last_signed_in_at`

// scanAccount reads one account row, from either a QueryRow or a Rows.
//
// The interface is the intersection of the two rather than pgx.Row, because ListAccounts scans out of
// pgx.Rows and a second copy of the field order is exactly the kind of duplication that goes wrong
// silently when a column is added in the middle.
//
// A NULL last-sign-in is scanned through a pointer and turned into the zero time, rather than
// COALESCEd to the epoch in SQL. The two are not the same value: Account.LastSignedInAt.IsZero() is
// what every caller asks, and 1970 is not zero — so the shortcut produces a store that reports "never"
// as a date, disagreeing with the in-memory one about a field nothing else would have compared.
func scanAccount(row interface{ Scan(...any) error }) (Account, error) {
	var a Account
	var lastSignedIn *time.Time
	err := row.Scan(&a.ID, &a.TenantID, &a.Email, &a.EmailKey, &a.DisplayName, &a.PasswordHash,
		&a.CreatedAt, &lastSignedIn)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if lastSignedIn != nil {
		a.LastSignedInAt = *lastSignedIn
	}
	return a, wrap(err, "scanning an account")
}

// AccountByEmail returns the operator account an address names, or ErrNotFound.
//
// It runs through withResolveKey rather than withTenant because there is no tenant yet: the request is
// a sign-in form, and this lookup is what discovers which fleet the address belongs to. The policy on
// operator_accounts admits exactly the row whose email_key is named, which is the same single-row
// exemption migration 0004 built for certificates and enrolment tokens.
//
// Returning the password hash is deliberate: this is the one method that does, it is the sign-in path's
// whole reason for calling, and no view or API shape carries the field onwards.
func (p *Postgres) AccountByEmail(ctx context.Context, emailKey string) (Account, error) {
	var a Account
	err := p.withResolveKey(ctx, "looking up an operator account", emailKey, func(tx pgx.Tx) error {
		var scanErr error
		a, scanErr = scanAccount(tx.QueryRow(ctx,
			`SELECT `+accountColumns+` FROM operator_accounts WHERE email_key = $1`, emailKey))
		return scanErr
	})
	if err != nil {
		return Account{}, err
	}
	return a, nil
}

// SessionByToken returns the session a token names, or ErrNotFound.
//
// The operator-side counterpart to LookupCertificate, and written the same way for the same reason: it
// runs on every request a signed-in browser makes, and the row it returns is where that request finds
// out whose data it may touch. Expiry is left to the caller's clock — see Session.Valid.
func (p *Postgres) SessionByToken(ctx context.Context, tokenHash string) (Session, error) {
	var s Session
	err := p.withResolveKey(ctx, "looking up a session", tokenHash, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx, `
			SELECT token_hash, tenant_id, account_id, created_at, expires_at
			  FROM operator_sessions
			 WHERE token_hash = $1`, tokenHash,
		).Scan(&s.TokenHash, &s.TenantID, &s.AccountID, &s.CreatedAt, &s.ExpiresAt)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return wrap(scanErr, "scanning a session")
	})
	if err != nil {
		return Session{}, err
	}
	return s, nil
}

// CreateAccount records a new operator account, or ErrConflict if the address is taken.
func (s *scopedPostgres) CreateAccount(ctx context.Context, a Account) error {
	return s.withTenant(ctx, "creating an operator account", func(tx pgx.Tx) error {
		var createdAt *time.Time
		if !a.CreatedAt.IsZero() {
			createdAt = &a.CreatedAt
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO operator_accounts
			       (id, tenant_id, email, email_key, display_name, password_hash, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::timestamptz, now()))`,
			a.ID, string(s.tenant), a.Email, a.EmailKey, a.DisplayName, a.PasswordHash, createdAt)
		// wrap turns a unique violation into ErrConflict, which here is an address already in use —
		// possibly by another fleet, because operator_accounts_email is unique across the installation.
		return wrap(err, "inserting an operator account")
	})
}

// GetAccount returns one of this fleet's accounts by id, or ErrNotFound.
func (s *scopedPostgres) GetAccount(ctx context.Context, id string) (Account, error) {
	var a Account
	err := s.withTenant(ctx, "reading an operator account", func(tx pgx.Tx) error {
		var scanErr error
		a, scanErr = scanAccount(tx.QueryRow(ctx,
			`SELECT `+accountColumns+` FROM operator_accounts WHERE id = $1 AND tenant_id = $2`,
			id, string(s.tenant)))
		return scanErr
	})
	if err != nil {
		return Account{}, err
	}
	return a, nil
}

// ListAccounts returns this fleet's accounts, oldest first.
//
// The id breaks ties, so that two accounts created in the same transaction do not swap places between
// listings for a reason nobody can see — the same tiebreak ListTenants uses.
func (s *scopedPostgres) ListAccounts(ctx context.Context) ([]Account, error) {
	var out []Account
	err := s.withTenant(ctx, "listing operator accounts", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+accountColumns+` FROM operator_accounts
			  WHERE tenant_id = $1 ORDER BY created_at, id`, string(s.tenant))
		if err != nil {
			return wrap(err, "listing operator accounts")
		}
		defer rows.Close()

		for rows.Next() {
			a, scanErr := scanAccount(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, a)
		}
		return wrap(rows.Err(), "listing operator accounts")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateAccountPassword replaces one account's password hash, or returns ErrNotFound.
func (s *scopedPostgres) UpdateAccountPassword(ctx context.Context, id, passwordHash string) error {
	return s.withTenant(ctx, "changing an operator's password", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE operator_accounts SET password_hash = $3
			 WHERE id = $1 AND tenant_id = $2`, id, string(s.tenant), passwordHash)
		if err != nil {
			return wrap(err, "changing an operator's password")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// RecordAccountSignIn stamps when an account last signed in, or returns ErrNotFound.
func (s *scopedPostgres) RecordAccountSignIn(ctx context.Context, id string, at time.Time) error {
	return s.withTenant(ctx, "recording a sign-in", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE operator_accounts SET last_signed_in_at = $3
			 WHERE id = $1 AND tenant_id = $2`, id, string(s.tenant), at)
		if err != nil {
			return wrap(err, "recording a sign-in")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// DeleteAccount removes an account and every session it holds, or returns ErrNotFound.
//
// The sessions go by the schema's ON DELETE CASCADE rather than by a second statement here, so that
// the two cannot come apart under a failure between them.
func (s *scopedPostgres) DeleteAccount(ctx context.Context, id string) error {
	return s.withTenant(ctx, "deleting an operator account", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM operator_accounts WHERE id = $1 AND tenant_id = $2`, id, string(s.tenant))
		if err != nil {
			return wrap(err, "deleting an operator account")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// CreateSession records a signed-in browser and clears that account's expired sessions.
//
// One transaction for both, so a sign-in either produces a usable session and a tidy table or changes
// nothing. The sweep is scoped to the account rather than to the fleet: a sign-in should not pay for
// however many colleagues have stale rows, and the account signing in is the one whose rows are certain
// to be reachable cheaply through operator_sessions_account.
func (s *scopedPostgres) CreateSession(ctx context.Context, session Session) error {
	return s.withTenant(ctx, "recording a session", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			DELETE FROM operator_sessions
			 WHERE tenant_id = $1 AND account_id = $2 AND expires_at <= $3`,
			string(s.tenant), session.AccountID, session.CreatedAt,
		); err != nil {
			return wrap(err, "clearing expired sessions")
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO operator_sessions (token_hash, tenant_id, account_id, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5)`,
			session.TokenHash, string(s.tenant), session.AccountID, session.CreatedAt,
			session.ExpiresAt)
		return wrap(err, "recording a session")
	})
}

// DeleteSession ends one session, whether or not it had expired.
//
// A token naming no row is not an error: a second sign-out, or a sign-out of a session that had already
// expired, is not a failure the caller should have to tell apart from success.
func (s *scopedPostgres) DeleteSession(ctx context.Context, tokenHash string) error {
	return s.withTenant(ctx, "ending a session", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM operator_sessions WHERE token_hash = $1 AND tenant_id = $2`,
			tokenHash, string(s.tenant))
		return wrap(err, "ending a session")
	})
}

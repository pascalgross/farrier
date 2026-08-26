package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// accountColumns is the projection every account read shares.
//
// One constant rather than five copies, so that adding a column is one edit and cannot leave a reader
// scanning a shape the query no longer returns.
const accountColumns = `id, tenant_id, email, email_key, display_name, password_hash, created_at,
	last_signed_in_at`

// sessionColumns is the projection every session read shares, for the same reason.
const sessionColumns = `token_hash, account_id, created_at, expires_at, last_used_at, user_agent, source`

// apiTokenColumns is the projection every API-token read shares.
const apiTokenColumns = `hash, account_id, label, created_at, expires_at, last_used_at`

// rowScanner is the intersection of pgx.Row and pgx.Rows.
//
// The scan helpers below take it rather than pgx.Row because the listings scan out of pgx.Rows, and a
// second copy of a field order is exactly the kind of duplication that goes wrong silently when a
// column is added in the middle.
type rowScanner interface {
	// Scan reads one row into the given destinations.
	Scan(dest ...any) error
}

// scanAccount reads one account row.
//
// Two nullable columns come through pointers and become zero values, rather than being COALESCEd in
// SQL. A NULL tenant is what makes an account the installation's own administrator, and a NULL
// last-sign-in means never — and `IsZero()` is what every caller asks, so COALESCE to `epoch` would
// produce a store that reports "never" as a date in 1970 and disagrees with the in-memory one about a
// field nothing else would have compared. It did, until somebody ran the command.
func scanAccount(row rowScanner) (Account, error) {
	var a Account
	var tenant *string
	var lastSignedIn *time.Time
	err := row.Scan(&a.ID, &tenant, &a.Email, &a.EmailKey, &a.DisplayName, &a.PasswordHash,
		&a.CreatedAt, &lastSignedIn)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if tenant != nil {
		a.TenantID = TenantID(*tenant)
	}
	if lastSignedIn != nil {
		a.LastSignedInAt = *lastSignedIn
	}
	return a, wrap(err, "scanning an account")
}

// scanSession reads one session row.
func scanSession(row rowScanner) (Session, error) {
	var held Session
	var lastUsed *time.Time
	err := row.Scan(&held.TokenHash, &held.AccountID, &held.CreatedAt, &held.ExpiresAt,
		&lastUsed, &held.UserAgent, &held.Source)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if lastUsed != nil {
		held.LastUsedAt = *lastUsed
	}
	return held, wrap(err, "scanning a session")
}

// scanAPIToken reads one API-token row.
func scanAPIToken(row rowScanner) (APIToken, error) {
	var held APIToken
	var expires, lastUsed *time.Time
	err := row.Scan(&held.Hash, &held.AccountID, &held.Label, &held.CreatedAt, &expires, &lastUsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIToken{}, ErrNotFound
	}
	if expires != nil {
		held.ExpiresAt = *expires
	}
	if lastUsed != nil {
		held.LastUsedAt = *lastUsed
	}
	return held, wrap(err, "scanning an API token")
}

// Platform returns the accounts of the installation's own administrators.
//
// The handle is cheap on purpose — a pointer and an empty tenant — because it is made per request, and
// it differs from the tenant one only in which session setting its transactions carry.
func (p *Postgres) Platform() AccountScope { return &scopedPostgres{p: p} }

// withScope runs fn inside a transaction that has said which side of the tenant boundary it is on.
//
// One helper for both sides, because the difference is one set_config and two almost-identical helpers
// are how they eventually stop being identical. A handle with a tenant sets farrier.tenant and matches
// that fleet's rows; a handle without one sets farrier.platform and matches the rows that have no
// tenant. Neither can reach the other's: `NULL = 'anything'` is NULL rather than true, and a platform
// transaction names no tenant to compare against.
//
// LOCAL is the load-bearing word in both, for the reason withTenant gives: a session-level setting on a
// pooled connection would be inherited by whichever request borrowed it next.
func (s *scopedPostgres) withScope(ctx context.Context, what string, fn func(pgx.Tx) error) error {
	if s.tenant != "" {
		return s.withTenant(ctx, what, fn)
	}

	tx, err := s.p.pool.Begin(ctx)
	if err != nil {
		return wrap(err, what)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT set_config('farrier.platform', 'on', true)`); err != nil {
		return wrap(err, "naming the platform side while "+what)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return wrap(tx.Commit(ctx), what)
}

// withAccount runs fn inside a scoped transaction, having established that the account is this side's.
//
// The account id arrives from outside — a URL segment, a session row, a form — so the first thing done
// with it is to ask the database whether this handle may see the account at all. Under the scope set
// above, the accounts policy admits only this fleet's rows or only the installation's own, so no row
// means the account belongs to somebody else or to nobody, and both are ErrNotFound. That is the same
// answer GetAccount gives, deliberately: a fleet learning which of two ids exists elsewhere is a
// disclosure, however small.
//
// The lookup is not what keeps the credentials safe — migration 0010's policies do that, by making a
// session visible exactly when its account is, so that a method written later cannot leak by omission.
// This is here so the *answer* is right: without it, listing another fleet's sessions would return an
// empty slice rather than a refusal, and revoking their token would report success.
func (s *scopedPostgres) withAccount(ctx context.Context, what, accountID string, fn func(pgx.Tx) error) error {
	return s.withScope(ctx, what, func(tx pgx.Tx) error {
		var held int
		err := tx.QueryRow(ctx, `SELECT 1 FROM accounts WHERE id = $1`, accountID).Scan(&held)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return wrap(err, "finding whose account it is while "+what)
		}
		return fn(tx)
	})
}

// AccountByEmail returns the account an address names, or ErrNotFound.
//
// It runs through withResolveKey rather than withScope because there is no side yet: the request is a
// sign-in form, and this lookup is what discovers whether the address belongs to a fleet or to the
// installation. The policy admits exactly the row whose email_key is named, which is the same
// single-row exemption migration 0004 built for certificates and enrolment tokens.
//
// Returning the password hash is deliberate: this is the one method that does, it is the sign-in path's
// whole reason for calling, and no view or API shape carries the field onwards.
func (p *Postgres) AccountByEmail(ctx context.Context, emailKey string) (Account, error) {
	var a Account
	err := p.withResolveKey(ctx, "looking up an account", emailKey, func(tx pgx.Tx) error {
		var scanErr error
		a, scanErr = scanAccount(tx.QueryRow(ctx,
			`SELECT `+accountColumns+` FROM accounts WHERE email_key = $1`, emailKey))
		return scanErr
	})
	if err != nil {
		return Account{}, err
	}
	return a, nil
}

// SessionByToken returns a session and the account it belongs to, or ErrNotFound.
//
// Two statements in one transaction, with the resolve key set twice: the first names the session token
// the caller presented, the second names the account id the first produced. Both are keys reachable
// only by having got past the one before, which is what keeps the exemption a row wide.
//
// One transaction rather than two calls because the pair is one question, and because a session deleted
// between them would produce an account with no session — a state no caller has a branch for.
func (p *Postgres) SessionByToken(ctx context.Context, tokenHash string) (Session, Account, error) {
	var session Session
	var account Account
	err := p.withResolveKey(ctx, "looking up a session", tokenHash, func(tx pgx.Tx) error {
		var scanErr error
		session, scanErr = scanSession(tx.QueryRow(ctx,
			`SELECT `+sessionColumns+` FROM sessions WHERE token_hash = $1`, tokenHash))
		if scanErr != nil {
			return scanErr
		}
		account, scanErr = resolveAccount(ctx, tx, session.AccountID)
		return scanErr
	})
	if err != nil {
		return Session{}, Account{}, err
	}
	return session, account, nil
}

// APITokenByHash returns a token and the account it belongs to, or ErrNotFound.
//
// The same shape as SessionByToken and for the same reason. Usability is not checked here: the caller
// checks it against its own clock, matching every other validity window in Farrier.
func (p *Postgres) APITokenByHash(ctx context.Context, hash string) (APIToken, Account, error) {
	var token APIToken
	var account Account
	err := p.withResolveKey(ctx, "looking up an API token", hash, func(tx pgx.Tx) error {
		var scanErr error
		token, scanErr = scanAPIToken(tx.QueryRow(ctx,
			`SELECT `+apiTokenColumns+` FROM api_tokens WHERE hash = $1`, hash))
		if scanErr != nil {
			return scanErr
		}
		account, scanErr = resolveAccount(ctx, tx, token.AccountID)
		return scanErr
	})
	if err != nil {
		return APIToken{}, Account{}, err
	}
	return token, account, nil
}

// resolveAccount reads the account a credential named, inside the transaction that resolved it.
//
// It re-points farrier.resolve_key at the account id, which the policy admits for the same reason it
// admits a certificate fingerprint: 128 bits generated here, holdable only by whoever already got past
// the credential that produced it.
func resolveAccount(ctx context.Context, tx pgx.Tx, accountID string) (Account, error) {
	if _, err := tx.Exec(ctx,
		`SELECT set_config('farrier.resolve_key', $1, true)`, accountID,
	); err != nil {
		return Account{}, wrap(err, "naming the account behind a credential")
	}
	return scanAccount(tx.QueryRow(ctx,
		`SELECT `+accountColumns+` FROM accounts WHERE id = $1`, accountID))
}

// CreateAccount records a new account, or ErrConflict if the address is taken.
func (s *scopedPostgres) CreateAccount(ctx context.Context, a Account) error {
	return s.withScope(ctx, "creating an account", func(tx pgx.Tx) error {
		var createdAt *time.Time
		if !a.CreatedAt.IsZero() {
			createdAt = &a.CreatedAt
		}
		// A platform account's tenant is NULL rather than the empty string, and the difference is
		// load-bearing: the policy admits `tenant_id IS NULL`, and an empty string is a tenant id no
		// tenant has — so the row would be written and then unreachable from either side.
		var tenant *string
		if s.tenant != "" {
			id := string(s.tenant)
			tenant = &id
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO accounts
			       (id, tenant_id, email, email_key, display_name, password_hash, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::timestamptz, now()))`,
			a.ID, tenant, a.Email, a.EmailKey, a.DisplayName, a.PasswordHash, createdAt)
		// wrap turns a unique violation into ErrConflict, which here is an address already in use —
		// possibly by another fleet, because the index on email_key spans the installation.
		return wrap(err, "inserting an account")
	})
}

// GetAccount returns one of this side's accounts by id, or ErrNotFound.
func (s *scopedPostgres) GetAccount(ctx context.Context, id string) (Account, error) {
	var a Account
	err := s.withScope(ctx, "reading an account", func(tx pgx.Tx) error {
		var scanErr error
		a, scanErr = scanAccount(tx.QueryRow(ctx,
			`SELECT `+accountColumns+` FROM accounts WHERE id = $1`, id))
		return scanErr
	})
	if err != nil {
		return Account{}, err
	}
	return a, nil
}

// ListAccounts returns this side's accounts, oldest first.
//
// The id breaks ties, so that two accounts created in the same transaction do not swap places between
// listings for a reason nobody can see — the same tiebreak ListTenants uses.
func (s *scopedPostgres) ListAccounts(ctx context.Context) ([]Account, error) {
	var out []Account
	err := s.withScope(ctx, "listing accounts", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+accountColumns+` FROM accounts ORDER BY created_at, id`)
		if err != nil {
			return wrap(err, "listing accounts")
		}
		defer rows.Close()

		for rows.Next() {
			a, scanErr := scanAccount(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, a)
		}
		return wrap(rows.Err(), "listing accounts")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateAccountPassword replaces one account's password hash, or returns ErrNotFound.
func (s *scopedPostgres) UpdateAccountPassword(ctx context.Context, id, passwordHash string) error {
	return s.withScope(ctx, "changing a password", func(tx pgx.Tx) error {
		return affectOne(tx.Exec(ctx,
			`UPDATE accounts SET password_hash = $2 WHERE id = $1`, id, passwordHash))
	})
}

// RecordAccountSignIn stamps when an account last signed in, or returns ErrNotFound.
func (s *scopedPostgres) RecordAccountSignIn(ctx context.Context, id string, at time.Time) error {
	return s.withScope(ctx, "recording a sign-in", func(tx pgx.Tx) error {
		return affectOne(tx.Exec(ctx,
			`UPDATE accounts SET last_signed_in_at = $2 WHERE id = $1`, id, at))
	})
}

// DeleteAccount removes an account and every credential it holds, or returns ErrNotFound.
//
// Sessions and API tokens go by the schema's ON DELETE CASCADE rather than by two more statements
// here, so that they cannot come apart under a failure between them.
func (s *scopedPostgres) DeleteAccount(ctx context.Context, id string) error {
	return s.withScope(ctx, "deleting an account", func(tx pgx.Tx) error {
		return affectOne(tx.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, id))
	})
}

// CreateSession records a signed-in browser and clears that account's expired sessions.
//
// One transaction for both, so a sign-in either produces a usable session and a tidy table or changes
// nothing. The sweep is scoped to the account rather than to the installation: a sign-in should not pay
// for however many colleagues have stale rows.
func (s *scopedPostgres) CreateSession(ctx context.Context, session Session) error {
	return s.withAccount(ctx, "recording a session", session.AccountID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM sessions WHERE account_id = $1 AND expires_at <= $2`,
			session.AccountID, session.CreatedAt,
		); err != nil {
			return wrap(err, "clearing expired sessions")
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO sessions (token_hash, account_id, created_at, expires_at, user_agent, source)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			session.TokenHash, session.AccountID, session.CreatedAt, session.ExpiresAt,
			session.UserAgent, session.Source)
		return wrap(err, "recording a session")
	})
}

// ListSessions returns one account's sessions, newest first.
func (s *scopedPostgres) ListSessions(ctx context.Context, accountID string) ([]Session, error) {
	var out []Session
	err := s.withAccount(ctx, "listing sessions", accountID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+sessionColumns+` FROM sessions WHERE account_id = $1
			  ORDER BY created_at DESC, token_hash`, accountID)
		if err != nil {
			return wrap(err, "listing sessions")
		}
		defer rows.Close()

		for rows.Next() {
			held, scanErr := scanSession(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, held)
		}
		return wrap(rows.Err(), "listing sessions")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TouchSession extends one session and records that it was used.
func (s *scopedPostgres) TouchSession(ctx context.Context, accountID, tokenHash string, expiresAt, usedAt time.Time) error {
	return s.withAccount(ctx, "extending a session", accountID, func(tx pgx.Tx) error {
		return affectOne(tx.Exec(ctx,
			`UPDATE sessions SET expires_at = $3, last_used_at = $4
			  WHERE token_hash = $1 AND account_id = $2`, tokenHash, accountID, expiresAt, usedAt))
	})
}

// DeleteSession ends one session, whether or not it had expired.
//
// A token naming no row is not an error, and that silence is narrower than it looks: withAccount has
// already refused an account this handle does not hold, so what is being forgiven here is only a token
// that has already gone. Sign-out is idempotent — an expired session is swept by the next sign-in, and
// the browser still holding its cookie must be able to sign out afterwards.
func (s *scopedPostgres) DeleteSession(ctx context.Context, accountID, tokenHash string) error {
	return s.withAccount(ctx, "ending a session", accountID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM sessions WHERE token_hash = $1 AND account_id = $2`, tokenHash, accountID)
		return wrap(err, "ending a session")
	})
}

// DeleteSessionsFor ends every session one account holds, and reports how many.
func (s *scopedPostgres) DeleteSessionsFor(ctx context.Context, accountID string) (int, error) {
	var ended int
	err := s.withAccount(ctx, "ending every session", accountID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE account_id = $1`, accountID)
		if err != nil {
			return wrap(err, "ending every session")
		}
		ended = int(tag.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return ended, nil
}

// CreateAPIToken records a token belonging to one account.
func (s *scopedPostgres) CreateAPIToken(ctx context.Context, t APIToken) error {
	return s.withAccount(ctx, "recording an API token", t.AccountID, func(tx pgx.Tx) error {
		var expires *time.Time
		if !t.ExpiresAt.IsZero() {
			expires = &t.ExpiresAt
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO api_tokens (hash, account_id, label, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5)`, t.Hash, t.AccountID, t.Label, t.CreatedAt, expires)
		return wrap(err, "recording an API token")
	})
}

// ListAPITokens returns one account's tokens, newest first.
func (s *scopedPostgres) ListAPITokens(ctx context.Context, accountID string) ([]APIToken, error) {
	var out []APIToken
	err := s.withAccount(ctx, "listing API tokens", accountID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+apiTokenColumns+` FROM api_tokens WHERE account_id = $1
			  ORDER BY created_at DESC, hash`, accountID)
		if err != nil {
			return wrap(err, "listing API tokens")
		}
		defer rows.Close()

		for rows.Next() {
			held, scanErr := scanAPIToken(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, held)
		}
		return wrap(rows.Err(), "listing API tokens")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TouchAPIToken records that a token was used, or returns ErrNotFound.
func (s *scopedPostgres) TouchAPIToken(ctx context.Context, accountID, hash string, usedAt time.Time) error {
	return s.withAccount(ctx, "recording an API token's use", accountID, func(tx pgx.Tx) error {
		return affectOne(tx.Exec(ctx,
			`UPDATE api_tokens SET last_used_at = $3 WHERE hash = $1 AND account_id = $2`,
			hash, accountID, usedAt))
	})
}

// DeleteAPIToken revokes one token, or returns ErrNotFound.
func (s *scopedPostgres) DeleteAPIToken(ctx context.Context, accountID, hash string) error {
	return s.withAccount(ctx, "revoking an API token", accountID, func(tx pgx.Tx) error {
		return affectOne(tx.Exec(ctx,
			`DELETE FROM api_tokens WHERE hash = $1 AND account_id = $2`, hash, accountID))
	})
}

// affectOne turns a command tag into ErrNotFound when it changed nothing.
//
// Written once because nine statements here want it, and nine hand-written copies would eventually
// include one that reported success for a row that was not there — which for a password change or a
// revocation is precisely the failure that matters.
func affectOne(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return wrap(err, "applying a change")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

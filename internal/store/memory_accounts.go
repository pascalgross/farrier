package store

import (
	"context"
	"sort"
	"time"
)

// Platform returns the accounts of the installation's own administrators.
//
// A handle with no tenant, which is the same thing the record means by an empty TenantID. It is the
// in-memory expression of migration 0010's policy: a row with no tenant is unreachable from any fleet's
// handle, and this is the only door to it.
func (m *Memory) Platform() AccountScope { return &scopedMemory{store: m} }

// AccountByEmail returns the account an address names, or ErrNotFound.
//
// On *Memory rather than on a handle, matching the interface and matching PostgreSQL: it is the lookup
// that discovers which side of the boundary an address belongs to, so it cannot be behind a handle that
// requires already knowing. The address is unique across the store, which is the in-memory expression
// of the unique index migration 0009 put on email_key and 0010 kept.
func (m *Memory) AccountByEmail(_ context.Context, emailKey string) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, a := range m.accounts {
		if a.EmailKey == emailKey {
			return a, nil
		}
	}
	return Account{}, ErrNotFound
}

// SessionByToken returns a session and the account it belongs to, or ErrNotFound.
//
// Expiry is deliberately not checked. The caller checks it against its own clock — see Session.Valid —
// and a store that quietly refused an expired row would make the two implementations disagree about
// which layer owns the window.
//
// A session whose account has gone is ErrNotFound rather than a session with no account, because the
// schema's ON DELETE CASCADE means the pair cannot come apart there and a caller with a branch for it
// would be carrying a branch PostgreSQL can never take.
func (m *Memory) SessionByToken(_ context.Context, tokenHash string) (Session, Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	held, ok := m.sessions[tokenHash]
	if !ok {
		return Session{}, Account{}, ErrNotFound
	}
	account, ok := m.accounts[held.AccountID]
	if !ok {
		return Session{}, Account{}, ErrNotFound
	}
	return held, account, nil
}

// APITokenByHash returns a token and the account it belongs to, or ErrNotFound.
func (m *Memory) APITokenByHash(_ context.Context, hash string) (APIToken, Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	held, ok := m.apiTokens[hash]
	if !ok {
		return APIToken{}, Account{}, ErrNotFound
	}
	account, ok := m.accounts[held.AccountID]
	if !ok {
		return APIToken{}, Account{}, ErrNotFound
	}
	return held, account, nil
}

// CreateAccount records a new account, or ErrConflict if the address is taken.
//
// The address is checked across every side, not only this one, because the schema's unique index is on
// email_key alone. A per-side check here would let a memory-backed test create two accounts PostgreSQL
// would refuse, which is the sort of divergence that makes a green suite mean less.
func (s *scopedMemory) CreateAccount(_ context.Context, a Account) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if s.tenant != "" {
		if _, ok := m.tenants[s.tenant]; !ok {
			return errUnknownTenant(s.tenant)
		}
	}
	if _, exists := m.accounts[a.ID]; exists {
		return ErrConflict
	}
	for _, held := range m.accounts {
		if held.EmailKey == a.EmailKey {
			return ErrConflict
		}
	}
	a.TenantID = s.tenant
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	m.accounts[a.ID] = a
	return nil
}

// GetAccount returns one of this side's accounts by id, or ErrNotFound.
func (s *scopedMemory) GetAccount(_ context.Context, id string) (Account, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	a, ok := s.account(id)
	if !ok {
		return Account{}, ErrNotFound
	}
	return a, nil
}

// ListAccounts returns this side's accounts, oldest first.
//
// The id breaks ties. Two accounts created in the same clock tick is what a seeding script produces,
// and map order would otherwise make the listing flake.
func (s *scopedMemory) ListAccounts(_ context.Context) ([]Account, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	out := make([]Account, 0, len(s.store.accounts))
	for _, a := range s.store.accounts {
		if a.TenantID != s.tenant {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// UpdateAccountPassword replaces one account's password hash, or returns ErrNotFound.
func (s *scopedMemory) UpdateAccountPassword(_ context.Context, id, passwordHash string) error {
	return s.updateAccount(id, func(a *Account) { a.PasswordHash = passwordHash })
}

// RecordAccountSignIn stamps when an account last signed in, or returns ErrNotFound.
func (s *scopedMemory) RecordAccountSignIn(_ context.Context, id string, at time.Time) error {
	return s.updateAccount(id, func(a *Account) { a.LastSignedInAt = at })
}

// account returns an account if it exists on this handle's side. The caller holds the lock.
//
// Every account read goes through it so that "belongs to the other side of the boundary" and "does not
// exist" are one answer written once. Two spellings of that check would eventually disagree, and the
// one that disagreed by returning the row would be handing over a credential.
func (s *scopedMemory) account(id string) (Account, bool) {
	a, ok := s.store.accounts[id]
	if !ok || a.TenantID != s.tenant {
		return Account{}, false
	}
	return a, true
}

// updateAccount applies a mutation to one of this side's accounts, under the lock.
//
// Every write to an account goes through it, so the boundary check is written once and cannot be the
// one a new method forgets — which matters more here than for a host, because the row is a credential.
func (s *scopedMemory) updateAccount(id string, apply func(*Account)) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := s.account(id)
	if !ok {
		return ErrNotFound
	}
	apply(&a)
	m.accounts[id] = a
	return nil
}

// DeleteAccount removes an account and every credential it holds, or returns ErrNotFound.
//
// The two sweeps stand in for the schema's ON DELETE CASCADEs. Leaving either behind would be a
// credential naming an account that no longer exists, which is the one way deleting an operator can
// fail to end their access.
func (s *scopedMemory) DeleteAccount(_ context.Context, id string) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := s.account(id); !ok {
		return ErrNotFound
	}
	delete(m.accounts, id)
	for hash, held := range m.sessions {
		if held.AccountID == id {
			delete(m.sessions, hash)
		}
	}
	for hash, held := range m.apiTokens {
		if held.AccountID == id {
			delete(m.apiTokens, hash)
		}
	}
	return nil
}

// CreateSession records a signed-in browser and clears that account's expired sessions.
//
// The single mutex gives both halves the atomicity PostgreSQL gets from one transaction: a sign-in
// either produces a usable session and a tidy table, or changes nothing.
func (s *scopedMemory) CreateSession(_ context.Context, session Session) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := s.account(session.AccountID); !ok {
		// Migration 0010's WITH CHECK, expressed in Go: a session may be written only against an
		// account this handle can see. Unreachable and non-existent are one answer, as everywhere on
		// this boundary — the shipped store cannot tell them apart either, because the policy hides
		// the row before the foreign key ever looks at it.
		return ErrNotFound
	}
	for hash, held := range m.sessions {
		if held.AccountID == session.AccountID && !held.Valid(session.CreatedAt) {
			delete(m.sessions, hash)
		}
	}
	m.sessions[session.TokenHash] = session
	return nil
}

// ListSessions returns one account's sessions, newest first.
func (s *scopedMemory) ListSessions(_ context.Context, accountID string) ([]Session, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	if _, ok := s.account(accountID); !ok {
		return nil, ErrNotFound
	}
	var out []Session
	for _, held := range s.store.sessions {
		if held.AccountID == accountID {
			out = append(out, held)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].TokenHash < out[j].TokenHash
	})
	return out, nil
}

// TouchSession extends one session and records that it was used.
func (s *scopedMemory) TouchSession(_ context.Context, accountID, tokenHash string, expiresAt, usedAt time.Time) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := s.account(accountID); !ok {
		return ErrNotFound
	}
	held, ok := m.sessions[tokenHash]
	if !ok || held.AccountID != accountID {
		return ErrNotFound
	}
	held.ExpiresAt = expiresAt
	held.LastUsedAt = usedAt
	m.sessions[tokenHash] = held
	return nil
}

// DeleteSession ends one session, whether or not it had expired.
//
// An account on the other side of the boundary is ErrNotFound, like every other method here. A token
// naming no row is not an error, and the difference between the two is the point: sign-out has to work
// for a credential that no longer authenticates, because an expired session is swept by the next
// sign-in while the browser still holds its cookie. So the silence covers a token that has gone, and
// nothing else.
func (s *scopedMemory) DeleteSession(_ context.Context, accountID, tokenHash string) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := s.account(accountID); !ok {
		return ErrNotFound
	}
	if held, ok := m.sessions[tokenHash]; ok && held.AccountID == accountID {
		delete(m.sessions, tokenHash)
	}
	return nil
}

// DeleteSessionsFor ends every session one account holds, and reports how many.
func (s *scopedMemory) DeleteSessionsFor(_ context.Context, accountID string) (int, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := s.account(accountID); !ok {
		return 0, ErrNotFound
	}
	ended := 0
	for hash, held := range m.sessions {
		if held.AccountID == accountID {
			delete(m.sessions, hash)
			ended++
		}
	}
	return ended, nil
}

// CreateAPIToken records a token belonging to one account.
func (s *scopedMemory) CreateAPIToken(_ context.Context, t APIToken) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := s.account(t.AccountID); !ok {
		return ErrNotFound
	}
	if _, exists := m.apiTokens[t.Hash]; exists {
		return ErrConflict
	}
	m.apiTokens[t.Hash] = t
	return nil
}

// ListAPITokens returns one account's tokens, newest first.
func (s *scopedMemory) ListAPITokens(_ context.Context, accountID string) ([]APIToken, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	if _, ok := s.account(accountID); !ok {
		return nil, ErrNotFound
	}
	var out []APIToken
	for _, held := range s.store.apiTokens {
		if held.AccountID == accountID {
			out = append(out, held)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Hash < out[j].Hash
	})
	return out, nil
}

// TouchAPIToken records that a token was used, or returns ErrNotFound.
func (s *scopedMemory) TouchAPIToken(_ context.Context, accountID, hash string, usedAt time.Time) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := s.account(accountID); !ok {
		return ErrNotFound
	}
	held, ok := m.apiTokens[hash]
	if !ok || held.AccountID != accountID {
		return ErrNotFound
	}
	held.LastUsedAt = usedAt
	m.apiTokens[hash] = held
	return nil
}

// DeleteAPIToken revokes one token, or returns ErrNotFound.
//
// ErrNotFound rather than silence, unlike DeleteSession: revoking a token is a deliberate act aimed at
// a row somebody is looking at, so "there was nothing there" is information they want.
func (s *scopedMemory) DeleteAPIToken(_ context.Context, accountID, hash string) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := s.account(accountID); !ok {
		return ErrNotFound
	}
	held, ok := m.apiTokens[hash]
	if !ok || held.AccountID != accountID {
		return ErrNotFound
	}
	delete(m.apiTokens, hash)
	return nil
}

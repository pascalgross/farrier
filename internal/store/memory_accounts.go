package store

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// accountKey identifies one operator account the way the schema does, by tenant and id.
//
// The tenant is in the key rather than in a check the caller remembers to make, for the same reason
// jobKey carries one. Account ids are generated here from the same 128 bits of randomness host ids use,
// so a collision is not the worry; the worry is a scoped method that reaches a row by id alone and
// therefore reaches somebody else's operator.
type accountKey struct {
	// tenant owns the account.
	tenant TenantID

	// id is the account's own identifier.
	id string
}

// AccountByEmail returns the operator account an address names, or ErrNotFound.
//
// On *Memory rather than on the handle, matching the interface and matching PostgreSQL: it is the
// lookup that discovers which fleet an address belongs to, so it cannot be scoped to one. The address
// key is unique across the store, which is the in-memory expression of the unique index migration 0009
// puts on email_key.
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

// SessionByToken returns the session a token names, or ErrNotFound.
//
// Expiry is deliberately not checked here. The caller checks it against its own clock — see
// Session.Valid — and a store that quietly refused an expired row would make the two implementations
// disagree about which layer owns the window.
func (m *Memory) SessionByToken(_ context.Context, tokenHash string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[tokenHash]
	if !ok {
		return Session{}, ErrNotFound
	}
	return s, nil
}

// CreateAccount records a new operator account, or ErrConflict if the address is taken.
//
// The address is checked across every tenant, not only this one, because the schema's unique index is
// on email_key alone. A per-tenant check here would let a memory-backed test create two accounts that
// PostgreSQL would refuse, which is the sort of divergence that makes a green test suite mean less.
func (s *scopedMemory) CreateAccount(_ context.Context, a Account) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.tenants[s.tenant]; !ok {
		return errUnknownTenant(s.tenant)
	}
	key := accountKey{tenant: s.tenant, id: a.ID}
	if _, exists := m.accounts[key]; exists {
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
	m.accounts[key] = a
	return nil
}

// GetAccount returns one of this fleet's accounts by id, or ErrNotFound.
func (s *scopedMemory) GetAccount(_ context.Context, id string) (Account, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	a, ok := s.store.accounts[accountKey{tenant: s.tenant, id: id}]
	if !ok {
		return Account{}, ErrNotFound
	}
	return a, nil
}

// ListAccounts returns this fleet's accounts, oldest first.
//
// The id breaks ties. Two accounts created in the same clock tick is what a seeding script produces,
// and map order would otherwise make the listing flake.
func (s *scopedMemory) ListAccounts(_ context.Context) ([]Account, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	out := make([]Account, 0, len(s.store.accounts))
	for key, a := range s.store.accounts {
		if key.tenant != s.tenant {
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

// updateAccount applies a mutation to one of this tenant's accounts, under the lock.
//
// Every write to an account goes through it, so the tenant check is written once and cannot be the one
// a new method forgets — the same reasoning as the host `update` helper, and it matters more here
// because the row being written is a credential.
func (s *scopedMemory) updateAccount(id string, apply func(*Account)) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	key := accountKey{tenant: s.tenant, id: id}
	a, ok := m.accounts[key]
	if !ok {
		return ErrNotFound
	}
	apply(&a)
	m.accounts[key] = a
	return nil
}

// DeleteAccount removes an account and every session it holds, or returns ErrNotFound.
//
// The session sweep stands in for the schema's ON DELETE CASCADE. Leaving one behind would be a
// credential naming an account that no longer exists, which is the one way deleting an operator can
// fail to end their access.
func (s *scopedMemory) DeleteAccount(_ context.Context, id string) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	key := accountKey{tenant: s.tenant, id: id}
	if _, ok := m.accounts[key]; !ok {
		return ErrNotFound
	}
	delete(m.accounts, key)
	for hash, session := range m.sessions {
		if session.TenantID == s.tenant && session.AccountID == id {
			delete(m.sessions, hash)
		}
	}
	return nil
}

// CreateSession records a signed-in browser and clears that account's expired sessions.
//
// The single mutex gives both halves the atomicity PostgreSQL gets from running them in one
// transaction: a sign-in either produces a usable session and a tidy table, or changes nothing.
func (s *scopedMemory) CreateSession(_ context.Context, session Session) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.accounts[accountKey{tenant: s.tenant, id: session.AccountID}]; !ok {
		// The foreign key from operator_sessions to operator_accounts, expressed in Go. It is
		// errUnknownTenant's sibling: an unclassified error, because that is what the database raises.
		return errUnknownAccount(s.tenant, session.AccountID)
	}
	for hash, held := range m.sessions {
		if held.TenantID == s.tenant && held.AccountID == session.AccountID &&
			!held.Valid(session.CreatedAt) {
			delete(m.sessions, hash)
		}
	}
	session.TenantID = s.tenant
	m.sessions[session.TokenHash] = session
	return nil
}

// DeleteSession ends one session, whether or not it had expired.
//
// A token naming no row, or naming another tenant's, is not an error — the same answer either way,
// because sign-out is idempotent and because telling the two apart would say whether a token exists.
func (s *scopedMemory) DeleteSession(_ context.Context, tokenHash string) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if held, ok := m.sessions[tokenHash]; ok && held.TenantID == s.tenant {
		delete(m.sessions, tokenHash)
	}
	return nil
}

// errUnknownAccount reports a session naming an account that does not exist in this tenant.
//
// A plain error rather than a sentinel, for the reason errUnknownTenant gives: the shipped store raises
// a foreign-key violation, which arrives unclassified, and returning ErrNotFound here would let a test
// assert against Memory something PostgreSQL does not do.
func errUnknownAccount(tenant TenantID, id string) error {
	return fmt.Errorf("store: no such operator account %q in tenant %q", id, tenant)
}

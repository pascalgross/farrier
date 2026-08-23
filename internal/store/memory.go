package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/pascalgross/farrier/internal/protocol"
)

// Memory is an in-memory Store.
//
// It exists so tests do not need a database, and so `farrier-server serve --store memory` can run a
// demonstration or an integration harness without one. It is **not** a supported production backend and
// the server logs loudly when it is used: everything is lost on restart, nothing is shared between
// replicas, and none of the PostgreSQL properties the real store depends on — atomic claiming, GIN
// indexes on facts, LISTEN/NOTIFY — is really being exercised.
//
// Keeping it honest matters more than keeping it complete: where a behaviour here differs from
// PostgreSQL in a way a caller could notice, the difference is written down at the method rather than
// papered over, so that a test passing against Memory is not mistaken for a test passing.
type Memory struct {
	// mu guards every field below. One lock for the whole store is right here: the memory store exists
	// for tests, where contention is irrelevant and a single obvious lock is worth more than
	// throughput.
	mu sync.Mutex

	// tokens are enrolment tokens by hash.
	tokens map[string]EnrollmentToken

	// hosts are enrolled hosts by id.
	hosts map[string]Host

	// certs are issued certificates by fingerprint.
	certs map[string]Certificate

	// jobs are pending jobs by host id, in delivery order.
	jobs map[string][]protocol.Job

	// results are recorded results by job id, which is what makes recording idempotent.
	results map[string]protocol.ResultRequest

	// jobHost records which host each job was issued to, so a result can be checked against it.
	//
	// It outlives the job in m.jobs, which is emptied on claim: a result arrives after the claim, and a
	// forged one must still be refused.
	jobHost map[string]string

	// waiters are channels to wake per host, standing in for LISTEN/NOTIFY.
	waiters map[string][]chan struct{}
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		tokens:  map[string]EnrollmentToken{},
		hosts:   map[string]Host{},
		certs:   map[string]Certificate{},
		jobs:    map[string][]protocol.Job{},
		results: map[string]protocol.ResultRequest{},
		jobHost: map[string]string{},
		waiters: map[string][]chan struct{}{},
	}
}

// Migrate does nothing; an empty map is already up to date.
func (m *Memory) Migrate(_ context.Context) error { return nil }

// Close does nothing; there is nothing to release.
func (m *Memory) Close() error { return nil }

// CreateEnrollmentToken records a new token by its hash.
func (m *Memory) CreateEnrollmentToken(_ context.Context, t EnrollmentToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.tokens[t.Hash]; exists {
		return ErrConflict
	}
	m.tokens[t.Hash] = t
	return nil
}

// ConsumeEnrollmentToken atomically redeems a token, or reports ErrTokenUnusable.
//
// The single mutex gives the same atomicity PostgreSQL gets from a conditional UPDATE: two agents
// presenting the same token concurrently cannot both succeed.
func (m *Memory) ConsumeEnrollmentToken(_ context.Context, hash, hostID string, now time.Time) (EnrollmentToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.tokens[hash]
	if !ok || !t.Usable(now) {
		// One error for unknown, expired and consumed. Distinguishing them for the caller would mean
		// distinguishing them for whoever is guessing tokens.
		return EnrollmentToken{}, ErrTokenUnusable
	}
	t.ConsumedAt = now
	t.ConsumedByHost = hostID
	m.tokens[hash] = t
	return t, nil
}

// ListEnrollmentTokens returns tokens for the UI, newest first.
func (m *Memory) ListEnrollmentTokens(_ context.Context) ([]EnrollmentToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]EnrollmentToken, 0, len(m.tokens))
	for _, t := range m.tokens {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// CreateEnrolledHost records a newly enrolled host and its first certificate together.
//
// Both or neither, matching the transaction the PostgreSQL store runs. A host row without its
// certificate claims the machine-id hash while being unable to authenticate, which is a machine that
// cannot enrol again either.
func (m *Memory) CreateEnrolledHost(_ context.Context, h Host, c Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.hosts[h.ID]; exists {
		return ErrConflict
	}
	for _, existing := range m.hosts {
		if h.MachineIDHash != "" && !existing.Revoked && existing.MachineIDHash == h.MachineIDHash {
			return ErrConflict
		}
	}
	m.hosts[h.ID] = h
	m.certs[c.Fingerprint] = c
	return nil
}

// DeleteHost removes a host and everything that references it.
func (m *Memory) DeleteHost(_ context.Context, hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.hosts[hostID]; !ok {
		return ErrNotFound
	}
	delete(m.hosts, hostID)
	for fp, c := range m.certs {
		if c.HostID == hostID {
			delete(m.certs, fp)
		}
	}
	delete(m.jobs, hostID)
	for id, host := range m.jobHost {
		if host == hostID {
			delete(m.jobHost, id)
		}
	}
	return nil
}

// GetHost returns one host by id, or ErrNotFound.
func (m *Memory) GetHost(_ context.Context, id string) (Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	h, ok := m.hosts[id]
	if !ok {
		return Host{}, ErrNotFound
	}
	return h, nil
}

// GetHostByMachineID returns the live host with a machine-id hash, or ErrNotFound.
//
// Revoked hosts are skipped, matching the partial unique index in the schema: revoking a host is what
// releases its machine for re-enrolment.
func (m *Memory) GetHostByMachineID(_ context.Context, hash string) (Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, h := range m.hosts {
		if h.MachineIDHash == hash && hash != "" && !h.Revoked {
			return h, nil
		}
	}
	return Host{}, ErrNotFound
}

// ListHosts returns every host, ordered by hostname then id.
//
// The secondary sort on id matters: hostnames are not unique, and an unstable order would make the
// fleet list reshuffle between page loads for no reason a reader could see.
func (m *Memory) ListHosts(_ context.Context) ([]Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]Host, 0, len(m.hosts))
	for _, h := range m.hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// RecordHeartbeat applies a heartbeat's fields to a host.
func (m *Memory) RecordHeartbeat(_ context.Context, hostID string, u HeartbeatUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	h, ok := m.hosts[hostID]
	if !ok {
		return ErrNotFound
	}
	h.AgentVersion = u.AgentVersion
	h.BootID = u.BootID
	h.UptimeSeconds = u.UptimeSeconds
	h.ClockOffsetSeconds = u.ClockOffsetSeconds
	h.Paused = u.Paused
	h.LastSeen = u.LastSeen
	m.hosts[hostID] = h
	return nil
}

// StoreFacts records a full facts document and its digest.
func (m *Memory) StoreFacts(_ context.Context, hostID, digest string, document []byte) error {
	return m.setDocument(hostID, func(h *Host) {
		h.Facts = document
		h.FactsDigest = digest
	})
}

// StorePolicy records a host's effective policy and its digest.
func (m *Memory) StorePolicy(_ context.Context, hostID, digest string, document []byte) error {
	return m.setDocument(hostID, func(h *Host) {
		h.Policy = document
		h.PolicyDigest = digest
	})
}

// StoreSigners records a host's trusted key identities and their digest.
func (m *Memory) StoreSigners(_ context.Context, hostID, digest string, document []byte) error {
	return m.setDocument(hostID, func(h *Host) {
		h.Signers = document
		h.SignersDigest = digest
	})
}

// setDocument applies a mutation to a host under the lock.
func (m *Memory) setDocument(hostID string, apply func(*Host)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	h, ok := m.hosts[hostID]
	if !ok {
		return ErrNotFound
	}
	apply(&h)
	m.hosts[hostID] = h
	return nil
}

// AddCertificate records an issued certificate by fingerprint.
func (m *Memory) AddCertificate(_ context.Context, c Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs[c.Fingerprint] = c
	return nil
}

// LookupCertificate returns a certificate by fingerprint, or ErrNotFound.
func (m *Memory) LookupCertificate(_ context.Context, fingerprint string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.certs[fingerprint]
	if !ok {
		return Certificate{}, ErrNotFound
	}
	return c, nil
}

// RevokeHost marks a host and all its certificates as revoked.
func (m *Memory) RevokeHost(_ context.Context, hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	h, ok := m.hosts[hostID]
	if !ok {
		return ErrNotFound
	}
	h.Revoked = true
	m.hosts[hostID] = h

	now := time.Now()
	for fp, c := range m.certs {
		if c.HostID == hostID {
			c.Revoked = true
			c.RevokedAt = now
			m.certs[fp] = c
		}
	}
	return nil
}

// Enqueue adds a job for a host and wakes any long-poll waiting for it.
//
// It is not part of the Store interface because the control plane does not create jobs yet: there is no
// job-creation API, so no job of any class reaches a host from the server side. It exists so that tests
// and the integration harness can exercise the delivery path — including the wake-up — before there is
// anything to deliver.
func (m *Memory) Enqueue(hostID string, job protocol.Job) {
	m.mu.Lock()
	m.jobs[hostID] = append(m.jobs[hostID], job)
	m.jobHost[job.ID] = hostID
	waiters := m.waiters[hostID]
	m.waiters[hostID] = nil
	m.mu.Unlock()

	for _, w := range waiters {
		close(w)
	}
}

// ClaimJobs takes up to limit jobs for a host.
//
// Removing the jobs under the lock gives the same at-most-once delivery PostgreSQL gets from
// SELECT … FOR UPDATE SKIP LOCKED.
func (m *Memory) ClaimJobs(_ context.Context, hostID string, limit int) ([]protocol.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pending := m.jobs[hostID]
	if len(pending) == 0 {
		return nil, nil
	}
	if limit > 0 && len(pending) > limit {
		m.jobs[hostID] = pending[limit:]
		return pending[:limit], nil
	}
	delete(m.jobs, hostID)
	return pending, nil
}

// RecordResult stores a job result idempotently, for a job that belongs to the reporting host.
func (m *Memory) RecordResult(_ context.Context, hostID string, r protocol.ResultRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Every enrolled host is authenticated and none is trusted. A result for somebody else's job is
	// refused rather than stored, because recording is idempotent and a forged result would otherwise
	// suppress the real one when it arrived.
	if owner, known := m.jobHost[r.JobID]; !known || owner != hostID {
		return ErrNotFound
	}
	if _, exists := m.results[r.JobID]; exists {
		// Already recorded. A repeated result changes nothing and is not an error: the agent retries
		// until it gets a 2xx, and a second delivery means the first response was lost, not that the
		// work happened twice.
		return nil
	}
	m.results[r.JobID] = r
	return nil
}

// Result returns a recorded result, for tests.
func (m *Memory) Result(jobID string) (protocol.ResultRequest, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.results[jobID]
	return r, ok
}

// Subscribe registers interest in work for a host and returns a channel closed when some arrives.
func (m *Memory) Subscribe(hostID string) (<-chan struct{}, func()) {
	wake := make(chan struct{})

	m.mu.Lock()
	m.waiters[hostID] = append(m.waiters[hostID], wake)
	m.mu.Unlock()

	return wake, func() { m.removeWaiter(hostID, wake) }
}

// removeWaiter drops a waiter, whether it was woken or gave up.
//
// It is idempotent, because the caller always releases its subscription and the waker has usually
// already removed it.
func (m *Memory) removeWaiter(hostID string, wake chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	waiters := m.waiters[hostID]
	for i, w := range waiters {
		if w == wake {
			m.waiters[hostID] = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(m.waiters[hostID]) == 0 {
		delete(m.waiters, hostID)
	}
}

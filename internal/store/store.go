// Package store persists the control plane's state.
//
// The Store interface exists so that tests do not need a database. It is **not** a portability layer,
// and pull requests adding MySQL or SQLite backends will be declined — docs/EXTENDING.md says so and
// this comment says so again, because the interface's existence is the thing that invites the
// misunderstanding.
//
// Farrier depends on PostgreSQL features that are load-bearing rather than incidental: JSONB with GIN
// indexes for facts that gain fields constantly, partial indexes for the job claim, LISTEN/NOTIFY to
// wake long-polls without Redis, and SELECT … FOR UPDATE SKIP LOCKED for atomic claiming. Abstracting
// those away would mean reimplementing a job queue and a pub/sub system badly, and then shipping a
// second service as a dependency — which is precisely the four-service Compose stack this project
// chose not to be.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/pegasusnetworks/farrier/internal/protocol"
)

// Sentinel errors every implementation returns for the same conditions.
//
// They are values rather than strings so that handlers can map them to status codes without matching on
// text, which is how a reworded error message turns into a 500 that used to be a 404.
var (
	// ErrNotFound reports that no such row exists.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict reports a uniqueness violation, such as a second host with the same machine id.
	ErrConflict = errors.New("store: conflict")

	// ErrTokenUnusable reports a bootstrap token that is unknown, expired or already consumed.
	//
	// It deliberately covers all three. Telling an attacker which of the three applies is free
	// reconnaissance, so the distinction is not carried out of the store at all rather than being
	// carried and then remembered not to reveal.
	ErrTokenUnusable = errors.New("store: token unusable")
)

// EnrollmentToken authorises exactly one enrolment.
type EnrollmentToken struct {
	// Hash is the SHA-256 of the token as issued. The token itself is never stored.
	//
	// Storing only the hash means a database dump does not let its holder enrol hosts. The token is
	// shown to the operator once, at creation, and is not recoverable afterwards.
	Hash string

	// Label is what the operator called it, for the UI.
	Label string

	// Group is the fleet group hosts enrolled with this token join.
	Group string

	// Bootstrap names a provisioning template this token may request, empty for none.
	Bootstrap string

	// CreatedAt is when it was issued.
	CreatedAt time.Time

	// ExpiresAt is when it stops working.
	ExpiresAt time.Time

	// ConsumedAt is when it was used, zero if unused.
	ConsumedAt time.Time

	// ConsumedByHost is the host that used it, empty if unused.
	ConsumedByHost string
}

// Usable reports whether a token may still be redeemed at the given instant.
func (t EnrollmentToken) Usable(now time.Time) bool {
	return t.ConsumedAt.IsZero() && now.Before(t.ExpiresAt)
}

// Host is one enrolled machine.
type Host struct {
	// ID is the control plane's identifier, and the certificate subject common name.
	ID string

	// Hostname is what the host calls itself, for display only.
	//
	// It is never used for identity: two hosts can share a hostname, and a host can change its own.
	Hostname string

	// MachineIDHash is the salted hash the host reported at enrolment.
	MachineIDHash string

	// Group is the fleet group, from the enrolment token.
	Group string

	// AgentVersion is the build reported in the last heartbeat.
	AgentVersion string

	// EnrolledAt is when the host first enrolled.
	EnrolledAt time.Time

	// LastSeen is the time of the last heartbeat, by the server's clock.
	LastSeen time.Time

	// BootID identifies the host's current boot, so a reboot is visible without comparing uptimes.
	BootID string

	// UptimeSeconds is what the host last reported.
	UptimeSeconds int64

	// ClockOffsetSeconds is the host's own measurement of its offset from the server.
	//
	// Beyond five minutes, privileged intents refuse on the host and the UI flags it. The value is
	// stored for display; nothing on the server adjusts anything because of it.
	ClockOffsetSeconds int64

	// Paused reports whether /etc/farrier/paused exists on the host.
	Paused bool

	// FactsDigest, PolicyDigest and SignersDigest are what the host last reported.
	//
	// They are compared against the stored documents to decide whether to ask for a full report. That
	// comparison is the entire digest-first design: without it, five hundred hosts send their whole
	// inventory every minute.
	FactsDigest   string
	PolicyDigest  string
	SignersDigest string

	// Facts, Policy and Signers are the last full documents received, as JSON.
	Facts   []byte
	Policy  []byte
	Signers []byte

	// Revoked reports that this host's certificates are no longer accepted.
	Revoked bool
}

// Online reports whether the host has been heard from recently enough to be considered up.
//
// The threshold is generous relative to the heartbeat interval because a host that missed one beat is
// not down, and a fleet list that flickers red teaches its reader to ignore red.
func (h Host) Online(now time.Time, heartbeatSeconds int) bool {
	if h.LastSeen.IsZero() {
		return false
	}
	grace := time.Duration(heartbeatSeconds) * time.Second * 3
	return now.Sub(h.LastSeen) < grace
}

// Certificate is one issued agent certificate.
type Certificate struct {
	// Fingerprint is the SHA-256 of the DER certificate, lower-case hex.
	//
	// This is the revocation mechanism: every authenticated request looks the fingerprint up, and a
	// row that is absent or revoked ends the request. No CRL, no OCSP, no distribution delay.
	Fingerprint string

	// HostID is the host this certificate identifies.
	HostID string

	// Serial is the certificate serial, hex, for correlating with logs.
	Serial string

	// IssuedAt and NotAfter bound its validity.
	IssuedAt time.Time
	NotAfter time.Time

	// Revoked reports that this certificate is no longer accepted.
	Revoked bool

	// RevokedAt is when it was revoked, zero if it was not.
	RevokedAt time.Time
}

// HeartbeatUpdate is what one heartbeat changes about a host.
//
// It is a separate struct from Host so that a heartbeat cannot accidentally overwrite fields it does
// not carry — enrolment time, group, the stored facts document — by writing a zero value over them.
type HeartbeatUpdate struct {
	// AgentVersion is the build the host reported.
	AgentVersion string

	// BootID identifies the host's current boot.
	BootID string

	// UptimeSeconds is what the host reported.
	UptimeSeconds int64

	// ClockOffsetSeconds is the host's own measurement.
	ClockOffsetSeconds int64

	// Paused reports the host's kill-switch state.
	Paused bool

	// LastSeen is the server's clock reading for this heartbeat.
	LastSeen time.Time
}

// Note that a heartbeat deliberately carries no digests.
//
// The digest columns on a host record what the *server holds*, and are written only by StoreFacts,
// StorePolicy and StoreSigners — that is, only when a document actually arrives. Recording the digest a
// host claimed would make the server believe it held a document it had never received: it would ask
// once, and if that one full report were lost to a network failure it would compare the next heartbeat
// against the claim it had stored, conclude it was up to date, and never ask again.

// Store is the control plane's persistence.
//
// Every method takes a context because every one of them can be waiting on a database that has stopped
// answering, and a control plane that cannot shed a stuck query is a control plane a single slow host
// can take down.
type Store interface {
	// Migrate brings the schema up to date. It is safe to call on every start.
	Migrate(ctx context.Context) error

	// CreateEnrollmentToken records a new token by its hash.
	CreateEnrollmentToken(ctx context.Context, t EnrollmentToken) error

	// ConsumeEnrollmentToken atomically redeems a token, or reports ErrTokenUnusable.
	//
	// Atomicity is the whole point: two agents presenting the same token in the same instant must not
	// both enrol, and checking-then-updating in the handler would let them.
	ConsumeEnrollmentToken(ctx context.Context, hash, hostID string, now time.Time) (EnrollmentToken, error)

	// ListEnrollmentTokens returns tokens for the UI, newest first.
	ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error)

	// CreateHost records a newly enrolled host.
	CreateHost(ctx context.Context, h Host) error

	// GetHost returns one host by id, or ErrNotFound.
	GetHost(ctx context.Context, id string) (Host, error)

	// GetHostByMachineID returns the host with a machine-id hash, or ErrNotFound.
	GetHostByMachineID(ctx context.Context, hash string) (Host, error)

	// ListHosts returns every host, ordered by hostname.
	ListHosts(ctx context.Context) ([]Host, error)

	// RecordHeartbeat applies a heartbeat's fields to a host.
	RecordHeartbeat(ctx context.Context, hostID string, u HeartbeatUpdate) error

	// StoreFacts records a full facts document and its digest.
	StoreFacts(ctx context.Context, hostID, digest string, document []byte) error

	// StorePolicy records a host's effective policy and its digest.
	StorePolicy(ctx context.Context, hostID, digest string, document []byte) error

	// StoreSigners records a host's trusted key identities and their digest.
	StoreSigners(ctx context.Context, hostID, digest string, document []byte) error

	// AddCertificate records an issued certificate by fingerprint.
	AddCertificate(ctx context.Context, c Certificate) error

	// LookupCertificate returns a certificate by fingerprint, or ErrNotFound.
	//
	// This is called on every authenticated request. It is the revocation check.
	LookupCertificate(ctx context.Context, fingerprint string) (Certificate, error)

	// RevokeHost marks a host and all its certificates as revoked, taking effect on the next request.
	RevokeHost(ctx context.Context, hostID string) error

	// ClaimJobs atomically takes up to limit jobs for a host.
	//
	// Atomic claiming is what lets a control plane run more than one replica. In PostgreSQL it is
	// SELECT … FOR UPDATE SKIP LOCKED against a partial index; the interface says nothing about that,
	// but the guarantee it makes — a job is delivered to one agent, once — is the one callers rely on.
	ClaimJobs(ctx context.Context, hostID string, limit int) ([]protocol.Job, error)

	// RecordResult stores a job result idempotently, keyed by job id.
	//
	// A repeated result for a job that already has one changes nothing and does not error. Work that
	// succeeded but whose result was lost must never re-execute: that is how a retry turns one reboot
	// into a reboot loop.
	//
	// A result for a job that does not belong to hostID returns ErrNotFound. Every enrolled host is
	// authenticated but none of them is trusted: without this check any host could post a result for
	// another host's job, and because recording is idempotent the forged result would then suppress the
	// real one when it arrived.
	RecordResult(ctx context.Context, hostID string, r protocol.ResultRequest) error

	// Subscribe registers interest in work for a host and returns a channel closed when some arrives.
	//
	// It is deliberately separate from claiming, and the caller must subscribe *before* it looks at the
	// queue. Doing it the other way round leaves a gap: a job inserted between the empty read and the
	// subscription fires its notification with nobody listening, and the agent then holds a long-poll
	// for its full duration over work that was already waiting. The gap is small and the consequence is
	// only latency, which is exactly why it would never be diagnosed.
	//
	// This is what makes the long-poll a long-poll rather than a sleep. In PostgreSQL it is LISTEN on a
	// channel the job insert NOTIFYs, which is why Farrier needs no Redis. The channel may be closed
	// spuriously — the caller re-checks the queue — but a wake-up must not be missed indefinitely.
	//
	// The returned function releases the subscription and must always be called, or a fleet whose
	// agents reconnect every twenty-five seconds accumulates one dead waiter per poll.
	Subscribe(hostID string) (<-chan struct{}, func())

	// Close releases the store's resources.
	Close() error
}

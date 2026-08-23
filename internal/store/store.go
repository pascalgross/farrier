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

	"github.com/pascalgross/farrier/internal/protocol"
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

// NewJob is a job as the control plane creates it.
//
// It is a separate type from protocol.Job because the two answer different questions. protocol.Job is
// what goes on the wire to a host and carries only what the host needs; this carries what the control
// plane must remember about the decision to issue it — who asked, and whether a second person still
// has to agree.
type NewJob struct {
	// Job is what the host will receive, unchanged.
	Job protocol.Job

	// HostID is the host it is issued to.
	HostID string

	// CreatedBy is the operator identity that asked for it, for the audit trail.
	//
	// It is recorded even though the guarantee does not rest on it. A compromised administrator account
	// is inside the threat model by construction; what this protects is the ability to answer "who
	// asked for this reboot" afterwards, which is a different and still necessary thing.
	CreatedBy string

	// ApprovalRequired reports whether a second operator must agree before a host may claim it.
	//
	// docs/SECURITY.md §3 requires it for the destructive tier. It is a field rather than something
	// derived from the class on read, so that the row records the rule as it stood when the job was
	// created: a later build that classified an intent differently must not change what an
	// already-queued job needed.
	ApprovalRequired bool
}

// JobRecord is one job as the control plane holds it, with its result if one has arrived.
type JobRecord struct {
	// Job is what the host receives.
	Job protocol.Job

	// HostID is the host it was issued to.
	HostID string

	// CreatedAt is when the control plane created it.
	CreatedAt time.Time

	// CreatedBy is the operator who asked for it.
	CreatedBy string

	// ApprovalRequired reports whether a second operator had to agree.
	ApprovalRequired bool

	// ApprovedAt is when the second operator agreed, zero if they have not.
	ApprovedAt time.Time

	// ApprovedBy is who agreed, empty if nobody has.
	ApprovedBy string

	// ClaimedAt is when a host took it, zero if none has.
	ClaimedAt time.Time

	// CompletedAt is when a result arrived, zero if none has.
	CompletedAt time.Time

	// Result is what the host reported, nil until it does.
	Result *protocol.ResultRequest
}

// Claimable reports whether a host may take this job now.
//
// It exists so that the API and the UI answer the question the same way the claim query does, rather
// than each deciding for itself what "waiting" means and disagreeing on the one row where it matters.
func (r JobRecord) Claimable() bool {
	if !r.ClaimedAt.IsZero() || !r.CompletedAt.IsZero() {
		return false
	}
	return !r.ApprovalRequired || !r.ApprovedAt.IsZero()
}

// JobFilter narrows a job listing.
type JobFilter struct {
	// HostID limits the listing to one host, empty for the whole fleet.
	HostID string

	// Limit bounds how many are returned, newest first. Zero takes the implementation's default.
	Limit int
}

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

	// CreateEnrolledHost records a newly enrolled host and its first certificate together.
	//
	// The two are one operation because half of it is worse than neither. A host row without its
	// certificate is a machine that cannot authenticate and, because its machine-id hash is taken,
	// cannot enrol again either — permanently stuck on a failure that happened once, in a fraction of a
	// second, on the server.
	CreateEnrolledHost(ctx context.Context, h Host, c Certificate) error

	// GetHost returns one host by id, or ErrNotFound.
	GetHost(ctx context.Context, id string) (Host, error)

	// GetHostByMachineID returns the live host with a machine-id hash, or ErrNotFound.
	//
	// Revoked hosts are excluded, which is what makes a revoked machine able to enrol again. Its old row
	// stays for the audit trail; what it loses is its claim on the machine id.
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

	// DeleteHost removes a host and everything that references it.
	//
	// Revocation is the ordinary answer and this is not a substitute for it: a revoked host keeps its
	// history, which is what an audit needs. Deletion exists for the row that should never have been
	// there — an enrolment abandoned midway, a test host, a machine that has been decommissioned and
	// whose facts nobody will ever read again.
	DeleteHost(ctx context.Context, hostID string) error

	// CreateJob records a job for a host and wakes any long-poll waiting for it.
	//
	// It returns ErrConflict when a signed job's nonce has already been queued for that host. The host
	// refuses a replayed nonce itself and that is the check the guarantee rests on; this one is earlier
	// and cheaper, because a job queued twice is delivered twice, refused on the host, and reported as
	// a failure nobody can explain.
	CreateJob(ctx context.Context, j NewJob) error

	// ApproveJob records a second operator's agreement, making the job claimable.
	//
	// The refusal to self-approve is enforced here rather than only in the handler, because it must
	// hold against two requests arriving at once. A read-then-write in the caller would let the same
	// operator approve their own job by racing it against itself, which is the one way this check could
	// be defeated by someone who already has the credential.
	//
	// It returns ErrNotFound for a job that does not exist, and ErrConflict for one that needs no
	// approval, already has it, or would be approved by whoever created it.
	ApproveJob(ctx context.Context, jobID, approver string, now time.Time) error

	// ListJobs returns jobs newest first, with their results.
	ListJobs(ctx context.Context, f JobFilter) ([]JobRecord, error)

	// GetJob returns one job and its result, or ErrNotFound.
	GetJob(ctx context.Context, jobID string) (JobRecord, error)

	// ClaimJobs atomically takes up to limit jobs for a host.
	//
	// Atomic claiming is what lets a control plane run more than one replica. In PostgreSQL it is
	// SELECT … FOR UPDATE SKIP LOCKED against a partial index; the interface says nothing about that,
	// but the guarantee it makes — a job is delivered to one agent, once — is the one callers rely on.
	//
	// A job still waiting for its second operator is never returned. That check belongs here rather
	// than in the handler: the handler is not the only thing that will ever claim, and an approval
	// requirement enforced by whoever remembers to ask is not a requirement.
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

// Compile-time proof that both implementations satisfy the interface.
//
// Without it, a method added to Store is a compile error only where a Store value is assigned — which
// in this package's tests is inside a test helper, so a missing method on one implementation surfaces
// as a confusing failure in an unrelated test rather than here, next to the interface it belongs to.
var (
	_ Store = (*Postgres)(nil)
	_ Store = (*Memory)(nil)
)

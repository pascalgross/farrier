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

	// TenantID is the tenant that host belongs to.
	//
	// It is carried here because this lookup is where an agent request finds out which tenant it is:
	// the certificate is presented before anything else is known, and everything the request goes on to
	// touch is scoped by the answer. Storing it on the row rather than joining to hosts also means the
	// composite foreign key can refuse a certificate that claims one tenant and points at another's
	// host, which is the exact shape of a successful cross-tenant write.
	TenantID TenantID

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

	// ApprovalRequired reports whether somebody must release this job before a host may claim it.
	//
	// It comes from the tenant's approval mode and the intent's class, and it is a field rather than
	// something derived on read so that the row records the rule as it stood when the job was created.
	// Two different changes would otherwise rewrite history: a later build that classified an intent
	// differently, and — since the rule became a tenant setting — an operator who relaxed the setting
	// after queueing the job.
	ApprovalRequired bool

	// ApprovalDistinctOperator reports whether the release must come from somebody other than CreatedBy.
	//
	// Separate from ApprovalRequired because they are separate questions, and a tenant answers them
	// separately: "somebody must deliberately release this" is worth having in an installation with one
	// operator, where "somebody else must" would be a requirement nobody could meet.
	ApprovalDistinctOperator bool
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

	// ApprovalRequired reports whether somebody had to release it.
	ApprovalRequired bool

	// ApprovalDistinctOperator reports whether that somebody had to be other than its creator.
	//
	// Carried out of the store so that a client can say which rule this job was created under, rather
	// than reporting the tenant's current setting beside a job the setting no longer governs.
	ApprovalDistinctOperator bool

	// ApprovedAt is when it was released, zero if it has not been.
	ApprovedAt time.Time

	// ApprovedBy is who released it, empty if nobody has.
	ApprovedBy string

	// ClaimedAt is when a host took it, zero if none has.
	ClaimedAt time.Time

	// CompletedAt is when a result arrived, zero if none has.
	CompletedAt time.Time

	// Result is what the host reported, nil until it does.
	Result *protocol.ResultRequest
}

// AwaitingApproval reports whether this job is waiting for somebody to release it.
//
// It exists so that the two store implementations, the API's state word and the partial index in
// migration 0004 all mean the same thing by "awaiting approval". The predicate is small enough to write
// out at each site and that is exactly the problem: the copy somebody forgets to update is the one that
// decides whether a destructive job appears on the page a second operator is reading.
func (r JobRecord) AwaitingApproval() bool {
	return r.ApprovalRequired && r.ApprovedAt.IsZero()
}

// Claimable reports whether a host may take this job now.
//
// It exists so that the API and the UI answer the question the same way the claim query does, rather
// than each deciding for itself what "waiting" means and disagreeing on the one row where it matters.
func (r JobRecord) Claimable() bool {
	if !r.ClaimedAt.IsZero() || !r.CompletedAt.IsZero() {
		return false
	}
	return !r.AwaitingApproval()
}

// JobFilter narrows a job listing.
type JobFilter struct {
	// HostID limits the listing to one host, empty for the whole fleet.
	HostID string

	// Limit bounds how many are returned, newest first. Zero takes DefaultJobLimit.
	Limit int

	// AwaitingApproval narrows the listing to jobs that require a second operator and have not had
	// one.
	//
	// It exists because those are the only jobs whose visibility is load-bearing. Everything else in
	// the list is history, and history that scrolls off the end is a nuisance; a destructive job that
	// scrolls off the end before anybody approved it is docs/SECURITY.md §3 failing quietly, because
	// the second person the mechanism depends on can no longer find the thing to look at.
	AwaitingApproval bool
}

// DefaultJobLimit is how many jobs a listing returns when the caller does not say.
//
// A screenful with room to scroll. It is small on purpose: the list is read on every page load and the
// rows carry parameter objects and result output.
const DefaultJobLimit = 100

// MaxJobLimit is the largest listing a caller may ask for.
//
// A ceiling rather than no ceiling, because one query that asks for everything is how a control plane
// with a year of history becomes a control plane that times out. A caller that needs more than this
// wants the awaiting-approval filter or a per-host listing, both of which are cheaper and are what the
// question behind the request usually is.
const MaxJobLimit = 500

// TenantID identifies one tenant: one isolated fleet, with its own hosts, its own operators and its
// own settings.
//
// It is a defined type rather than a string so that a host id, a job id or an operator subject cannot
// be passed where a tenant belongs. Every one of those is also a bare identifier, and the compiler is
// the only reader that will reliably notice.
type TenantID string

// ApprovalMode is how one tenant releases a destructive job.
//
// It is a property of the tenant rather than of the installation because a control plane that serves a
// one-person shop and a regulated customer at the same time cannot answer the question once for both.
// See docs/SECURITY.md §3.
type ApprovalMode string

// The three ways a tenant can answer "who has to agree before a host may claim this".
const (
	// ApprovalNone releases a destructive job as soon as it is created.
	//
	// The offline signature is then the whole of the control-plane-side authorisation, which is also
	// the only part the guarantee in docs/SECURITY.md §1 rests on: the key is one this control plane
	// does not hold, and the host verifies it against its own trust anchor. This is the default.
	ApprovalNone ApprovalMode = "none"

	// ApprovalSelf requires somebody to release the job, and lets that be whoever created it.
	//
	// It buys the deliberate second act and an audit row naming who took it, in an installation with
	// one operator where requiring a second person would mean requiring the impossible.
	ApprovalSelf ApprovalMode = "self"

	// ApprovalSecondPerson requires somebody other than the creator to release the job.
	ApprovalSecondPerson ApprovalMode = "second_person"
)

// Valid reports whether a mode is one of the three.
//
// Checked on the way in rather than trusted, because the column has the same CHECK constraint and a
// value that fails it would surface as a database error at the moment somebody was configuring their
// tenant.
func (m ApprovalMode) Valid() bool {
	switch m {
	case ApprovalNone, ApprovalSelf, ApprovalSecondPerson:
		return true
	default:
		return false
	}
}

// RequiresApproval reports whether a destructive job under this mode waits for a release.
func (m ApprovalMode) RequiresApproval() bool { return m == ApprovalSelf || m == ApprovalSecondPerson }

// RequiresDistinctOperator reports whether the release must come from somebody other than the creator.
func (m ApprovalMode) RequiresDistinctOperator() bool { return m == ApprovalSecondPerson }

// Tenant is one isolated fleet.
type Tenant struct {
	// ID is the identifier every scoped row carries.
	ID TenantID

	// Slug is a short stable handle for URLs, logs and support tickets.
	//
	// Separate from DisplayName because a customer renaming themselves must not change the identifier
	// everything else refers to.
	Slug string

	// DisplayName is what the tenant is called in the interface.
	DisplayName string

	// CreatedAt is when the tenant was created.
	CreatedAt time.Time

	// ApprovalMode is how this tenant releases a destructive job.
	ApprovalMode ApprovalMode

	// WebhookURL is where this tenant's events are posted, empty for nowhere.
	//
	// It belongs to the tenant rather than to the process because the alternative was not a missing
	// feature but a leak: one list of sinks for the whole installation delivers one customer's
	// hostnames and operator names to another customer's endpoint.
	WebhookURL string
}

// Store is the control plane's persistence.
//
// Every method takes a context because every one of them can be waiting on a database that has stopped
// answering, and a control plane that cannot shed a stuck query is a control plane a single slow host
// can take down.
//
// What is on *this* interface rather than on Scoped is the complete list of operations that are not
// scoped to a tenant, and it is short on purpose. Two of them are the lookups that *discover* which
// tenant a caller belongs to, so they cannot be behind a gate that requires already knowing the answer;
// the rest administer tenants themselves, or belong to no tenant at all. Everything that touches a
// tenant's data is on Scoped and is unreachable without naming a tenant — see In.
type Store interface {
	// Migrate brings the schema up to date. It is safe to call on every start.
	Migrate(ctx context.Context) error

	// In returns everything an operator or an agent can reach, scoped to one tenant.
	//
	// This is the whole isolation design in one method. A tenant-scoped operation is not a method you
	// remember to pass a tenant to; it is a method you cannot reach without one, and in PostgreSQL the
	// returned handle runs every statement inside a transaction that has set the tenant, so
	// row-level security refuses a row from anywhere else even if the statement's own WHERE clause
	// forgot to.
	In(tenant TenantID) Scoped

	// LookupCertificate returns a certificate by fingerprint, or ErrNotFound.
	//
	// This is called on every authenticated agent request, it is the revocation check, and it is how an
	// agent request finds out which tenant it belongs to — which is why it is here and not on Scoped.
	// The fingerprint is the SHA-256 of a certificate this CA issued, so naming one is not a way of
	// discovering another.
	LookupCertificate(ctx context.Context, fingerprint string) (Certificate, error)

	// TenantForEnrollmentToken returns the tenant a token belongs to, or ErrTokenUnusable.
	//
	// Enrolment needs the tenant before it has anything else: the machine-id check is per tenant, and a
	// token is how a new machine joins one. It deliberately returns nothing but the tenant, and it does
	// not consume the token — a host retrying an enrolment it has already completed must not burn a
	// second token in the course of being told no.
	TenantForEnrollmentToken(ctx context.Context, hash string) (TenantID, error)

	// CreateTenant records a new tenant.
	CreateTenant(ctx context.Context, t Tenant) error

	// GetTenant returns one tenant, or ErrNotFound.
	GetTenant(ctx context.Context, id TenantID) (Tenant, error)

	// ListTenants returns every tenant, oldest first.
	ListTenants(ctx context.Context) ([]Tenant, error)

	// UpdateTenant applies a tenant's display name, approval mode and webhook.
	//
	// The slug is not among them. It is what logs, support tickets and any external system refer to a
	// tenant by, so a rename would leave every one of those pointing at a name that no longer answers.
	//
	// Changing the approval mode affects jobs created afterwards and nothing already queued. That is
	// deliberate and it is the same rule migration 0002 wrote down for approval_required: a job records
	// what it required, so relaxing the setting cannot release work that was queued under a stricter
	// one.
	UpdateTenant(ctx context.Context, t Tenant) error

	// DeleteTenant removes a tenant and everything belonging to it.
	DeleteTenant(ctx context.Context, id TenantID) error

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
	// It is not tenant-scoped, and that is a decision rather than an omission. A wake-up carries no
	// data — a waiter is either closed or it is not — and it is keyed on a host id, which is 128 bits
	// of randomness generated here. Scoping it would mean one LISTEN connection per tenant, which is
	// the resource problem the single fan-out connection exists to avoid, and with hosting the tenant
	// count is the number that grows. What somebody who guessed a host id could learn is that work
	// arrived for it; the work itself is behind the claim, which is scoped.
	//
	// The returned function releases the subscription and must always be called, or a fleet whose
	// agents reconnect every twenty-five seconds accumulates one dead waiter per poll.
	Subscribe(hostID string) (<-chan struct{}, func())

	// Close releases the store's resources.
	Close() error
}

// Scoped is every operation that touches one tenant's data.
//
// It is a separate interface rather than a tenant argument on twenty-four methods because the two fail
// differently. An argument is something a caller can pass wrongly and a reviewer has to notice; a
// handle is something a caller cannot obtain without saying whose data they are asking for. The
// PostgreSQL implementation then sets that tenant on the transaction, so the database refuses rows
// from anywhere else — the predicate in each statement is the optimisation, and the policy is the rule.
type Scoped interface {
	// Tenant reports whose data this handle reaches, for logs and for assertions.
	Tenant() TenantID

	// CreateEnrollmentToken records a new token by its hash.
	CreateEnrollmentToken(ctx context.Context, t EnrollmentToken) error

	// ConsumeEnrollmentToken atomically redeems a token, or reports ErrTokenUnusable.
	//
	// Atomicity is the whole point: two agents presenting the same token in the same instant must not
	// both enrol, and checking-then-updating in the handler would let them.
	ConsumeEnrollmentToken(ctx context.Context, hash, hostID string, now time.Time) (EnrollmentToken, error)

	// ListEnrollmentTokens returns this tenant's tokens for the UI, newest first.
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
	//
	// The claim is per tenant. Across the installation it would be an oracle: enrolling a machine that
	// belongs to somebody else would tell you that it belongs to somebody else.
	GetHostByMachineID(ctx context.Context, hash string) (Host, error)

	// ListHosts returns every host in this tenant, ordered by hostname.
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
	// It returns ErrConflict when the job id is already taken in this tenant, or when a signed job's
	// nonce has already been queued for that host. The host refuses a replayed nonce itself and that is
	// the check the guarantee rests on; this one is earlier and cheaper, because a job queued twice is
	// delivered twice, refused on the host, and reported as a failure nobody can explain.
	CreateJob(ctx context.Context, j NewJob) error

	// ApproveJob records an operator's release of a job, making it claimable.
	//
	// Whether the approver may be the job's creator is recorded on the job row at creation, from the
	// tenant's approval mode, and is enforced *here* rather than only in the handler — because it must
	// hold against two requests arriving at once. A read-then-write in the caller would let the same
	// operator approve their own job by racing it against itself, which is the one way this check could
	// be defeated by someone who already has the credential.
	//
	// It returns ErrNotFound for a job that does not exist, and ErrConflict for one that needs no
	// approval, already has it, or would be released by whoever created it under a mode that forbids
	// that.
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
	// A job still waiting to be released is never returned. That check belongs here rather than in the
	// handler: the handler is not the only thing that will ever claim, and an approval requirement
	// enforced by whoever remembers to ask is not a requirement.
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

// clampJobLimit turns a caller's requested listing size into one the store will run.
//
// It is shared by both implementations rather than written twice, because a default that differed
// between them would make the in-memory store — which every server test runs against — prove a page
// size the shipped store does not have.
func clampJobLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultJobLimit
	case n > MaxJobLimit:
		return MaxJobLimit
	default:
		return n
	}
}

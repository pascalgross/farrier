package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pegasusnetworks/farrier/internal/protocol"
)

// migrationFiles holds the schema, embedded so the binary is self-contained.
//
// A single binary plus PostgreSQL is the whole deployment. Shipping migrations as separate files an
// operator has to place correctly would reintroduce exactly the friction that decision avoided.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// jobChannel is the LISTEN/NOTIFY channel that wakes job long-polls.
//
// Its payload is the host id, so one listener connection can serve the whole fleet. That fan-out is not
// a nicety: a design that opened a PostgreSQL connection per waiting agent would need five hundred
// connections to hold five hundred long-polls, which is more than most instances allow in total.
const jobChannel = "farrier_job"

// Postgres is the production Store.
type Postgres struct {
	// pool serves ordinary queries.
	pool *pgxpool.Pool

	// dsn is kept because the listener needs its own connection, outside the pool.
	//
	// A connection running LISTEN cannot be returned to a pool and reused for queries without losing
	// the subscription, so it is held separately for the process's lifetime.
	dsn string

	// mu guards waiters.
	mu sync.Mutex

	// waiters maps a host id to the channels waiting for work for it.
	waiters map[string][]chan struct{}

	// listenerOnce ensures the single listener goroutine is started at most once.
	listenerOnce sync.Once

	// closed is closed when the store shuts down, stopping the listener.
	closed chan struct{}
}

// OpenPostgres connects to PostgreSQL and returns a Store.
//
// It does not run migrations; the caller decides when, so that a replica rolling out during a deploy
// does not race another replica's migration.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parsing the database URL: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connecting: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: connecting: %w", err)
	}
	return &Postgres{
		pool:    pool,
		dsn:     dsn,
		waiters: map[string][]chan struct{}{},
		closed:  make(chan struct{}),
	}, nil
}

// Close releases the pool and stops the listener.
func (p *Postgres) Close() error {
	select {
	case <-p.closed:
	default:
		close(p.closed)
	}
	p.pool.Close()
	return nil
}

// Migrate applies every embedded migration that has not run yet.
//
// A PostgreSQL advisory lock serialises this across replicas: several instances starting at once must
// not run the same migration concurrently, and an advisory lock costs nothing when there is no
// contention. The lock number is arbitrary but must never change, which is why it is a named constant
// rather than a literal at the call site.
func (p *Postgres) Migrate(ctx context.Context) error {
	const migrationLock = 8_412_679_001

	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquiring a connection to migrate: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLock); err != nil {
		return fmt.Errorf("store: taking the migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLock); err != nil {
			slog.Error("could not release the migration lock", "error", err)
		}
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS farrier_schema_version (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("store: creating the version table: %w", err)
	}

	names, err := migrationNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		var applied bool
		if err := conn.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM farrier_schema_version WHERE version = $1)", name,
		).Scan(&applied); err != nil {
			return fmt.Errorf("store: checking migration %s: %w", name, err)
		}
		if applied {
			continue
		}

		body, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("store: reading migration %s: %w", name, err)
		}
		if _, err := conn.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("store: applying migration %s: %w", name, err)
		}
		if _, err := conn.Exec(ctx,
			"INSERT INTO farrier_schema_version (version) VALUES ($1)", name,
		); err != nil {
			return fmt.Errorf("store: recording migration %s: %w", name, err)
		}
		slog.Info("applied database migration", "migration", name)
	}
	return nil
}

// migrationNames lists the embedded migrations in lexical order.
//
// Lexical order is the apply order, which is why the files are numbered. Sorting explicitly rather than
// relying on the filesystem means the order is the same on every platform.
func migrationNames() ([]string, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: reading embedded migrations: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// CreateEnrollmentToken records a new token by its hash.
func (p *Postgres) CreateEnrollmentToken(ctx context.Context, t EnrollmentToken) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO enrollment_tokens (hash, label, fleet_group, bootstrap, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		t.Hash, t.Label, t.Group, t.Bootstrap, t.CreatedAt, t.ExpiresAt)
	return wrap(err, "creating an enrolment token")
}

// ConsumeEnrollmentToken atomically redeems a token, or reports ErrTokenUnusable.
//
// The condition is in the UPDATE rather than in a preceding SELECT, so two agents presenting the same
// token in the same instant cannot both succeed. A check-then-update in the handler would let them, and
// the window is exactly as wide as the round trip between the two statements.
func (p *Postgres) ConsumeEnrollmentToken(ctx context.Context, hash, hostID string, now time.Time) (EnrollmentToken, error) {
	var t EnrollmentToken
	err := p.pool.QueryRow(ctx, `
		UPDATE enrollment_tokens
		   SET consumed_at = $3, consumed_by_host = $2
		 WHERE hash = $1
		   AND consumed_at IS NULL
		   AND expires_at > $3
		RETURNING hash, label, fleet_group, bootstrap, created_at, expires_at, consumed_at, consumed_by_host`,
		hash, hostID, now,
	).Scan(&t.Hash, &t.Label, &t.Group, &t.Bootstrap, &t.CreatedAt, &t.ExpiresAt,
		&t.ConsumedAt, &t.ConsumedByHost)

	if errors.Is(err, pgx.ErrNoRows) {
		// Unknown, expired and already consumed all arrive here and all return the same error.
		// Distinguishing them for the caller would mean distinguishing them for whoever is guessing.
		return EnrollmentToken{}, ErrTokenUnusable
	}
	return t, wrap(err, "consuming an enrolment token")
}

// ListEnrollmentTokens returns tokens for the UI, newest first.
func (p *Postgres) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT hash, label, fleet_group, bootstrap, created_at, expires_at,
		       COALESCE(consumed_at, 'epoch'::timestamptz), COALESCE(consumed_by_host, '')
		  FROM enrollment_tokens
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil, wrap(err, "listing enrolment tokens")
	}
	defer rows.Close()

	var out []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.Hash, &t.Label, &t.Group, &t.Bootstrap, &t.CreatedAt, &t.ExpiresAt,
			&t.ConsumedAt, &t.ConsumedByHost); err != nil {
			return nil, wrap(err, "scanning an enrolment token")
		}
		if t.ConsumedAt.Unix() == 0 {
			t.ConsumedAt = time.Time{}
		}
		out = append(out, t)
	}
	return out, wrap(rows.Err(), "listing enrolment tokens")
}

// CreateHost records a newly enrolled host.
func (p *Postgres) CreateHost(ctx context.Context, h Host) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO hosts (id, hostname, machine_id_hash, fleet_group, agent_version, enrolled_at)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6)`,
		h.ID, h.Hostname, h.MachineIDHash, h.Group, h.AgentVersion, h.EnrolledAt)
	return wrap(err, "creating a host")
}

// hostColumns is the column list every host query selects, in the order scanHost expects.
//
// It is a constant shared by the three queries that return a host so that adding a column is one edit
// rather than three, and so that the three cannot drift into returning different shapes.
const hostColumns = `
	id, hostname, COALESCE(machine_id_hash, ''), fleet_group, agent_version, enrolled_at,
	COALESCE(last_seen, 'epoch'::timestamptz), boot_id, uptime_seconds, clock_offset_seconds, paused,
	facts_digest, policy_digest, signers_digest,
	COALESCE(facts, 'null'::jsonb), COALESCE(policy, 'null'::jsonb), COALESCE(signers, 'null'::jsonb),
	revoked`

// scanHost reads one host row.
func scanHost(row pgx.Row) (Host, error) {
	var h Host
	err := row.Scan(&h.ID, &h.Hostname, &h.MachineIDHash, &h.Group, &h.AgentVersion, &h.EnrolledAt,
		&h.LastSeen, &h.BootID, &h.UptimeSeconds, &h.ClockOffsetSeconds, &h.Paused,
		&h.FactsDigest, &h.PolicyDigest, &h.SignersDigest,
		&h.Facts, &h.Policy, &h.Signers, &h.Revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if h.LastSeen.Unix() == 0 {
		h.LastSeen = time.Time{}
	}
	return h, wrap(err, "scanning a host")
}

// GetHost returns one host by id, or ErrNotFound.
func (p *Postgres) GetHost(ctx context.Context, id string) (Host, error) {
	return scanHost(p.pool.QueryRow(ctx, `SELECT `+hostColumns+` FROM hosts WHERE id = $1`, id))
}

// GetHostByMachineID returns the host with a machine-id hash, or ErrNotFound.
func (p *Postgres) GetHostByMachineID(ctx context.Context, hash string) (Host, error) {
	if hash == "" {
		return Host{}, ErrNotFound
	}
	return scanHost(p.pool.QueryRow(ctx,
		`SELECT `+hostColumns+` FROM hosts WHERE machine_id_hash = $1`, hash))
}

// ListHosts returns every host, ordered by hostname then id.
//
// The secondary sort on id matters: hostnames are not unique, and an unstable order makes the fleet
// list reshuffle between page loads for no reason a reader can see.
func (p *Postgres) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+hostColumns+` FROM hosts ORDER BY hostname, id`)
	if err != nil {
		return nil, wrap(err, "listing hosts")
	}
	defer rows.Close()

	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, wrap(rows.Err(), "listing hosts")
}

// RecordHeartbeat applies a heartbeat's fields to a host.
//
// Only the columns a heartbeat carries are written. Updating the whole row would let a heartbeat
// overwrite the enrolment group or the stored facts document with a zero value, which is the kind of
// bug that shows up as data quietly disappearing.
func (p *Postgres) RecordHeartbeat(ctx context.Context, hostID string, u HeartbeatUpdate) error {
	tag, err := p.pool.Exec(ctx, `
		UPDATE hosts
		   SET agent_version = $2, boot_id = $3, uptime_seconds = $4, clock_offset_seconds = $5,
		       paused = $6, facts_digest = $7, policy_digest = $8, signers_digest = $9, last_seen = $10
		 WHERE id = $1`,
		hostID, u.AgentVersion, u.BootID, u.UptimeSeconds, u.ClockOffsetSeconds,
		u.Paused, u.FactsDigest, u.PolicyDigest, u.SignersDigest, u.LastSeen)
	if err != nil {
		return wrap(err, "recording a heartbeat")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// StoreFacts records a full facts document and its digest.
func (p *Postgres) StoreFacts(ctx context.Context, hostID, digest string, document []byte) error {
	return p.storeDocument(ctx, hostID, "facts", "facts_digest", digest, document)
}

// StorePolicy records a host's effective policy and its digest.
func (p *Postgres) StorePolicy(ctx context.Context, hostID, digest string, document []byte) error {
	return p.storeDocument(ctx, hostID, "policy", "policy_digest", digest, document)
}

// StoreSigners records a host's trusted key identities and their digest.
func (p *Postgres) StoreSigners(ctx context.Context, hostID, digest string, document []byte) error {
	return p.storeDocument(ctx, hostID, "signers", "signers_digest", digest, document)
}

// storeDocument writes one JSONB column and its digest.
//
// The column names come from the three call sites above and never from anything external, which is why
// interpolating them into the statement is safe here and would not be anywhere a value is involved.
func (p *Postgres) storeDocument(ctx context.Context, hostID, column, digestColumn, digest string, document []byte) error {
	if !json.Valid(document) {
		return fmt.Errorf("store: %s document for host %s is not valid JSON", column, hostID)
	}
	stmt := fmt.Sprintf(`UPDATE hosts SET %s = $2, %s = $3 WHERE id = $1`, column, digestColumn)
	tag, err := p.pool.Exec(ctx, stmt, hostID, document, digest)
	if err != nil {
		return wrap(err, "storing a "+column+" document")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AddCertificate records an issued certificate by fingerprint.
func (p *Postgres) AddCertificate(ctx context.Context, c Certificate) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO certificates (fingerprint, host_id, serial, issued_at, not_after)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (fingerprint) DO NOTHING`,
		c.Fingerprint, c.HostID, c.Serial, c.IssuedAt, c.NotAfter)
	return wrap(err, "recording a certificate")
}

// LookupCertificate returns a certificate by fingerprint, or ErrNotFound.
//
// This runs on every authenticated request and is the revocation mechanism. It is a primary-key lookup
// precisely so that making it unconditional costs nothing worth optimising away.
func (p *Postgres) LookupCertificate(ctx context.Context, fingerprint string) (Certificate, error) {
	var c Certificate
	err := p.pool.QueryRow(ctx, `
		SELECT fingerprint, host_id, serial, issued_at, not_after, revoked,
		       COALESCE(revoked_at, 'epoch'::timestamptz)
		  FROM certificates WHERE fingerprint = $1`, fingerprint,
	).Scan(&c.Fingerprint, &c.HostID, &c.Serial, &c.IssuedAt, &c.NotAfter, &c.Revoked, &c.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	if c.RevokedAt.Unix() == 0 {
		c.RevokedAt = time.Time{}
	}
	return c, wrap(err, "looking up a certificate")
}

// RevokeHost marks a host and all its certificates as revoked.
//
// Both happen in one transaction, because a host marked revoked whose certificates were not would keep
// authenticating, and certificates revoked without the host would leave a host that could re-enrol.
func (p *Postgres) RevokeHost(ctx context.Context, hostID string) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return wrap(err, "revoking a host")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `UPDATE hosts SET revoked = true WHERE id = $1`, hostID)
	if err != nil {
		return wrap(err, "revoking a host")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`UPDATE certificates SET revoked = true, revoked_at = now() WHERE host_id = $1`, hostID,
	); err != nil {
		return wrap(err, "revoking a host's certificates")
	}
	return wrap(tx.Commit(ctx), "revoking a host")
}

// ClaimJobs atomically takes up to limit jobs for a host.
//
// FOR UPDATE SKIP LOCKED against the partial index is what lets the control plane run more than one
// replica: two instances claiming for the same host at the same moment take disjoint rows rather than
// blocking or double-delivering.
func (p *Postgres) ClaimJobs(ctx context.Context, hostID string, limit int) ([]protocol.Job, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := p.pool.Query(ctx, `
		WITH claimed AS (
			SELECT id FROM jobs
			 WHERE host_id = $1 AND claimed_at IS NULL AND completed_at IS NULL
			 ORDER BY issued_at
			 LIMIT $2
			 FOR UPDATE SKIP LOCKED
		)
		UPDATE jobs SET claimed_at = now()
		 WHERE id IN (SELECT id FROM claimed)
		RETURNING id, intent, params, class, issued_at, not_before, not_after, nonce,
		          COALESCE(signature, ''), COALESCE(signer_key_id, ''), COALESCE(signer_algorithm, '')`,
		hostID, limit)
	if err != nil {
		return nil, wrap(err, "claiming jobs")
	}
	defer rows.Close()

	var out []protocol.Job
	for rows.Next() {
		var j protocol.Job
		if err := rows.Scan(&j.ID, &j.Intent, &j.Params, &j.Class, &j.IssuedAt,
			&j.NotBefore, &j.NotAfter, &j.Nonce,
			&j.Signature, &j.SignerKeyID, &j.SignerAlgorithm); err != nil {
			return nil, wrap(err, "scanning a claimed job")
		}
		out = append(out, j)
	}
	return out, wrap(rows.Err(), "claiming jobs")
}

// RecordResult stores a job result idempotently, keyed by job id.
func (p *Postgres) RecordResult(ctx context.Context, hostID string, r protocol.ResultRequest) error {
	resultJSON := []byte("null")
	if r.Result != nil {
		encoded, err := json.Marshal(r.Result)
		if err != nil {
			return fmt.Errorf("store: encoding a job result: %w", err)
		}
		resultJSON = encoded
	}

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return wrap(err, "recording a job result")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// DO NOTHING rather than DO UPDATE. A repeated result means the first response was lost, not that
	// the work happened twice, and overwriting would replace a genuine record with a retry's view of
	// it.
	if _, err := tx.Exec(ctx, `
		INSERT INTO job_results (job_id, host_id, status, started_at, finished_at, exit_code,
		                         output, output_truncated, result, error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (job_id) DO NOTHING`,
		r.JobID, hostID, r.Status, r.StartedAt, r.FinishedAt, r.ExitCode,
		r.Output, r.OutputTruncated, resultJSON, r.Error,
	); err != nil {
		return wrap(err, "recording a job result")
	}
	if _, err := tx.Exec(ctx,
		`UPDATE jobs SET completed_at = COALESCE(completed_at, now()) WHERE id = $1 AND host_id = $2`,
		r.JobID, hostID,
	); err != nil {
		return wrap(err, "completing a job")
	}
	return wrap(tx.Commit(ctx), "recording a job result")
}

// WaitForJob blocks until a job may be available for a host, or the context ends.
//
// One connection LISTENs for the whole process and fans notifications out in memory. A design that
// opened a connection per waiting agent would need five hundred PostgreSQL connections to hold five
// hundred long-polls, which is more than most instances allow in total — so the fan-out is what makes
// the long-poll affordable at fleet scale.
func (p *Postgres) WaitForJob(ctx context.Context, hostID string) error {
	p.listenerOnce.Do(func() { go p.listen() })

	p.mu.Lock()
	wake := make(chan struct{})
	p.waiters[hostID] = append(p.waiters[hostID], wake)
	p.mu.Unlock()

	select {
	case <-wake:
		return nil
	case <-ctx.Done():
		p.removeWaiter(hostID, wake)
		return ctx.Err()
	case <-p.closed:
		return errors.New("store: closing")
	}
}

// removeWaiter drops a waiter that gave up before being woken.
//
// Without this, a fleet whose agents time out and reconnect every twenty-five seconds would accumulate
// dead channels for the process's lifetime — a slow leak that only shows up after a week of uptime,
// which is the worst kind.
func (p *Postgres) removeWaiter(hostID string, wake chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()

	waiters := p.waiters[hostID]
	for i, w := range waiters {
		if w == wake {
			p.waiters[hostID] = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(p.waiters[hostID]) == 0 {
		delete(p.waiters, hostID)
	}
}

// listen holds the single LISTEN connection and wakes waiters.
//
// It reconnects with backoff rather than exiting. Losing the listener silently would turn every
// long-poll into a plain twenty-five-second poll: still correct, still functional, and slower in a way
// nobody would notice until they wondered why jobs took half a minute to start.
func (p *Postgres) listen() {
	backoff := time.Second
	for {
		select {
		case <-p.closed:
			return
		default:
		}

		if err := p.listenOnce(); err != nil {
			select {
			case <-p.closed:
				return
			default:
			}
			slog.Error("job notification listener failed; retrying",
				"error", err, "retry_in", backoff)
			time.Sleep(backoff)
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

// listenOnce opens a dedicated connection, LISTENs, and relays notifications until it fails.
func (p *Postgres) listenOnce() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-p.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	conn, err := pgx.Connect(ctx, p.dsn)
	if err != nil {
		return fmt.Errorf("store: connecting the listener: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	if _, err := conn.Exec(ctx, "LISTEN "+jobChannel); err != nil {
		return fmt.Errorf("store: LISTEN %s: %w", jobChannel, err)
	}

	// Waking everyone once on connect closes the gap in which a job was inserted while the listener
	// was down. Spurious wake-ups are harmless — the caller re-checks the queue — and a missed one is
	// a job that sits until the next poll.
	p.wakeAll()

	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			return fmt.Errorf("store: waiting for a notification: %w", err)
		}
		p.wake(notification.Payload)
	}
}

// wake releases the waiters for one host.
func (p *Postgres) wake(hostID string) {
	p.mu.Lock()
	waiters := p.waiters[hostID]
	delete(p.waiters, hostID)
	p.mu.Unlock()

	for _, w := range waiters {
		close(w)
	}
}

// wakeAll releases every waiter, used after the listener reconnects.
func (p *Postgres) wakeAll() {
	p.mu.Lock()
	all := p.waiters
	p.waiters = map[string][]chan struct{}{}
	p.mu.Unlock()

	for _, waiters := range all {
		for _, w := range waiters {
			close(w)
		}
	}
}

// wrap adds context to a database error, translating the ones callers switch on.
//
// Unique-violation becomes ErrConflict so that handlers can return 409 without matching on a driver
// string, which is how a PostgreSQL upgrade turns a 409 into a 500.
func wrap(err error, what string) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: %s", ErrConflict, what)
	}
	return fmt.Errorf("store: %s: %w", what, err)
}

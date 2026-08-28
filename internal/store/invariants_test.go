package store

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGuaranteeATenantIDIsNeverEmpty pins the value the tenant boundary cannot survive.
//
// `current_setting('farrier.tenant', true)` returns NULL only until some transaction on that pooled
// connection has set it; afterwards, for the rest of the connection's life, an unset value reads as the
// empty string. Every isolation policy compares a tenant column against that setting. Comparing against
// NULL yields NULL, which admits nothing; comparing against the empty string is an ordinary comparison,
// which admits every row whose tenant is empty — so such a tenant would be the one fleet reachable by a
// statement that named no tenant at all, including every resolve-key lookup. Nothing errors; the wrong
// rows simply become readable.
//
// Asserted against both stores because the refusal has to be the same refusal. The reason is a
// PostgreSQL reason and does not apply to a map, and a memory store that accepted the value would let a
// test pass where the shipped store fails.
func TestGuaranteeATenantIDIsNeverEmpty(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		err := s.CreateTenant(context.Background(), Tenant{
			ID: "", Slug: "empty", DisplayName: "Empty", CreatedAt: time.Now().UTC(),
		})
		if err == nil {
			t.Fatal("a tenant with an empty id was created; every unscoped statement can now reach it")
		}
	})
}

// TestGuaranteeTheEmptyTenantIsRefusedByTheDatabaseNotOnlyByGo is the same rule one layer down.
//
// CreateTenant's own guard is the one a caller meets, and it is not the one that matters here: the
// failure this prevents arrives through an INSERT that never went near it — a maintenance script, a
// data import, a refactor that dropped the check. This inserts directly on the pool, past every line of
// Go, and requires the schema to refuse it.
func TestGuaranteeTheEmptyTenantIsRefusedByTheDatabaseNotOnlyByGo(t *testing.T) {
	pg := newPostgres(t)

	_, err := pg.pool.Exec(context.Background(),
		`INSERT INTO tenants (id, slug, display_name) VALUES ('', 'empty', 'Empty')`)
	if err == nil {
		t.Fatal("the schema accepted a tenant with an empty id. tenants_id_nonempty is missing, and " +
			"the invariant rests on every future writer remembering it")
	}
}

// TestGuaranteeTheResolveKeyExemptionIsReadOnly asserts the shape of every isolation policy at once.
//
// farrier.resolve_key exists for the lookups that must happen before the tenant is known, and what
// makes it narrow is that it admits one row whose key the caller already holds. In a `USING` clause
// that is a read of a row they could already name. In a `WITH CHECK` clause it is something else
// entirely: `farrier.tenant` is unset in exactly those transactions, so the tenant half of the
// predicate is NULL and the resolve-key half becomes the whole rule — a writer could create or move a
// row into any tenant, so long as its key matched the one they named.
//
// The sweep is over every policy rather than over a list of tables, because a list is a thing a new
// table is added without. It reads pg_policies, which is the database's own account of what is in
// force — not the migration files, which are what somebody meant to put there.
func TestGuaranteeTheResolveKeyExemptionIsReadOnly(t *testing.T) {
	pg := newPostgres(t)

	rows, err := pg.pool.Query(context.Background(), `
		SELECT tablename, policyname, with_check
		  FROM pg_policies
		 WHERE schemaname = current_schema()
		   AND with_check LIKE '%farrier.resolve_key%'`)
	if err != nil {
		t.Fatalf("reading the policies: %v", err)
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var table, policy, check string
		if err := rows.Scan(&table, &policy, &check); err != nil {
			t.Fatalf("scanning a policy: %v", err)
		}
		found = true
		t.Errorf("the WITH CHECK of %s on %s names farrier.resolve_key:\n  %s\n"+
			"The exemption is read-only. In a WITH CHECK it admits a write into any tenant whose row "+
			"carries the key the caller named, because farrier.tenant is unset in exactly the "+
			"transactions that set a resolve key.", policy, table, check)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading the policies: %v", err)
	}
	if found {
		return
	}

	// And the other half, without which the sweep above passes on a database with no policies at all:
	// the exemption must still exist where it is needed, in the reads.
	var reads int
	if err := pg.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM pg_policies
		 WHERE schemaname = current_schema()
		   AND qual LIKE '%farrier.resolve_key%'`).Scan(&reads); err != nil {
		t.Fatalf("counting the read exemptions: %v", err)
	}
	if reads == 0 {
		t.Error("no policy admits a row through farrier.resolve_key at all; the pre-tenant lookups " +
			"an agent request and a sign-in depend on cannot work, and the check above passed " +
			"because there was nothing to check")
	}
}

// TestGuaranteeConcurrentRenewalsCannotExceedTheCertificateCap is the check-then-act this replaced.
//
// The renewal limiter permits a burst, so several renewals for one host can be in flight at once. With
// the count and the insert in separate transactions each of them sees room and each takes it, and the
// host ends up holding more live certificates than the cap advertises — after which honest renewals are
// refused until the extra ones expire, which is the cap doing the opposite of its job.
//
// The assertion is on the count afterwards rather than on how many calls returned an error: a store that
// refused everything would satisfy "not more than three" and would be a control plane no host can renew
// against, so the successes are counted too.
func TestGuaranteeConcurrentRenewalsCannotExceedTheCertificateCap(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "renewals", ApprovalNone)
		host := enrolTestHost(t, tenant, "01JHOSTR", "web-01.example.org")

		const cap, racers = 3, 12
		now := time.Now().UTC()

		var admitted atomic.Int32
		var start sync.WaitGroup
		var done sync.WaitGroup
		start.Add(1)
		for i := range racers {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				err := tenant.RenewCertificate(ctx, Renewal{
					Replacement: Certificate{
						Fingerprint: "fp-renewal-" + strconv.Itoa(i),
						HostID:      host.ID,
						TenantID:    tenant.Tenant(),
						Serial:      "1" + strconv.Itoa(i),
						IssuedAt:    now,
						NotAfter:    now.Add(90 * 24 * time.Hour),
					},
					// Every racer presents the certificate enrolment issued, which is what a burst of
					// renewals from one host actually looks like.
					Presented:   "fp-" + string(tenant.Tenant()) + "-" + host.ID,
					SupersedeAt: now.Add(48 * time.Hour),
					MaxLive:     cap,
					Now:         now,
				})
				switch {
				case err == nil:
					admitted.Add(1)
				case errors.Is(err, ErrTooManyCertificates):
				default:
					t.Errorf("renewing: %v", err)
				}
			}()
		}
		start.Done()
		done.Wait()

		if admitted.Load() == 0 {
			t.Fatal("every concurrent renewal was refused; a host could never renew at all")
		}

		live, err := tenant.CountLiveCertificates(ctx, host.ID, now)
		if err != nil {
			t.Fatalf("counting: %v", err)
		}
		if live > cap {
			t.Errorf("%d concurrent renewals left %d live certificates against a cap of %d; the count "+
				"and the insert are not one decision", racers, live, cap)
		}
	})
}

// TestGuaranteeARefusedRenewalRetiresNothing is the other half of making the renewal one operation.
//
// Recording a replacement without retiring the presented certificate is not merely untidy, and it is not
// self-correcting: a later renewal retires the fingerprint *it* presents, which by then is the
// replacement, so a certificate forgotten once stays valid to its natural expiry with nothing pointing
// at it. The two writes therefore have to land together or not at all — and this is the "not at all"
// direction, which a refusal at the cap is the easiest way to reach.
func TestGuaranteeARefusedRenewalRetiresNothing(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "refused", ApprovalNone)
		host := enrolTestHost(t, tenant, "01JHOSTQ", "web-01.example.org")
		presented := "fp-" + string(tenant.Tenant()) + "-" + host.ID
		now := time.Now().UTC()

		// A cap of zero refuses the first renewal there could be, which is the shortest path to the
		// refusal branch and says nothing about which number the cap is.
		err := tenant.RenewCertificate(ctx, Renewal{
			Replacement: Certificate{
				Fingerprint: "fp-never-recorded", HostID: host.ID, TenantID: tenant.Tenant(),
				Serial: "99", IssuedAt: now, NotAfter: now.Add(90 * 24 * time.Hour),
			},
			Presented:   presented,
			SupersedeAt: now.Add(48 * time.Hour),
			MaxLive:     0,
			Now:         now,
		})
		if !errors.Is(err, ErrTooManyCertificates) {
			t.Fatalf("a renewal against a cap of zero returned %v, want ErrTooManyCertificates", err)
		}

		// The host still has the credential it came in with. A refusal that retired it anyway would
		// take a working host off the fleet for asking a question.
		live, err := tenant.CountLiveCertificates(ctx, host.ID, now)
		if err != nil {
			t.Fatalf("counting: %v", err)
		}
		if live != 1 {
			t.Errorf("a refused renewal left %d live certificates, want the 1 the host arrived with", live)
		}
	})
}

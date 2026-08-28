package store

import (
	"context"
	"testing"
	"time"
)

// TestGuaranteeATenantIDIsNeverEmpty pins the value the tenant boundary cannot survive.
//
// `current_setting('farrier.tenant', true)` returns NULL only until some transaction on that pooled
// connection has set it; afterwards, for the rest of the connection's life, an unset value reads as the
// empty string. Every isolation policy compares a tenant column against that setting, and `x = NULL` is
// NULL while `x = ''` is an ordinary comparison — so a tenant whose id were `''` would be the one fleet
// reachable by a statement that named no tenant at all, including every resolve-key lookup. Nothing
// errors; the wrong rows simply become readable.
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

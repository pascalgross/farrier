package store

import (
	"context"
	"fmt"
)

// ConnectionRole reports the database role this store connects as, and whether it can see through
// row-level security.
//
// It exists so that farrier-server can refuse to start on a role that would make tenant isolation a
// no-op. PostgreSQL exempts two kinds of role from every policy — a superuser, and one with BYPASSRLS —
// and the exemption is total: the policies are still in the schema, the predicates are still in the
// queries, and every query returns every tenant's rows anyway. There is no symptom. A control plane
// serving several customers in that state looks exactly like one that is working.
//
// It lives in its own file rather than among the queries because it is not one: it asks about the
// connection rather than about the data, and the answer is a deployment fact.
func (p *Postgres) ConnectionRole(ctx context.Context) (role string, superuser, bypassRLS bool, err error) {
	err = p.pool.QueryRow(ctx, `
		SELECT rolname, rolsuper, rolbypassrls
		  FROM pg_roles
		 WHERE rolname = current_user`).Scan(&role, &superuser, &bypassRLS)
	if err != nil {
		return "", false, false, fmt.Errorf("store: reading the current role: %w", err)
	}
	return role, superuser, bypassRLS, nil
}

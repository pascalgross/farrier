#!/bin/bash
# Create the role and database the control plane connects as.
#
# This is the single most consequential line in the whole deployment, and it looks like boilerplate.
# The image's POSTGRES_USER is the cluster's bootstrap superuser, and PostgreSQL exempts a superuser
# from every row-level security policy in the schema — so a control plane connected as it does not have
# a weakened tenant boundary, it has none, and nothing about the running system looks wrong. Hence an
# ordinary role that owns its own database. hostseal-server checks this for itself at startup and
# refuses to serve on a role that bypasses RLS; see docs/SECURITY.md §5.
#
# The bootstrap role cannot drop its own SUPERUSER attribute, so demoting it is not an alternative.
set -euo pipefail

: "${HOSTSEAL_DB_USER:?HOSTSEAL_DB_USER must be set}"
: "${HOSTSEAL_DB_PASSWORD:?HOSTSEAL_DB_PASSWORD must be set}"
: "${HOSTSEAL_DB_NAME:?HOSTSEAL_DB_NAME must be set}"

# Values reach SQL as psql variables rather than through the shell: :'x' quotes a literal and :"x"
# quotes an identifier, both by psql's own rules. A password with an apostrophe in it would otherwise
# end the string it is in, which is a way to turn a strong password into a syntax error at best.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
	-v user="$HOSTSEAL_DB_USER" -v password="$HOSTSEAL_DB_PASSWORD" -v db="$HOSTSEAL_DB_NAME" <<-'SQL'
	CREATE ROLE :"user" LOGIN PASSWORD :'password';
	CREATE DATABASE :"db" OWNER :"user";
SQL

# Said out loud, because the whole point is that the mistake this prevents has no symptom.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -tA \
	-v user="$HOSTSEAL_DB_USER" <<-'SQL'
	SELECT format(
		'hostseal: role %I is superuser=%s bypassrls=%s (both must be false, or tenants are not isolated)',
		rolname, rolsuper, rolbypassrls)
	FROM pg_roles WHERE rolname = :'user';
SQL

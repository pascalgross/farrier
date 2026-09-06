#!/bin/bash
# Create the replication role, and let it in through pg_hba.conf.
#
# Both halves exist on a cluster with no standby, on purpose. Adding a role is trivial; adding a pg_hba
# line to a primary that is already serving means a reload at the moment somebody is trying to build a
# replica under time pressure, and pg_hba is where that goes wrong quietly — a rejected walsender looks
# like a network problem from the standby's side.
#
# The role has REPLICATION and LOGIN and nothing else: it can stream WAL and take a base backup, and it
# cannot read a table. A standby copies the whole cluster anyway, which is the honest way to think about
# this credential — it is worth exactly as much as a database dump.
set -euo pipefail

: "${HOSTSEAL_REPLICATION_USER:?HOSTSEAL_REPLICATION_USER must be set}"
: "${HOSTSEAL_REPLICATION_PASSWORD:?HOSTSEAL_REPLICATION_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
	-v user="$HOSTSEAL_REPLICATION_USER" -v password="$HOSTSEAL_REPLICATION_PASSWORD" <<-'SQL'
	CREATE ROLE :"user" WITH REPLICATION LOGIN PASSWORD :'password';
SQL

# samenet by default: any address in a subnet this server is directly attached to, which inside Compose
# is the project's own network and nothing else. Set HOSTSEAL_REPLICATION_HBA to a CIDR when the standby
# is on another host — and then put the connection on a network you would be willing to send a base
# backup over, or in front of a TLS terminator, because scram-sha-256 authenticates the login and does
# not encrypt the stream that follows it.
hba_source="${HOSTSEAL_REPLICATION_HBA:-samenet}"

{
	printf '\n# Added by HostSeal: streaming replication and pg_basebackup for the role below.\n'
	printf 'host    replication    %s    %s    scram-sha-256\n' \
		"$HOSTSEAL_REPLICATION_USER" "$hba_source"
} >> "${PGDATA:?}/pg_hba.conf"

echo "hostseal: replication role $HOSTSEAL_REPLICATION_USER may connect from $hba_source"

#!/bin/bash
# Bring up a streaming standby: take a base backup on the first start, then be an ordinary PostgreSQL.
#
# It is a script rather than a documented sequence of commands because the sequence is short, and every
# minute of it happens when somebody is either building a replica for the first time or has just lost a
# primary. What it does not do is fail over — no automatic promotion, no leader election. A standby that
# promotes itself on a network partition is two primaries, and reconciling those means choosing which
# fleet's job results to throw away. Promotion is `pg_ctl promote`, run by a person who has decided.
set -euo pipefail

: "${HOSTSEAL_PRIMARY_HOST:?HOSTSEAL_PRIMARY_HOST must be set}"
: "${HOSTSEAL_REPLICATION_USER:?HOSTSEAL_REPLICATION_USER must be set}"
: "${HOSTSEAL_REPLICATION_PASSWORD:?HOSTSEAL_REPLICATION_PASSWORD must be set}"
primary_port="${HOSTSEAL_PRIMARY_PORT:-5432}"
slot="${HOSTSEAL_STANDBY_SLOT:-standby1}"
data="${PGDATA:?}"

# The password goes in a password file rather than into primary_conninfo, because pg_basebackup --write
# -recovery-conf writes primary_conninfo into postgresql.auto.conf — a file that ends up in this
# standby's own base backups, in a dump, and in anything that copies the data directory. libpq reads
# this file at every connection attempt, so streaming resumes after a restart without the password ever
# being written into the cluster's configuration.
export PGPASSFILE="${PGPASSFILE:-/var/lib/postgresql/.pgpass}"
(
	umask 077
	printf '%s:%s:*:%s:%s\n' \
		"$HOSTSEAL_PRIMARY_HOST" "$primary_port" "$HOSTSEAL_REPLICATION_USER" \
		"$HOSTSEAL_REPLICATION_PASSWORD" > "$PGPASSFILE"
)

if [ ! -s "$data/PG_VERSION" ]; then
	echo "hostseal: no data directory yet; taking a base backup from $HOSTSEAL_PRIMARY_HOST" >&2

	# The primary may still be initialising — on a first `compose up` the two containers start together,
	# and the primary runs its initdb scripts before it accepts connections. Waiting here rather than
	# relying on a restart loop keeps the reason legible in the logs.
	for _ in $(seq 1 60); do
		if pg_isready --host "$HOSTSEAL_PRIMARY_HOST" --port "$primary_port" \
			--username "$HOSTSEAL_REPLICATION_USER" --quiet; then
			break
		fi
		sleep 2
	done

	# --create-slot, so the slot exists before the first byte of the backup is read: without one, the
	# primary is free to recycle WAL written while the backup runs, and a base backup that finishes
	# against a primary that has moved on is a standby that can never start.
	#
	# --wal-method=stream fetches that WAL on a second connection as the backup proceeds, which is what
	# makes the result self-contained; --checkpoint=fast asks the primary to checkpoint now rather than
	# at its own pace, which is the difference between a backup starting in seconds and in minutes.
	if ! pg_basebackup \
		--host "$HOSTSEAL_PRIMARY_HOST" --port "$primary_port" \
		--username "$HOSTSEAL_REPLICATION_USER" --no-password \
		--pgdata "$data" --wal-method=stream --checkpoint=fast \
		--write-recovery-conf --create-slot --slot "$slot" --progress --verbose; then
		echo "hostseal: the base backup failed." >&2
		echo "  If the primary says the replication slot \"$slot\" already exists, this standby is" >&2
		echo "  being rebuilt: drop it there with" >&2
		echo "    SELECT pg_drop_replication_slot('$slot');" >&2
		echo "  or give this one a name of its own with HOSTSEAL_STANDBY_SLOT." >&2
		# Whatever the failed backup wrote is removed, so the next start begins from an empty directory
		# rather than from a data directory PostgreSQL would refuse and a base backup would not replace.
		# Only ever reached on a start that found the directory empty, so this can delete nothing that
		# was here before.
		find "$data" -mindepth 1 -delete
		exit 1
	fi

	# pg_basebackup reproduces the primary's permissions, but a directory that came from an older
	# primary or a restored archive may not; PostgreSQL refuses to start on anything wider.
	chmod 0700 "$data"
	echo "hostseal: base backup complete; starting as a hot standby on slot $slot" >&2
fi

# The image's own entry point from here: it finds a populated data directory, skips initialisation and
# starts the server, which reads standby.signal and begins streaming.
exec docker-entrypoint.sh postgres "$@"

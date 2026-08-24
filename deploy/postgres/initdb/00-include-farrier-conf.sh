#!/bin/bash
# Make the generated postgresql.conf read farrier.conf, from the end.
#
# The alternative — mounting a complete postgresql.conf, or passing every setting as a -c flag — either
# discards what initdb tuned for this container or moves the configuration into a place where nobody
# reading the database's own configuration would find it. An include line does neither, and because it
# is appended it wins over anything above it.
#
# This runs once, during the first start, on an empty data directory. Editing farrier.conf afterwards
# takes effect on the next reload or restart of the container, which is the behaviour somebody editing a
# configuration file expects; adding the include line to an existing cluster is a one-line manual step
# documented in deploy/README.md.
set -euo pipefail

conf="${PGDATA:?}/postgresql.conf"
include="include_if_exists = '/etc/postgresql/farrier.conf'"

# An if rather than an early `exit 0`: the image's entry point executes a script in this directory when
# it is executable and sources it when it is not, and an `exit` in a sourced script would end the
# initialisation with the scripts after this one silently never run.
if grep -qF "$include" "$conf"; then
	echo "farrier: postgresql.conf already includes /etc/postgresql/farrier.conf"
else
	{
		printf '\n# Added by Farrier: settings that make replication and point-in-time recovery possible\n'
		printf '# without a restart later. The file is mounted read-only from deploy/postgres/farrier.conf.\n'
		printf "%s\n" "$include"
	} >> "$conf"
	echo "farrier: postgresql.conf now includes /etc/postgresql/farrier.conf"
fi

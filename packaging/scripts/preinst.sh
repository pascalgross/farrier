#!/bin/sh
# Create the unprivileged system account the agent runs as.
#
# This runs before unpacking so that the directories nfpm creates with owner farrier have a user to
# belong to. The account has no login shell and no home directory of its own: it exists to own
# /var/lib/farrier and nothing else. It is deliberately never added to the docker group — Docker socket
# access is root equivalence and would silently undo every hardening line in farrier-agent.service.
set -e

case "$1" in
	install|upgrade)
		if ! getent group farrier >/dev/null 2>&1; then
			addgroup --system --quiet farrier
		fi
		if ! getent passwd farrier >/dev/null 2>&1; then
			adduser --system --quiet \
				--ingroup farrier \
				--no-create-home \
				--home /var/lib/farrier \
				--shell /usr/sbin/nologin \
				--gecos "Farrier fleet management agent" \
				farrier
		fi
		;;
esac

exit 0

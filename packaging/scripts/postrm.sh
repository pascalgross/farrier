#!/bin/sh
# Clean up after removal, and on purge remove the state this package created.
#
# The conffiles in /etc/farrier are removed by dpkg on purge, not here; this only takes the empty
# directory afterwards. State under /var/lib/farrier goes on purge and not on remove, so that
# removing and reinstalling the agent does not lose the host's identity, its pending job results or
# its machine-id salt.
set -e

case "$1" in
	purge)
		rm -rf /var/lib/farrier /var/log/farrier
		rmdir /etc/farrier 2>/dev/null || true

		if getent passwd farrier >/dev/null 2>&1; then
			deluser --system --quiet farrier >/dev/null 2>&1 || true
		fi
		if getent group farrier >/dev/null 2>&1; then
			delgroup --system --quiet farrier >/dev/null 2>&1 || true
		fi
		;;
	remove)
		if [ -d /run/systemd/system ]; then
			systemctl daemon-reload >/dev/null 2>&1 || true
		fi
		;;
esac

exit 0

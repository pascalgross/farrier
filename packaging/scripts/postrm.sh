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

# The sudoers file phase 0 shipped is gone, and dpkg does not remove a conffile just because a package
# stopped shipping it — it leaves it behind as an obsolete conffile, for ever. On a host upgraded from a
# build that had one, that would leave /etc/sudoers.d/farrier granting the farrier account passwordless
# root on all three helpers: a privilege grant nothing uses, that nobody would look for, arriving
# through the release that was supposed to remove it.
#
# The version guard covers every build that predates the socket boundary. No version has been released
# yet, so nothing on any real host matches; it is here because the cost of being wrong about that is a
# permanent hole, and the cost of being wrong the other way is three lines that never fire.
if command -v dpkg-maintscript-helper >/dev/null 2>&1; then
	dpkg-maintscript-helper rm_conffile /etc/sudoers.d/farrier 0.1.0~ farrier-agent -- "$@"
fi

exit 0

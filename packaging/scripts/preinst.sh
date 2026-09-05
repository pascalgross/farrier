#!/bin/sh
# Create the unprivileged system account the agent runs as.
#
# This runs before unpacking so that the directories nfpm creates with owner hostseal have a user to
# belong to. The account has no login shell and no home directory of its own: it exists to own
# /var/lib/hostseal and nothing else. It is deliberately never added to the docker group — Docker socket
# access is root equivalence and would silently undo every hardening line in hostseal-agent.service.
set -e

case "$1" in
	install|upgrade)
		if ! getent group hostseal >/dev/null 2>&1; then
			addgroup --system --quiet hostseal
		fi
		if ! getent passwd hostseal >/dev/null 2>&1; then
			adduser --system --quiet \
				--ingroup hostseal \
				--no-create-home \
				--home /var/lib/hostseal \
				--shell /usr/sbin/nologin \
				--gecos "HostSeal fleet management agent" \
				hostseal
		fi
		;;
esac

# The sudoers file phase 0 shipped is gone, and dpkg does not remove a conffile just because a package
# stopped shipping it — it leaves it behind as an obsolete conffile, for ever. On a host upgraded from a
# build that had one, that would leave /etc/sudoers.d/hostseal granting the hostseal account passwordless
# root on all three helpers: a privilege grant nothing uses, that nobody would look for, arriving
# through the release that was supposed to remove it.
#
# The version guard covers every build that predates the socket boundary. No version has been released
# yet, so nothing on any real host matches; it is here because the cost of being wrong about that is a
# permanent hole, and the cost of being wrong the other way is three lines that never fire.
if command -v dpkg-maintscript-helper >/dev/null 2>&1; then
	dpkg-maintscript-helper rm_conffile /etc/sudoers.d/hostseal 0.1.0~ hostseal-agent -- "$@"
fi

exit 0

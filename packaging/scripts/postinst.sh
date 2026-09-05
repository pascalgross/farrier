#!/bin/sh
# Finish installation: state directories, the machine-id salt, the helper sockets and the agent unit.
#
# Nothing here touches /etc/hostseal/policy.toml or /etc/hostseal/trusted-signers. They are dpkg
# conffiles and an administrator's edits must survive every upgrade; testfleet/ has a test that asserts
# exactly that, and it is a security test rather than a convenience one.
set -e

STATE_DIR=/var/lib/hostseal
SALT_FILE="$STATE_DIR/machine-id-salt"

case "$1" in
	configure)
		install -d -o hostseal -g hostseal -m 0750 "$STATE_DIR"
		install -d -o hostseal -g hostseal -m 0750 "$STATE_DIR/pending-results"
		install -d -o hostseal -g hostseal -m 0750 /var/log/hostseal

		# The raw /etc/machine-id is documented by systemd as confidential, so HostSeal transmits a
		# salted hash of it instead. The salt is generated here, per host, and never leaves the machine:
		# without it, the same hash from two fleets would be correlatable by whoever saw both.
		if [ ! -s "$SALT_FILE" ]; then
			old_umask=$(umask)
			umask 077
			head -c 32 /dev/urandom | base64 > "$SALT_FILE"
			umask "$old_umask"
			chown hostseal:hostseal "$SALT_FILE"
			chmod 0600 "$SALT_FILE"
		fi

		if [ -d /run/systemd/system ]; then
			systemctl daemon-reload >/dev/null 2>&1 || true

			# /run is a tmpfs, so at boot the directory comes from tmpfiles.d before sockets.target.
			# This is the install-time case, where the sockets are about to start and the directory
			# they live in does not exist yet.
			systemd-tmpfiles --create /usr/lib/tmpfiles.d/hostseal.conf >/dev/null 2>&1 || true

			# The three helper sockets are the agent's only route to root. They are enabled and started
			# here rather than left to the agent, because a host whose sockets never came up is one that
			# reports perfectly and silently cannot be patched — and the symptom would appear weeks
			# later, as a job that failed.
			for socket in hostseal-apply-updates hostseal-restart-unit hostseal-reboot-host; do
				systemctl enable "$socket.socket" >/dev/null 2>&1 || true
				systemctl restart "$socket.socket" >/dev/null 2>&1 || true
			done

			systemctl enable hostseal-agent.service >/dev/null 2>&1 || true
			if systemctl is-active --quiet hostseal-agent.service; then
				systemctl try-restart hostseal-agent.service >/dev/null 2>&1 || true
			else
				systemctl start hostseal-agent.service >/dev/null 2>&1 || true
			fi
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

#!/bin/sh
# Finish installation: state directories, the machine-id salt, and the systemd unit.
#
# Nothing here touches /etc/farrier/policy.toml or /etc/farrier/trusted-signers. They are dpkg
# conffiles and an administrator's edits must survive every upgrade; testfleet/ has a test that asserts
# exactly that, and it is a security test rather than a convenience one.
set -e

STATE_DIR=/var/lib/farrier
SALT_FILE="$STATE_DIR/machine-id-salt"

case "$1" in
	configure)
		install -d -o farrier -g farrier -m 0750 "$STATE_DIR"
		install -d -o farrier -g farrier -m 0750 "$STATE_DIR/pending-results"
		install -d -o farrier -g farrier -m 0750 /var/log/farrier

		# The raw /etc/machine-id is documented by systemd as confidential, so Farrier transmits a
		# salted hash of it instead. The salt is generated here, per host, and never leaves the machine:
		# without it, the same hash from two fleets would be correlatable by whoever saw both.
		if [ ! -s "$SALT_FILE" ]; then
			old_umask=$(umask)
			umask 077
			head -c 32 /dev/urandom | base64 > "$SALT_FILE"
			umask "$old_umask"
			chown farrier:farrier "$SALT_FILE"
			chmod 0600 "$SALT_FILE"
		fi

		if [ -d /run/systemd/system ]; then
			systemctl daemon-reload >/dev/null 2>&1 || true
			systemctl enable farrier-agent.service >/dev/null 2>&1 || true
			if systemctl is-active --quiet farrier-agent.service; then
				systemctl try-restart farrier-agent.service >/dev/null 2>&1 || true
			else
				systemctl start farrier-agent.service >/dev/null 2>&1 || true
			fi
		fi
		;;
esac

exit 0

#!/bin/sh
# Stop the agent and its helper sockets before they are removed.
#
# Only on an actual removal. On an upgrade the unit is left running and postinst restarts it, so that
# an agent upgrade does not open a window in which the host is unmonitored.
set -e

case "$1" in
	remove|deconfigure)
		if [ -d /run/systemd/system ]; then
			systemctl stop farrier-agent.service >/dev/null 2>&1 || true
			systemctl disable farrier-agent.service >/dev/null 2>&1 || true

			# The sockets go with it. Leaving an enabled socket behind that activates a binary the
			# next line is about to delete would turn every connection into a failed unit start, for
			# ever, on a machine where Farrier is no longer installed.
			for socket in farrier-apply-updates farrier-restart-unit farrier-reboot-host; do
				systemctl stop "$socket.socket" >/dev/null 2>&1 || true
				systemctl disable "$socket.socket" >/dev/null 2>&1 || true
			done
		fi
		;;
esac

exit 0

#!/bin/sh
# Stop the agent before it is removed.
#
# Only on an actual removal. On an upgrade the unit is left running and postinst restarts it, so that
# an agent upgrade does not open a window in which the host is unmonitored.
set -e

case "$1" in
	remove|deconfigure)
		if [ -d /run/systemd/system ]; then
			systemctl stop farrier-agent.service >/dev/null 2>&1 || true
			systemctl disable farrier-agent.service >/dev/null 2>&1 || true
		fi
		;;
esac

exit 0

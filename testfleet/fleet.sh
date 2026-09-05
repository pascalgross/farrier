#!/usr/bin/env bash
# Drive a real fleet of Ubuntu and Debian machines against the real .deb.
#
# This exists because the failures HostSeal most needs to avoid do not reproduce against mocks. A
# conffile prompt that hangs, a reboot marker that is an Ubuntu convention rather than a standard, a
# package upgrade that quietly replaces a trust anchor, a job result lost because the machine went away
# before it was sent — every one of those is a property of a real machine running a real package
# manager, and a test double would confirm whatever the double's author believed.
#
# Usage:
#   ./fleet.sh up                 launch the fleet and install the package
#   ./fleet.sh test [scenario…]   run scenarios, all of them by default
#   ./fleet.sh shell <release>    open a shell on one machine
#   ./fleet.sh down               destroy the fleet
#   ./fleet.sh ci                 up, test, down — what the integration workflow runs
#
# Environment:
#   HOSTSEAL_RELEASES   which releases to cover, space-separated
#   HOSTSEAL_VM=0       use system containers instead of virtual machines; faster, and the reboot
#                      scenarios then test rather less than they claim to
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$HERE/.." && pwd)
# shellcheck source=testfleet/lib.sh
. "$HERE/lib.sh"

# require_lxd fails early with an instruction rather than late with a confusing error.
require_lxd() {
	command -v lxc >/dev/null 2>&1 || {
		echo "lxc is not installed. On Ubuntu: sudo snap install lxd && sudo lxd init --auto" >&2
		exit 1
	}
}

# build_package builds the .deb the fleet installs.
#
# The fleet installs the same artefact a user would, from the same Makefile target. A harness that built
# differently would be testing a build nobody ships.
build_package() {
	say "building the package"
	local version=${HOSTSEAL_TEST_VERSION:-0.0.0-testfleet}
	make -C "$REPO" deb VERSION="$version" >/dev/null
	# The path comes from the Makefile rather than a glob: `make deb` never empties dist/packages, so a
	# glob would happily install whichever package happened to sort first from an earlier run.
	make -s -C "$REPO" deb-path VERSION="$version"
}

# up launches every machine and installs the package on it.
up() {
	require_lxd
	local deb
	deb=$(build_package)
	[ -f "$deb" ] || { echo "the package was not built at $deb" >&2; exit 1; }
	say "built $deb"

	for release in $HOSTSEAL_RELEASES; do
		local instance
		instance=$(instance_name "$release")

		if lxc info "$instance" >/dev/null 2>&1; then
			say "$instance already exists"
		else
			say "launching $instance from $(lxd_image "$release")"
			if [ "$HOSTSEAL_VM" = "1" ]; then
				lxc launch "$(lxd_image "$release")" "$instance" --vm -c limits.memory=1GiB
			else
				lxc launch "$(lxd_image "$release")" "$instance"
			fi
		fi

		wait_for_boot "$instance"

		say "installing on $instance"
		lxc file push "$deb" "$instance/tmp/hostseal-agent.deb"
		# unattended-upgrades and needrestart are Recommends and are installed here deliberately: the
		# scenarios test what HostSeal does with them present, and a fleet that skipped them would be
		# testing the degraded path only.
		run_sh "$instance" 'export DEBIAN_FRONTEND=noninteractive
			apt-get update -qq
			apt-get install -y -qq unattended-upgrades needrestart
			apt-get install -y -qq /tmp/hostseal-agent.deb'
		wait_for_agent "$instance"
		pass "$instance is up with $(run "$instance" hostseal-agent version)"
	done
}

# down destroys every machine.
down() {
	require_lxd
	for release in $HOSTSEAL_RELEASES; do
		local instance
		instance=$(instance_name "$release")
		if lxc info "$instance" >/dev/null 2>&1; then
			say "deleting $instance"
			lxc delete --force "$instance"
		fi
	done
}

# test runs the scenarios.
test_fleet() {
	require_lxd
	local requested=("$@")
	if [ "${#requested[@]}" -eq 0 ]; then
		mapfile -t requested < <(find "$HERE/scenarios" -name '*.sh' -printf '%f\n' | sort | sed 's/\.sh$//')
	fi

	local failures=0
	for scenario in "${requested[@]}"; do
		local script="$HERE/scenarios/${scenario}.sh"
		[ -f "$script" ] || { echo "no such scenario: $scenario" >&2; exit 1; }

		for release in $HOSTSEAL_RELEASES; do
			local instance
			instance=$(instance_name "$release")
			say "$scenario on $release"
			if REPO="$REPO" INSTANCE="$instance" RELEASE="$release" bash "$script"; then
				pass "$scenario on $release"
			else
				fail "$scenario on $release" || true
				journal "$instance"
				failures=$((failures + 1))
			fi
		done
	done

	if [ "$failures" -ne 0 ]; then
		echo >&2
		echo "$failures scenario run(s) failed." >&2
		exit 1
	fi
	echo
	say "every scenario passed on every release"
}

# shell opens an interactive shell on one machine.
shell() {
	require_lxd
	local release=${1:?usage: fleet.sh shell <release>}
	lxc exec "$(instance_name "$release")" -- bash
}

case "${1:-}" in
	up) up ;;
	down) down ;;
	test) shift; test_fleet "$@" ;;
	shell) shift; shell "$@" ;;
	ci)
		# The trap is installed before `up`, not after: a failure inside up — a launch that fails, a
		# boot that times out — would otherwise leave machines running on a shared runner.
		trap down EXIT
		up
		test_fleet
		;;
	*)
		sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		exit 2
		;;
esac

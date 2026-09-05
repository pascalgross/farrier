#!/usr/bin/env bash
# Shared helpers for the HostSeal test fleet.
#
# Sourced by fleet.sh and by every scenario. Nothing here is clever: the value of this harness is that
# it drives real machines running the real .deb, so the helpers exist to keep the scenarios readable
# rather than to abstract anything.

set -euo pipefail

# The releases the fleet covers.
#
# It is the support policy written out: the Ubuntu LTS releases in standard support, plus Debian stable
# and oldstable. Ubuntu 20.04 is absent because it is ESM-only. Every scenario runs on all five, because
# the differences that matter between them — security-origin patterns, the reboot marker, whether
# needrestart is present — produce silent wrong answers rather than errors, and a harness that tested
# one release would confirm the wrong answer.
HOSTSEAL_RELEASES=${HOSTSEAL_RELEASES:-"ubuntu/22.04 ubuntu/24.04 ubuntu/26.04 debian/12 debian/13"}

# The prefix every instance name carries, so a stray instance is obviously ours.
HOSTSEAL_PREFIX=${HOSTSEAL_PREFIX:-hostseal-test}

# Whether to launch virtual machines or system containers.
#
# Virtual machines are the default and are what the reboot scenarios need: a container's "reboot" does
# not exercise the thing being tested, which is that a job result fsynced before the machine goes down
# is delivered after it comes back. Containers are faster and are offered for the local edit-run loop.
HOSTSEAL_VM=${HOSTSEAL_VM:-1}

# ANSI colours, disabled when the output is not a terminal so log files stay readable.
if [ -t 1 ]; then
	C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
else
	C_RESET=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''
fi

# say prints a progress line.
# Narration goes to stderr, not stdout. build_package returns the package path by printing it, so a
# progress line on stdout ends up inside the caller's variable — which is exactly how the fleet spent a
# run reporting that it could not find a package at a path with a status message glued to the front.
say() { printf '%s==>%s %s\n' "$C_DIM" "$C_RESET" "$*" >&2; }

# pass records a scenario assertion that held.
pass() { printf '%s  ✓%s %s\n' "$C_GREEN" "$C_RESET" "$*" >&2; }

# fail records a scenario assertion that did not hold, and stops the scenario.
fail() { printf '%s  ✗%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; return 1; }

# skip records an assertion that cannot run yet, with the reason.
#
# It exists so that a scenario which depends on write capability is visible as pending rather than
# quietly absent. A test suite whose gaps are invisible is one whose coverage is a guess.
skip() { printf '%s  ↷%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }

# instance_name renders the LXD instance name for a release.
instance_name() {
	local release=$1
	printf '%s-%s' "$HOSTSEAL_PREFIX" "${release//[\/.]/-}"
}

# lxd_image renders the image alias for a release, choosing the remote by distribution.
#
# Ubuntu comes from the `ubuntu:` remote and everything else from `images:`. They used to be the same
# remote; the community `images:` server stopped publishing Ubuntu, so `images:ubuntu/24.04` is now not
# a stale image but no image at all — which is a launch failure that reads like a broken harness rather
# than like a changed upstream.
lxd_image() {
	local release=$1
	case "$release" in
	ubuntu/*) printf 'ubuntu:%s' "${release#ubuntu/}" ;;
	*) printf 'images:%s' "$release" ;;
	esac
}

# run executes a command inside an instance and returns its exit status.
run() {
	local instance=$1; shift
	lxc exec "$instance" -- "$@"
}

# run_sh executes a shell snippet inside an instance.
#
# The harness may use a shell inside the instances it drives; the rule against assembling shell
# invocations is about the shipped agent and helpers, which is why internal/intent's source scan
# excludes this directory.
run_sh() {
	local instance=$1; shift
	lxc exec "$instance" -- sh -euc "$*"
}

# wait_for_agent blocks until the agent unit is running, or fails after a timeout.
wait_for_agent() {
	local instance=$1 deadline=$((SECONDS + 120))
	while [ "$SECONDS" -lt "$deadline" ]; do
		if run "$instance" systemctl is-active --quiet hostseal-agent.service; then
			return 0
		fi
		sleep 2
	done
	fail "hostseal-agent did not become active on $instance"
}

# wait_for_boot blocks until an instance has finished booting.
wait_for_boot() {
	local instance=$1 deadline=$((SECONDS + 300))
	while [ "$SECONDS" -lt "$deadline" ]; do
		if run "$instance" systemctl is-system-running --wait >/dev/null 2>&1; then
			return 0
		fi
		# is-system-running exits non-zero in the "degraded" state, which is normal on a minimal image
		# with a masked unit or two and is not a reason to wait any longer.
		if run "$instance" test -d /run/systemd/system >/dev/null 2>&1 &&
			run "$instance" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'; then
			return 0
		fi
		sleep 3
	done
	fail "$instance did not finish booting"
}

# journal prints an instance's HostSeal journal, for a failing scenario's output.
journal() {
	local instance=$1
	run "$instance" journalctl -u hostseal-agent.service --no-pager -n 60 2>/dev/null || true
}

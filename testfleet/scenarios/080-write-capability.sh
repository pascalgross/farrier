#!/usr/bin/env bash
# The write capability exists, and is bounded by the file the control plane cannot touch.
#
# This scenario used to assert the opposite. Phase 0 shipped no executors, and it checked that every
# privileged helper exited 4 under a deliberately permissive policy — with a note saying it was expected
# to stop passing when phase 1 began, and that the failure was the notification. Phase 1 has begun, so
# here is the deliberate, visible replacement.
#
# What it asserts now is the harder half. That a host *can* be changed is easy to demonstrate and worth
# little on its own; what matters is that the shipped policy refuses everything, that a permissive one
# permits exactly what it names, and that the answer comes from /etc/farrier/policy.toml rather than
# from anything the caller said.
#
# Two operations are deliberately never carried out for real: applying updates would dist-upgrade the
# instance and make every later assertion in the run a measurement of a different machine, and rebooting
# it is 070's job. Both are exercised through --dry-run, which evaluates the same decision through the
# same code and stops before acting.
set -euo pipefail
# shellcheck source=testfleet/lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/../lib.sh"

: "${INSTANCE:?}" "${REPO:?}"

# ---------------------------------------------------------------------------------------------------
# Under the shipped policy, a fresh host refuses everything privileged.
# ---------------------------------------------------------------------------------------------------

check_refused() {
	local description=$1; shift
	local status=0
	run_sh "$INSTANCE" "$*" >/dev/null 2>&1 || status=$?
	# 3 is "refused by local policy". 4 would mean "no executor in this build", which is what phase 0
	# answered and must never be the reason again — a host that refuses because the executor is missing
	# looks identical on a dashboard to one that refuses because its administrator said no.
	case "$status" in
		3) pass "$description is refused by local policy" ;;
		4) fail "$description exited 4: this build has no executor, which is a phase 0 answer" ;;
		*) fail "$description exited $status, expected 3 (refused by local policy)" ;;
	esac
}

# These are real invocations, not dry runs. The shipped policy has restartable = [] and reboot =
# "never", so the refusal happens before anything is done — and running them for real is what makes the
# exit-4 branch above reachable at all. A dry run cannot reach an executor, so it could never tell us
# whether one exists.
check_refused "restarting a unit" \
	'/usr/libexec/farrier/restart-unit --action restart --unit farrier-agent.service'
check_refused "rebooting" \
	'/usr/libexec/farrier/reboot-host'

# Updates are the one exception, and stay a dry run even here. If the shipped policy were ever wrong
# about allow = "security", the cost of finding that out with a real invocation is a dist-upgraded
# instance and every later assertion in this run measuring a different machine.
check_refused "applying all updates" \
	'/usr/libexec/farrier/apply-updates --intent packages.applyAll --dry-run'

# ---------------------------------------------------------------------------------------------------
# Under a permissive policy, the same operations are permitted — and one of them actually happens.
# ---------------------------------------------------------------------------------------------------

say "installing a permissive policy"
run_sh "$INSTANCE" 'cat > /etc/farrier/policy.toml <<TOML
[updates]
allow = "all"
auto_apply = true
window = "daily 00:00-00:00"
timezone = "UTC"
reboot = "window"

[services]
restartable = ["farrier-agent.service"]

[limits]
max_job_age_seconds = 900
TOML'
run "$INSTANCE" farrier-agent policy check >/dev/null || fail "the permissive fixture does not parse"

check_permitted() {
	local description=$1; shift
	run_sh "$INSTANCE" "$*" >/dev/null 2>&1 \
		|| fail "$description was refused under a policy that permits it"
	pass "$description is permitted when the policy says so"
}

check_permitted "applying all updates" \
	'/usr/libexec/farrier/apply-updates --intent packages.applyAll --dry-run'
check_permitted "rebooting inside an open window" \
	'/usr/libexec/farrier/reboot-host --dry-run'

# The one operation that is carried out rather than evaluated. farrier-agent.service is chosen because
# it exists on every instance by definition and restarting it costs nothing; a unit that only some
# releases ship would make this assertion skip on exactly the machine it needed to run on.
say "restarting a permitted unit for real"
before=$(run_sh "$INSTANCE" 'systemctl show farrier-agent.service --property=ExecMainStartTimestampMonotonic --value')
run_sh "$INSTANCE" '/usr/libexec/farrier/restart-unit --action restart --unit farrier-agent.service' \
	>/dev/null || fail "the helper could not restart a unit the policy permits"
after=$(run_sh "$INSTANCE" 'systemctl show farrier-agent.service --property=ExecMainStartTimestampMonotonic --value')
[ "$before" != "$after" ] || fail "the helper reported success but the unit did not restart"
run "$INSTANCE" systemctl is-active --quiet farrier-agent.service \
	|| fail "the unit is not running after the helper restarted it"
pass "a permitted unit was actually restarted, and the unit is running afterwards"

# A unit the policy does not name is still refused, under the same permissive policy. This is the check
# that proves the restart above came from services.restartable rather than from allow = "all".
status=0
run_sh "$INSTANCE" '/usr/libexec/farrier/restart-unit --action stop --unit systemd-journald.service' \
	>/dev/null 2>&1 || status=$?
[ "$status" -eq 3 ] || fail "stopping an unnamed unit exited $status, expected 3"
pass "a unit outside services.restartable is refused even under a permissive policy"

# ---------------------------------------------------------------------------------------------------
# The pause marker still outranks all of it.
# ---------------------------------------------------------------------------------------------------

run "$INSTANCE" touch /etc/farrier/paused
status=0
run_sh "$INSTANCE" '/usr/libexec/farrier/restart-unit --action restart --unit farrier-agent.service' \
	>/dev/null 2>&1 || status=$?
[ "$status" -eq 3 ] || fail "a paused host exited $status on a permitted restart, expected 3"
run "$INSTANCE" rm -f /etc/farrier/paused
pass "the pause marker refuses an operation the policy permits and an executor exists for"

# ---------------------------------------------------------------------------------------------------
# The structure of the privileged path, which no phase changes.
# ---------------------------------------------------------------------------------------------------

count=$(run_sh "$INSTANCE" 'ls -1 /usr/libexec/farrier | wc -l')
[ "$count" -eq 3 ] || fail "there are $count root helpers, expected exactly 3"
pass "there are exactly three root helpers"

for helper in apply-updates restart-unit reboot-host; do
	run_sh "$INSTANCE" "! /usr/libexec/farrier/$helper --help 2>&1 | grep -qiE 'command|script|exec|shell'" \
		|| fail "$helper advertises an option that names a program to run"
done
pass "no helper accepts a command, a script or a path to execute"

# And there is no second way in. The helpers are reachable over their sockets and by a root shell; the
# sudoers entry that phase 0 shipped is gone, and its absence is asserted rather than assumed.
run_sh "$INSTANCE" '[ ! -e /etc/sudoers.d/farrier ]' \
	|| fail "an /etc/sudoers.d/farrier survives; there must be exactly one privileged path"
run_sh "$INSTANCE" 'sudo -u farrier farrier-agent doctor' >/dev/null \
	|| fail "the agent's own account cannot reach the root helpers"
pass "the socket is the only privileged path, and the agent's account can reach it"

say "restoring the shipped policy"
lxc file push "$REPO/packaging/policy.toml" "$INSTANCE/etc/farrier/policy.toml"

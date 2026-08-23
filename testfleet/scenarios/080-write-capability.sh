#!/usr/bin/env bash
# This build ships no write capability at all.
#
# It is asserted on a real machine, against the installed package, because "phase 0 ships no write
# capability" is a claim about what an operator receives rather than about what the source says. The
# scenario is expected to *stop passing* when phase 1 lands, and the failure is the notification.
set -euo pipefail
# shellcheck source=testfleet/lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/../lib.sh"

: "${INSTANCE:?}" "${REPO:?}"

# A permissive policy, so a refusal here cannot be the policy's doing.
run_sh "$INSTANCE" 'cat > /etc/farrier/policy.toml <<TOML
[updates]
allow = "all"
auto_apply = true
window = "daily 00:00-00:00"
timezone = "UTC"
reboot = "window"

[services]
restartable = ["nginx.service"]

[limits]
max_job_age_seconds = 900
TOML'
run "$INSTANCE" farrier-agent policy check >/dev/null || fail "the permissive fixture does not parse"

check_not_implemented() {
	local description=$1; shift
	local status=0
	run_sh "$INSTANCE" "$*" >/dev/null 2>&1 || status=$?
	# 4 is "no executor in this build". 3 would mean the policy refused, which would make this scenario
	# prove nothing, so the two are distinguished rather than both accepted.
	[ "$status" -eq 4 ] || fail "$description exited $status, expected 4 (no executor)"
	pass "$description is refused for want of an executor"
}

check_not_implemented "applying all updates" \
	'/usr/libexec/farrier/apply-updates --intent packages.applyAll'
check_not_implemented "applying security updates" \
	'/usr/libexec/farrier/apply-updates --intent packages.applySecurity'
check_not_implemented "restarting a permitted unit" \
	'/usr/libexec/farrier/restart-unit --action restart --unit nginx.service'
check_not_implemented "rebooting inside an open window" \
	'/usr/libexec/farrier/reboot-host'

# There is no fourth helper, and there never will be one that runs a configured command.
count=$(run_sh "$INSTANCE" 'ls -1 /usr/libexec/farrier | wc -l')
[ "$count" -eq 3 ] || fail "there are $count root helpers, expected exactly 3"
pass "there are exactly three root helpers"

# And none of them accepts a program to run.
#
# The "Usage of ..." header is dropped before matching. It carries the helper's own path, and
# that path contains /usr/libexec — so searching the whole output finds `exec` in the install
# directory and reports every helper as advertising an option it does not have. The property
# being asserted belongs to the options, so only the option lines are searched.
for helper in apply-updates restart-unit reboot-host; do
	run_sh "$INSTANCE" "! /usr/libexec/farrier/$helper --help 2>&1 | grep -v '^Usage of ' | grep -qiE 'command|script|exec|shell'" \
		|| fail "$helper advertises an option that names a program to run"
done
pass "no helper accepts a command, a script or a path to execute"

say "restoring the shipped policy"
lxc file push "$REPO/packaging/policy.toml" "$INSTANCE/etc/farrier/policy.toml"

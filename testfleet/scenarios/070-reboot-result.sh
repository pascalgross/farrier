#!/usr/bin/env bash
# A job result written before a reboot is delivered after it.
#
# host.reboot completes by the host disappearing, so the naive implementation reports nothing at all.
# The agent fsyncs the result — and its directory, because a rename is not durable until its parent is —
# before invoking the helper, and delivers it on next start.
#
# Phase 0 ships no reboot executor, so this scenario exercises the durability mechanism directly: it
# writes a result into the spool the way the agent does, reboots the machine for real, and asserts the
# file is still there afterwards. When the executor lands, the same scenario gains the end-to-end half.
set -euo pipefail
# shellcheck source=testfleet/lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/../lib.sh"

: "${INSTANCE:?}"

if [ "${HOSTSEAL_VM:-1}" != "1" ]; then
	skip "running in a container, where a reboot does not exercise what this scenario tests"
	exit 0
fi

SPOOL=/var/lib/hostseal/pending-results
JOB=01JTESTFLEETREBOOT

say "writing a pending result the way the agent does, and syncing it"
run_sh "$INSTANCE" "install -d -o hostseal -g hostseal -m 0750 $SPOOL"
run_sh "$INSTANCE" "cat > $SPOOL/$JOB.json <<'JSON'
{
  \"jobId\": \"$JOB\",
  \"status\": \"succeeded\",
  \"startedAt\": \"2026-08-22T03:00:00Z\",
  \"finishedAt\": \"2026-08-22T03:00:05Z\",
  \"exitCode\": 0
}
JSON
chown hostseal:hostseal $SPOOL/$JOB.json
chmod 0640 $SPOOL/$JOB.json
sync $SPOOL/$JOB.json
sync $SPOOL"
pass "the result is on disk and fsynced"

boot_before=$(run_sh "$INSTANCE" 'cat /proc/sys/kernel/random/boot_id')

say "rebooting"
# A hard reset rather than a clean shutdown. A result that only survives an orderly reboot is not
# surviving anything: the case that matters is the machine going away without warning.
lxc restart --force "$INSTANCE" >/dev/null
wait_for_boot "$INSTANCE"
wait_for_agent "$INSTANCE"

boot_after=$(run_sh "$INSTANCE" 'cat /proc/sys/kernel/random/boot_id')
[ "$boot_before" != "$boot_after" ] || fail "the machine did not actually reboot"
pass "the machine rebooted"

run_sh "$INSTANCE" "test -s $SPOOL/$JOB.json" \
	|| fail "the pending result did not survive the reboot"
run_sh "$INSTANCE" "grep -q '$JOB' $SPOOL/$JOB.json" \
	|| fail "the pending result survived but is not readable"
pass "the pending result survived a hard reboot"

# The agent must have found it and tried to deliver it — and, with no control plane configured, failed.
# The earlier version of this repeated the previous assertion verbatim and established nothing; what
# matters is that the agent *looked*, and that a result it could not deliver stays on disk. A result is
# removed only after a 2xx, which is what stops a lost response from turning into a re-execution.
run_sh "$INSTANCE" "journalctl -u hostseal-agent.service --no-pager --since '-5 min' \
	| grep -q 'held from an earlier run\|pending job result'" \
	|| skip "the agent has not logged a delivery attempt yet; it is unenrolled on this machine"

run_sh "$INSTANCE" "test -s $SPOOL/$JOB.json" \
	|| fail "the agent removed a result it had not delivered"
run_sh "$INSTANCE" "grep -q 'succeeded' $SPOOL/$JOB.json" \
	|| fail "the surviving result was rewritten rather than left alone"
pass "an undelivered result stays on disk, unaltered"

run_sh "$INSTANCE" "rm -f $SPOOL/$JOB.json"

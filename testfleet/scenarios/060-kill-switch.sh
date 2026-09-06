#!/usr/bin/env bash
# The local kill switch is one the control plane cannot override.
#
# `systemctl stop hostseal-agent` and `/etc/hostseal/paused` are the two ways an administrator stops a host
# from acting, and there is deliberately no agent.resume intent: an off switch that something else can
# flip back on is not an off switch. This asserts both halves on a real machine.
set -euo pipefail
# shellcheck source=testfleet/lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/../lib.sh"

: "${INSTANCE:?}"

say "creating /etc/hostseal/paused"
run "$INSTANCE" touch /etc/hostseal/paused

run_sh "$INSTANCE" 'hostseal-agent policy check | grep -q "^paused *true"' \
	|| fail "the agent does not report itself paused"
pass "the agent reports itself paused"

# Every privileged path must refuse while the marker exists, including one the policy would otherwise
# permit. Pausing a host means pausing it, not pausing the interesting half.
run_sh "$INSTANCE" "sed -i 's/^restartable = \[\]/restartable = [\"nginx.service\"]/' /etc/hostseal/policy.toml"
status=0
run_sh "$INSTANCE" '/usr/libexec/hostseal/restart-unit --action restart --unit nginx.service' \
	>/dev/null 2>&1 || status=$?
[ "$status" -eq 3 ] || fail "the helper exited $status on a paused host, expected 3"
pass "a paused host refuses an operation its policy would otherwise permit"

say "removing the marker"
run "$INSTANCE" rm -f /etc/hostseal/paused
run_sh "$INSTANCE" "sed -i 's/^restartable = \[\"nginx.service\"\]/restartable = []/' /etc/hostseal/policy.toml"

# The agent must not be able to remove the marker itself, which is what makes it a kill switch rather
# than a suggestion.
run "$INSTANCE" touch /etc/hostseal/paused
run_sh "$INSTANCE" '! sudo -u hostseal rm -f /etc/hostseal/paused' \
	|| fail "the agent user can remove the pause marker"
pass "the agent cannot remove the marker itself"
run "$INSTANCE" rm -f /etc/hostseal/paused

say "stopping the unit"
run "$INSTANCE" systemctl stop hostseal-agent.service
run_sh "$INSTANCE" '! systemctl is-active --quiet hostseal-agent.service' \
	|| fail "the unit is still active after being stopped"
pass "the unit stops and nothing restarts it"

run "$INSTANCE" systemctl start hostseal-agent.service
wait_for_agent "$INSTANCE"

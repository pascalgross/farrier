#!/usr/bin/env bash
# The package installs cleanly and leaves a host that reports and does nothing else.
#
# It is the first scenario because everything after it assumes this held, and because a fresh install
# refusing every privileged operation is the product's whole posture in one machine.
set -euo pipefail
# shellcheck source=testfleet/lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/../lib.sh"

: "${INSTANCE:?}"

run "$INSTANCE" systemctl is-active --quiet hostseal-agent.service \
	|| fail "the agent unit is not active"
pass "the agent unit is active"

run "$INSTANCE" id hostseal >/dev/null || fail "the hostseal user was not created"
pass "the hostseal system account exists"

# The account must not be able to log in and must not be in the docker group. Docker socket access is
# root equivalence and would silently undo every hardening line in the unit.
run_sh "$INSTANCE" 'getent passwd hostseal | grep -qE "(nologin|false)$"' \
	|| fail "the hostseal account has a login shell"
run_sh "$INSTANCE" '! id -nG hostseal | tr " " "\n" | grep -qx docker' \
	|| fail "the hostseal account is in the docker group"
pass "the account cannot log in and is not in the docker group"

# The conffiles must be root-owned and not writable by the agent. This is the mechanism, not a detail:
# a policy file the agent can write is not a policy file.
run_sh "$INSTANCE" '[ "$(stat -c %U:%G:%a /etc/hostseal/policy.toml)" = "root:root:644" ]' \
	|| fail "policy.toml is not root:root 0644"
run_sh "$INSTANCE" '[ "$(stat -c %U:%G:%a /etc/hostseal/trusted-signers)" = "root:root:644" ]' \
	|| fail "trusted-signers is not root:root 0644"
pass "the configuration files are root-owned and the agent cannot write them"

# There is no sudoers file any more, and its absence is asserted rather than assumed. A leftover
# NOPASSWD entry for the hostseal account on an upgraded host would be a privilege grant nothing uses
# and nobody would notice.
run_sh "$INSTANCE" '[ ! -e /etc/sudoers.d/hostseal ]' \
	|| fail "an /etc/sudoers.d/hostseal survives; the agent reaches the helpers over a socket now"
pass "there is no sudoers entry"

# The privilege boundary. root:hostseal 0660 is what makes the socket reachable by the agent's account
# and by nothing else; the helper reads SO_PEERCRED as well, but the mode is the first line and the one
# a package upgrade could silently change.
for helper in apply-updates restart-unit reboot-host; do
	run "$INSTANCE" systemctl is-active --quiet "hostseal-$helper.socket" \
		|| fail "hostseal-$helper.socket is not listening"
	run_sh "$INSTANCE" "[ \"\$(stat -c %U:%G:%a /run/hostseal/$helper.sock)\" = \"root:hostseal:660\" ]" \
		|| fail "/run/hostseal/$helper.sock is not root:hostseal 0660"
done
pass "the three helper sockets are listening, root-owned and reachable only by the agent's group"

# trusted-signers ships empty. A fresh agent executes nothing destructive until an administrator puts a
# key in it, and this is what "empty by default" means on a real machine.
run_sh "$INSTANCE" '! grep -qE "^(ed25519|ecdsa-p256) " /etc/hostseal/trusted-signers' \
	|| fail "the shipped trusted-signers file contains a key"
pass "trusted-signers ships with no keys"

run "$INSTANCE" hostseal-agent policy check >/dev/null || fail "the shipped policy does not parse"
pass "the shipped policy parses"

# The privilege boundary, exercised from the agent's own account and changing nothing. The intent it
# sends is in no catalogue and on no route, so each helper refuses it at its very first check — which
# proves the socket exists, that this account may reach it, that systemd started the helper as root,
# and that the helper refuses what it does not serve.
run_sh "$INSTANCE" 'sudo -u hostseal hostseal-agent doctor' >/dev/null \
	|| fail "the agent's own account cannot reach the root helpers"
pass "the agent's account reaches all three helpers, and each refuses what it does not serve"

# The whole product in one command: an operation going through the only privileged path that exists and
# being told no by a file the control plane cannot touch. Run as root deliberately — if even root going
# through the helper is refused, the agent certainly is.
status=0
run_sh "$INSTANCE" '/usr/libexec/hostseal/restart-unit --action restart --unit nginx.service' \
	>/dev/null 2>&1 || status=$?
[ "$status" -eq 3 ] || fail "the helper exited $status, expected 3 (refused by local policy)"
pass "the helper refuses a restart the local policy does not permit"

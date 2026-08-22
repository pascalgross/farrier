#!/usr/bin/env bash
# The package installs cleanly and leaves a host that reports and does nothing else.
#
# It is the first scenario because everything after it assumes this held, and because a fresh install
# refusing every privileged operation is the product's whole posture in one machine.
set -euo pipefail
# shellcheck source=testfleet/lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/../lib.sh"

: "${INSTANCE:?}"

run "$INSTANCE" systemctl is-active --quiet farrier-agent.service \
	|| fail "the agent unit is not active"
pass "the agent unit is active"

run "$INSTANCE" id farrier >/dev/null || fail "the farrier user was not created"
pass "the farrier system account exists"

# The account must not be able to log in and must not be in the docker group. Docker socket access is
# root equivalence and would silently undo every hardening line in the unit.
run_sh "$INSTANCE" 'getent passwd farrier | grep -qE "(nologin|false)$"' \
	|| fail "the farrier account has a login shell"
run_sh "$INSTANCE" '! id -nG farrier | tr " " "\n" | grep -qx docker' \
	|| fail "the farrier account is in the docker group"
pass "the account cannot log in and is not in the docker group"

# The conffiles must be root-owned and not writable by the agent. This is the mechanism, not a detail:
# a policy file the agent can write is not a policy file.
run_sh "$INSTANCE" '[ "$(stat -c %U:%G:%a /etc/farrier/policy.toml)" = "root:root:644" ]' \
	|| fail "policy.toml is not root:root 0644"
run_sh "$INSTANCE" '[ "$(stat -c %U:%G:%a /etc/farrier/trusted-signers)" = "root:root:644" ]' \
	|| fail "trusted-signers is not root:root 0644"
run_sh "$INSTANCE" '[ "$(stat -c %U:%G:%a /etc/sudoers.d/farrier)" = "root:root:440" ]' \
	|| fail "the sudoers file is not root:root 0440"
pass "the configuration files are root-owned and the agent cannot write them"

# trusted-signers ships empty. A fresh agent executes nothing destructive until an administrator puts a
# key in it, and this is what "empty by default" means on a real machine.
run_sh "$INSTANCE" '! grep -qE "^(ed25519|ecdsa-p256) " /etc/farrier/trusted-signers' \
	|| fail "the shipped trusted-signers file contains a key"
pass "trusted-signers ships with no keys"

run "$INSTANCE" farrier-agent policy check >/dev/null || fail "the shipped policy does not parse"
pass "the shipped policy parses"

# The whole product in one command: the agent's own account, going through the only privileged path
# that exists, being told no by a file the control plane cannot touch.
status=0
run_sh "$INSTANCE" 'sudo -u farrier sudo -n /usr/libexec/farrier/restart-unit \
	--action restart --unit nginx.service' >/dev/null 2>&1 || status=$?
[ "$status" -eq 3 ] || fail "the helper exited $status, expected 3 (refused by local policy)"
pass "the helper refuses a restart the local policy does not permit"

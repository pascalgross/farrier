#!/usr/bin/env bash
# The agent runs with the hardening the unit file claims.
#
# systemd silently ignores directives it does not understand, and it will happily start a unit whose
# sandboxing options were dropped by a typo. Reading the *effective* properties back from systemd is the
# only way to know the hardening is in force rather than merely written down — and this is the sort of
# thing that regresses in a one-line edit nobody reviews closely.
set -euo pipefail
# shellcheck source=testfleet/lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/../lib.sh"

: "${INSTANCE:?}"

property() {
	run "$INSTANCE" systemctl show farrier-agent.service --property "$1" --value | tr -d '\r'
}

[ "$(property User)" = "farrier" ] || fail "the unit does not run as farrier"
pass "runs as the unprivileged farrier user"

[ "$(property NoNewPrivileges)" = "yes" ] || fail "NoNewPrivileges is not in force"
[ "$(property MemoryDenyWriteExecute)" = "yes" ] || fail "MemoryDenyWriteExecute is not in force"
[ "$(property ProtectKernelTunables)" = "yes" ] || fail "ProtectKernelTunables is not in force"
[ "$(property ProtectKernelModules)" = "yes" ] || fail "ProtectKernelModules is not in force"
[ "$(property ProtectClock)" = "yes" ] || fail "ProtectClock is not in force"
[ "$(property RestrictSUIDSGID)" = "yes" ] || fail "RestrictSUIDSGID is not in force"
[ "$(property LockPersonality)" = "yes" ] || fail "LockPersonality is not in force"
pass "the sandboxing directives are in force"

[ "$(property ProtectSystem)" = "strict" ] || fail "ProtectSystem is not strict"
pass "the filesystem is read-only outside the state directories"

# An empty capability bounding set is the claim "zero capabilities" made concrete. systemd renders an
# empty set as an empty string.
[ -z "$(property CapabilityBoundingSet)" ] || fail "the capability bounding set is not empty"
pass "the process holds no capabilities"

# The agent must be able to write its state and nothing else.
#
# These run *inside* the unit's sandbox, with systemd-run --property=... reproducing it, rather than as
# `sudo -u farrier` from outside. That distinction is the whole test: `sudo -u farrier touch` tests file
# permissions, which is worth knowing but is not what ProtectSystem=strict does. Checking the ownership
# separately below covers the case where systemd-run is unavailable.
sandbox="--uid=farrier --property=ProtectSystem=strict --property=ProtectHome=yes \
	--property=ReadWritePaths=/var/lib/farrier --property=NoNewPrivileges=yes"

if run_sh "$INSTANCE" 'command -v systemd-run >/dev/null'; then
	run_sh "$INSTANCE" "systemd-run --wait --quiet --collect $sandbox \
		/usr/bin/touch /var/lib/farrier/probe" \
		|| fail "the agent cannot write its own state directory inside the sandbox"
	run "$INSTANCE" rm -f /var/lib/farrier/probe

	# ProtectSystem=strict makes everything outside ReadWritePaths read-only, so this must fail even
	# though the file permissions alone would not stop it.
	if run_sh "$INSTANCE" "systemd-run --wait --quiet --collect $sandbox \
		/usr/bin/touch /etc/farrier/probe" 2>/dev/null; then
		run "$INSTANCE" rm -f /etc/farrier/probe
		fail "the sandbox permits writing /etc/farrier, which would defeat local policy sovereignty"
	fi
	pass "inside the sandbox the agent can write its state and cannot write its policy"
else
	skip "systemd-run is unavailable; the sandbox itself was not exercised"
fi

# File permissions as well, which hold whether or not the sandbox is in force.
run_sh "$INSTANCE" '[ "$(stat -c %U /var/lib/farrier)" = "farrier" ]' \
	|| fail "the state directory is not owned by the agent"
run_sh "$INSTANCE" '! sudo -u farrier test -w /etc/farrier/policy.toml' \
	|| fail "the agent user can write policy.toml by file permissions alone"
pass "the state directory is the agent's and the policy file is not"

# The salt must exist and be private to the agent. Without it the machine-id hash would be correlatable
# between fleets by anyone who saw both.
run_sh "$INSTANCE" '[ -s /var/lib/farrier/machine-id-salt ]' || fail "no machine-id salt was generated"
run_sh "$INSTANCE" '[ "$(stat -c %U:%a /var/lib/farrier/machine-id-salt)" = "farrier:600" ]' \
	|| fail "the machine-id salt is not private to the agent"
pass "a private per-host machine-id salt exists"

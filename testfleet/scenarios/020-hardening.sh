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

# The agent must be able to write its state and nothing else. A write outside ReadWritePaths is what
# ProtectSystem=strict is for, and testing it directly is worth more than trusting the directive.
run_sh "$INSTANCE" 'sudo -u farrier touch /var/lib/farrier/probe && rm -f /var/lib/farrier/probe' \
	|| fail "the agent cannot write its own state directory"
run_sh "$INSTANCE" '! sudo -u farrier touch /etc/farrier/probe' \
	|| fail "the agent can write /etc/farrier, which would defeat local policy sovereignty"
pass "the agent can write its state and cannot write its policy"

# The salt must exist and be private to the agent. Without it the machine-id hash would be correlatable
# between fleets by anyone who saw both.
run_sh "$INSTANCE" '[ -s /var/lib/farrier/machine-id-salt ]' || fail "no machine-id salt was generated"
run_sh "$INSTANCE" '[ "$(stat -c %U:%a /var/lib/farrier/machine-id-salt)" = "farrier:600" ]' \
	|| fail "the machine-id salt is not private to the agent"
pass "a private per-host machine-id salt exists"

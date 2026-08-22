#!/usr/bin/env bash
# A package upgrade does not replace a locally edited policy.toml or trusted-signers.
#
# The trusted-signers half of this is a **security** test rather than a convenience one. A package
# upgrade that silently reset the trust anchor would re-open every destructive operation an
# administrator had deliberately closed, and would do it on a schedule the administrator did not choose.
# It is the kind of failure that is invisible until the day it is exploited.
set -euo pipefail
# shellcheck source=testfleet/lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/../lib.sh"

: "${INSTANCE:?}" "${REPO:?}"

MARKER_KEY='ed25519 AAAAC3NzaC1lZDI1NTE5AAAATESTFLEETEDITXXXXXXXXXXXXXXXXXXXX testfleet-edit'

say "editing the conffiles as an administrator would"
run_sh "$INSTANCE" "printf '%s\n' '$MARKER_KEY' >> /etc/farrier/trusted-signers"
run_sh "$INSTANCE" "sed -i 's/^allow = \"security\"/allow = \"all\"/' /etc/farrier/policy.toml"
run_sh "$INSTANCE" "sed -i 's/^restartable = \[\]/restartable = [\"nginx.service\"]/' /etc/farrier/policy.toml"

before_policy=$(run_sh "$INSTANCE" 'md5sum /etc/farrier/policy.toml | cut -d" " -f1')
before_signers=$(run_sh "$INSTANCE" 'md5sum /etc/farrier/trusted-signers | cut -d" " -f1')

run "$INSTANCE" farrier-agent policy check >/dev/null || fail "the edited policy does not parse"
pass "the edited policy parses"

say "building and installing a newer package"
make -C "$REPO" deb VERSION=0.0.1-testfleet >/dev/null
newer=$(ls "$REPO"/dist/packages/farrier-agent_0.0.1-testfleet_*.deb | head -n1)
lxc file push "$newer" "$INSTANCE/tmp/farrier-agent-newer.deb"
run_sh "$INSTANCE" 'export DEBIAN_FRONTEND=noninteractive
	apt-get install -y -qq --allow-downgrades /tmp/farrier-agent-newer.deb'

after_policy=$(run_sh "$INSTANCE" 'md5sum /etc/farrier/policy.toml | cut -d" " -f1')
after_signers=$(run_sh "$INSTANCE" 'md5sum /etc/farrier/trusted-signers | cut -d" " -f1')

[ "$before_policy" = "$after_policy" ] || fail "the upgrade replaced /etc/farrier/policy.toml"
pass "policy.toml survived the upgrade"

[ "$before_signers" = "$after_signers" ] || fail "the upgrade replaced /etc/farrier/trusted-signers"
run_sh "$INSTANCE" "grep -q 'testfleet-edit' /etc/farrier/trusted-signers" \
	|| fail "the administrator's key is gone from trusted-signers"
pass "trusted-signers survived the upgrade, and the key is still there"

# dpkg must also have left no .dpkg-dist or .dpkg-new files lying about that somebody could mistake for
# the live configuration during an incident.
run_sh "$INSTANCE" '! ls /etc/farrier/*.dpkg-* >/dev/null 2>&1' \
	|| fail "the upgrade left .dpkg-* files in /etc/farrier"
pass "no stray .dpkg-* files were left behind"

wait_for_agent "$INSTANCE"
pass "the agent is running again after the upgrade"

say "restoring the shipped configuration"
run_sh "$INSTANCE" "sed -i '/testfleet-edit/d' /etc/farrier/trusted-signers"
run_sh "$INSTANCE" "sed -i 's/^allow = \"all\"/allow = \"security\"/' /etc/farrier/policy.toml"
run_sh "$INSTANCE" "sed -i 's/^restartable = \[\"nginx.service\"\]/restartable = []/' /etc/farrier/policy.toml"

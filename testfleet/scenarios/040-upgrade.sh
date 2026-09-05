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
run_sh "$INSTANCE" "printf '%s\n' '$MARKER_KEY' >> /etc/hostseal/trusted-signers"
run_sh "$INSTANCE" "sed -i 's/^allow = \"security\"/allow = \"all\"/' /etc/hostseal/policy.toml"
run_sh "$INSTANCE" "sed -i 's/^restartable = \[\]/restartable = [\"nginx.service\"]/' /etc/hostseal/policy.toml"

before_policy=$(run_sh "$INSTANCE" 'md5sum /etc/hostseal/policy.toml | cut -d" " -f1')
before_signers=$(run_sh "$INSTANCE" 'md5sum /etc/hostseal/trusted-signers | cut -d" " -f1')

run "$INSTANCE" hostseal-agent policy check >/dev/null || fail "the edited policy does not parse"
pass "the edited policy parses"

say "building and installing a newer package"
make -C "$REPO" deb VERSION=0.0.1-testfleet >/dev/null
# `make deb-path` rather than a glob. Debian has no notion of a prerelease, so nfpm's semver schema
# writes 0.0.1-testfleet as 0.0.1~testfleet, and a glob built from the version silently matches nothing.
newer=$(make -s -C "$REPO" deb-path VERSION=0.0.1-testfleet)
[ -f "$newer" ] || fail "the newer package was not built at $newer"
lxc file push "$newer" "$INSTANCE/tmp/hostseal-agent-newer.deb"
run_sh "$INSTANCE" 'export DEBIAN_FRONTEND=noninteractive
	apt-get install -y -qq --allow-downgrades /tmp/hostseal-agent-newer.deb'

after_policy=$(run_sh "$INSTANCE" 'md5sum /etc/hostseal/policy.toml | cut -d" " -f1')
after_signers=$(run_sh "$INSTANCE" 'md5sum /etc/hostseal/trusted-signers | cut -d" " -f1')

[ "$before_policy" = "$after_policy" ] || fail "the upgrade replaced /etc/hostseal/policy.toml"
pass "policy.toml survived the upgrade"

[ "$before_signers" = "$after_signers" ] || fail "the upgrade replaced /etc/hostseal/trusted-signers"
run_sh "$INSTANCE" "grep -q 'testfleet-edit' /etc/hostseal/trusted-signers" \
	|| fail "the administrator's key is gone from trusted-signers"
pass "trusted-signers survived the upgrade, and the key is still there"

# dpkg must also have left no .dpkg-dist or .dpkg-new files lying about that somebody could mistake for
# the live configuration during an incident.
run_sh "$INSTANCE" '! ls /etc/hostseal/*.dpkg-* >/dev/null 2>&1' \
	|| fail "the upgrade left .dpkg-* files in /etc/hostseal"
pass "no stray .dpkg-* files were left behind"

wait_for_agent "$INSTANCE"
pass "the agent is running again after the upgrade"

say "restoring the shipped configuration"
run_sh "$INSTANCE" "sed -i '/testfleet-edit/d' /etc/hostseal/trusted-signers"
run_sh "$INSTANCE" "sed -i 's/^allow = \"all\"/allow = \"security\"/' /etc/hostseal/policy.toml"
run_sh "$INSTANCE" "sed -i 's/^restartable = \[\"nginx.service\"\]/restartable = []/' /etc/hostseal/policy.toml"

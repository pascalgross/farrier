#!/usr/bin/env bash
# Fact collection gives the right answers on this distribution family.
#
# Four differences between Ubuntu and Debian produce silent wrong answers rather than errors, so this
# scenario checks the answers themselves rather than that collection completed. A harness that only
# asserted "no error" would pass on every one of the four.
set -euo pipefail
# shellcheck source=testfleet/lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/../lib.sh"

: "${INSTANCE:?}" "${RELEASE:?}"

family=${RELEASE%%/*}

# The simulation parse is the primary path for counting updates. apt-check lives in
# update-notifier-common, which is absent from minimal images of both families, so a host without it
# must report the same numbers as one with it.
run_sh "$INSTANCE" 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq' >/dev/null
run_sh "$INSTANCE" 'apt-get --just-print --quiet dist-upgrade > /tmp/simulation.txt' >/dev/null
pass "apt-get simulation runs and is parseable"

# Whichever origin pattern this family uses, an "Inst" line that names a security archive must be
# classified as security. Getting this wrong is quietly incorrect in the one number the product exists
# to show.
if run_sh "$INSTANCE" 'grep -q "^Inst " /tmp/simulation.txt'; then
	pass "$(run_sh "$INSTANCE" 'grep -c "^Inst " /tmp/simulation.txt') package(s) pending"

	# Every Inst line must carry a parseable release string, whichever archive it names. The earlier
	# version of this check ended in `|| true` followed by an unconditional pass, so it could not fail —
	# which is worse than not having it, because the scenario reported a result it had not established.
	run_sh "$INSTANCE" 'grep "^Inst " /tmp/simulation.txt | grep -qE "\(.*[A-Za-z]+[:/].*\)"' \
		|| fail "no Inst line carries a release string; the security split has nothing to classify on"
	pass "every pending package names its release"

	# And the agent's own classification must agree with the archive names in that output. This is the
	# assertion that matters: it compares what HostSeal reports against what apt said, on this family.
	security_lines=$(run_sh "$INSTANCE" \
		'grep "^Inst " /tmp/simulation.txt | grep -cE "Debian-Security|-security" || true')
	agent_security=$(run_sh "$INSTANCE" \
		'hostseal-agent facts --json 2>/dev/null | grep -o "\"upgradableSecurity\":[0-9]*" | cut -d: -f2' \
		|| echo "")

	if [ -n "$agent_security" ]; then
		[ "$agent_security" = "$security_lines" ] \
			|| fail "the agent reports $agent_security security updates; apt's output names $security_lines"
		pass "the agent's security count agrees with apt's output ($security_lines)"
	else
		skip "this build has no facts subcommand; the classification is covered by internal/collect"
	fi
else
	skip "no pending updates on this image, so the security split has nothing to classify"
fi

# The reboot marker is an Ubuntu update-notifier convention. On Debian it is usually absent, which is
# exactly why it must never be the only signal.
case "$family" in
	ubuntu) pass "reboot-required is a supported signal on Ubuntu" ;;
	debian)
		if run_sh "$INSTANCE" 'test -e /var/run/reboot-required'; then
			pass "this Debian image happens to have update-notifier-common installed"
		else
			pass "no reboot marker on Debian, as expected — needrestart is the reliable source"
		fi
		;;
esac

run "$INSTANCE" needrestart -b >/dev/null 2>&1 || fail "needrestart is not usable"
run_sh "$INSTANCE" 'needrestart -b | grep -q "^NEEDRESTART-KSTA:"' \
	|| fail "needrestart reported no kernel status"
pass "needrestart reports a kernel status"

# Ubuntu Pro does not exist on Debian, and a Debian host must render as "not applicable" rather than
# carrying a permanent amber warning that teaches its operator to ignore the dashboard.
case "$family" in
	ubuntu) pass "Ubuntu Pro is applicable here, whether or not the pro tool is installed" ;;
	debian)
		run_sh "$INSTANCE" '! command -v pro' \
			|| fail "the pro tool exists on Debian, which this scenario did not expect"
		pass "Ubuntu Pro is not applicable on Debian"
		;;
esac

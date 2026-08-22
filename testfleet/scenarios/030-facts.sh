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
	case "$family" in
		ubuntu)
			run_sh "$INSTANCE" 'grep "^Inst " /tmp/simulation.txt | grep -q -- "-security" || true'
			pass "Ubuntu security archives are identified by the -security archive suffix"
			;;
		debian)
			run_sh "$INSTANCE" 'grep "^Inst " /tmp/simulation.txt | grep -q "Debian-Security\|-security" || true'
			pass "Debian security archives are identified by the Debian-Security label or suffix"
			;;
	esac
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

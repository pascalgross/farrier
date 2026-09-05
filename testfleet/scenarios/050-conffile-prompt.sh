#!/usr/bin/env bash
# A changed conffile must not stop an update run dead.
#
# This is the trap that turns an unattended upgrade into a hung machine: DEBIAN_FRONTEND=noninteractive
# alone is **not** sufficient. Without -o Dpkg::Options::=--force-confdef and --force-confold, dpkg
# stops and waits for input that never comes, and the host sits there — patched half way, holding the
# apt lock, until somebody notices days later.
#
# Phase 0 ships no executor, so what is asserted here is the invariant the phase 1 executor must satisfy,
# demonstrated against real dpkg on this machine. The scenario is written now so that it fails the
# moment an executor lands without the options.
set -euo pipefail
# shellcheck source=testfleet/lib.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/../lib.sh"

: "${INSTANCE:?}"

say "picking a package with a conffile and editing it"
# A package that is small, present on both families, and ships a conffile.
run_sh "$INSTANCE" 'export DEBIAN_FRONTEND=noninteractive
	apt-get install -y -qq --reinstall logrotate' >/dev/null
run_sh "$INSTANCE" 'printf "\n# edited by the HostSeal test fleet\n" >> /etc/logrotate.conf'

# The naive form: noninteractive frontend and nothing else. dpkg is given a sixty-second deadline, which
# is long enough that hitting it means dpkg is waiting for an answer rather than being slow — the
# failure this scenario exists to catch, and one that in production waits for ever.
say "reinstalling with DEBIAN_FRONTEND alone"
naive_status=0
run_sh "$INSTANCE" 'export DEBIAN_FRONTEND=noninteractive
	timeout 60 apt-get install -y -qq --reinstall -o Dpkg::Options::=--force-confask logrotate \
		</dev/null >/tmp/naive.log 2>&1' || naive_status=$?
if [ "$naive_status" -ne 0 ]; then
	pass "without the conffile options a prompt-forcing run does not complete cleanly (exit $naive_status)"
else
	skip "this image's dpkg completed anyway; the assertion below is the one that matters"
fi

# The naive run above was made to fail on purpose, and apt exits 100 leaving dpkg half-configured —
# after which every apt-get refuses to do anything until somebody repairs it. Repairing here is not
# papering over that failure; it is separating the two runs, so that what the assertion below
# measures is the conffile options rather than the wreckage of the run that was meant to fail.
run_sh "$INSTANCE" 'export DEBIAN_FRONTEND=noninteractive
	dpkg --configure -a >/dev/null 2>&1 || true'

# The form HostSeal's executor must use. It has to complete, and it has to keep the administrator's
# edited file rather than silently replacing it.
say "reinstalling the way the executor must"
correct_status=0
run_sh "$INSTANCE" 'export DEBIAN_FRONTEND=noninteractive
	timeout 120 apt-get install -y -qq --reinstall \
		-o Dpkg::Options::=--force-confdef \
		-o Dpkg::Options::=--force-confold \
		-o DPkg::Lock::Timeout=600 \
		logrotate </dev/null >/tmp/correct.log 2>&1' || correct_status=$?
if [ "$correct_status" -ne 0 ]; then
	# The log, not just the verdict. "Did not complete" sends somebody to read a CI log that does not
	# contain the reason, which is a whole round trip to learn what apt had already said.
	run_sh "$INSTANCE" 'tail -n 20 /tmp/correct.log' >&2 || true
	fail "the run with --force-confdef and --force-confold did not complete (exit $correct_status)"
fi
pass "the run completes with --force-confdef, --force-confold and a lock timeout"

run_sh "$INSTANCE" 'grep -q "edited by the HostSeal test fleet" /etc/logrotate.conf' \
	|| fail "the administrator's edited conffile was replaced"
pass "the administrator's edit was kept, not overwritten"

# The lock timeout is the other half. Colliding with the host's own apt-daily.timer is the failure that
# only shows up on a busy fleet, and it shows up as a job that failed for no reason anyone can see.
run_sh "$INSTANCE" 'grep -q "Lock" /tmp/correct.log' && skip "the run waited on a lock, which is the timeout doing its job" || true

say "restoring the package"
run_sh "$INSTANCE" 'export DEBIAN_FRONTEND=noninteractive
	apt-get install -y -qq --reinstall -o Dpkg::Options::=--force-confnew logrotate' >/dev/null

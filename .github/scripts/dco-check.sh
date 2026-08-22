#!/usr/bin/env bash
# Verify that every commit in a range carries a Developer Certificate of Origin sign-off.
#
# Farrier uses the DCO and no CLA. That is not a formality: under the DCO, relicensing would require the
# agreement of every contributor, which means no future owner of this repository can take it
# proprietary — including Pegasus Networks. For a security tool whose value is that its claims can be
# verified, that permanence is worth more than the flexibility it costs, and this check is the mechanism
# that makes it true rather than intended.
#
# The sign-off email must match the commit author's, because a sign-off is a statement by the author
# about their own right to submit the work.
#
# Usage: dco-check.sh <base-ref> <head-ref>
set -euo pipefail

BASE=${1:?usage: dco-check.sh <base-ref> <head-ref>}
HEAD=${2:?usage: dco-check.sh <base-ref> <head-ref>}

commits=$(git rev-list "${BASE}..${HEAD}")
if [ -z "$commits" ]; then
	echo "No commits to check between ${BASE} and ${HEAD}."
	exit 0
fi

failed=0
for commit in $commits; do
	subject=$(git show -s --format=%s "$commit")
	author_email=$(git show -s --format=%ae "$commit")
	author_name=$(git show -s --format=%an "$commit")

	# Merge commits are created by GitHub, not by a contributor, and have nothing to certify.
	if [ "$(git rev-list --parents -n 1 "$commit" | wc -w)" -gt 2 ]; then
		continue
	fi

	signoffs=$(git show -s --format=%B "$commit" | grep -i '^Signed-off-by:' || true)
	if [ -z "$signoffs" ]; then
		echo "✗ ${commit:0:8} ${subject}"
		echo "    no Signed-off-by line."
		failed=1
		continue
	fi

	if ! grep -qiF "<${author_email}>" <<<"$signoffs"; then
		echo "✗ ${commit:0:8} ${subject}"
		echo "    signed off as: ${signoffs}"
		echo "    authored by:   ${author_name} <${author_email}>"
		echo "    the sign-off email must match the author's."
		failed=1
		continue
	fi

	echo "✓ ${commit:0:8} ${subject}"
done

if [ "$failed" -ne 0 ]; then
	cat <<'MESSAGE'

Every commit needs a Developer Certificate of Origin sign-off whose email matches its author.

  git commit -s                        # when writing a new commit
  git commit --amend -s --no-edit      # to fix the last one
  git rebase --signoff origin/main     # to fix a whole branch

See https://developercertificate.org/ and CONTRIBUTING.md. There is no CLA: this is what keeps the
Apache-2.0 licence permanent, because relicensing under the DCO would need every contributor's
agreement.
MESSAGE
	exit 1
fi

echo
echo "All commits are signed off."

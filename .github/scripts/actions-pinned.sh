#!/usr/bin/env bash
#
# Every third-party action is pinned to a commit.
#
# A `uses:` naming a tag names something the action's owner can move afterwards, and the release
# workflow builds the .deb that every enrolled host installs and runs maintainer scripts from as root.
# So a moved tag in this repository is not "a newer version of a helper step"; it is code of somebody
# else's choosing running beside the archive signing key. A commit cannot be moved, which is the whole
# of the argument.
#
# Run by `make actions-pinned`, which `make ci` includes, so the finding lands on the machine of
# whoever added the step rather than on a red pull request nobody expected.
set -euo pipefail

root="${1:-.}"
workflows="$root/.github/workflows"

if [ ! -d "$workflows" ]; then
  echo "no workflow directory at $workflows" >&2
  exit 1
fi

# Local actions (./ and ../) and reusable workflows in this repository name a path rather than a
# revision, and there is nothing to pin: they are the repository, at the commit the run checked out.
unpinned=$(
  grep -rhoE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*[^[:space:]]+' "$workflows" \
    | sed -E 's/^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*//' \
    | grep -v '^\.\{1,2\}/' \
    | grep -vE '@[0-9a-f]{40}$' \
    || true
)

if [ -n "$unpinned" ]; then
  echo "these workflow steps name a mutable reference rather than a commit:" >&2
  printf '  %s\n' $unpinned >&2
  echo >&2
  echo "Pin each to the full 40-character commit SHA, with the version in a trailing comment:" >&2
  echo "  uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0" >&2
  exit 1
fi

count=$(grep -rhE '^[[:space:]]*(-[[:space:]]+)?uses:' "$workflows" | wc -l | tr -d ' ')
echo "actions: all $count steps are pinned to a commit"

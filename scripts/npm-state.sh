#!/usr/bin/env bash
# Print what npm holds for a tarball's name@version: ABSENT or SAME; fails on DIFFERENT
# (scripts/lib-registry-state.sh). Read-only.
#
#   usage: scripts/npm-state.sh <tarball.tgz>
set -euo pipefail
tarball=$(realpath "${1:?usage: npm-state.sh <tarball.tgz>}")
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-registry-state.sh
source scripts/lib-registry-state.sh
readonly NPM_NOT_FOUND=E404

manifest=$(tar -xzOf "$tarball" package/package.json)
spec="$(jq -r .name <<<"$manifest")@$(jq -r .version <<<"$manifest")"
# npm's integrity format: sha512, base64.
ours="sha512-$(openssl dgst -sha512 -binary "$tarball" | base64 -w0)"

# Absent = E404 (no package) or empty output (no version). Any other error is NOT
# evidence of absence.
errors=$(mktemp)
trap 'rm -f "$errors"' EXIT
if theirs=$(npm view "$spec" dist.integrity 2>"$errors"); then
  :
elif grep -q "$NPM_NOT_FOUND" "$errors"; then
  theirs=''
else
  echo "npm-state: could not query the registry for $spec:" >&2
  cat "$errors" >&2
  exit 1
fi

if [ -z "$theirs" ]; then
  echo "$STATE_ABSENT"
elif [ "$theirs" = "$ours" ]; then
  echo "$STATE_SAME"
else
  echo "$STATE_DIFFERENT"
  echo "npm-state: $spec is already published with different contents ($theirs, ours $ours)." >&2
  echo "  A published version cannot be replaced; cut a new version." >&2
  exit 1
fi

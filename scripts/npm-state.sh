#!/usr/bin/env bash
# Print what the npm registry already holds for a tarball's name@version: ABSENT, SAME or
# DIFFERENT (scripts/lib-registry-state.sh). Read-only. The publish job publishes on
# ABSENT, skips on SAME, and this script fails on DIFFERENT — which makes the job safe to
# re-run after a partial failure, and lets the first release candidate be published by a
# human (npm's trusted publishing can only be configured on a package that exists) and
# then approved: the job finds SAME and moves on.
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
# The registry's own integrity string for a tarball: sha512, base64.
ours="sha512-$(openssl dgst -sha512 -binary "$tarball" | base64 -w0)"

# A package that does not exist is E404. A version that does not exist on a package that
# does is an empty answer with exit 0. Anything else — a network error above all — is NOT
# evidence of absence, and must not be read as permission to publish.
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

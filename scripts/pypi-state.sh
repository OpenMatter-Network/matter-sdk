#!/usr/bin/env bash
# Print what PyPI holds for a directory of wheels at one version: ABSENT, PARTIAL or SAME
# (scripts/lib-registry-state.sh); fails on DIFFERENT. Read-only. Proves per file that
# existing uploads are byte-identical, so `skip-existing` cannot hide a conflict.
#
#   usage: scripts/pypi-state.sh <wheels-dir> <pep440-version>
set -euo pipefail
readonly USAGE='usage: pypi-state.sh <wheels-dir> <pep440-version>'
dir=$(realpath "${1:?$USAGE}")
version=${2:?$USAGE}
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-registry-state.sh
source scripts/lib-registry-state.sh
readonly PACKAGE=matter-sdk
readonly HTTP_OK=200
readonly HTTP_NOT_FOUND=404

response=$(mktemp)
trap 'rm -f "$response"' EXIT
status=$(curl --silent --show-error --location --max-time 30 --output "$response" \
  --write-out '%{http_code}' "https://pypi.org/pypi/$PACKAGE/$version/json")
# Only a 404 means absent; 5xx or timeout is an error.
case "$status" in
  "$HTTP_NOT_FOUND") echo "$STATE_ABSENT"; exit 0 ;;
  "$HTTP_OK") ;;
  *) echo "pypi-state: PyPI answered HTTP $status for $PACKAGE $version" >&2; exit 1 ;;
esac

present=0
total=0
for wheel in "$dir"/*.whl; do
  total=$((total + 1))
  theirs=$(jq -r --arg name "$(basename "$wheel")" '.urls[] | select(.filename == $name) | .digests.sha256' "$response")
  [ -n "$theirs" ] || continue
  ours=$(sha256sum "$wheel" | cut -d' ' -f1)
  if [ "$theirs" != "$ours" ]; then
    echo "$STATE_DIFFERENT"
    echo "pypi-state: $(basename "$wheel") is already on PyPI with different contents ($theirs, ours $ours)." >&2
    echo "  A filename cannot be uploaded twice; cut a new version." >&2
    exit 1
  fi
  present=$((present + 1))
done

if [ "$present" = 0 ]; then
  echo "$STATE_ABSENT"
elif [ "$present" = "$total" ]; then
  echo "$STATE_SAME"
else
  echo "$STATE_PARTIAL"
fi

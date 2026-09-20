#!/usr/bin/env bash
# Fail if the pre-2.0 name reappears outside the places that legitimately keep it.
#
# Allowed to keep it:
#   audit/          - a historical record of a 2026-06 review; rewriting it would falsify it
#   docs/migration/ - the migration guide has to name what changed
#   CHANGELOG.md    - same reason
#   this script     - it contains the pattern by definition
#
# Note: MV-xx audit finding IDs use a hyphen and are not matched here.
set -euo pipefail
cd "$(dirname "$0")/.."

pattern='matter-vault|matter_vault|mattervault|MatterVault|MATTER_VAULT'

hits=$(git ls-files -z \
  | grep -zZv '^audit/' \
  | grep -zZv '^docs/migration/' \
  | grep -zZv '^CHANGELOG.md$' \
  | grep -zZv '^scripts/check-old-names.sh$' \
  | xargs -0 grep -nIE "$pattern" 2>/dev/null || true)

if [ -n "$hits" ]; then
  echo "The pre-2.0 name is back in tracked files:" >&2
  echo "$hits" >&2
  echo >&2
  echo "Use matter-sdk / matter_sdk / mattersdk / MatterSDK, or add a deliberate exception here." >&2
  exit 1
fi
echo "no stale names"

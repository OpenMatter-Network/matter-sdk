#!/usr/bin/env bash
# Fail if the pre-2.0 name (or its C ABI prefix / Go alias) appears outside CHANGELOG.md
# and this script.
set -euo pipefail
cd "$(dirname "$0")/.."

pattern='matter-vault|matter_vault|mattervault|MatterVault|MATTER_VAULT|Matter Vault'
pattern+='|\bmv_[a-z]|\bMv[A-Z][a-z]|\bMV_ERR_|\bmv "github|\bmv\.[A-Z]'

hits=$(git ls-files -z \
  | grep -zZv '^CHANGELOG.md$' \
  | grep -zZv '^scripts/check-old-names.sh$' \
  | xargs -0 grep -nIE "$pattern" 2>/dev/null || true)

if [ -n "$hits" ]; then
  echo "The pre-2.0 name is back in tracked files:" >&2
  echo "$hits" >&2
  echo >&2
  echo "Use matter-sdk / matter_sdk / mattersdk / MatterSDK / msdk_, or add a deliberate exception here." >&2
  exit 1
fi
echo "no stale names"

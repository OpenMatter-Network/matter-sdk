#!/usr/bin/env bash
# Fail if a published package's LICENSE copy is missing or differs from ./LICENSE.
# npm and maturin only ship a LICENSE inside the package dir, and npm does not warn.
set -euo pipefail
cd "$(dirname "$0")/.."

readonly -a PUBLISHED_PACKAGES=(packages/typescript-core packages/typescript bindings/python)

fail=0
for package in "${PUBLISHED_PACKAGES[@]}"; do
  if ! cmp -s LICENSE "$package/LICENSE"; then
    echo "license copy: $package/LICENSE is missing or differs from ./LICENSE (cp LICENSE $package/)" >&2
    fail=1
  fi
done

[ "$fail" = 0 ] && echo "license copies identical in ${#PUBLISHED_PACKAGES[@]} packages"
exit "$fail"

#!/usr/bin/env bash
# Fail if a published package's LICENSE is missing or differs from the repository's.
#
# npm and maturin only ship a license file that sits inside the package directory, so
# the root LICENSE reaches no artifact. Each published package carries a copy, and a
# copy is a second home for the text: this is what keeps the homes identical. A
# missing copy is not reported by npm — the tarball just ships without one.
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

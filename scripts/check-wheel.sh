#!/usr/bin/env bash
# Assert that a directory of wheels is exactly the set we mean to upload to PyPI, by
# reading the wheels. PyPI never lets a filename be replaced, so a wrong wheel is fixed
# only by burning the version.
#
#   usage: scripts/check-wheel.sh <wheels-dir> <pep440-version> [--partial]
#     --partial   accept a subset of the platforms (local runs); every wheel present is
#                 still checked, and an unexpected file is still an error.
#
# Needs twine (pip install -r bindings/python/requirements-release.txt).
set -euo pipefail
readonly USAGE='usage: check-wheel.sh <wheels-dir> <pep440-version> [--partial]'
dir=$(realpath "${1:?$USAGE}")
version=${2:?$USAGE}
case "${3:-}" in
  '') partial=false ;;
  --partial) partial=true ;;
  *) echo "$USAGE" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-targets.sh
source scripts/lib-targets.sh

readonly DIST=matter_sdk
readonly ABI_TAG=cp39-abi3 # one wheel per platform serves every CPython >= 3.9
readonly NATIVE_MODULE="$DIST/_native.abi3.so"
readonly -a REQUIRED_METADATA=(
  "Version: $version"
  'License-Expression: Apache-2.0'
  'Requires-Python: >=3.9'
  'Provides-Extra: sdk'
  'Project-URL: '
  # chain.py imports scalecodec directly; relying on substrate-interface to bring it
  # works until the day that package stops depending on it.
  'Requires-Dist: scalecodec'
)
# What the extension may load at run time. glibc: libraries the manylinux policy
# guarantees on every conforming system. musl: libc alone — a bare Alpine image has no
# libgcc_s, so a wheel that needs it installs cleanly and then fails to import.
declare -rA ALLOWED_NEEDED=(
  [glibc]='libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libutil.so.1 libgcc_s.so.1 ld-linux-x86-64.so.2 ld-linux-aarch64.so.1'
  [musl]='libc.so'
)

fail=0
bad() { echo "check-wheel: $1" >&2; fail=1; }
wheel_name() { echo "$DIST-$version-$ABI_TAG-$(target_field "$1" wheel_tag).whl"; }

declare -A expected=()
while read -r id; do expected[$(wheel_name "$id")]=$id; done < <(target_ids)

for path in "$dir"/*; do
  name=$(basename "$path")
  [ -n "${expected[$name]:-}" ] || bad "unexpected file $name (not a wheel the platform table and version $version predict)"
done
for name in "${!expected[@]}"; do
  [ -f "$dir/$name" ] || [ "$partial" = true ] || bad "missing $name"
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for name in "${!expected[@]}"; do
  wheel="$dir/$name"
  [ -f "$wheel" ] || continue
  libc=$(target_field "${expected[$name]}" libc)
  listing=$(unzip -Z1 "$wheel")
  for member in "$NATIVE_MODULE" "$DIST-$version.dist-info/licenses/LICENSE"; do
    grep -qxF "$member" <<<"$listing" || bad "$name: missing $member"
  done
  metadata=$(unzip -p "$wheel" "$DIST-$version.dist-info/METADATA")
  for line in "${REQUIRED_METADATA[@]}"; do
    grep -qF "$line" <<<"$metadata" || bad "$name: METADATA lacks '$line'"
  done
  if [ -n "$libc" ]; then
    unzip -qo "$wheel" "$NATIVE_MODULE" -d "$work"
    for lib in $(readelf -d "$work/$NATIVE_MODULE" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'); do
      case " ${ALLOWED_NEEDED[$libc]} " in
        *" $lib "*) ;;
        *) bad "$name: the extension needs $lib, which a $libc system does not guarantee" ;;
      esac
    done
  fi
done

python3 -m twine check --strict "$dir"/*.whl >/dev/null || bad "twine check --strict rejected the wheels"

[ "$fail" = 0 ] && echo "wheels ok: $(find "$dir" -name '*.whl' | wc -l) of ${#expected[@]} platforms at $version"
exit "$fail"

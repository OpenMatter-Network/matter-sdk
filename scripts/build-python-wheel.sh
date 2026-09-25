#!/usr/bin/env bash
# Build the abi3 PyPI wheel (CPython >= 3.9) for one row of scripts/native-targets.json.
#
#   usage: scripts/build-python-wheel.sh <target-id> <out-dir>
#
# Needs: pip install -r bindings/python/requirements-release.txt
#
# Linux wheels cross-link on the host with zig (not a manylinux container): the host holds
# the private-deps git credentials, and zig pins manylinux2014's glibc 2.17 symbols.
# No sdist: it could not build outside this repo.
set -euo pipefail
readonly USAGE='usage: build-python-wheel.sh <target-id> <out-dir>'
id=${1:?$USAGE}
# Not `realpath -m`: macOS realpath has no -m.
mkdir -p "${2:?$USAGE}"
out=$(cd "$2" && pwd)
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-targets.sh
source scripts/lib-targets.sh

triple=$(target_field "$id" rust_target)
read -ra maturin_args <<<"$(target_field "$id" maturin_args)"

rustup target add "$triple" >/dev/null 2>&1
cd bindings/python
# ${arr[@]+...}: bash 3.2 (macOS) treats an empty array as unbound under set -u.
maturin build --release --locked --strip --out "$out" --target "$triple" ${maturin_args[@]+"${maturin_args[@]}"}

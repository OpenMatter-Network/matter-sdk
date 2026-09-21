#!/usr/bin/env bash
# Build the PyPI wheel for one row of scripts/native-targets.json. The extension is abi3,
# so one wheel per platform serves every CPython from 3.9 up.
#
#   usage: scripts/build-python-wheel.sh <target-id> <out-dir>
#
# Needs the pinned tools: pip install -r bindings/python/requirements-release.txt
#
# Linux wheels are cross-linked on the host with zig, never in a manylinux container.
# The private core crates are fetched with credentials that live in the host's git
# config, which a container does not see; and zig pins the glibc 2.17 symbol versions
# manylinux2014 promises, where the host's own linker binds whatever glibc it has (a
# plain build on ubuntu-24.04 comes out tagged manylinux_2_34). The core has no C
# dependencies, so there is nothing else for a cross toolchain to provide.
#
# Wheels only: an sdist could not build anywhere else, because its path dependencies
# reach outside bindings/python and the crypto core's source is private.
set -euo pipefail
readonly USAGE='usage: build-python-wheel.sh <target-id> <out-dir>'
id=${1:?$USAGE}
# Not `realpath -m`: the darwin rows build on macOS, whose realpath has no -m.
mkdir -p "${2:?$USAGE}"
out=$(cd "$2" && pwd)
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-targets.sh
source scripts/lib-targets.sh

triple=$(target_field "$id" rust_target)
read -ra maturin_args <<<"$(target_field "$id" maturin_args)"

rustup target add "$triple" >/dev/null 2>&1
cd bindings/python
maturin build --release --locked --strip --out "$out" --target "$triple" "${maturin_args[@]}"

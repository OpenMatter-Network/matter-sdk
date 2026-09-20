#!/usr/bin/env bash
# Fail if the manifests disagree about the release version.
#
# Before 2.0 they had drifted three ways (Cargo 1.3.1, npm/PyPI 1.2.0, wasm 1.1.0)
# against tag v1.3.2, so a published npm package advertised a version no tag matched.
# scripts/set-version.sh writes them all; this checks nobody edited one by hand.
set -euo pipefail
cd "$(dirname "$0")/.."

read_toml() { sed -n '0,/^version = /s|^version = "\(.*\)"|\1|p' "$1"; }
read_json() { sed -n '0,/"version":/s|.*"version": "\(.*\)".*|\1|p' "$1"; }

declare -A v
v[Cargo.toml]=$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml | sed -n 's|^version = "\(.*\)"|\1|p')
v[bindings/wasm/Cargo.toml]=$(read_toml bindings/wasm/Cargo.toml)
v[bindings/python/Cargo.toml]=$(read_toml bindings/python/Cargo.toml)
v[bindings/python/pyproject.toml]=$(read_toml bindings/python/pyproject.toml)
v[packages/typescript/package.json]=$(read_json packages/typescript/package.json)
v[packages/typescript-core/package.json]=$(read_json packages/typescript-core/package.json)

want=${v[Cargo.toml]}
fail=0
for f in "${!v[@]}"; do
  if [ "${v[$f]}" != "$want" ]; then
    echo "version mismatch: $f is ${v[$f]}, Cargo.toml is $want" >&2
    fail=1
  fi
done

# The TS client's dependency range on the core must admit the version we ship.
dep=$(sed -n 's|.*"@openmatter-network/matter-sdk-core": "\^\([0-9][^"]*\)".*|\1|p' packages/typescript/package.json | head -1)
if [ -n "$dep" ] && [ "${dep%%.*}" != "${want%%.*}" ]; then
  echo "version mismatch: TS client depends on core ^$dep, shipping $want" >&2
  fail=1
fi

[ "$fail" = 0 ] && echo "all manifests at $want"
exit "$fail"

#!/usr/bin/env bash
# Set the release version in every manifest and lockfile (checked by
# scripts/check-versions.sh).
#
#   usage: scripts/set-version.sh 2.1.1        (or 2.1.1-rc.1)
#
# Needs cargo and npm.
set -euo pipefail
v=${1:?usage: set-version.sh <version>}
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-version.sh
source scripts/lib-version.sh
version_channel "$v" >/dev/null

# Excluded bindings carry their own version; Python's comes from bindings/python/Cargo.toml.
readonly -a CARGO_ROOTS=(. bindings/wasm bindings/python)
for root in "${CARGO_ROOTS[@]}"; do
  sed -i "0,/^version = /s|^version = .*|version = \"$v\"|" "$root/Cargo.toml"
done

# npm: both packages, plus the client's range on the core.
readonly -a NPM_ROOTS=(packages/typescript-core packages/typescript)
for root in "${NPM_ROOTS[@]}"; do
  sed -i "0,/\"version\":/s|\"version\": \".*\"|\"version\": \"$v\"|" "$root/package.json"
done
sed -i "s|\(\"@openmatter-network/matter-sdk-core\": \)\"\^[0-9][^\"]*\"|\1\"^$v\"|" packages/typescript/package.json

for example in examples/client-go examples/go-e2e; do
  sed -i "s|\(matter-sdk-go/v[0-9]* \)v[^ ]*|\1v$v|" "$example/go.mod"
done

# README: the Rust git tag.
sed -i "s|\(^matter-sdk = { git = \"[^\"]*\", tag = \"\)v[^\"]*\"|\1v$v\"|" README.md

# Lockfiles last; only local entries move.
for root in "${CARGO_ROOTS[@]}"; do
  (cd "$root" && cargo update --workspace --quiet)
done
for root in "${NPM_ROOTS[@]}"; do
  (cd "$root" && npm install --package-lock-only --ignore-scripts --no-audit --no-fund --silent)
done

scripts/check-versions.sh --expect "$v"

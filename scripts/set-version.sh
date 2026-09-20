#!/usr/bin/env bash
# Set the release version across every manifest that carries one.
#
# The manifests had drifted three ways (1.3.1 / 1.2.0 / 1.1.0 against tag v1.3.2),
# so the version lives in one place now: this script writes them all, and CI
# (scripts/check-versions.sh) fails when they disagree.
#
#   usage: scripts/set-version.sh 2.0.0
set -euo pipefail
v=${1:?usage: set-version.sh <version>}
cd "$(dirname "$0")/.."

# Rust: the workspace inherits into every crate; the two excluded bindings carry their own.
sed -i "0,/^version = /s|^version = .*|version = \"$v\"|" Cargo.toml
sed -i "0,/^version = /s|^version = .*|version = \"$v\"|" bindings/wasm/Cargo.toml
sed -i "0,/^version = /s|^version = .*|version = \"$v\"|" bindings/python/Cargo.toml

# Python (maturin reads pyproject, not Cargo.toml, for the distribution version).
sed -i "0,/^version = /s|^version = .*|version = \"$v\"|" bindings/python/pyproject.toml

# npm: the two published packages, plus the client's dependency range on the core.
for p in packages/typescript packages/typescript-core; do
  sed -i "0,/\"version\":/s|\"version\": \".*\"|\"version\": \"$v\"|" "$p/package.json"
done
sed -i "s|\(\"@openmatter-network/matter-sdk-core\": \)\"\^[0-9][^\"]*\"|\1\"^$v\"|" packages/typescript/package.json

echo "version set to $v"

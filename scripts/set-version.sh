#!/usr/bin/env bash
# Set the release version everywhere it is recorded.
#
# The manifests had drifted three ways (1.3.1 / 1.2.0 / 1.1.0 against tag v1.3.2),
# so the version lives in one place now: this script writes them all, and CI
# (scripts/check-versions.sh) fails when they disagree.
#
# It refreshes the five lockfiles too. It used not to, so a bump left Cargo.lock naming
# the old local-crate versions and `cargo build --locked` (the musl consumer job) refused
# the tree it had just been handed.
#
#   usage: scripts/set-version.sh 2.1.1        (or 2.1.1-rc.1)
#
# Needs cargo and npm; both only rewrite the local entries of their lockfiles.
set -euo pipefail
v=${1:?usage: set-version.sh <version>}
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-version.sh
source scripts/lib-version.sh
version_channel "$v" >/dev/null

# Rust: the workspace inherits into every crate; the two excluded bindings carry their own.
# Python has no entry of its own — maturin reads bindings/python/Cargo.toml.
readonly -a CARGO_ROOTS=(. bindings/wasm bindings/python)
for root in "${CARGO_ROOTS[@]}"; do
  sed -i "0,/^version = /s|^version = .*|version = \"$v\"|" "$root/Cargo.toml"
done

# npm: the two published packages, plus the client's dependency range on the core.
readonly -a NPM_ROOTS=(packages/typescript-core packages/typescript)
for root in "${NPM_ROOTS[@]}"; do
  sed -i "0,/\"version\":/s|\"version\": \".*\"|\"version\": \"$v\"|" "$root/package.json"
done
sed -i "s|\(\"@openmatter-network/matter-sdk-core\": \)\"\^[0-9][^\"]*\"|\1\"^$v\"|" packages/typescript/package.json

# Go: the examples name the module version they are written against.
for example in examples/client-go examples/go-e2e; do
  sed -i "s|\(matter-sdk-go/v[0-9]* \)v[^ ]*|\1v$v|" "$example/go.mod"
done

# README: the git tag a Rust consumer is told to depend on (Rust's only release channel).
sed -i "s|\(^matter-sdk = { git = \"[^\"]*\", tag = \"\)v[^\"]*\"|\1v$v\"|" README.md

# Lockfiles last, from the manifests just written. --workspace / --package-lock-only keep
# every third-party resolution where it is; only the local entries move.
for root in "${CARGO_ROOTS[@]}"; do
  (cd "$root" && cargo update --workspace --quiet)
done
for root in "${NPM_ROOTS[@]}"; do
  (cd "$root" && npm install --package-lock-only --ignore-scripts --no-audit --no-fund --silent)
done

scripts/check-versions.sh --expect "$v"

#!/usr/bin/env bash
# Depend on matter-sdk the way a Rust consumer does — as a git dependency, from a crate
# OUTSIDE this workspace — and prove it resolves and type-checks.
#
#   usage: scripts/smoke-rust-consumer.sh <git-url> <rev>
#     e.g. scripts/smoke-rust-consumer.sh "file://$PWD" "$(git rev-parse HEAD)"
#
# Rust is the one language that does not ship through its registry: crates.io rejects git
# dependencies and publishes source, and the crypto core is private. So the git tag IS
# the Rust release channel, and nothing inside the workspace exercises it — every example
# here is a workspace member with a path dependency. What can break only for an outside
# consumer: workspace-inherited fields and path dependencies resolving through a git
# checkout, and anything that quietly relies on this repository's .cargo/config.toml,
# which a consumer's build never reads.
set -euo pipefail
url=${1:?usage: smoke-rust-consumer.sh <git-url> <rev>}
rev=${2:?usage: smoke-rust-consumer.sh <git-url> <rev>}
readonly CRATE=matter-sdk

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
cargo new --quiet --lib --vcs none consumer
cd consumer

# This is the one setting a consumer must supply themselves, and the README says so: the
# core is pinned by ssh:// URL, and only the git CLI carries their GitHub credentials.
# It is set in the environment, not borrowed from the repository's own config.
export CARGO_NET_GIT_FETCH_WITH_CLI=true
cargo add --quiet "$CRATE" --git "$url" --rev "$rev"
cargo check --quiet

echo "rust consumer smoke ok: $CRATE @ ${rev:0:12} on $(rustc --version)"

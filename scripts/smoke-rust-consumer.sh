#!/usr/bin/env bash
# Depend on matter-sdk as a git dependency from a crate outside this workspace and prove it
# resolves and type-checks (a consumer never reads this repo's .cargo/config.toml).
#
#   usage: scripts/smoke-rust-consumer.sh <git-url> <rev>
#     e.g. scripts/smoke-rust-consumer.sh "file://$PWD" "$(git rev-parse HEAD)"
set -euo pipefail
url=${1:?usage: smoke-rust-consumer.sh <git-url> <rev>}
rev=${2:?usage: smoke-rust-consumer.sh <git-url> <rev>}
readonly CRATE=matter-sdk

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
cargo new --quiet --lib --vcs none consumer
cd consumer

# The one setting consumers must supply (README): private ssh:// deps need the git CLI.
export CARGO_NET_GIT_FETCH_WITH_CLI=true
cargo add --quiet "$CRATE" --git "$url" --rev "$rev"
cargo check --quiet

echo "rust consumer smoke ok: $CRATE @ ${rev:0:12} on $(rustc --version)"

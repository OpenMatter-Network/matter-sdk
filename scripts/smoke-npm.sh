#!/usr/bin/env bash
# Install the npm packages into a project outside this repo and prove they work. Used
# before publish (tarballs) and after (registry).
#
#   usage: scripts/smoke-npm.sh <core-spec> <client-spec>
#     spec: a path to a .tgz, or a registry spec such as @openmatter-network/matter-sdk-core@2.1.1
set -euo pipefail
readonly USAGE='usage: smoke-npm.sh <core-spec> <client-spec>'
repo=$(cd "$(dirname "$0")/.." && pwd)
readonly repo
readonly TYPESCRIPT='typescript@^5.6.0' # same range the packages build with

spec() { if [ -f "$1" ]; then realpath "$1"; else echo "$1"; fi; }
core=$(spec "${1:?$USAGE}")
client=$(spec "${2:?$USAGE}")

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
install() { npm install --no-audit --no-fund --silent "$@"; }
project() { mkdir "$work/$1" && cd "$work/$1" && npm init -y >/dev/null; }

# 1. The core alone: must have zero runtime dependencies.
project core-only
install "$core"
extras=$(npm ls --all --parseable | tail -n +2 | grep -v '/@openmatter-network/matter-sdk-core$' || true)
[ -z "$extras" ] || { echo "smoke-npm: the core pulled in runtime dependencies:" >&2; echo "$extras" >&2; exit 1; }
cp "$repo/scripts/smoke/npm-core.mjs" .
node npm-core.mjs "$repo/testvectors/open_secret.json"

# 2. Core + client together.
project with-client
install "$core" "$client"
cp "$repo/scripts/smoke/npm-client.mjs" .
node npm-client.mjs

# 3. Types resolve through `exports` under nodenext.
install --save-dev "$TYPESCRIPT"
cp "$repo/scripts/smoke/npm-types.ts" .
npx --no-install tsc --noEmit --strict --skipLibCheck --target es2022 \
  --module nodenext --moduleResolution nodenext npm-types.ts

echo "npm smoke ok on node $(node --version)"

#!/usr/bin/env bash
# Assert that an npm tarball is the package we mean to publish, by reading the tarball —
# not the directory it was packed from, and not `npm pack`'s own report of it.
#
# dist/, wasm/ and wasm-web/ are build output and gitignored, so a pack from a tree that
# was never built still succeeds: the v0.2.0-v0.4.0 tarballs were 8.1 KB with no wasm in
# them. The publish job uploads exactly the file checked here.
#
#   usage: scripts/check-npm-tarball.sh <tarball.tgz> <version>
set -euo pipefail
tarball=$(realpath "${1:?usage: check-npm-tarball.sh <tarball.tgz> <version>}")
version=${2:?usage: check-npm-tarball.sh <tarball.tgz> <version>}
cd "$(dirname "$0")/.."

readonly CORE='@openmatter-network/matter-sdk-core'
readonly CLIENT='@openmatter-network/matter-sdk'
readonly -a COMMON_FILES=(package.json README.md LICENSE dist/index.js dist/index.d.ts)
# wasm/package.json is load-bearing, not wasm-pack litter: it carries no "type", which is
# what makes the nodejs-target glue CommonJS inside this ESM package. Without it Node
# parses `require` as ESM and the package cannot be imported at all.
readonly -a CORE_FILES=(
  wasm/package.json wasm/matter_sdk_wasm.js wasm/matter_sdk_wasm_bg.wasm
  wasm-web/package.json wasm-web/matter_sdk_wasm.js wasm-web/matter_sdk_wasm_bg.js wasm-web/matter_sdk_wasm_bg.wasm
)
# npm provenance compares repository.url to the building repository case-sensitively
# (E422 on mismatch), and the organisation is spelled OpenMatter-Network.
repo=${GITHUB_REPOSITORY:-$(git remote get-url origin | sed -E 's|^.*github\.com[:/]||; s|\.git$||')}
readonly repo

listing=$(tar -tzf "$tarball")
fail=0
bad() { echo "npm tarball $(basename "$tarball"): $1" >&2; fail=1; }
has() { grep -qxF "package/$1" <<<"$listing"; }
json() { tar -xzOf "$tarball" "package/$1" | jq -r "${@:2}"; }
expect() { [ "$2" = "$3" ] || bad "$1 is '$2', expected '$3'"; }

name=$(json package.json .name)
case "$name" in
  "$CORE") required=("${COMMON_FILES[@]}" "${CORE_FILES[@]}") ;;
  "$CLIENT") required=("${COMMON_FILES[@]}") ;;
  *) bad "unexpected package name '$name'"; required=() ;;
esac
for f in "${required[@]}"; do has "$f" || bad "missing $f"; done

expect version "$(json package.json .version)" "$version"
expect repository.url "$(json package.json '.repository | if type == "object" then .url else . end')" "git+https://github.com/$repo.git"
expect publishConfig.access "$(json package.json .publishConfig.access)" public
# A registry override here outranks the CLI's, and the old one pointed at GitHub Packages.
expect publishConfig.registry "$(json package.json '.publishConfig.registry // "unset"')" unset

local_specs=$(json package.json '(.dependencies // {}) | to_entries[] | select(.value | test("^(file|link|workspace):")) | "\(.key)=\(.value)"')
[ -z "$local_specs" ] || bad "dependencies resolve outside the registry: $local_specs"

if [ "$name" = "$CORE" ]; then
  expect 'dependencies (the core advertises none)' "$(json package.json '(.dependencies // {}) | length')" 0
  # A wasm directory left over from an earlier build still packs cleanly; its own
  # manifest is the only thing in the tarball that says which build it came from.
  for dir in wasm wasm-web; do
    has "$dir/package.json" && expect "$dir/package.json version" "$(json "$dir/package.json" .version)" "$version"
  done
  has wasm/package.json && expect 'wasm/package.json type (must stay CommonJS)' "$(json wasm/package.json '.type // "commonjs"')" commonjs
  has wasm-web/package.json && expect 'wasm-web/package.json type' "$(json wasm-web/package.json .type)" module
else
  # Exactly ^<version>: no looser range admits a release candidate of the core.
  # shellcheck disable=SC2016  # $core is jq's variable (--arg), not the shell's
  expect "dependencies[$CORE]" "$(json package.json --arg core "$CORE" '.dependencies[$core]')" "^$version"
fi

[ "$fail" = 0 ] && echo "npm tarball ok: $name@$version ($(wc -l <<<"$listing") files)"
exit "$fail"

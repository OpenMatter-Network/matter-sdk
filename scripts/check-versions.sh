#!/usr/bin/env bash
# Fail if any recorded version disagrees with Cargo.toml, or (--expect) if Cargo.toml
# disagrees with the version being released. scripts/set-version.sh writes all of them.
#
#   usage: scripts/check-versions.sh [--expect <version>]
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-version.sh
source scripts/lib-version.sh

readonly USAGE='usage: check-versions.sh [--expect <version>]'
readonly CORE_PACKAGE='@openmatter-network/matter-sdk-core'
readonly GO_MODULE_FILE=packages/go/mattersdk/go.mod
case "${1:-}" in
  '') expect='' ;;
  --expect) expect=${2:?$USAGE} ;;
  *) echo "$USAGE" >&2; exit 2 ;;
esac

want=$(workspace_version)
version_channel "$want" >/dev/null

read_toml() { sed -n '0,/^version = /s|^version = "\(.*\)"|\1|p' "$1"; }

# Local packages of a Cargo.lock (no `source`); `--locked` builds refuse stale ones.
lock_locals() {
  awk '
    function flush() { if (name != "" && !remote) print name "\t" version }
    /^\[\[package\]\]/ { flush(); name = ""; remote = 0 }
    /^name = /         { gsub(/"/, "", $3); name = $3 }
    /^version = /      { gsub(/"/, "", $3); version = $3 }
    /^source = /       { remote = 1 }
    END                { flush() }
  ' "$1"
}

# Every recorded version, as "<where>\t<X.Y.Z[-rc.N]>".
recorded() {
  local f name version
  for f in bindings/wasm/Cargo.toml bindings/python/Cargo.toml; do
    printf '%s\t%s\n' "$f" "$(read_toml "$f")"
  done
  for f in packages/typescript packages/typescript-core; do
    printf '%s\t%s\n' "$f/package.json" "$(jq -r .version "$f/package.json")"
    printf '%s\t%s\n' "$f/package-lock.json" "$(jq -r .version "$f/package-lock.json")"
    printf '%s\t%s\n' "$f/package-lock.json (root package)" "$(jq -r '.packages[""].version' "$f/package-lock.json")"
  done
  for f in Cargo.lock bindings/wasm/Cargo.lock bindings/python/Cargo.lock; do
    while IFS=$'\t' read -r name version; do
      printf '%s\t%s\n' "$f ($name)" "$version"
    done < <(lock_locals "$f")
  done
  # Exactly ^<version>: a looser range is unsatisfiable for a prerelease core.
  version=$(jq -r --arg core "$CORE_PACKAGE" '.dependencies[$core]' packages/typescript/package.json)
  printf '%s\t%s\n' "packages/typescript/package.json ($CORE_PACKAGE range $version)" "${version#^}"
  for f in examples/client-go/go.mod examples/go-e2e/go.mod; do
    version=$(sed -n 's|.*matter-sdk-go/v[0-9]* v\([^ ]*\).*|\1|p' "$f" | head -1)
    printf '%s\t%s\n' "$f (require)" "$version"
  done
  # Rust ships by git tag, copied from the README.
  version=$(sed -n 's|^matter-sdk = { git = "[^"]*", tag = "v\([^"]*\)".*|\1|p' README.md | head -1)
  printf '%s\t%s\n' 'README.md (Rust git tag)' "$version"
}

fail=0
while IFS=$'\t' read -r where version; do
  if [ "$version" != "$want" ]; then
    echo "version mismatch: $where is '$version', Cargo.toml is $want" >&2
    fail=1
  fi
done < <(recorded)

# Go majors >= 2 need a /vN module path suffix.
major=${want%%.*}
if [ "$major" -ge 2 ]; then suffix="/v$major"; else suffix=''; fi
module=$(sed -n 's|^module ||p' "$GO_MODULE_FILE")
if [ "$module" != "${module%/v[0-9]*}$suffix" ]; then
  echo "version mismatch: $GO_MODULE_FILE declares $module, major $major wants a '${suffix:-<none>}' suffix" >&2
  fail=1
fi

# maturin derives the PEP 440 version from bindings/python/Cargo.toml.
if grep -qE '^version[[:space:]]*=' bindings/python/pyproject.toml ||
  ! grep -qE '^dynamic = \[.*"version".*\]' bindings/python/pyproject.toml; then
  echo 'version mismatch: bindings/python/pyproject.toml must declare dynamic = ["version"] and no static version' >&2
  fail=1
fi

if [ -n "$expect" ] && [ "$expect" != "$want" ]; then
  echo "version mismatch: releasing $expect, but the manifests say $want." >&2
  echo "  Run scripts/set-version.sh, commit, and cut a NEW tag — never move a pushed tag." >&2
  fail=1
fi

[ "$fail" = 0 ] && echo "everything at $want"
exit "$fail"

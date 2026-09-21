#!/usr/bin/env bash
# Fail if anything that records the release version disagrees with Cargo.toml — or, with
# --expect, if Cargo.toml disagrees with the version being released.
#
# Before 2.0 the manifests had drifted three ways (Cargo 1.3.1, npm/PyPI 1.2.0, wasm 1.1.0)
# against tag v1.3.2. This check fixed that and left the next hole open: it compared the
# manifests to each other but never to the tag, so v2.1.0 was cut over manifests that all
# said 2.0.0, with CI green. --expect is the release gate that closes it.
#
#   usage: scripts/check-versions.sh [--expect <version>]
#
# scripts/set-version.sh writes everything this reads.
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

# The local packages of a Cargo.lock are the ones with no `source`. `cargo build --locked`
# (the musl consumer job) refuses a lockfile whose local versions lag the manifests.
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

# Every place the version is recorded, as "<where>\t<version>" with the version reduced
# to the bare X.Y.Z[-rc.N] form, so one comparison below covers them all.
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
  # The client's range on the core must be exactly ^<version>. A major-only comparison
  # accepts ^2.0.0 while shipping 2.1.1-rc.1 — a range no prerelease satisfies, so the
  # release-candidate client could not be installed.
  version=$(jq -r --arg core "$CORE_PACKAGE" '.dependencies[$core]' packages/typescript/package.json)
  printf '%s\t%s\n' "packages/typescript/package.json ($CORE_PACKAGE range $version)" "${version#^}"
  for f in examples/client-go/go.mod examples/go-e2e/go.mod; do
    version=$(sed -n 's|.*matter-sdk-go/v[0-9]* v\([^ ]*\).*|\1|p' "$f" | head -1)
    printf '%s\t%s\n' "$f (require)" "$version"
  done
  # The git tag is Rust's release channel, and the README is where a consumer copies it from.
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

# Go spells the major in the import path, so a major bump that skips go.mod ships a module
# the toolchain refuses to resolve.
major=${want%%.*}
if [ "$major" -ge 2 ]; then suffix="/v$major"; else suffix=''; fi
module=$(sed -n 's|^module ||p' "$GO_MODULE_FILE")
if [ "$module" != "${module%/v[0-9]*}$suffix" ]; then
  echo "version mismatch: $GO_MODULE_FILE declares $module, major $major wants a '${suffix:-<none>}' suffix" >&2
  fail=1
fi

# maturin takes the distribution version from bindings/python/Cargo.toml and spells it
# for PEP 440 itself; a static one here is a second home that cannot hold an rc.
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

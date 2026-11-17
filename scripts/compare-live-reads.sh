#!/usr/bin/env bash
# Hold the four bindings to the same bytes: run every catalogue read
# (testvectors/facade_reads.json, with the arguments in testvectors/live_reads.json)
# against a live chain at ONE finalized block, in Rust, TypeScript, Python and Go,
# and require byte-identical canonical JSON from all four. Each binding records a
# result as the text its own canonical-JSON entry point produced, so what is
# compared is the bytes a caller gets, not a re-serialization of them.
#
# Read-only: no key, no submission. Needs the network and each binding built
# (the Go tests link target/release/libmatter_sdk_ffi.a; the Python tests need the
# wheel installed in the interpreter PYTEST runs).
#
#   scripts/compare-live-reads.sh
#   MATTER_RPC_URL=wss://… PYTEST="uv run pytest" scripts/compare-live-reads.sh
set -euo pipefail
cd "$(dirname "$0")/.."

readonly PYTEST=${PYTEST:-python -m pytest}
readonly -a BINDINGS=(rust typescript python go)

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
export MATTER_LIVE=yes

run() {
  local binding=$1
  shift
  echo "== $binding" >&2
  if ! MATTER_LIVE_READS_OUT="$out/$binding.json" "$@" >"$out/$binding.log" 2>&1; then
    cat "$out/$binding.log" >&2
    echo "compare-live-reads: the $binding run failed" >&2
    exit 1
  fi
  [ -s "$out/$binding.json" ] || {
    cat "$out/$binding.log" >&2
    echo "compare-live-reads: the $binding run wrote no results" >&2
    exit 1
  }
}

# Rust resolves the finalized head; the other three are pinned to the block it used.
run rust cargo test -p matter-sdk --features chain --test live_chain -- \
  --ignored every_catalogue_read_decodes_against_the_live_runtime
MATTER_AT_BLOCK=$(jq -er .at "$out/rust.json")
export MATTER_AT_BLOCK

(cd packages/typescript && run typescript npx vitest run test/liveReads.test.ts)
# shellcheck disable=SC2086 # PYTEST is a command line, split on purpose.
(cd bindings/python && run python $PYTEST -q tests/test_live_reads.py)
(cd packages/go/mattersdk && run go go test -count=1 -run 'TestLiveReads' ./...)

# One binding's results, normalized: without the reads that describe the node at
# the moment it was asked, which no two runs can agree on.
comparable() {
  jq -S -c --slurpfile live testvectors/live_reads.json '
    ($live[0].reads | map(select(.volatile == true) | [.facade, .method])) as $volatile
    | .reads |= map(select([.facade, .method] as $read | $volatile | index([$read]) | not))
  ' "$out/$1.json"
}

digest() { comparable "$1" | sha256sum | cut -d' ' -f1; }

expected=$(digest rust)
status=0
for binding in "${BINDINGS[@]}"; do
  actual=$(digest "$binding")
  printf '%-10s %s\n' "$binding" "$actual"
  if [ "$actual" != "$expected" ]; then
    status=1
    echo "compare-live-reads: $binding differs from rust:" >&2
    diff <(comparable rust | jq .) <(comparable "$binding" | jq .) >&2 || true
  fi
done

reads=$(comparable rust | jq '.reads | length')
if [ "$status" -eq 0 ]; then
  echo "compare-live-reads: $reads reads agree across ${#BINDINGS[@]} bindings at $MATTER_AT_BLOCK"
fi
exit "$status"

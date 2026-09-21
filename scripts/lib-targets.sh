#!/usr/bin/env bash
# Read scripts/native-targets.json, the one list of platforms we ship native code for.
# Sourced, never executed.
#
# One row per platform. The static-library build, the wheel build, both smoke matrices,
# the generated cgo link file and the README's platform table are all projections of
# it, so adding a platform is adding a row. What can be derived from a row is derived
# here rather than stored, because a stored copy is one that can contradict its row.

TARGETS_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/native-targets.json"
readonly TARGETS_FILE
readonly FFI_LIB_STEM=libmatter_sdk_ffi
# Oldest macOS the native artifacts may run on, and the version in the macOS wheel tags.
# Set explicitly for every build: unset, rustc and maturin take the build host's version
# (or a per-arch default), and the artifacts then claim a platform nobody chose.
export MACOSX_DEPLOYMENT_TARGET=11.0

# target_ids: every row id, in table order.
target_ids() { jq -r '.[].id' "$TARGETS_FILE"; }

# target_field <id> <field>: fails on an unknown id or field rather than printing "null".
target_field() {
  jq -er --arg id "$1" --arg field "$2" \
    '.[] | select(.id == $id) | if has($field) then .[$field] else null end' "$TARGETS_FILE" ||
    { echo "native-targets.json: no field '$2' for target '$1'" >&2; return 1; }
}

# target_archive <id>: the archive's file name in the Go module, which follows the
# convention Go developers already know from confluent-kafka-go.
target_archive() { echo "${FFI_LIB_STEM}_$1.a"; }

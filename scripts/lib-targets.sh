#!/usr/bin/env bash
# Read scripts/native-targets.json, the single list of native platforms (builds, smoke
# matrices, cgo link file, README table). Sourced, never executed. Values derivable from
# a row are computed here, not stored in the JSON.

TARGETS_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/native-targets.json"
readonly TARGETS_FILE
readonly FFI_LIB_STEM=libmatter_sdk_ffi
# Minimum macOS for native artifacts and wheel tags; unset, the build host's is used.
export MACOSX_DEPLOYMENT_TARGET=11.0

target_ids() { jq -r '.[].id' "$TARGETS_FILE"; }

# target_field <id> <field>: fails on an unknown id or field.
target_field() {
  jq -er --arg id "$1" --arg field "$2" \
    '.[] | select(.id == $id) | if has($field) then .[$field] else null end' "$TARGETS_FILE" ||
    { echo "native-targets.json: no field '$2' for target '$1'" >&2; return 1; }
}

# target_archive <id>: the archive's file name in the Go module.
target_archive() { echo "${FFI_LIB_STEM}_$1.a"; }

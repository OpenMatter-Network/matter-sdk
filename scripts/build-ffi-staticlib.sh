#!/usr/bin/env bash
# Build the FFI static archive for one row of scripts/native-targets.json.
#
#   usage: scripts/build-ffi-staticlib.sh <target-id> <out-dir>
#
# `cargo rustc --crate-type staticlib`: needs no cross-linker, and is the only way LTO
# ([profile.release-ffi]) applies, since cargo skips LTO for crates that declare `rlib`.
set -euo pipefail
readonly USAGE='usage: build-ffi-staticlib.sh <target-id> <out-dir>'
id=${1:?$USAGE}
# Not `realpath -m`: macOS realpath has no -m.
mkdir -p "${2:?$USAGE}"
out=$(cd "$2" && pwd)
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-targets.sh
source scripts/lib-targets.sh

readonly PROFILE=release-ffi
# Fails the build if LTO stops applying (~30 MB without it).
readonly MAX_ARCHIVE_BYTES=$((12 * 1024 * 1024))
# Libraries every C driver links on its own; rustc lists them, a cgo line need not.
readonly -a IMPLICIT_LIBS=(-lc -lgcc_s -lSystem)

triple=$(target_field "$id" rust_target)
rustflags=$(target_field "$id" ffi_rustflags)
ldflags=$(target_field "$id" ldflags)

rustup target add "$triple" >/dev/null 2>&1
rustup component add llvm-tools >/dev/null 2>&1

log=$(mktemp)
trap 'rm -f "$log"' EXIT
# Keep builder paths out of panic messages in the published binary.
remap="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
remap+=" --remap-path-prefix=$PWD=/matter-sdk"
remap+=" --remap-path-prefix=$(rustc --print sysroot)=/rustc"
# --color never: native-static-libs is parsed below and ANSI codes would corrupt it.
RUSTFLAGS="$remap $rustflags" \
  cargo rustc --color never -p matter-sdk-ffi --lib --locked --profile "$PROFILE" --target "$triple" \
  --crate-type staticlib -- --print native-static-libs 2>&1 | tee "$log" >&2

# The row's ldflags become the cgo link line; every library rustc requires must be in it,
# or consumers get undefined symbols.
needed=$(sed -n 's/.*native-static-libs: //p' "$log" | tail -1)
[ -n "$needed" ] || { echo "build-ffi-staticlib: rustc did not report native-static-libs for $triple" >&2; exit 1; }
for lib in $needed; do
  case " ${IMPLICIT_LIBS[*]} $ldflags " in
    *" $lib "*) ;;
    *) echo "build-ffi-staticlib: $triple needs '$lib', which the '$id' row's ldflags omit ($ldflags)" >&2; exit 1 ;;
  esac
done

archive="target/$triple/$PROFILE/$FFI_LIB_STEM.a"
# Profile `strip` never applies to a static archive; strip std's debug info here.
host=$(rustc -vV | sed -n 's/^host: //p')
"$(rustc --print sysroot)/lib/rustlib/$host/bin/llvm-strip" --strip-debug "$archive"

bytes=$(wc -c <"$archive")
if [ "$bytes" -gt "$MAX_ARCHIVE_BYTES" ]; then
  echo "build-ffi-staticlib: $archive is $bytes bytes, over the $MAX_ARCHIVE_BYTES budget — did LTO stop applying?" >&2
  exit 1
fi

install -m 644 "$archive" "$out/$(target_archive "$id")"
echo "built $(target_archive "$id"): $bytes bytes"

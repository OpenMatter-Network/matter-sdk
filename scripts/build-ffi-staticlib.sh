#!/usr/bin/env bash
# Build the FFI static archive for one row of scripts/native-targets.json — the file a Go
# consumer links, so they need neither a Rust toolchain nor the private core's source.
#
#   usage: scripts/build-ffi-staticlib.sh <target-id> <out-dir>
#
# `cargo rustc --crate-type staticlib`, not `cargo build`, for two reasons. A static
# archive is assembled by rustc's own archiver, so no cross-linker is needed for any
# target. And matter-sdk-ffi also declares `rlib`, for which cargo silently skips LTO;
# overriding the crate type is what lets [profile.release-ffi] take effect at all.
set -euo pipefail
readonly USAGE='usage: build-ffi-staticlib.sh <target-id> <out-dir>'
id=${1:?$USAGE}
# Not `realpath -m`: the darwin rows build on macOS, whose realpath has no -m.
mkdir -p "${2:?$USAGE}"
out=$(cd "$2" && pwd)
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-targets.sh
source scripts/lib-targets.sh

readonly PROFILE=release-ffi
# Without LTO the archive is 30 MB. A budget turns "LTO quietly stopped applying" from
# a slow bloat of every release into a failed build.
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
# Remapping keeps the builder's home directory out of the panic messages in a public
# binary: dependency sources, this checkout, and (where rust-src is installed) std's own.
remap="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
remap+=" --remap-path-prefix=$PWD=/matter-sdk"
remap+=" --remap-path-prefix=$(rustc --print sysroot)=/rustc"
RUSTFLAGS="$remap $rustflags" \
  cargo rustc -p matter-sdk-ffi --lib --locked --profile "$PROFILE" --target "$triple" \
  --crate-type staticlib -- --print native-static-libs 2>&1 | tee "$log" >&2

# rustc is the authority on what the archive must be linked with. The row's ldflags
# become a cgo line in the published module; if rustc names a library the row lacks,
# consumers get undefined symbols at link time, on their machine, with no pointer here.
needed=$(sed -n 's/.*native-static-libs: //p' "$log" | tail -1)
[ -n "$needed" ] || { echo "build-ffi-staticlib: rustc did not report native-static-libs for $triple" >&2; exit 1; }
for lib in $needed; do
  case " ${IMPLICIT_LIBS[*]} $ldflags " in
    *" $lib "*) ;;
    *) echo "build-ffi-staticlib: $triple needs '$lib', which the '$id' row's ldflags omit ($ldflags)" >&2; exit 1 ;;
  esac
done

archive="target/$triple/$PROFILE/$FFI_LIB_STEM.a"
# A static archive has no link step, so profile `strip` never applies to it; the debug
# info of the prebuilt std objects is carried in whole unless it is removed here.
host=$(rustc -vV | sed -n 's/^host: //p')
"$(rustc --print sysroot)/lib/rustlib/$host/bin/llvm-strip" --strip-debug "$archive"

bytes=$(wc -c <"$archive")
if [ "$bytes" -gt "$MAX_ARCHIVE_BYTES" ]; then
  echo "build-ffi-staticlib: $archive is $bytes bytes, over the $MAX_ARCHIVE_BYTES budget — did LTO stop applying?" >&2
  exit 1
fi

install -m 644 "$archive" "$out/$(target_archive "$id")"
echo "built $(target_archive "$id"): $bytes bytes"

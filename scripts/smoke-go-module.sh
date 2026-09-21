#!/usr/bin/env bash
# `go get` the Go module the way a consumer does, from a module outside this repository,
# and prove it builds and runs with no Rust toolchain and nothing on the library path.
# Run before publishing against the assembled tree, and after against the real proxy:
# the same script, so "verified" and "published" are the same claim.
#
#   usage: scripts/smoke-go-module.sh <assembled-dir | vX.Y.Z>
#     GOTAGS            build tags for this platform (musl on Alpine)
#     SMOKE_BINARY_OUT  copy the built consumer here, to run on a bare image afterwards
#
# An assembled tree is resolved through go's own VCS path — a throwaway git repository
# standing in for GitHub — not through a `replace`. A replace skips everything that goes
# wrong for real consumers: tag and /vN semantics, module-zip creation (which drops
# symlinks and any directory named vendor), and ${SRCDIR} pointing into the module cache.
set -euo pipefail
spec=${1:?usage: smoke-go-module.sh <assembled-dir | vX.Y.Z>}
repo=$(cd "$(dirname "$0")/.." && pwd)
readonly repo
readonly MODULE=github.com/openmatter-network/matter-sdk-go/v2
readonly MODULE_URL=https://github.com/openmatter-network/matter-sdk-go
readonly NOCGO_SENTINEL=mattersdk_requires_cgo
readonly VECTOR="$repo/testvectors/open_secret.json"
tags=${GOTAGS:-}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# -modcacherw: the module cache is read-only by default, which would defeat the cleanup.
export GOWORK=off GOMODCACHE="$work/modcache" GOFLAGS="-modcacherw${tags:+ -tags=$tags}"

if [ -d "$spec" ]; then
  major=${MODULE##*/v}
  version="v$major.0.0-smoke"
  git init -q "$work/remote"
  cp -R "$spec"/. "$work/remote"/
  git -C "$work/remote" add -A
  git -C "$work/remote" -c user.name=smoke -c user.email=smoke@invalid commit -qm smoke
  git -C "$work/remote" tag "$version"
  export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.file://$work/remote.insteadOf" GIT_CONFIG_VALUE_0="$MODULE_URL"
  export GOPRIVATE="$MODULE" # fetch this one module direct from "GitHub"; everything else via the proxy
else
  version=$spec
fi

mkdir "$work/consumer" && cd "$work/consumer"
cp "$repo/scripts/smoke/go-consumer.go" main.go
go mod init smoke.test/consumer >/dev/null 2>&1
go get "$MODULE@$version" >/dev/null 2>&1 || go get "$MODULE@$version" # quiet unless it fails

CGO_ENABLED=1 go build -o smoke .
env -u LD_LIBRARY_PATH -u DYLD_LIBRARY_PATH ./smoke "$VECTOR"

# The core must be IN the binary. libgcc_s counts: a bare Alpine or distroless image has
# none, so a binary that needs it starts on the build machine and nowhere it is deployed.
case "$(go env GOOS)" in
  linux) dynamic=$(readelf -d smoke | grep -E 'NEEDED.*(matter_sdk_ffi|libgcc_s)' || true) ;;
  darwin) dynamic=$(otool -L smoke | grep matter_sdk_ffi || true) ;;
esac
[ -z "$dynamic" ] || { echo "smoke-go-module: the consumer links dynamically: $dynamic" >&2; exit 1; }

# The module's own suite, from the module cache: its fixtures travel with it.
go vet "$MODULE"
go test "$MODULE"

# Vendoring copies only the files of imported package directories, so archives kept
# anywhere else would silently vanish for every consumer who vendors.
go mod vendor
go build -mod=vendor -o smoke-vendored .

# The failures a consumer is likeliest to hit must say what is wrong, at compile time.
expect_error() { # <pattern> <command...>
  local pattern=$1 output
  shift
  if output=$("$@" 2>&1); then echo "smoke-go-module: expected '$*' to fail" >&2; exit 1; fi
  grep -q "$pattern" <<<"$output" || { echo "smoke-go-module: '$*' failed without saying '$pattern':" >&2; echo "$output" >&2; exit 1; }
}
expect_error "$NOCGO_SENTINEL" env CGO_ENABLED=0 go build -o /dev/null .
if [ "$(go env GOOS)" = linux ]; then
  case " $tags " in
    *" musl "*) expect_error 'build with -tags musl' env GOFLAGS=-modcacherw go build -o /dev/null . ;;
    *) expect_error 'libc is glibc' go build -tags musl -o /dev/null . ;;
  esac
fi

[ -z "${SMOKE_BINARY_OUT:-}" ] || install -m 755 smoke "$SMOKE_BINARY_OUT"
echo "go module smoke ok: $MODULE@$version on $(go env GOOS)/$(go env GOARCH)${tags:+ (tags: $tags)}"

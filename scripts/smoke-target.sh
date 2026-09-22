#!/usr/bin/env bash
# Run one consumer smoke test for one row of scripts/native-targets.json, where that row
# says it must run: on this machine, or inside the container image that carries the
# platform's real libc. The release workflow calls it twice per platform — on the built
# artifacts before publishing, and on the registries after — so "where and how a
# platform is tested" is written down once.
#
#   usage: scripts/smoke-target.sh <go|python> <target-id> <spec>
#     spec: a directory of artifacts, or a published version (see the smoke-*.sh scripts)
set -euo pipefail
readonly USAGE='usage: smoke-target.sh <go|python> <target-id> <spec>'
kind=${1:?$USAGE}
id=${2:?$USAGE}
spec=${3:?$USAGE}
repo=$(cd "$(dirname "$0")/.." && pwd)
readonly repo
# shellcheck source=scripts/lib-targets.sh
source "$repo/scripts/lib-targets.sh"

readonly LIBC_MUSL=musl
readonly GO_TAG_MUSL=musl
# Oldest and newest CPython the abi3 wheel claims, as the PyPA images lay them out.
readonly -a PYPA_INTERPRETERS=(/opt/python/cp39-cp39/bin/python /opt/python/cp313-cp313/bin/python)
# What the Go smoke needs on the Alpine Go image, and the image the binary must then run
# on with nothing added: no compiler, no libgcc_s — what a minimal deployment looks like.
readonly ALPINE_BUILD_PACKAGES='bash build-base git'
readonly BARE_IMAGE=alpine:3

# A directory spec is mounted into the container; a version spec is passed through.
# Expanded as ${mount[@]+"${mount[@]}"}: bash 3.2 (macOS runners) treats a plain
# expansion of an empty array as an unbound variable under set -u.
mount=()
inner=$spec
if [ -d "$spec" ]; then
  mount=(-v "$(cd "$spec" && pwd):/artifacts:ro")
  inner=/artifacts
fi

case "$kind" in
  go)
    image=$(target_field "$id" go_smoke_image)
    if [ "$(target_field "$id" libc)" = "$LIBC_MUSL" ]; then tags=$GO_TAG_MUSL; else tags=''; fi
    if [ -z "$image" ]; then
      GOTAGS=$tags "$repo/scripts/smoke-go-module.sh" "$spec"
    else
      out=$(mktemp -d)
      trap 'rm -rf "$out"' EXIT
      docker run --rm -v "$repo:/repo:ro" ${mount[@]+"${mount[@]}"} -v "$out:/out" -e GOTAGS="$tags" -e SMOKE_BINARY_OUT=/out/smoke "$image" \
        sh -c "apk add --no-cache $ALPINE_BUILD_PACKAGES >/dev/null && /repo/scripts/smoke-go-module.sh '$inner'"
      docker run --rm -v "$out:/out:ro" -v "$repo/testvectors:/vectors:ro" "$BARE_IMAGE" /out/smoke /vectors/open_secret.json
      echo "go consumer binary runs on bare $BARE_IMAGE"
    fi
    ;;
  python)
    image=$(target_field "$id" python_smoke_image)
    if [ -z "$image" ]; then
      "$repo/scripts/smoke-python-wheel.sh" "$spec"
    else
      for python in "${PYPA_INTERPRETERS[@]}"; do
        docker run --rm -v "$repo:/repo:ro" ${mount[@]+"${mount[@]}"} -e PYTHON="$python" "$image" /repo/scripts/smoke-python-wheel.sh "$inner"
      done
    fi
    ;;
  *)
    echo "$USAGE" >&2
    exit 2
    ;;
esac

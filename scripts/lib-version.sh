#!/usr/bin/env bash
# The version shapes a release may carry, and what each one means to every registry.
# Sourced by the scripts that decide or check a release; never executed.
#
# Two shapes only. Each extra shape is a rule somebody has to get right on npm (which
# dist-tag moves), PyPI (how it normalises) and the Go proxy (which caches it forever),
# so anything else is refused until that rule is written down here.

readonly CHANNEL_STABLE=stable
readonly CHANNEL_RC=rc
# `latest` is what a bare `npm install` resolves; a release candidate must not move it.
readonly DIST_TAG_STABLE=latest
readonly DIST_TAG_RC=next

# SemVer numeric identifiers: no leading zeros, so 2.01.0 cannot alias 2.1.0.
readonly _NUM='(0|[1-9][0-9]*)'
readonly VERSION_STABLE="^${_NUM}\.${_NUM}\.${_NUM}$"
readonly VERSION_RC="^${_NUM}\.${_NUM}\.${_NUM}-rc\.${_NUM}$"

# version_channel <version> -> stable | rc. Fails on any other shape.
version_channel() {
  if [[ $1 =~ $VERSION_STABLE ]]; then
    echo "$CHANNEL_STABLE"
  elif [[ $1 =~ $VERSION_RC ]]; then
    echo "$CHANNEL_RC"
  else
    echo "unsupported version '$1': expected X.Y.Z or X.Y.Z-rc.N" >&2
    return 1
  fi
}

# pep440 <version>: the spelling PyPI and the wheel filename use (2.1.1-rc.1 -> 2.1.1rc1).
pep440() { echo "${1/-rc./rc}"; }

# The one version every manifest must agree with: [workspace.package] in Cargo.toml.
workspace_version() {
  sed -n '/^\[workspace.package\]/,/^\[/p' "$(dirname "${BASH_SOURCE[0]}")/../Cargo.toml" |
    sed -n 's|^version = "\(.*\)"|\1|p'
}

# plan_line <version> <publish>: what releasing <version> means, as key=value words.
plan_line() {
  local channel
  channel=$(version_channel "$1") || return 1
  local -A dist_tag=([$CHANNEL_STABLE]=$DIST_TAG_STABLE [$CHANNEL_RC]=$DIST_TAG_RC)
  local -A prerelease=([$CHANNEL_STABLE]=false [$CHANNEL_RC]=true)
  echo "version=$1 channel=$channel npm_dist_tag=${dist_tag[$channel]}" \
    "pep440=$(pep440 "$1") prerelease=${prerelease[$channel]} publish=$2"
}

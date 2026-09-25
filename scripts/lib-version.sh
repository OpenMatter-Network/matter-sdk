#!/usr/bin/env bash
# Release version shapes (X.Y.Z, X.Y.Z-rc.N) and their registry mappings. Sourced, never
# executed. Any other shape is refused.

readonly CHANNEL_STABLE=stable
readonly CHANNEL_RC=rc
# A release candidate must not move `latest`.
readonly DIST_TAG_STABLE=latest
readonly DIST_TAG_RC=next

# No leading zeros, so 2.01.0 cannot alias 2.1.0.
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

# The source-of-truth version: [workspace.package] in Cargo.toml.
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

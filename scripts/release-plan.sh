#!/usr/bin/env bash
# Decide what a workflow run releases, as key=value lines for $GITHUB_OUTPUT.
# Pinned by scripts/test-release-plan.sh.
#
#   usage: scripts/release-plan.sh <event_name> <ref_type> <ref_name>
#
# Only a pushed tag publishes. Anything else is a dry run for the tag, or, off a tag,
# for the manifests' version.
set -euo pipefail
readonly EVENT_PUSH=push
readonly REF_TYPE_TAG=tag
readonly TAG_PREFIX=v

event=${1:?usage: release-plan.sh <event_name> <ref_type> <ref_name>}
ref_type=${2:?usage: release-plan.sh <event_name> <ref_type> <ref_name>}
ref_name=${3:?usage: release-plan.sh <event_name> <ref_type> <ref_name>}
# shellcheck source=scripts/lib-version.sh
source "$(dirname "$0")/lib-version.sh"

if [ "$ref_type" = "$REF_TYPE_TAG" ]; then
  [[ $ref_name == "$TAG_PREFIX"* ]] || { echo "tag '$ref_name' does not start with '$TAG_PREFIX'" >&2; exit 1; }
  version=${ref_name#"$TAG_PREFIX"}
else
  version=$(workspace_version)
fi

if [ "$event" = "$EVENT_PUSH" ] && [ "$ref_type" = "$REF_TYPE_TAG" ]; then publish=true; else publish=false; fi

# Build the whole plan first: a refusal must not leave half a plan on stdout.
plan=$(plan_line "$version" "$publish")
tr ' ' '\n' <<<"$plan"

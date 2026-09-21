#!/usr/bin/env bash
# Decide what a workflow run releases, as key=value lines for $GITHUB_OUTPUT.
#
# "Publish or not" used to be re-derived by a `startsWith(github.ref, ...)` on each
# upload step, and the published npm version was rewritten from the tag at publish
# time — so a tag could (and did, v2.1.0 over 2.0.0 manifests) name a version no
# manifest carried. The decision lives here once; scripts/test-release-plan.sh pins it.
#
#   usage: scripts/release-plan.sh <event_name> <ref_type> <ref_name>
#
# Only a pushed tag publishes. Any other run is a dry run of the same plan: for the tag
# it was dispatched on, or, off a tag, for whatever the manifests currently say.
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

# Build the whole plan before printing any of it: a refusal must not leave half a plan
# on stdout for a caller to act on.
plan=$(plan_line "$version" "$publish")
tr ' ' '\n' <<<"$plan"

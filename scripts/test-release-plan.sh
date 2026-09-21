#!/usr/bin/env bash
# Table tests for the release gate: scripts/release-plan.sh (what a ref publishes, and
# under which names) and scripts/check-versions.sh --expect (the tag/manifest gate).
#
# The gate is the one place a release decides "publish or not" and "latest or next", and
# a wrong answer is irreversible on a public registry — so its rule is pinned here as a
# table rather than re-derived by reading the workflow. Toolchain-free; runs in `guards`.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-version.sh
source scripts/lib-version.sh

readonly REJECTED='<rejected>'
manifest=$(workspace_version)
readonly manifest

# event | ref_type | ref_name | expected stdout, keys space-separated (or $REJECTED)
readonly -a CASES=(
  "push|tag|v2.1.1|version=2.1.1 channel=stable npm_dist_tag=latest pep440=2.1.1 prerelease=false publish=true"
  "push|tag|v2.1.1-rc.1|version=2.1.1-rc.1 channel=rc npm_dist_tag=next pep440=2.1.1rc1 prerelease=true publish=true"
  "push|tag|v10.20.30-rc.12|version=10.20.30-rc.12 channel=rc npm_dist_tag=next pep440=10.20.30rc12 prerelease=true publish=true"
  # A dispatch is a dry run whatever it is dispatched on: same plan, never publishes.
  "workflow_dispatch|tag|v2.1.1-rc.1|version=2.1.1-rc.1 channel=rc npm_dist_tag=next pep440=2.1.1rc1 prerelease=true publish=false"
  # Off a tag there is no tag to read, so the plan is for whatever the manifests say.
  "workflow_dispatch|branch|main|$(plan_line "$manifest" false)"
  "push|branch|main|$(plan_line "$manifest" false)"
  # Shapes no registry rule was written for are refused outright, not guessed at.
  "push|tag|2.1.1|$REJECTED"
  "push|tag|v2.1|$REJECTED"
  "push|tag|v2.1.1-rc1|$REJECTED"
  "push|tag|v2.1.1-beta.1|$REJECTED"
  "push|tag|v2.1.1+build.5|$REJECTED"
  "push|tag|v02.1.1|$REJECTED"
  "push|tag|v2.1.1-rc.01|$REJECTED"
  "push|tag|vlatest|$REJECTED"
)

fail=0
check() { # <label> <expected> <actual>
  [ "$2" = "$3" ] && return 0
  printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3" >&2
  fail=1
}

for case in "${CASES[@]}"; do
  IFS='|' read -r event ref_type ref_name expected <<<"$case"
  if out=$(scripts/release-plan.sh "$event" "$ref_type" "$ref_name" 2>/dev/null); then
    actual=$(tr '\n' ' ' <<<"$out" | sed 's/ $//')
  else
    # A refusal must not leave a half-written plan behind for a caller to act on.
    actual=$REJECTED${out:+ (but printed: $out)}
  fi
  check "release-plan $event $ref_type $ref_name" "$expected" "$actual"
done

# The tag gate: the manifests' own version is accepted, anything else is refused.
gate() { scripts/check-versions.sh --expect "$1" >/dev/null 2>&1 && echo accepted || echo refused; }
check "check-versions --expect $manifest" accepted "$(gate "$manifest")"
check "check-versions --expect 9.9.9" refused "$(gate 9.9.9)"
check "check-versions --expect (no value)" refused "$(scripts/check-versions.sh --expect >/dev/null 2>&1 && echo accepted || echo refused)"

[ "$fail" = 0 ] && echo "release gate: ${#CASES[@]} plan cases + 3 gate cases pass"
exit "$fail"

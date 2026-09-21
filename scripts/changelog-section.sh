#!/usr/bin/env bash
# Print the CHANGELOG.md section for a version; fail if there is none or it is empty.
# The release gate runs it to refuse a tag nobody has described, and the GitHub Release
# takes its notes from the same output — so what is announced is what was reviewed.
#
#   usage: scripts/changelog-section.sh <version>
#
# A release candidate is described by its final version's section: 2.1.1-rc.1 ships what
# [2.1.1] says, and giving each candidate a section of its own would only invite drift.
set -euo pipefail
version=${1:?usage: changelog-section.sh <version>}
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-version.sh
source scripts/lib-version.sh
version_channel "$version" >/dev/null
readonly CHANGELOG=CHANGELOG.md
final=${version%%-*}

section=$(awk -v heading="## [$final]" '
  index($0, heading) == 1 { found = 1; next }
  found && /^## \[/       { exit }
  found                   { print }
' "$CHANGELOG")

if [ -z "$(tr -d '[:space:]' <<<"$section")" ]; then
  echo "changelog: $CHANGELOG has no (or an empty) '## [$final]' section for $version" >&2
  exit 1
fi
printf '%s\n' "$section"

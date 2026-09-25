#!/usr/bin/env bash
# Print the CHANGELOG.md section for a version; fail if missing or empty. Used by the
# release gate and as the GitHub Release notes.
#
#   usage: scripts/changelog-section.sh <version>
#
# A pre-release uses its final version's section (2.1.1-rc.1 -> [2.1.1]).
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

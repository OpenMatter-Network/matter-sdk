#!/usr/bin/env bash
# Render the supported-platforms table from scripts/native-targets.json, or check that a
# document carries the current one. The table developers read is a projection of the
# table the release builds from, so the documentation cannot promise a platform that is
# not shipped, nor forget one that is.
#
#   usage: scripts/platform-table.sh                  print the markdown table
#          scripts/platform-table.sh --check <file>   fail unless <file> holds it, between
#                                                     the platforms:begin / platforms:end markers
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-targets.sh
source scripts/lib-targets.sh
readonly BEGIN='<!-- platforms:begin -->'
readonly END='<!-- platforms:end -->'

table() {
  echo '| OS | Architecture | C library | Python wheel | Go build |'
  echo '|---|---|---|---|---|'
  jq -r '
    {"linux": "Linux", "darwin": "macOS"} as $os
    | {"amd64": "x86-64", "arm64": "arm64"} as $arch
    | .[]
    | "| \($os[.goos]) | \($arch[.goarch]) | \(if .libc == "" then "—" else .libc end) | `\(.wheel_tag | split(".")[0])` | \(if .libc == "musl" then "`go build -tags musl`" else "`go build`" end) |"
  ' "$TARGETS_FILE"
}

case "${1:-}" in
  '') table ;;
  --check)
    file=${2:?usage: platform-table.sh --check <file>}
    documented=$(sed -n "/^$BEGIN\$/,/^$END\$/p" "$file" | sed '1d;$d')
    if [ "$documented" != "$(table)" ]; then
      echo "platform table: $file is out of date with scripts/native-targets.json." >&2
      echo "  Replace the lines between '$BEGIN' and '$END' with the output of scripts/platform-table.sh" >&2
      exit 1
    fi
    echo "platform table in $file is current"
    ;;
  *) echo 'usage: platform-table.sh [--check <file>]' >&2; exit 2 ;;
esac

#!/usr/bin/env bash
# Render the read catalogue from testvectors/facade_reads.json, or check a doc.
#
#   usage: scripts/read-catalogue.sh                  print the markdown table
#          scripts/read-catalogue.sh --check <file>   fail unless <file> holds it, between
#                                                     the reads:begin / reads:end markers
set -euo pipefail
cd "$(dirname "$0")/.."
readonly CATALOGUE=testvectors/facade_reads.json
readonly BEGIN='<!-- reads:begin -->'
readonly END='<!-- reads:end -->'

table() {
  echo '| Read | Answers | Sources |'
  echo '|---|---|---|'
  jq -r '
    .reads[]
    | "| `\(.facade).\(.method)(\(.args | map(.name) | join(", ")))` | \(.summary) | \(.sources | map("`\(.name)`") | join(", ")) |"
  ' "$CATALOGUE"
}

case "${1:-}" in
  '') table ;;
  --check)
    file=${2:?usage: read-catalogue.sh --check <file>}
    documented=$(sed -n "/^$BEGIN\$/,/^$END\$/p" "$file" | sed '1d;$d')
    if [ "$documented" != "$(table)" ]; then
      echo "read catalogue: $file is out of date with $CATALOGUE." >&2
      echo "  Replace the lines between '$BEGIN' and '$END' with the output of scripts/read-catalogue.sh" >&2
      exit 1
    fi
    echo "read catalogue in $file is current"
    ;;
  *) echo 'usage: read-catalogue.sh [--check <file>]' >&2; exit 2 ;;
esac

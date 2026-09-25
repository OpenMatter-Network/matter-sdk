#!/usr/bin/env bash
# Fail on documentation links a reader cannot follow:
#   1. relative links/images in tracked Markdown must resolve (anchors not checked);
#   2. no links to the private core repositories;
#   3. npm/PyPI READMEs use absolute links only (the Go README is rewritten on assembly).
set -euo pipefail
cd "$(dirname "$0")/.."

readonly PRIVATE_REPOS='github\.com/openmatter-network/(matter-crypto|matter-kgc|matter-node)'
readonly -a REGISTRY_READMES=(
  bindings/python/README.md
  packages/typescript/README.md
  packages/typescript-core/README.md
)

problems=()

# Relative targets of `](target)` and `src="target"`, one per line.
relative_targets() {
  grep -oE '\]\([^)[:space:]]+\)|src="[^"]+"' "$1" \
    | sed -E 's/^\]\(//; s/\)$//; s/^src="//; s/"$//' \
    | grep -vE '^(https?:|mailto:|#)' || true
}

while IFS= read -r -d '' file; do
  dir=$(dirname "$file")
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    path=${target%%#*}
    [ -e "$dir/$path" ] || problems+=("$file: broken relative link '$target'")
  done < <(relative_targets "$file")

  if grep -qiE "$PRIVATE_REPOS" "$file"; then
    problems+=("$file: links a private repository (a public reader gets a 404)")
  fi
done < <(git ls-files -z --cached --others --exclude-standard '*.md')

for file in "${REGISTRY_READMES[@]}"; do
  if [ -n "$(relative_targets "$file")" ]; then
    problems+=("$file: publishes to a registry, so its links must be absolute")
  fi
done

if [ ${#problems[@]} -gt 0 ]; then
  printf '%s\n' "${problems[@]}" >&2
  exit 1
fi
echo "doc links ok"

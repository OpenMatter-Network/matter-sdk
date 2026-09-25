#!/usr/bin/env bash
# Commit the assembled Go module to matter-sdk-go and tag it. The module proxy caches a
# tag forever: never move one; fix a bad release with `retract`.
#
#   usage: scripts/publish-go.sh <assembled-dir> <version> <remote-url>
#     GO_REPO_DEPLOY_KEY_FILE  private half of matter-sdk-go's write deploy key (ssh remotes)
#
# Prints the registry state (scripts/lib-registry-state.sh); safe to re-run.
set -euo pipefail
readonly USAGE='usage: publish-go.sh <assembled-dir> <version> <remote-url>'
tree=$(realpath "${1:?$USAGE}")
version=${2:?$USAGE}
remote=${3:?$USAGE}
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib-registry-state.sh
source scripts/lib-registry-state.sh
# shellcheck source=scripts/lib-version.sh
source scripts/lib-version.sh
version_channel "$version" >/dev/null
source_commit=$(git rev-parse HEAD)
readonly source_commit

readonly BRANCH=main
readonly TAG="v$version"
readonly COMMITTER_NAME='matter-sdk release'
readonly COMMITTER_EMAIL='admin@openmatter.network'
# GitHub's published ed25519 host key, pinned (no trust-on-first-use).
readonly GITHUB_HOST_KEY='github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ -n "${GO_REPO_DEPLOY_KEY_FILE:-}" ]; then
  echo "$GITHUB_HOST_KEY" >"$work/known_hosts"
  export GIT_SSH_COMMAND="ssh -i $GO_REPO_DEPLOY_KEY_FILE -o IdentitiesOnly=yes -o UserKnownHostsFile=$work/known_hosts -o StrictHostKeyChecking=yes"
fi

# Requires an existing commit on main (RELEASING.md): the proxy caches an empty-repo miss.
git clone --quiet --branch "$BRANCH" "$remote" "$work/clone"
cd "$work/clone"
find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -R "$tree"/. .
git add -A
staged=$(git write-tree)

if published=$(git rev-parse --quiet --verify "refs/tags/$TAG^{tree}"); then
  if [ "$published" = "$staged" ]; then
    echo "$STATE_SAME"
    exit 0
  fi
  echo "$STATE_DIFFERENT"
  echo "publish-go: $TAG already exists in $remote with a different tree ($published, staged $staged)." >&2
  echo "  The module proxy caches a version forever; cut a new version instead." >&2
  exit 1
fi

git -c user.name="$COMMITTER_NAME" -c user.email="$COMMITTER_EMAIL" \
  commit --quiet --allow-empty -m "$TAG (OpenMatter-Network/matter-sdk@$source_commit)"
git -c user.name="$COMMITTER_NAME" -c user.email="$COMMITTER_EMAIL" tag -a "$TAG" -m "$TAG"
# --atomic: branch and tag land together or not at all.
git push --quiet --atomic origin "$BRANCH" "refs/tags/$TAG"
echo "$STATE_ABSENT"

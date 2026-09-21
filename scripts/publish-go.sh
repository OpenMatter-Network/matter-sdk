#!/usr/bin/env bash
# Publish the assembled Go module: commit it to the matter-sdk-go repository and tag it.
# The tag IS the Go release — the module proxy serves whatever the tag points at, and
# caches it forever, so a tag is never moved and a wrong one is fixed only by `retract`.
#
#   usage: scripts/publish-go.sh <assembled-dir> <version> <remote-url>
#     GO_REPO_DEPLOY_KEY_FILE  private half of matter-sdk-go's write deploy key (ssh remotes)
#
# Prints the registry state it found (scripts/lib-registry-state.sh). Safe to re-run: a
# tag that already holds exactly this tree is success; one that holds anything else is a
# hard stop.
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
# GitHub's published ed25519 host key, pinned: a release must not trust whatever key
# answers first (ssh-keyscan) on the one connection that can write to a public module.
readonly GITHUB_HOST_KEY='github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ -n "${GO_REPO_DEPLOY_KEY_FILE:-}" ]; then
  echo "$GITHUB_HOST_KEY" >"$work/known_hosts"
  export GIT_SSH_COMMAND="ssh -i $GO_REPO_DEPLOY_KEY_FILE -o IdentitiesOnly=yes -o UserKnownHostsFile=$work/known_hosts -o StrictHostKeyChecking=yes"
fi

# The repository must already exist with a commit on main (RELEASING.md): the first
# proxy lookup of a module whose repository is empty fails, and that failure is cached.
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
# --atomic: the branch and the tag land together or not at all, so there is never a
# commit on main that no tag names, nor a tag whose commit main does not contain.
git push --quiet --atomic origin "$BRANCH" "refs/tags/$TAG"
echo "$STATE_ABSENT"

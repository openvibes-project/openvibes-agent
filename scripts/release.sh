#!/usr/bin/env bash
# Cut a release: pick a version, get Cargo.toml to it, tag it, push the tag.
#
# Pushing the tag vX.Y.Z starts .github/workflows/release.yml, which builds the
# packages and publishes the GitHub Release. That workflow fails unless the tag
# equals the workspace version in Cargo.toml.
#
# main is protected, so a release is two runs of this script:
#   1. Pick a version above the last release. The script bumps Cargo.toml and
#      Cargo.lock on a release-vX.Y.Z branch, pushes it and opens a pull request.
#   2. Merge that pull request, then run the script again on main. It sees that
#      Cargo.toml is ahead of the last release, and tags and pushes it.
#
# Usage: bash scripts/release.sh [VERSION]
#   VERSION  optional, e.g. 0.3.0; without it you are prompted, with the next
#            patch version (0.2.4 -> 0.2.5) offered as the default.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

remote=origin
branch=main

die() { echo "error: $*" >&2; exit 1; }

# 0.2.4 -> comparable only when it is plain X.Y.Z.
is_semver() { [[ $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; }

# True when $1 is strictly greater than $2 (both X.Y.Z).
version_gt() {
  [[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1) == "$1" ]]
}

[[ $(git rev-parse --abbrev-ref HEAD) == "$branch" ]] || die "run this from the $branch branch"
[[ -z $(git status --porcelain) ]] || die "working tree is not clean"

git fetch --quiet --tags "$remote" "$branch"
[[ $(git rev-parse HEAD) == "$(git rev-parse "$remote/$branch")" ]] \
  || die "$branch is not in sync with $remote/$branch (pull or push first)"

# The workspace version, as release.yml reads it.
current=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)
is_semver "$current" || die "cannot read a X.Y.Z workspace version from Cargo.toml (got '$current')"

# The highest version already released: the tags, not Cargo.toml (which may be
# ahead of them once a release pull request has merged).
highest=0.0.0
while read -r tag; do
  v=${tag#v}
  is_semver "$v" && version_gt "$v" "$highest" && highest=$v
done < <(git tag --list 'v*')

if version_gt "$current" "$highest"; then
  suggested=$current   # the bump is merged; only the tag is missing
else
  IFS=. read -r major minor patch <<<"$highest"
  suggested="$major.$minor.$((patch + 1))"
fi

echo "Cargo.toml version: $current"
echo "Highest release:    $highest"

version=${1:-}
if [[ -z $version ]]; then
  read -r -p "New version [$suggested]: " version
  version=${version:-$suggested}
fi
version=${version#v}

is_semver "$version" || die "'$version' is not a version like 1.2.3"
version_gt "$version" "$highest" || die "$version is not higher than the existing release $highest"
git rev-parse -q --verify "refs/tags/v$version" > /dev/null && die "tag v$version already exists"

if [[ $version == "$current" ]]; then
  read -r -p "Tag v$version on $(git rev-parse --short HEAD) and push to $remote? [y/N] " answer
  [[ $answer == [yY]* ]] || die "cancelled"
  git tag -a "v$version" -m "v$version"
  git push "$remote" "v$version"
  echo "Released v$version. Watch the Release workflow in the repository's Actions tab."
  exit 0
fi

git rev-parse -q --verify "refs/heads/release-v$version" > /dev/null && die "branch release-v$version already exists"
read -r -p "Open a pull request bumping $current to $version? [y/N] " answer
[[ $answer == [yY]* ]] || die "cancelled"

git switch --quiet -c "release-v$version"
# Only the first match: the workspace version, not a dependency's.
sed -i '0,/^version = ".*"/s//version = "'"$version"'"/' Cargo.toml
cargo update --workspace --offline --quiet
git add Cargo.toml Cargo.lock
git commit --quiet -m "Release v$version"
git push --quiet -u "$remote" "release-v$version"
git switch --quiet "$branch"

if command -v gh > /dev/null; then
  gh pr create --head "release-v$version" --base "$branch" \
    --title "Release v$version" --body "Bump the workspace version to $version." \
    || echo "gh could not open it; open a pull request from release-v$version into $branch."
else
  echo "Open a pull request from release-v$version into $branch."
fi
echo "Merge it, then run this script again on $branch to tag v$version."

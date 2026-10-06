#!/usr/bin/env bash
# Cut a release: pick a version, bump Cargo.toml, tag, push.
#
# Pushing the tag vX.Y.Z starts .github/workflows/release.yml, which builds the
# packages and publishes the GitHub Release. That workflow fails unless the tag
# equals the workspace version in Cargo.toml, so this script bumps both together.
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

# The highest version already released: tags on the remote, not just Cargo.toml.
highest=$current
while read -r tag; do
  v=${tag#v}
  is_semver "$v" && version_gt "$v" "$highest" && highest=$v
done < <(git tag --list 'v*')

IFS=. read -r major minor patch <<<"$highest"
suggested="$major.$minor.$((patch + 1))"

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

read -r -p "Release v$version (commit, tag, push to $remote)? [y/N] " answer
[[ $answer == [yY]* ]] || die "cancelled"

# Only the first match: the workspace version, not a dependency's.
sed -i '0,/^version = ".*"/s//version = "'"$version"'"/' Cargo.toml
cargo update --workspace --offline --quiet

git add Cargo.toml Cargo.lock
git commit --quiet -m "Release v$version"
git tag -a "v$version" -m "v$version"

git push "$remote" "$branch"
git push "$remote" "v$version"

echo "Released v$version. Watch the Release workflow in the repository's Actions tab."

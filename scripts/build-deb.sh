#!/usr/bin/env bash
# Builds target/deb/openvibes-agent_<version>-<release>_amd64.deb around a
# release binary, the same one the RPM carries (offline install spec §4),
# and openvibes-test from the same folder as BINARY.
# Usage: scripts/build-deb.sh BINARY [VERSION]; OV_RELEASE is the Debian
# revision (default 1; CI sets 1.1.ci<run>). Needs debhelper, dpkg-dev, lintian.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -ge 1 && -f $1 ]] || { echo "usage: $0 BINARY [VERSION]" >&2; exit 2; }
bin=$(realpath "$1")
version=${2:-$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)}
release=${OV_RELEASE:-1}
W=target/deb/src
rm -rf target/deb; mkdir -p "$W/files"
cp -r packaging/debian "$W/debian"
cp packaging/rpm/openvibes-agent.service "$W/debian/openvibes-agent.service"
install -m 0755 "$bin" "$W/openvibes-agent"
install -m 0755 "$(dirname "$bin")/openvibes-test" "$W/openvibes-test"
cp packaging/rpm/{agent.toml,openvibes-agent.rules,audit-setup,audit-fallback,owners.conf} "$W/files/"
cp packaging/rpm/openvibes-agent.sysusers "$W/files/openvibes-agent.conf"
cat > "$W/debian/changelog" <<CHANGELOG
openvibes-agent ($version-$release) unstable; urgency=medium

  * Release $version.

 -- OpenVIBES <26064407+itismelime@users.noreply.github.com>  $(date -R)
CHANGELOG
(cd "$W" && dpkg-buildpackage -b -us -uc >&2)
deb=$(ls target/deb/openvibes-agent_"$version-$release"_amd64.deb)
lintian --fail-on error --suppress-tags-from-file packaging/debian/openvibes-agent.lintian-overrides "$deb" >&2
echo "$deb"

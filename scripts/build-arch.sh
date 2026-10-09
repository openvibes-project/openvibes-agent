#!/usr/bin/env bash
# Builds target/arch/openvibes-agent-<version>-<pkgrel>-x86_64.pkg.tar.zst
# around a release binary, the same one the RPM carries (offline install
# spec §4), and openvibes-test and openvibes-agent-facts from the same folder as BINARY. Usage (as root
# in archlinux:base-devel):
#   scripts/build-arch.sh BINARY [VERSION]; OV_PKGREL (default 1; CI 1.<run>).
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -ge 1 && -f $1 ]] || { echo "usage: $0 BINARY [VERSION]" >&2; exit 2; }
version=${2:-$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)}
W=target/arch
rm -rf "$W"; mkdir -p "$W"
install -m 0755 "$1" "$W/openvibes-agent"
install -m 0755 "$(dirname "$1")/openvibes-test" "$W/openvibes-test"
install -m 0755 "$(dirname "$1")/openvibes-agent-facts" "$W/openvibes-agent-facts"
cp packaging/arch/PKGBUILD packaging/arch/openvibes-agent.install LICENSE "$W/"
cp packaging/rpm/{openvibes-agent.service,openvibes-agent.sysusers,agent.toml,openvibes-agent.rules,audit-setup,audit-fallback,retire-owners,openvibes-agent-facts.service,openvibes-agent-facts.timer} "$W/"
id builder >/dev/null 2>&1 || useradd -m builder
chown -R builder "$W"
runuser -u builder -- env OV_VERSION="$version" OV_PKGREL="${OV_PKGREL:-1}" \
    bash -c "cd '$W' && makepkg --force --nodeps --noconfirm" >&2
pkg=$(ls "$W"/openvibes-agent-"$version"-*-x86_64.pkg.tar.zst)
namcap "$pkg" >&2
echo "$pkg"

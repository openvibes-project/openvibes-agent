#!/usr/bin/env bash
# One package format on one system, under a real systemd (podman): install,
# static checks (check-package.sh), an edited agent.toml kept across an
# upgrade to NEXT, then erase. Usage: scripts/pkg-test.sh IMAGE DIR, DIR
# holding the BASE (workspace version) and NEXT (next patch) packages of
# IMAGE's format. CI packages are unsigned: a local-file install checks no
# signature in dnf, apt or pacman -U.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $# == 2 ]] || { echo "usage: $0 IMAGE DIR" >&2; exit 2; }
IMAGE=$1 DIR=$(realpath "$2")
PODMAN=${PODMAN:-podman}
C=ov-pkg-test
fail() { echo "FAIL ($IMAGE): $*" >&2; exit 1; }
ok() { echo "ok ($IMAGE): $*"; }
in_c() { "$PODMAN" exec "$C" bash -c "$1"; }
BASE=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml")
NEXT=${BASE%.*}.$((${BASE##*.} + 1))
one() { # GLOB: exactly one file
    local f; f=$(compgen -G "$1") || fail "no package $1"
    [[ $(wc -l <<<"$f") == 1 ]] || fail "more than one package $1"
    echo "$f"
}
case $IMAGE in
    *debian:*|*ubuntu:*)
        prep='apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q systemd dbus procps >/dev/null'
        base=$(one "$DIR/openvibes-agent_$BASE-*_amd64.deb") next=$(one "$DIR/openvibes-agent_$NEXT-*_amd64.deb")
        install() { echo "DEBIAN_FRONTEND=noninteractive apt-get install -y -q /pkgs/$(basename "$1")"; }
        # shellcheck disable=SC2016  # dpkg-query's own ${...} fields, expanded in the container
        version='dpkg-query -W -f="\${Version}" openvibes-agent'
        erase='apt-get remove -y -q openvibes-agent'
        # shellcheck disable=SC2016  # the same
        gone='! dpkg-query -W -f="\${Status}" openvibes-agent 2>/dev/null | grep -q "install ok installed"' ;;
    *archlinux*)
        prep='pacman -Syu --noconfirm --needed procps-ng >/dev/null'
        base=$(one "$DIR/openvibes-agent-$BASE-*-x86_64.pkg.tar.zst") next=$(one "$DIR/openvibes-agent-$NEXT-*-x86_64.pkg.tar.zst")
        install() { echo "pacman -U --noconfirm /pkgs/$(basename "$1")"; }
        version="pacman -Q openvibes-agent | cut -d' ' -f2"
        erase='pacman -R --noconfirm openvibes-agent' gone='! pacman -Q openvibes-agent 2>/dev/null' ;;
    *almalinux*|*rockylinux*|*fedora*)
        prep='dnf -q -y install systemd procps-ng >/dev/null'
        base=$(one "$DIR/openvibes-agent-$BASE-*.x86_64.rpm") next=$(one "$DIR/openvibes-agent-$NEXT-*.x86_64.rpm")
        install() { echo "dnf -q -y install /pkgs/$(basename "$1")"; }
        version="rpm -q --qf '%{VERSION}-%{RELEASE}' openvibes-agent"
        erase='dnf -q -y remove openvibes-agent' gone='! rpm -q openvibes-agent' ;;
    *) fail "no package format for $IMAGE" ;;
esac
cleanup() {
    local s=$?
    ((s == 0)) || "$PODMAN" exec "$C" journalctl --no-pager -n 40 2>/dev/null || true
    "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
    exit "$s"
}
trap cleanup EXIT
"$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
"$PODMAN" run -d --systemd=always --privileged --name "$C" -v "$DIR:/pkgs:ro,z" -v "$ROOT/scripts:/scripts:ro,z" \
    "$IMAGE" bash -c "$prep && exec /usr/lib/systemd/systemd" >/dev/null
up='systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"'
for _ in $(seq 300); do in_c "$up" 2>/dev/null && break; sleep 1; done
in_c "$up" || fail "systemd did not come up"
in_c "$(install "$base")" >/dev/null || fail "install $BASE"
in_c 'bash /scripts/check-package.sh' || fail "static checks"
ok "installed $BASE, static checks pass"
in_c 'echo "# kept across upgrades" >> /etc/openvibes-agent/agent.toml'
in_c "$(install "$next")" >/dev/null || fail "upgrade to $NEXT"
[[ $(in_c "$version") == "$NEXT"-* ]] || fail "not at $NEXT after the upgrade: $(in_c "$version")"
in_c 'grep -qx "# kept across upgrades" /etc/openvibes-agent/agent.toml' || fail "the upgrade lost an edit to agent.toml"
in_c 'bash /scripts/check-package.sh' >/dev/null || fail "static checks after the upgrade"
ok "upgraded to $NEXT, agent.toml edit kept"
in_c "$erase" >/dev/null || fail "erase"
in_c "$gone" || fail "still installed after erase"
in_c '[ ! -e /etc/audit/rules.d/openvibes-agent.rules ]' || fail "erase left the audit rule"
ok "erased"

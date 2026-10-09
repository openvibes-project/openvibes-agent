#!/usr/bin/env bash
# Static checks of an installed openvibes-agent package, any format: RPM,
# .deb or Arch (run as root on the installed system).
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_stat() { # PATH MODE OWNER:GROUP
    [[ "$(stat -c '%a %U:%G' "$1")" == "$2 $3" ]] || fail "$1 is $(stat -c '%a %U:%G' "$1"), want $2 $3"
}
if command -v rpm >/dev/null && rpm -q openvibes-agent >/dev/null 2>&1; then
    pkg_files() { rpm -ql openvibes-agent; }
    is_conffile() { rpm -q --qf '[%{FILENAMES} %{FILEFLAGS:fflags}\n]' openvibes-agent | grep -qx "$1 cn"; }
elif command -v dpkg-query >/dev/null && dpkg-query -W openvibes-agent >/dev/null 2>&1; then
    pkg_files() { dpkg-query -L openvibes-agent; }
    # Not a conffile on purpose (a changed template would stop unattended upgrades at
    # dpkg's prompt): postinst copies the template once, and the package never owns it.
    is_conffile() {
        [[ -f $1 ]] && pkg_files | grep -qx /usr/share/openvibes-agent/agent.toml &&
            ! dpkg-query -W -f='${Conffiles}\n' openvibes-agent | awk '{print $1}' | grep -qx "$1"
    }
elif command -v pacman >/dev/null && pacman -Q openvibes-agent >/dev/null 2>&1; then
    pkg_files() { pacman -Qlq openvibes-agent; }
    # pacman 7: "Backup Files    : /etc/openvibes-agent/agent.toml [unmodified]".
    is_conffile() { pacman -Qii openvibes-agent | grep -qF " $1 ["; }
else
    fail "openvibes-agent is not installed by rpm, dpkg or pacman"
fi
UNIT=$(systemctl show -P FragmentPath openvibes-agent)
[[ -n $UNIT ]] || fail "systemd does not know openvibes-agent.service"
getent passwd openvibes_agent >/dev/null || fail "no user openvibes_agent"
expect_stat /etc/openvibes-agent 750 root:openvibes_agent
expect_stat /etc/openvibes-agent/agent.toml 640 root:openvibes_agent
is_conffile /etc/openvibes-agent/agent.toml || fail "agent.toml is not kept as the host's configuration"
# The exec audit rule is a template; audit-setup copies it on fallback hosts only.
expect_stat /usr/share/openvibes-agent/openvibes-agent.rules 644 root:root
expect_stat /usr/libexec/openvibes-agent/audit-setup 755 root:root
expect_stat /usr/libexec/openvibes-agent/audit-fallback 755 root:root
! pkg_files | grep -qx /etc/audit/rules.d/openvibes-agent.rules ||
    fail "the package must not own /etc/audit/rules.d/openvibes-agent.rules (eBPF hosts get no audit rule)"
# A directive this systemd does not know is ignored, and the sandbox weaker: fail on it.
out=$(systemd-analyze verify "$UNIT" 2>&1) || fail "unit verification: $out"
! grep -qi 'unknown key\|unknown lvalue' <<<"$out" || fail "this systemd ignores part of the unit: $out"
# The owners drop-in (P15) ships as documentation only, never enabled.
# (By the package's file list: images that skip docs still list it.)
pkg_files | grep -qx /usr/share/doc/openvibes-agent/owners.conf || fail "owners.conf is not shipped"
[[ ! -e /etc/systemd/system/openvibes-agent.service.d/owners.conf ]] || fail "owners.conf is enabled"
! grep -q 'CAP_SYS_PTRACE\|CAP_DAC_READ_SEARCH' "$UNIT" || fail "the unit grants an owner capability"
# Directives that would blind the collectors or cut the agent off.
for forbidden in ProtectProc=invisible ProcSubset=pid PrivateNetwork=yes PrivateUsers=yes ProtectHostname=yes; do
    ! grep -q "^$forbidden" "$UNIT" || fail "unit sets $forbidden"
done
# --offline exists from systemd 252; the unit is the same file everywhere,
# and the Fedora test (systemd-test.sh) always measures it.
exposure=$(systemd-analyze security --offline=true "$UNIT" 2>/dev/null | sed -n 's/.*exposure level for openvibes-agent.service: \([0-9.]*\).*/\1/p' || true)
if [[ -n $exposure ]]; then
    awk -v e="$exposure" 'BEGIN { exit !(e <= 2.5) }' || fail "exposure $exposure > 2.5"
    echo "exposure: $exposure"
else
    echo "exposure: not measured (systemd $(systemctl --version | awk 'NR == 1 {print $2}'))"
fi
[[ "$(systemctl is-enabled openvibes-agent 2>/dev/null || true)" == disabled ]] || fail "service not disabled after install"
status=0; /usr/bin/openvibes-agent >/dev/null 2>&1 || status=$?
((status == 2)) || fail "openvibes-agent without arguments exited $status, want 2 (usage)"
# audit-setup under this system's awk (mawk on Debian and Ubuntu): the
# fallback and its undo in a scratch root holding Fedora's -a task,never.
r=$(mktemp -d); mkdir -p "$r/etc/audit/rules.d"
printf -- '-D\n-a task,never\n' > "$r/etc/audit/rules.d/audit.rules"
/usr/libexec/openvibes-agent/audit-setup fallback --root "$r" >/dev/null
[[ -f $r/etc/audit/rules.d/openvibes-agent.rules ]] || fail "audit-setup fallback wrote no rule"
grep -q '^# disabled by openvibes-agent.*-a task,never$' "$r/etc/audit/rules.d/audit.rules" ||
    fail "audit-setup fallback did not disable -a task,never: $(cat "$r/etc/audit/rules.d/audit.rules")"
/usr/libexec/openvibes-agent/audit-setup remove --root "$r" >/dev/null
[[ ! -e $r/etc/audit/rules.d/openvibes-agent.rules ]] || fail "audit-setup remove left the rule"
[[ "$(cat "$r/etc/audit/rules.d/audit.rules")" == $'-D\n-a task,never' ]] ||
    fail "audit-setup remove did not restore audit.rules: $(cat "$r/etc/audit/rules.d/audit.rules")"
rm -rf "$r"
[[ $(/usr/libexec/openvibes-agent/audit-setup decide) =~ ^(ebpf|fallback)$ ]] || fail "audit-setup decide"
echo "check-package: ok"

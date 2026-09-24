#!/usr/bin/env bash
# Static checks of an installed openvibes-agent RPM (run as root).
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_stat() { # PATH MODE OWNER:GROUP
    [[ "$(stat -c '%a %U:%G' "$1")" == "$2 $3" ]] || fail "$1 is $(stat -c '%a %U:%G' "$1"), want $2 $3"
}
UNIT=/usr/lib/systemd/system/openvibes-agent.service
getent passwd openvibes_agent >/dev/null || fail "no user openvibes_agent"
expect_stat /etc/openvibes-agent 750 root:openvibes_agent
expect_stat /etc/openvibes-agent/agent.toml 640 root:openvibes_agent
[[ "$(rpm -q --qf '[%{FILENAMES} %{FILEFLAGS:fflags}\n]' openvibes-agent | grep -c '^/etc/openvibes-agent/agent.toml cn$')" == 1 ]] ||
    fail "agent.toml is not %config(noreplace)"
systemd-analyze verify "$UNIT" || fail "unit verification"
# Directives that would blind the collectors or cut the agent off.
for forbidden in ProtectProc=invisible ProcSubset=pid PrivateNetwork=yes PrivateUsers=yes; do
    ! grep -q "^$forbidden" "$UNIT" || fail "unit sets $forbidden"
done
exposure=$(systemd-analyze security --offline=true "$UNIT" 2>/dev/null | sed -n 's/.*exposure level for openvibes-agent.service: \([0-9.]*\).*/\1/p')
[[ -n "$exposure" ]] || fail "no exposure score"
awk -v e="$exposure" 'BEGIN { exit !(e <= 2.5) }' || fail "exposure $exposure > 2.5"
echo "exposure: $exposure"
[[ "$(systemctl is-enabled openvibes-agent 2>/dev/null || true)" == disabled ]] || fail "service not disabled after install"
status=0; /usr/bin/openvibes-agent >/dev/null 2>&1 || status=$?
((status == 2)) || fail "openvibes-agent without arguments exited $status, want 2 (usage)"
echo "check-rpm: ok"

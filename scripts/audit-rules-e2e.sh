#!/usr/bin/env bash
# The package's audit-rule handling (spec 2026-10-08 §4.2-4.3) in fresh
# fedora:44 containers (no systemd needed: no auditd runs there, so the
# script reports "load them with: augenrules --load" instead of loading):
#   1. eBPF host: install touches no audit rule.
#   2. Upgrade from the released 0.2.5 on an eBPF host: 0.2.5's rule file is
#      gone and the `-a task,never` it commented out is back.
#   3. The same with 0.2.5's rule edited: saved as .rpmsave, reported.
#      Then a downgrade back to 0.2.5 sets its audit setup up again.
#   4. audit-fallback: the rule installed, `-a task,never` commented out;
#      erase gives the host its rules back.
# The containers see the host's /sys, so this runs on a host with BTF and a
# kernel >= 5.8 (CI runners, the lab, developer machines).
# Usage: scripts/audit-rules-e2e.sh RPM_DIR OLD_RPM
#   RPM_DIR  holds openvibes-agent at the next patch version (NEXT), as
#            systemd-test.sh builds it; OLD_RPM is the released 0.2.5 RPM,
#            already checksum-verified by the caller.
set -euo pipefail
cd "$(dirname "$0")/.."
PODMAN=${PODMAN:-podman}
IMAGE=registry.fedoraproject.org/fedora:44
C=ov-agent-audit-rules-e2e
MARK='# disabled by openvibes-agent (exec alarms need it off): '
[[ $# == 2 ]] || { echo "usage: $0 RPM_DIR OLD_RPM" >&2; exit 2; }
RPMS=$(readlink -f "$1") OLD=$(readlink -f "$2")
BASE=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)
NEXT=${BASE%.*}.$((${BASE##*.} + 1))
new=$(find "$RPMS" -maxdepth 1 -name "openvibes-agent-$NEXT-*.rpm" | head -1)
[[ -f $new && -f $OLD ]] || { echo "need $RPMS/openvibes-agent-$NEXT-*.rpm and $OLD" >&2; exit 2; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
in_c() { "$PODMAN" exec "$C" bash -c "$1"; }
cleanup() { "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# fresh: a container with Fedora's default audit.rules and both RPMs.
fresh() {
    cleanup
    "$PODMAN" run -d --name "$C" -v "$RPMS:/new:Z,ro" -v "$OLD:/old.rpm:Z,ro" "$IMAGE" sleep infinity >/dev/null
    in_c "mkdir -p /etc/audit/rules.d && printf -- '-D\n-a task,never\n' > /etc/audit/rules.d/audit.rules"
}
rules() { in_c 'cat /etc/audit/rules.d/audit.rules'; }
has_rule() { in_c 'test -e /etc/audit/rules.d/openvibes-agent.rules'; }

[[ $(sh packaging/rpm/audit-setup decide) == ebpf ]] ||
    fail "this host is not an eBPF host (no BTF or kernel < 5.8): run it on one"

# 1. eBPF host: nothing touched.
fresh
in_c "dnf -q -y install /new/$(basename "$new")" >/dev/null 2>&1 || fail "install"
! has_rule || fail "eBPF host: the exec rule was installed"
grep -qx -- '-a task,never' <<<"$(rules)" || fail "eBPF host: -a task,never was edited"
ok "eBPF host: no audit rule, -a task,never untouched"

# 2. Upgrade from 0.2.5: 0.2.5 sets up audit, the new package undoes it.
fresh
in_c 'dnf -q -y install /old.rpm' >/dev/null 2>&1 || fail "install 0.2.5"
has_rule || fail "0.2.5 did not install its rule (test premise)"
grep -qxF -- "${MARK}-a task,never" <<<"$(rules)" || fail "0.2.5 did not comment out -a task,never (test premise)"
out=$(in_c "dnf -y upgrade /new/$(basename "$new") 2>&1") || fail "upgrade from 0.2.5"
! has_rule || fail "upgrade: 0.2.5's rule file is still there"
in_c 'test ! -e /etc/audit/rules.d/openvibes-agent.rules.rpmsave' || fail "upgrade: unexpected .rpmsave"
grep -qx -- '-a task,never' <<<"$(rules)" || fail "upgrade: -a task,never not restored: $(rules)"
ok "upgrade from 0.2.5: rule removed, -a task,never restored"
in_c 'dnf -q -y downgrade /old.rpm' >/dev/null 2>&1 || fail "downgrade to 0.2.5"
has_rule || fail "downgrade: 0.2.5 did not install its rule again"
[[ $(grep -c "^${MARK}" <<<"$(rules)") == 1 ]] || fail "downgrade: -a task,never not marked exactly once"
ok "downgrade to 0.2.5: its rule and edit are back, marked once"

# 3. Upgrade from 0.2.5 with the rule edited: .rpmsave, reported.
fresh
in_c 'dnf -q -y install /old.rpm' >/dev/null 2>&1 || fail "install 0.2.5"
in_c "echo '# local edit' >> /etc/audit/rules.d/openvibes-agent.rules"
out=$(in_c "dnf -y upgrade /new/$(basename "$new") 2>&1") || fail "upgrade from 0.2.5 (edited rule)"
! has_rule || fail "edited upgrade: the rule still loads"
in_c 'grep -q "local edit" /etc/audit/rules.d/openvibes-agent.rules.rpmsave' || fail "edited upgrade: no .rpmsave with the edit"
grep -q 'no longer loads' <<<"$out" || fail "edited upgrade: not reported"
grep -qx -- '-a task,never' <<<"$(rules)" || fail "edited upgrade: -a task,never not restored"
ok "upgrade from 0.2.5 with an edited rule: saved as .rpmsave, reported, -a task,never restored"

# 4. audit-fallback by hand, then erase.
fresh
in_c "dnf -q -y install /new/$(basename "$new")" >/dev/null 2>&1 || fail "install"
out=$(in_c '/usr/libexec/openvibes-agent/audit-fallback')
has_rule || fail "audit-fallback: rule not installed"
in_c 'cmp -s /usr/share/openvibes-agent/openvibes-agent.rules /etc/audit/rules.d/openvibes-agent.rules' || fail "audit-fallback: rule differs from the template"
[[ $(in_c 'stat -c %a /etc/audit/rules.d/openvibes-agent.rules') == 640 ]] || fail "audit-fallback: rule mode"
grep -qxF -- "${MARK}-a task,never" <<<"$(rules)" || fail "audit-fallback: -a task,never not commented out"
grep -q 'augenrules --load' <<<"$out" || fail "audit-fallback: no hint to load the rules (no auditd here)"
in_c '/usr/libexec/openvibes-agent/audit-fallback' >/dev/null
[[ $(grep -c "^${MARK}" <<<"$(rules)") == 1 ]] || fail "audit-fallback twice: marked more than once"
ok "audit-fallback: rule installed, -a task,never commented out, idempotent"
in_c 'dnf -q -y remove openvibes-agent' >/dev/null 2>&1 || fail "erase"
! has_rule || fail "erase: the rule is still there"
grep -qx -- '-a task,never' <<<"$(rules)" || fail "erase: -a task,never not restored"
ok "erase: rule removed, -a task,never restored"
echo "audit-rules-e2e: all checks passed"

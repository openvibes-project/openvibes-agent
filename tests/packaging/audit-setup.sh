#!/usr/bin/env bash
# Unit tests for packaging/rpm/audit-setup on temporary trees (no root needed).
set -euo pipefail
cd "$(dirname "$0")/../.."
S=packaging/rpm/audit-setup
T=packaging/rpm/openvibes-agent.rules
M='# disabled by openvibes-agent (exec alarms need it off): '
pass() { echo "ok $1"; }
fail() { echo "FAIL $1"; exit 1; }
tree() { # a fresh root with Fedora's default audit.rules
    local r; r=$(mktemp -d)
    mkdir -p "$r/etc/audit/rules.d" "$r/etc/openvibes-agent"
    printf -- '-D\n-a task,never\n' > "$r/etc/audit/rules.d/audit.rules"
    echo "$r"
}
btf=$(mktemp); trap 'rm -f "$btf"' EXIT   # stands for /sys/kernel/btf/vmlinux
run() { sh "$S" "$@" --template "$T"; }

[[ $(run decide --btf "$btf" --kernel 6.8.0) == ebpf ]] || fail decide_ebpf; pass decide_ebpf
[[ $(run decide --btf /nonexistent --kernel 6.8.0) == fallback ]] || fail decide_no_btf; pass decide_no_btf
[[ $(run decide --btf "$btf" --kernel 5.4.0-150-generic) == fallback ]] || fail decide_old_kernel; pass decide_old_kernel
[[ $(run decide --btf "$btf" --kernel 5.8.0) == ebpf ]] || fail decide_5_8; pass decide_5_8

r=$(tree); run apply --root "$r" --btf "$btf" --kernel 6.8.0 >/dev/null
[[ ! -e $r/etc/audit/rules.d/openvibes-agent.rules ]] || fail ebpf_host_installs_nothing
grep -qx -- '-a task,never' "$r/etc/audit/rules.d/audit.rules" || fail ebpf_host_keeps_task_never
pass ebpf_host_touches_nothing

r=$(tree); run apply --root "$r" --btf /nonexistent --kernel 6.8.0 >/dev/null
cmp -s "$T" "$r/etc/audit/rules.d/openvibes-agent.rules" || fail fallback_installs_rule
grep -qxF -- "${M}-a task,never" "$r/etc/audit/rules.d/audit.rules" || fail fallback_comments_task_never
[[ $(stat -c %a "$r/etc/audit/rules.d/openvibes-agent.rules") == 640 ]] || fail fallback_mode
pass fallback_host_set_up

# Upgrade from 0.2.5 on an eBPF host: 0.2.5's rule + marked line → both undone.
r=$(tree); cp "$T" "$r/etc/audit/rules.d/openvibes-agent.rules"
sed -i "s/^-a task,never$/${M}-a task,never/" "$r/etc/audit/rules.d/audit.rules"
printf -- '%s-a never,task -F uid=1000\n# a comment of the admin\n' "$M" > "$r/etc/audit/rules.d/10-local.rules"
run apply --root "$r" --btf "$btf" --kernel 6.8.0 >/dev/null
[[ ! -e $r/etc/audit/rules.d/openvibes-agent.rules ]] || fail upgrade_removes_unchanged_rule
grep -qx -- '-a task,never' "$r/etc/audit/rules.d/audit.rules" || fail upgrade_restores_audit_rules
grep -qx -- '-a never,task -F uid=1000' "$r/etc/audit/rules.d/10-local.rules" || fail restores_only_marked_lines_in_every_file
grep -qx -- '# a comment of the admin' "$r/etc/audit/rules.d/10-local.rules" || fail admin_comment_untouched
pass restores_only_marked_lines_in_every_file

# An edited rule is kept and reported.
r=$(tree); { cat "$T"; echo '# local edit'; } > "$r/etc/audit/rules.d/openvibes-agent.rules"
out=$(run remove --root "$r")
[[ -e $r/etc/audit/rules.d/openvibes-agent.rules ]] || fail remove_keeps_edited_copy
grep -q 'edited' <<<"$out" || fail remove_reports_edited_copy
pass remove_restores_and_keeps_an_edited_copy

# Opt-out: no edit either way.
for host in "$btf" /nonexistent; do
    r=$(tree); echo 'manage_audit_rules = false' > "$r/etc/openvibes-agent/agent.toml"
    sed -i "s/^-a task,never$/${M}-a task,never/" "$r/etc/audit/rules.d/audit.rules"
    before=$(cat "$r/etc/audit/rules.d/audit.rules")
    run apply --root "$r" --btf "$host" --kernel 6.8.0 >/dev/null
    [[ $(cat "$r/etc/audit/rules.d/audit.rules") == "$before" && ! -e $r/etc/audit/rules.d/openvibes-agent.rules ]] || fail "opt_out ($host)"
done
pass opt_out_means_no_edit_either_way

# Idempotent; a fallback setup is undone once the host can use eBPF.
r=$(tree); run apply --root "$r" --btf /nonexistent --kernel 6.8.0 >/dev/null
run apply --root "$r" --btf /nonexistent --kernel 6.8.0 >/dev/null
[[ $(grep -c "^${M}" "$r/etc/audit/rules.d/audit.rules") == 1 ]] || fail apply_twice_marks_once
run apply --root "$r" --btf "$btf" --kernel 6.8.0 >/dev/null
grep -qx -- '-a task,never' "$r/etc/audit/rules.d/audit.rules" && [[ ! -e $r/etc/audit/rules.d/openvibes-agent.rules ]] || fail undo_after_kernel_upgrade
pass apply_is_idempotent_and_undoes_a_fallback_setup_on_an_ebpf_host

# fallback forces the setup on an eBPF-capable host.
r=$(tree); run fallback --root "$r" --btf "$btf" --kernel 6.8.0 >/dev/null
[[ -e $r/etc/audit/rules.d/openvibes-agent.rules ]] || fail fallback_command; pass fallback_command_forces_setup

# No augenrules / auditd: succeeds (root ≠ / skips reload; a PATH without augenrules for root=/ is covered in systemd-test).
r=$(tree); PATH=/usr/bin:/bin run apply --root "$r" --btf /nonexistent --kernel 6.8.0 >/dev/null || fail apply_without_augenrules
pass apply_without_augenrules_succeeds

sh "$S" bogus 2>/dev/null && fail usage_error; pass usage_error_exits_non_zero

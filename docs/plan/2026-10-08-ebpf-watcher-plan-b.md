# eBPF Process Watcher, Plan B (packaging) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The agent package touches audit policy only on hosts that will use the audit fallback, gives eBPF hosts their policy back when upgrading from 0.2.5, and ships the `audit-fallback` command the console names.

**Architecture:** All audit-rule logic moves out of the RPM scriptlets into one POSIX shell script the package ships, `/usr/libexec/openvibes-agent/audit-setup`, with subcommands (`decide`, `apply`, `fallback`, `remove`) that take a root directory and a BTF path, so every case is unit-tested on a temporary tree. The scriptlets only call it. The exec audit rule ships as an unowned template in `/usr/share/openvibes-agent/`; the script copies it into `/etc/audit/rules.d` on fallback hosts only.

**Tech Stack:** POSIX sh (the script), bash (tests), RPM spec scriptlets, podman + systemd (`scripts/systemd-test.sh`), the released 0.2.5 agent RPM for the upgrade test.

**Spec:** `docs/specs/2026-10-08-ebpf-process-watcher-design.md` §4.2–4.3 (read it first). Plan A (merged in #56) built the watcher, the unit and the health fields this plan relies on.

## Global Constraints

- eBPF host: `/sys/kernel/btf/vmlinux` exists and the running kernel is ≥ 5.8. Everything else is a fallback host.
- eBPF host: load no audit rule and touch no audit setting.
- Upgrade from 0.2.5 on an eBPF host: remove `/etc/audit/rules.d/openvibes-agent.rules` when unchanged from what 0.2.5 shipped, and restore every line 0.2.5 commented out with the marker `# disabled by openvibes-agent (exec alarms need it off): `, then reload the rules when auditd runs.
- Fallback host: install the exec rule into `rules.d`, comment out `-a task,never` (and `never,task`) with that same marker, load the rules; `manage_audit_rules = false` in `agent.toml` still opts out.
- `/usr/libexec/openvibes-agent/audit-fallback` (root, run by the admin) does what the package does for a fallback host.
- The running agent never changes system policy; only the package scriptlets and the admin's command do.
- Never restart services or reboot on the user's behalf.
- Commits end with `Co-Authored-By: Claude <noreply@anthropic.com>`; PRs only after the local gate in the workspace `testing.md`.

**Deviation from the spec, decided here (for the user's review of this plan):** spec §4.2 says an edited 0.2.5 rule file "is left and reported". Once the new package no longer owns `/etc/audit/rules.d/openvibes-agent.rules`, rpm itself erases it on upgrade when unchanged and renames it to `.rpmsave` when edited. A `.rpmsave` file is not read by `augenrules`, so an edited exec rule stops loading — which on an eBPF host is what we want — and the package reports it (Task 2) instead of leaving it active. Keeping an edited copy active would mean keeping the file owned, which keeps the exec rule (and auditd's per-exec disk write) on eBPF hosts. Task 3 updates the spec sentence.

## Review Focus

1. **`-a task,never` in a rules file other than `audit.rules`** (an admin's own `10-local.rules`, or several files) — the marker-based comment and restore must work in every `rules.d/*.rules` file and touch only lines carrying our marker (Task 1 test `restores_only_marked_lines_in_every_file`).
2. **auditd not installed or not running** (`augenrules` missing; minimal containers, Debian-family hosts later) — the script must succeed without reloading and say so, never fail the package transaction (Task 1 test `apply_without_augenrules_succeeds`).
3. **`manage_audit_rules = false`** — an admin who opted out gets no edit in either direction: no setup on a fallback host and no undo on an eBPF host (0.2.5 honoured the same key, so it made no edits there either) (Task 1 test `opt_out_means_no_edit_either_way`).
4. **A kernel upgrade that turns a fallback host into an eBPF host** (BTF appears) — the next package update or `audit-setup apply` undoes the fallback setup; until then the agent uses eBPF while the exec rule still loads (cost only). Documented, and `apply` is idempotent (Task 1 test `apply_is_idempotent_and_undoes_a_fallback_setup_on_an_ebpf_host`).
5. **Uninstall (erase)** — removes the copied rule when unchanged from the template, restores marked lines, reloads; an edited copy is left and reported (Task 1 test `remove_restores_and_keeps_an_edited_copy`).

---

## File structure

```
packaging/rpm/audit-setup                 new: POSIX sh, all audit-rule logic
packaging/rpm/openvibes-agent.rules       unchanged content; installed as a template now
packaging/rpm/openvibes-agent.spec        %install/%files/%post/%posttrans/%postun call audit-setup
packaging/rpm/agent.toml                  comment for manage_audit_rules (fallback hosts only)
tests/packaging/audit-setup.sh            new: bash unit tests on temporary trees
scripts/check-rpm.sh                      file list, modes, the template, no owned rules.d file
scripts/systemd-test.sh                   phases: eBPF host, upgrade from 0.2.5, forced fallback, erase
docs/components/packaging.md              the new behaviour, the deviation, audit-fallback
docs/specs/2026-10-08-ebpf-process-watcher-design.md   §4.2 edited-file sentence
```

---

### Task 1: `audit-setup`, the script, test-first

**Files:**
- Create: `packaging/rpm/audit-setup`, `tests/packaging/audit-setup.sh`

**Interfaces:**
- Produces: `audit-setup <decide|apply|fallback|remove> [--root DIR] [--btf PATH] [--kernel VERSION] [--template PATH]`
  - `--root` (default `/`): every path is under it; when not `/`, no reload is attempted.
  - `--btf` (default `/sys/kernel/btf/vmlinux`), `--kernel` (default `uname -r`), `--template` (default `/usr/share/openvibes-agent/openvibes-agent.rules`).
  - `decide` prints `ebpf` or `fallback`, exit 0.
  - `apply`: on an eBPF host → undo (restore marked lines in every `etc/audit/rules.d/*.rules`; delete `etc/audit/rules.d/openvibes-agent.rules` when byte-identical to the template, else keep it and print a notice); on a fallback host → set up (copy the template to `etc/audit/rules.d/openvibes-agent.rules` mode 0640 if absent, comment out `-a task,never`/`never,task` lines with the marker in every `*.rules` file). Then reload if anything changed. With `manage_audit_rules = false` in `etc/openvibes-agent/agent.toml`: print a notice, change nothing.
  - `fallback`: the fallback setup whatever `decide` says (the admin's command).
  - `remove`: undo (same as the eBPF branch of `apply`) — for package erase.
  - Reload: `augenrules --load` when root is `/`, `augenrules` exists and `systemctl -q is-active auditd`; otherwise print "rules updated; load them with: augenrules --load" when something changed.
  - Exit non-zero only for usage errors; any filesystem error on one file is printed and the rest goes on (a package scriptlet must not fail the transaction).
- The marker string is exactly `# disabled by openvibes-agent (exec alarms need it off): ` (what 0.2.5 wrote).

- [ ] **Step 1: Failing tests.** `tests/packaging/audit-setup.sh`:

```bash
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
```

- [ ] **Step 2: Run** `bash tests/packaging/audit-setup.sh` — Expected: FAIL (`packaging/rpm/audit-setup` missing).

- [ ] **Step 3: Implement `packaging/rpm/audit-setup`** (POSIX sh, `set -eu`, ShellCheck-clean):

```sh
#!/bin/sh
# OpenVIBES agent: audit rules for the exec audit fallback (spec 2026-10-08 §4.2-4.3).
# eBPF hosts (BTF and kernel >= 5.8) get no audit rule and no audit setting
# touched; fallback hosts get the exec rule and Fedora's `-a task,never`
# commented out. The running agent never changes system policy; the package
# and this command do. Usage: audit-setup decide|apply|fallback|remove
#   [--root DIR] [--btf PATH] [--kernel VERSION] [--template PATH]
set -eu
MARK='# disabled by openvibes-agent (exec alarms need it off): '
root=/ btf=/sys/kernel/btf/vmlinux kernel=$(uname -r)
template=/usr/share/openvibes-agent/openvibes-agent.rules
usage() { echo "usage: audit-setup decide|apply|fallback|remove [--root DIR] [--btf PATH] [--kernel VERSION] [--template PATH]" >&2; exit 2; }
[ $# -ge 1 ] || usage
cmd=$1; shift
while [ $# -gt 0 ]; do
    case $1 in
        --root) root=${2:?}; shift ;;
        --btf) btf=${2:?}; shift ;;
        --kernel) kernel=${2:?}; shift ;;
        --template) template=${2:?}; shift ;;
        *) usage ;;
    esac
    shift
done
case $cmd in decide|apply|fallback|remove) ;; *) usage ;; esac
d=${root%/}/etc/audit/rules.d
rule=$d/openvibes-agent.rules
changed=0
say() { printf 'openvibes-agent audit-setup: %s\n' "$*"; }

decide() {
    major=${kernel%%.*}; rest=${kernel#*.}; minor=${rest%%[!0-9]*}
    if [ -e "$btf" ] && { [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "${minor:-0}" -ge 8 ]; }; }; then
        echo ebpf
    else
        echo fallback
    fi
}

opted_out() {
    grep -Eq '^[[:space:]]*manage_audit_rules[[:space:]]*=[[:space:]]*false' \
        "${root%/}/etc/openvibes-agent/agent.toml" 2>/dev/null
}

undo() {
    for f in "$d"/*.rules; do
        [ -f "$f" ] || continue
        if grep -qF "$MARK" "$f"; then
            sed -i "s|^$(printf '%s' "$MARK" | sed 's/[][\\.*^$|/]/\\&/g')||" "$f" && changed=1 ||
                say "could not restore $f"
        fi
    done
    if [ -f "$rule" ]; then
        if cmp -s "$template" "$rule"; then
            rm -f "$rule" && changed=1
        else
            say "kept $rule: it was edited; remove it yourself if you no longer want the exec audit rule"
        fi
    fi
}

setup() {
    if [ ! -f "$rule" ]; then
        install -m 0640 "$template" "$rule" && changed=1 || say "could not install $rule"
    fi
    for f in "$d"/*.rules; do
        [ -f "$f" ] || continue
        if grep -Eq '^[[:space:]]*-a[[:space:]]+(task,never|never,task)([[:space:]].*)?$' "$f"; then
            sed -i -E "s/^([[:space:]]*-a[[:space:]]+(task,never|never,task)([[:space:]].*)?)\$/$(printf '%s' "$MARK" | sed 's/[][\\.*^$|/()]/\\&/g')\\1/" "$f" &&
                changed=1 || say "could not edit $f"
        fi
    done
}

reload() {
    [ "$changed" = 1 ] || return 0
    if [ "$root" = / ] && command -v augenrules >/dev/null 2>&1 && systemctl -q is-active auditd 2>/dev/null; then
        augenrules --load >/dev/null 2>&1 || say "augenrules --load failed; load the rules yourself"
    else
        say "rules updated; load them with: augenrules --load"
    fi
}

case $cmd in
    decide) decide ;;
    apply)
        if opted_out; then say "manage_audit_rules = false: audit rules left as they are"; exit 0; fi
        if [ "$(decide)" = ebpf ]; then undo; else setup; fi
        reload ;;
    fallback)
        if opted_out; then say "manage_audit_rules = false: audit rules left as they are"; exit 0; fi
        setup; reload ;;
    remove) undo; reload ;;
esac
```

Notes for the implementer: the two `sed` escapes turn the marker into a literal regex; check them with the tests (the marker contains `(` `)` `:`), and simplify if a cleaner POSIX form passes — e.g. matching the fixed marker prefix with `awk` index() instead of `sed`. `install` and `cmp` are coreutils/diffutils on Fedora; if `cmp` is missing on a minimal system, fall back to `cksum` comparison.

- [ ] **Step 4: Run** `bash tests/packaging/audit-setup.sh` and `shellcheck -s sh packaging/rpm/audit-setup` — Expected: every line `ok …`, exit 0; ShellCheck clean.
- [ ] **Step 5: Commit** `git add packaging/rpm/audit-setup tests/packaging/audit-setup.sh && git commit -m "packaging: audit-setup, the audit-rule logic as one tested script"`

---

### Task 2: The spec file calls the script; the rule becomes a template

**Files:**
- Modify: `packaging/rpm/openvibes-agent.spec` (`%install`, `%files`, scriptlets), `scripts/check-rpm.sh:14-16`, `packaging/rpm/agent.toml` (the `manage_audit_rules` comment)

**Interfaces:**
- Consumes: `audit-setup apply|remove` (Task 1).
- Produces: files `/usr/libexec/openvibes-agent/audit-setup` (0755), `/usr/libexec/openvibes-agent/audit-fallback` (0755, a two-line wrapper: `exec /usr/libexec/openvibes-agent/audit-setup fallback "$@"`), `/usr/share/openvibes-agent/openvibes-agent.rules` (0644 template). No longer owned: `/etc/audit/rules.d/openvibes-agent.rules`.

- [ ] **Step 1: Failing check.** In `scripts/check-rpm.sh`, replace the two `openvibes-agent.rules` lines with:

```bash
expect_stat /usr/share/openvibes-agent/openvibes-agent.rules 644 root:root
expect_stat /usr/libexec/openvibes-agent/audit-setup 755 root:root
expect_stat /usr/libexec/openvibes-agent/audit-fallback 755 root:root
! rpm -ql openvibes-agent | grep -qx /etc/audit/rules.d/openvibes-agent.rules ||
    fail "the package must not own /etc/audit/rules.d/openvibes-agent.rules (eBPF hosts get no audit rule)"
```

Run the RPM build and check in a Fedora container (`scripts/build-rpm.sh`, then `scripts/check-rpm.sh` as the CI `rpm` job does) — Expected: FAIL on the first `expect_stat`.

- [ ] **Step 2: The spec.** `%install`: replace the `openvibes-agent.rules` line with

```spec
install -D -m 0644 $S/packaging/rpm/openvibes-agent.rules %{buildroot}%{_datadir}/openvibes-agent/openvibes-agent.rules
install -D -m 0755 $S/packaging/rpm/audit-setup %{buildroot}%{_libexecdir}/openvibes-agent/audit-setup
printf '#!/bin/sh\n# Sets up the kernel-audit fallback for threat alarms (see audit-setup).\nexec %s/openvibes-agent/audit-setup fallback "$@"\n' %{_libexecdir} > %{buildroot}%{_libexecdir}/openvibes-agent/audit-fallback
chmod 0755 %{buildroot}%{_libexecdir}/openvibes-agent/audit-fallback
```

`%files`: remove the `%config(noreplace) … /etc/audit/rules.d/openvibes-agent.rules` line; add

```spec
%{_datadir}/openvibes-agent/openvibes-agent.rules
%dir %{_libexecdir}/openvibes-agent
%{_libexecdir}/openvibes-agent/audit-setup
%{_libexecdir}/openvibes-agent/audit-fallback
```

Scriptlets: delete the whole audit block from `%post` (keep `%systemd_post`), and the `augenrules` block from `%postun` (keep `%systemd_postun_with_restart`). Add, after `%postun`:

```spec
%posttrans
# After the whole transaction, so 0.2.5's rule file (unowned now) is already
# erased or renamed by rpm: set up or undo the audit fallback for this host.
%{_libexecdir}/openvibes-agent/audit-setup apply || :
if [ -e %{_sysconfdir}/audit/rules.d/openvibes-agent.rules.rpmsave ]; then
    echo "openvibes-agent: your edited exec audit rule was saved as %{_sysconfdir}/audit/rules.d/openvibes-agent.rules.rpmsave and no longer loads; this host uses eBPF or the package manages the rule now"
fi
```

and in `%preun` (package erase only, `$1 -eq 0`), before `%systemd_preun`'s effect matters:

```spec
if [ "$1" -eq 0 ]; then %{_libexecdir}/openvibes-agent/audit-setup remove || :; fi
```

(`%preun`, not `%postun`: on erase the script must still exist.)

`packaging/rpm/agent.toml`: rewrite the `manage_audit_rules` comment: on eBPF hosts the package touches no audit rule; on fallback hosts (no BTF or a kernel before 5.8) it installs the exec rule and comments out `-a task,never`; `false` keeps your audit rules as they are on every host; `/usr/libexec/openvibes-agent/audit-fallback` sets the fallback up by hand.

- [ ] **Step 3: Run** the container build + `check-rpm.sh` — Expected: PASS.
- [ ] **Step 4: Commit** `git commit -m "packaging: audit rules only on fallback hosts, via audit-setup; the rule is a template now"`

---

### Task 3: Under systemd — eBPF host, upgrade from 0.2.5, forced fallback, erase

**Files:**
- Modify: `scripts/systemd-test.sh`, `.github/workflows/ci.yml` (the `systemd` job downloads the 0.2.5 RPM), `docs/components/packaging.md`, `docs/specs/2026-10-08-ebpf-process-watcher-design.md` (§4.2 edited-file sentence)

**Interfaces:**
- Consumes: the package from Task 2; the released `openvibes-agent-0.2.5-1.fc44.x86_64.rpm` (GitHub release v0.2.5 of openvibes-agent; checksum from that release's `SHA256SUMS`).

- [ ] **Step 1: New phases in `scripts/systemd-test.sh`** (failing first: run the script against the Task 2 RPMs before writing the phases' fixes — the assertions below fail on 0.2.5-style behaviour). Before the existing install, seed Fedora's default rule in the container: `printf -- '-D\n-a task,never\n' > /etc/audit/rules.d/audit.rules`. Then:
  - **eBPF host** (CI runners and the lab have BTF): after `dnf install` of BASE — `/etc/audit/rules.d/openvibes-agent.rules` absent; `-a task,never` unmarked; `audit-setup decide` prints `ebpf`.
  - **Upgrade from 0.2.5:** in a fresh container, install the 0.2.5 RPM (by path; verify its SHA-256 against the release's `SHA256SUMS` first) with the seeded `audit.rules` — check 0.2.5 marked the line and installed the rule — then `dnf upgrade` to BASE: the marked line is restored to `-a task,never`, the rule file is gone, no `.rpmsave`. Repeat with the 0.2.5 rule edited first (`echo '# edit' >> …`) — after the upgrade: `.rpmsave` present, the notice printed, no active `openvibes-agent.rules`.
  - **Forced fallback:** `/usr/libexec/openvibes-agent/audit-fallback` → rule installed (0640, equal to the template), `-a task,never` marked; `audit-setup apply --btf /nonexistent` is idempotent.
  - **Erase:** `dnf remove openvibes-agent` → rule gone, line restored.
  - Containers cannot load audit rules: assert the "load them with: augenrules --load" notice instead of a reload.
- [ ] **Step 2: CI.** In the `systemd` job, before the test, download the 0.2.5 agent RPM and `SHA256SUMS` from the v0.2.5 release with `gh release download v0.2.5 -R openvibes-project/openvibes-agent -p 'openvibes-agent-0.2.5-1.fc44.x86_64.rpm' -p SHA256SUMS` (token: the workflow's `GITHUB_TOKEN`), `sha256sum -c --ignore-missing`, and pass its path to the script (`OLD_RPM=…`).
- [ ] **Step 3: Docs.** `docs/components/packaging.md`: replace the "comments out `task,never` on install" paragraph with the eBPF/fallback behaviour, the 0.2.5 upgrade restore, the `.rpmsave` handling and why, `audit-setup` and `audit-fallback` usage, and the kernel-upgrade note (a fallback host whose kernel gains BTF is undone at the next package update or `audit-setup apply`). Spec §4.2: replace "(only if unchanged from what 0.2.5 shipped; an edited copy is left and reported)" with "(rpm erases it when unchanged and renames an edited copy to `.rpmsave`, which no longer loads; the package reports that)".
- [ ] **Step 4: Gate and commit.** Workspace `testing.md` §4 plus `bash tests/packaging/audit-setup.sh` and `scripts/systemd-test.sh` locally (rootless podman). `git commit -m "systemd-test: eBPF host, upgrade from 0.2.5, forced fallback and erase"`. PR with all three tasks; CI green before review.

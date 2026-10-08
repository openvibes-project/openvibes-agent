#!/usr/bin/env bash
# What threat alarms cost (P14, board #86), for the CI job `alarms-cost` on
# a VM runner with sudo. Installs the packaged binary, unit and user from
# the RPM the `rpm` job built, runs it as systemd runs it, and measures the
# agent's RSS and CPU in three phases, with process_events off and then on:
#   idle   no load;
#   exec   ~100 execs/s with varying arguments that match no rule (what
#          every host pays);
#   storm  the same plus 10 new alarms a second.
# Then, alarms on only: crafted (the baseline's worst case on purpose) and
# restricted (a site rule set at its caps, board #108). Alarms on read
# process starts with eBPF, on an eBPF host: no exec audit rule, auditd
# stopped. A last exec phase reads them from kernel audit
# (`process_events_source = "audit"`, the packaged rule, auditd running)
# and also measures auditd. Gates (R22, R25): the eBPF agent's user CPU per
# 1,000 starts is at most the audit agent's plus auditd's (one clock tick
# of tolerance), and the eBPF exec phase adds at most 5,120 kB RSS.
# The agent has no reachable platform, so it never enrolls: alarms are
# evaluated and queued, not sent. The table goes to stdout and, in CI, to
# the job summary. auditd and the audit rules are put back as found on
# every exit.
# Usage: alarms-cost.sh RPM_DIR   (PHASE_SECONDS, default 120)
set -euo pipefail
cd "$(dirname "$0")/.."
RPMS=$(realpath "$1")
phase=${PHASE_SECONDS:-120}
fail() { echo "FAIL: $*" >&2; exit 1; }
W=$(mktemp -d)

# auditd and the audit rules as this script found them, restored on every
# exit (R31): runners are ephemeral, a lab or developer machine is not.
audit_was_up=no
! pidof auditd >/dev/null || audit_was_up=yes
audit_saved=$(mktemp)
sudo auditctl -l 2>/dev/null | grep -v '^No rules' >"$audit_saved" || true
restore_audit() {
    if [[ $audit_was_up == yes ]] && ! pidof auditd >/dev/null; then
        # A quick stop and start can hit audit-rules' start limit (Debian 13).
        sudo systemctl reset-failed auditd audit-rules 2>/dev/null || true
        sudo systemctl start auditd || echo "WARN: auditd did not start again" >&2
        # audit 4.x loads rules.d from its own unit after auditd.
        sudo systemctl start audit-rules 2>/dev/null || true
    fi
    sudo auditctl -D >/dev/null 2>&1 || true
    if [[ -s $audit_saved ]]; then
        sudo auditctl -R "$audit_saved" >/dev/null || echo "WARN: the saved audit rules did not all load" >&2
    fi
    rm -f "$audit_saved"
}
trap restore_audit EXIT
# Debian's and Ubuntu's auditd.service refuses `systemctl stop`
# (RefuseManualStop=yes): signal it, then wait until it is gone.
stop_auditd() {
    sudo systemctl kill -s TERM auditd 2>/dev/null || sudo pkill -x auditd || true
    local _
    for _ in $(seq 50); do
        pidof auditd >/dev/null || return 0
        sleep 0.2
    done
    fail "auditd is still running"
}

# Install what the RPM installs (Ubuntu has no rpm database to use).
# The RPM of this workspace's version (dist also holds a next-patch build).
version=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)
(cd "$W" && rpm2cpio "$RPMS"/openvibes-agent-"$version"-*.x86_64.rpm | cpio -idm --quiet)
sudo install -m 0755 "$W/usr/bin/openvibes-agent" /usr/bin/openvibes-agent
sudo install -m 0644 "$W/usr/lib/systemd/system/openvibes-agent.service" /etc/systemd/system/
sudo install -m 0644 "$W/usr/lib/sysusers.d/openvibes-agent.conf" /usr/lib/sysusers.d/
sudo systemd-sysusers
sudo install -d -m 0750 -g openvibes_agent /etc/openvibes-agent
# The host as each source leaves it. Audit: auditd running and only the
# packaged rule (none loaded twice, no `-a task,never` before it). eBPF: no
# exec rule and no auditd, so nothing of audit is paid for.
audit_host() {
    sudo systemctl start auditd
    # audit 4.x loads rules.d from its own unit, after auditd: let it finish
    # first, or it replaces the rule below (and adds `-a task,never`).
    sudo systemctl start audit-rules 2>/dev/null || true
    sudo auditctl -D >/dev/null
    sudo auditctl -R "$W/usr/share/openvibes-agent/openvibes-agent.rules" >/dev/null
}
ebpf_host() {
    sudo auditctl -D >/dev/null
    stop_auditd
}
# auditd's user plus system CPU, in clock ticks.
auditd_ticks() { sudo awk '{ print $14 + $15 }' "/proc/$(pidof auditd)/stat"; }
audit_host

# A platform that is never reached, with a CA the agent can parse.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=cost-test -keyout "$W/ca.key" -out "$W/ca.crt" 2>/dev/null
SIGN="$RPMS/sign_bundle"
chmod +x "$SIGN"
KEY=$("$SIGN" keygen "$W/signing.key" | tail -1)
cat > "$W/rules.json" <<'RULES'
{"schema_version":1,"rules":[
 {"id":"shell-from-fake-nginx","version":1,"title":"Shell from a web server","severity":"high","confidence":80,
  "kind":"process_event",
  "expression":"event['parent.name'] == 'fake-nginx' && event['process.cmdline'].startsWith('sh -c ')",
  "finding_message":"A web server started a shell"}]}
RULES
"$SIGN" sign "$W/signing.key" "$W/rules.json" baseline-alarms 1 org.rules 7 "$W/bundle.json" >/dev/null
sudo install -m 0640 -g openvibes_agent "$W/ca.crt" /etc/openvibes-agent/platform-ca.crt
sudo install -m 0640 -g openvibes_agent "$W/bundle.json" /etc/openvibes-agent/bundle.json
install -m 0755 /bin/bash /tmp/fake-nginx

configure() { # COLLECTORS [EXTRA_TOML]   (SOURCE_LINE: a top-level line)
    cat > "$W/agent.toml" <<TOML
state_dir = "/var/lib/openvibes-agent"
${SOURCE_LINE:-}
platform_url = "https://127.0.0.1:9"
platform_ca_file = "/etc/openvibes-agent/platform-ca.crt"
collectors = [$1]
[[rule_sets]]
id = "baseline-alarms"
bundle_file = "/etc/openvibes-agent/bundle.json"
trusted_keys = [{ issuer_key_id = "org.rules", public_key = "$KEY" }]
${2:-}
TOML
    sudo install -m 0640 -g openvibes_agent "$W/agent.toml" /etc/openvibes-agent/agent.toml
}

pid() { systemctl show -p MainPID --value openvibes-agent; }
# No task of the agent holds CAP_BPF (bit 39) or CAP_PERFMON (bit 38) in
# its effective, permitted or ambient set, whichever source it uses.
# Reading nothing (no process, a vanished one) is a failure, not a pass.
no_ebpf_caps() {
    local p sets v
    p=$(pid)
    [[ $p =~ ^[1-9][0-9]*$ ]] || fail "the agent is not running (pid '$p')"
    sets=$(sudo awk '/^Cap(Eff|Prm|Amb):/ { print $2 }' /proc/"$p"/task/*/status) ||
        fail "cannot read the agent's tasks"
    [[ -n $sets ]] || fail "no capability line read from the agent's tasks"
    while read -r v; do
        (((0x$v & 0xc000000000) == 0)) || fail "a task of the agent holds CAP_BPF or CAP_PERFMON ($v)"
    done <<<"$sets"
}
source_is() { # TEXT: the running agent's journal names this source
    sudo journalctl -u openvibes-agent -o cat _PID="$(pid)" | grep -q "reading process starts $1" ||
        fail "the agent does not read process starts $1"
}
rss_kb() { sudo awk '/^VmRSS:/ { print $2 }' "/proc/$(pid)/status"; }
ticks() { sudo awk '{ print $14, $15 }' "/proc/$(pid)/stat"; } # user, system

# Per thread, by name: "name cpu_ticks minor_faults context_switches".
thread_ticks() {
    local task
    for task in /proc/"$(pid)"/task/*; do
        sudo awk -v sw="$(sudo awk '/ctxt_switches/ { s += $2 } END { print s }' "$task/status")" \
            '{ c = $0; sub(/^[^(]*\(/, "", c); sub(/\).*/, "", c);
               n = split($0, f, ") "); split(f[n], g, " "); print c, g[12] + g[13], g[8], sw }' "$task/stat"
    done | sort
}


# ~100 execs a second for $1 seconds, with $2 of every 10 a new alarm.
load() { # SECONDS ALARMS_PER_TENTH
    /tmp/fake-nginx -c "end=\$((SECONDS + $1)); i=0
        while ((SECONDS < end)); do
            for ((j = $2; j < 10; j++)); do /bin/true \$i \$j; done
            for ((j = 0; j < $2; j++)); do sh -c \"true \$i \$j\"; done
            i=\$((i + 1)); sleep 0.1
        done
        echo \$((i * 11)) > $W/execs" # 10 programs and a sleep per tick
}

# The baseline's worst case on purpose (board #105): an unprivileged user
# runs ~100 shells a second (the table shows the count), each with a ~64 KiB argument, under five
# nested parents whose exe paths are ~4 KiB (17 directories of 220 bytes and
# a 250-byte name; PATH_MAX is 4,096). The shell passes the real baseline
# rules' program prefilter, and their comparisons over the ancestors and
# the command line run near their bounds. Each parent stays alive (it runs
# the next one as a child), so all five are the shell's ancestors.
crafted() { # SECONDS
    local deep=/tmp/ov-crafted level
    sudo rm -rf "$deep"
    for ((level = 0; level < 17; level++)); do deep+="/$(printf 'd%.0s' {1..220})"; done
    mkdir -p "$deep"
    local name
    name=$(printf 'p%.0s' {1..249})
    head -c 65000 /dev/zero | tr '\0' x > "$deep/pad"
    # level1 to level4 each start the next copy with its script; level5,
    # run by the fifth copy, is the loop. The shell's five ancestors are
    # then copies 5 down to 1.
    for level in 1 2 3 4 5; do
        cp /bin/bash "$deep/$name$level"
    done
    for level in 1 2 3 4; do
        printf '"%s" "%s"\n' "$deep/$name$((level + 1))" "$deep/level$((level + 1))" > "$deep/level$level"
    done
    cat > "$deep/level5" <<LOOP
end=\$((SECONDS + $1)); i=0; pad=\$(cat "$deep/pad")
# A builtin pause (read's timeout; the substitution forks, never execs),
# so each round is one exec and about 10 ms.
while ((SECONDS < end)); do sh -c "true \$pad"; i=\$((i + 1)); read -rt 0.0045 <> <(:) || true; done
echo \$i > "$deep/execs"
LOOP
    # Owned by the user that runs them, so no other local user can swap
    # the scripts before they run (Sonar S2612); the files stay readable.
    sudo chown -R nobody: /tmp/ov-crafted
    sudo -u nobody "$deep/${name}1" "$deep/level1" || fail "the crafted load did not run"
    cp "$deep/execs" "$W/execs" || fail "the crafted load counted no execs"
}

# A restricted rule set at its caps (board #108): 32 programs, 8 per rule
# over 16 rules, so each program is named by 4 rules. Each rule is 11
# `contains` over the command line, so a start of one of them with a
# 64 KiB argument costs ~45,000 of the shared 50,000 operations, on the
# masked event the agent builds for it. Nothing matches. `nobody` runs
# the 32 programs in turn, ~100 a second.
restricted() { # SECONDS
    local dir=/tmp/ov-site n
    sudo rm -rf "$dir"
    mkdir -p "$dir"
    for ((n = 1; n <= 32; n++)); do cp /bin/true "$dir/$(printf 'site-p%02d' "$n")"; done
    head -c 65000 /dev/zero | tr '\0' x > "$dir/pad"
    cat > "$dir/loop" <<LOOP
end=\$((SECONDS + $1)); i=0; pad=\$(cat "$dir/pad")
while ((SECONDS < end)); do
    "$dir/site-p\$(printf '%02d' \$((i % 32 + 1)))" "--password=\$i" "\$pad"
    i=\$((i + 1)); read -rt 0.0045 <> <(:) || true
done
echo \$i > "$dir/execs"
LOOP
    sudo chown -R nobody: "$dir"
    sudo -u nobody bash "$dir/loop" || fail "the restricted load did not run"
    cp "$dir/execs" "$W/execs" || fail "the restricted load counted no execs"
}

# Measures one phase: prints "RSS_KB CPU_PERCENT USER_PERCENT SYSTEM_PERCENT
# EXECS".
measure() { # SECONDS ALARMS_PER_TENTH (-1: no load, -2: crafted, -3: restricted)
    local u0 s0 u1 s1
    read -r u0 s0 <<<"$(ticks)"
    echo 0 > "$W/execs"
    if (($2 == -3)); then restricted "$1"; elif (($2 == -2)); then crafted "$1"; elif (($2 < 0)); then sleep "$1"; else load "$1" "$2"; fi
    read -r u1 s1 <<<"$(ticks)"
    # USER_HZ is 100: ticks per second = percent of one core.
    awk -v r="$(rss_kb)" -v u=$((u1 - u0)) -v k=$((s1 - s0)) -v s="$1" \
        -v e="$(cat "$W/execs")" \
        'BEGIN { printf "%d %.4f %.4f %.4f %d\n", r, (u + k) / s, u / s, k / s, e }'
}

declare -A result
for mode in off on; do
    if [[ $mode == on ]]; then
        ebpf_host # until the audit run below
        configure '"processes", "packages", "ports", "process_events"'
    else
        configure '"processes", "packages", "ports"'
    fi
    sudo systemctl restart openvibes-agent
    sleep 60 # the start-up scan and first tick settle
    [[ $(pid) != 0 ]] || fail "the agent is not running ($mode)"
    no_ebpf_caps
    [[ $mode == on ]] && source_is 'with eBPF'
    result[$mode.idle]=$(measure "$phase" -1)
    [[ $mode == on ]] && threads0=$(thread_ticks)
    result[$mode.exec]=$(measure "$phase" 0)
    [[ $mode == on ]] && threads1=$(thread_ticks)
    result[$mode.storm]=$(measure "$phase" 1)
    if [[ $mode == on ]]; then
        # Which system calls the agent makes under exec load (strace slows
        # it, so this is after the measured phases and only for counts).
        sudo timeout -s INT 30 strace -c -f -p "$(pid)" -o "$W/strace.txt" &
        sleep 1
        load 28 0
        wait || true
        syscalls=$(head -20 "$W/strace.txt")
        log=$(sudo journalctl -u openvibes-agent -o cat --since=-10min)
        grep -E 'receive buffer|lost before evaluation' <<<"$log" || true
        lost=$(grep -oE '\(([0-9]+) since start\)' <<<"$log" | tail -1 | grep -oE '[0-9]+' || echo 0)
        cap=$(sudo awk '/^CapEff:/ { print $2 }' "/proc/$(pid)/status")
        [[ $cap == 0000002000000000 ]] || fail "CapEff is $cap"
    fi
done
# Crafted (board #105): the real baseline-alarms rules, then an unprivileged
# user shaping starts to their worst case. Version 2, so the agent accepts
# it over the synthetic version 1. An agent with process events off never
# sees these starts, so off-mode idle is the reference.
"$SIGN" sign "$W/signing.key" crates/openvibes-rules/tests/fixtures/baseline-alarms-rules.json \
    baseline-alarms 2 org.rules 7 "$W/bundle2.json" >/dev/null
sudo install -m 0640 -g openvibes_agent "$W/bundle2.json" /etc/openvibes-agent/bundle.json
sudo systemctl restart openvibes-agent
sleep 60
[[ $(pid) != 0 ]] || fail "the agent is not running (crafted)"
result[off.crafted]=${result[off.idle]}
threads2=$(thread_ticks)
result[on.crafted]=$(measure "$phase" -2)
threads3=$(thread_ticks)
log=$(sudo journalctl -u openvibes-agent -o cat --since=-10min)
crafted_lost=$(grep -oE 'lost before evaluation \(([0-9]+) since start\)' <<<"$log" | tail -1 | grep -oE '[0-9]+' || echo 0)

# Restricted (board #108): the same agent plus a `site-alarms` set with no
# `restricted` key, so restricted, at its caps.
python3 - "$W/site.json" <<'PY'
import json, sys
names = [f"site-p{n:02d}" for n in range(1, 33)]
test = " || ".join(f"event['process.cmdline'].contains('zz{n}')" for n in range(11))
# Rule r names programs 2r to 2r+7 (wrapping): each program in 4 rules.
rules = [{"id": f"site.cap-{r}", "version": 1, "title": "At the caps", "severity": "low",
          "confidence": 50, "kind": "process_event",
          "programs": [names[(2 * r + j) % 32] for j in range(8)],
          "expression": test, "finding_message": "never"} for r in range(16)]
json.dump({"schema_version": 1, "rules": rules}, open(sys.argv[1], "w"))
PY
"$SIGN" sign "$W/signing.key" "$W/site.json" site-alarms 1 org.site 7 "$W/site-bundle.json" >/dev/null
sudo install -m 0640 -g openvibes_agent "$W/site-bundle.json" /etc/openvibes-agent/site-bundle.json
configure '"processes", "packages", "ports", "process_events"' "[[rule_sets]]
id = \"site-alarms\"
bundle_file = \"/etc/openvibes-agent/site-bundle.json\"
trusted_keys = [{ issuer_key_id = \"org.site\", public_key = \"$KEY\" }]"
sudo systemctl restart openvibes-agent
sleep 60
[[ $(pid) != 0 ]] || fail "the agent is not running (restricted)"
log=$(sudo journalctl -u openvibes-agent -o cat --since=-2min)
! grep -E 'rule set site-alarms:' <<<"$log" || fail "the site set was not accepted"
result[off.restricted]=${result[off.idle]}
threads4=$(thread_ticks)
result[on.restricted]=$(measure "$phase" -3)
threads5=$(thread_ticks)
log=$(sudo journalctl -u openvibes-agent -o cat --since=-10min)
restricted_lost=$(grep -oE 'lost before evaluation \(([0-9]+) since start\)' <<<"$log" | tail -1 | grep -oE '[0-9]+' || echo 0)
cuts=$(grep -oE 'hit the rule budget.*\(([0-9]+) since start\)' <<<"$log" | tail -1 | grep -oE '[0-9]+ since start' || true)

# The same exec phase with process starts from kernel audit, on an audit
# host (restored), with auditd's own CPU for the same starts.
audit_host
SOURCE_LINE='process_events_source = "audit"' configure '"processes", "packages", "ports", "process_events"'
sudo systemctl restart openvibes-agent
sleep 60
[[ $(pid) != 0 ]] || fail "the agent is not running (audit)"
no_ebpf_caps
source_is 'from kernel audit'
[[ $(sudo auditctl -l | grep -c 'key=openvibes-exec') == 2 ]] || fail "the audit run has no exec rule"
auditd0=$(auditd_ticks)
result[audit.exec]=$(measure "$phase" 0)
auditd_t=$(($(auditd_ticks) - auditd0))
[[ $(sudo auditctl -l | grep -c 'key=openvibes-exec') == 2 ]] || fail "the audit run lost its exec rule"
sudo systemctl stop openvibes-agent

row() { # PHASE
    read -r off_rss off_cpu _ _ _ <<<"${result[off.$1]}"
    read -r on_rss on_cpu on_user on_sys execs <<<"${result[on.$1]}"
    # CPU-seconds per 1,000 execs: Δ% × phase / 100 / execs × 1000.
    per=$(awk -v a="$on_cpu" -v b="$off_cpu" -v s="$phase" -v e="$execs" \
        'BEGIN { if (e > 0) printf "%.3f", (a - b) * s / 100 / e * 1000; else print "-" }')
    printf '| %s | %s | %s | %+d | %s | %s (user %s, system %s) | %+.2f | %s | %s |\n' "$1" \
        "$off_rss" "$on_rss" $((on_rss - off_rss)) "$off_cpu" "$on_cpu" "$on_user" "$on_sys" \
        "$(awk -v a="$on_cpu" -v b="$off_cpu" 'BEGIN { print a - b }')" "$execs" "$per"
}
# CPU-seconds per 1,000 starts, user and system apart: user is the agent's
# own work; system is mostly the kernel handing over records.
split() { # PHASE
    read -r _ _ off_user off_sys _ <<<"${result[off.$1]}"
    read -r _ _ on_user on_sys execs <<<"${result[on.$1]}"
    awk -v u="$on_user" -v ou="$off_user" -v k="$on_sys" -v ok="$off_sys" -v s="$phase" -v e="$execs" \
        'BEGIN { if (e > 0) printf "user %.3f, system %.3f", (u - ou) * s / 100 / e * 1000, (k - ok) * s / 100 / e * 1000; else print "-" }'
}
# User CPU-seconds per 1,000 starts in the exec phase, over alarms off.
user_per() { # RESULT_KEY
    read -r _ _ off_user _ _ <<<"${result[off.exec]}"
    read -r _ _ user _ execs <<<"${result[$1]}"
    awk -v u="$user" -v o="$off_user" -v s="$phase" -v e="$execs" 'BEGIN { printf "%.3f", (u - o) * s / 100 / e * 1000 }'
}
ebpf_user=$(user_per on.exec)
audit_user=$(user_per audit.exec)
read -r _ _ _ _ ebpf_execs <<<"${result[on.exec]}"
read -r _ _ _ _ audit_execs <<<"${result[audit.exec]}"
auditd_user=$(awk -v t="$auditd_t" -v e="$audit_execs" 'BEGIN { printf "%.4f", t / 100 / e * 1000 }')
# One clock tick over the eBPF window: strict comparisons flake at tick
# resolution.
tick=$(awk -v e="$ebpf_execs" 'BEGIN { printf "%.4f", 0.01 / e * 1000 }')
read -r off_rss _ <<<"${result[off.exec]}"
read -r ebpf_rss _ <<<"${result[on.exec]}"
ebpf_drss=$((ebpf_rss - off_rss))
{
    echo "### Alarms cost ($phase s per phase, $(nproc) CPUs, $(uname -r))"
    echo
    echo "CPU: $(lscpu | sed -n 's/^Model name: *//p'), $(lscpu | sed -n 's/^CPU max MHz: *//p; s/^CPU MHz: *//p' | head -1) MHz"
    echo
    echo '| phase | RSS off kB | RSS on kB | Δ kB | CPU off % | CPU on % | Δ % | execs | Δ CPU-s per 1,000 execs |'
    echo '|---|---|---|---|---|---|---|---|---|'
    row idle
    row exec
    row storm
    row crafted
    row restricted
    echo
    echo "crafted: ~100 shells a second by \`nobody\`, each with a 64 KiB argument under five parents with ~4 KiB paths, against the real \`baseline-alarms\` rules (worst case 136,068 operations per start). Starts lost: ${crafted_lost:-0}."
    echo "crafted CPU-s per 1,000 starts: $(split crafted)."
    echo "restricted: ~100 starts a second by \`nobody\` of the 32 programs a restricted \`site-alarms\` set names (16 rules × 8, each program named by 4 rules of ~11,000 operations on a 64 KiB argument, on the masked command line). Starts lost: ${restricted_lost:-0}. Budget cuts: ${cuts:-none logged}."
    echo "restricted CPU-s per 1,000 starts: $(split restricted)."
    echo 'Budget (spec §2.7): Δ RSS < 5,120 kB, Δ CPU < 1 % of one core. Crafted (board #106): user ≤ 0.18 CPU-s per 1,000 starts. Restricted (board #108): user ≤ 0.47 CPU-s per 1,000 starts. System time is the kernel'"'"'s share, printed, not gated.'
    echo
    echo "Exec phase, host cost by source, CPU-s per 1,000 starts: eBPF agent (user) $ebpf_user; audit agent (user) $audit_user + auditd (user+system, $auditd_t ticks) $auditd_user; tolerance one tick $tick (gate: eBPF ≤ audit + auditd + tick). Audit run: $(read -r rss cpu user sys execs <<<"${result[audit.exec]}"; echo "RSS $rss kB, CPU $cpu % (user $user, system $sys), $execs execs")."
    echo
    echo "Exec phase Δ RSS with eBPF: $ebpf_drss kB (gate: ≤ 5,120 kB)."
    echo
    echo "System calls under 30 s of exec load (strace -c):"
    echo
    echo '```'
    echo "$syscalls"
    echo '```'
    echo
    echo "Process starts lost (all phases, alarms on): ${lost:-0}. $(grep -oE 'receive buffer [0-9]+ KiB' <<<"$log" | tail -1)."
    echo
    echo "By thread during the exec phase, alarms on (CPU % of one core; per second: minor faults, context switches):"
    echo
    join <(echo "$threads0") <(echo "$threads1") |
        awk -v s="$phase" '{ printf "- %s: CPU %.2f, faults %.0f/s, switches %.0f/s\n", $1, ($5 - $2) / s, ($6 - $3) / s, ($7 - $4) / s }'
    echo
    echo "By thread during the crafted phase (same columns):"
    echo
    join <(echo "$threads2") <(echo "$threads3") |
        awk -v s="$phase" '{ printf "- %s: CPU %.2f, faults %.0f/s, switches %.0f/s\n", $1, ($5 - $2) / s, ($6 - $3) / s, ($7 - $4) / s }'
    echo
    echo "By thread during the restricted phase (same columns):"
    echo
    join <(echo "$threads4") <(echo "$threads5") |
        awk -v s="$phase" '{ printf "- %s: CPU %.2f, faults %.0f/s, switches %.0f/s\n", $1, ($5 - $2) / s, ($6 - $3) / s, ($7 - $4) / s }'
} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
awk -v e="$ebpf_user" -v a="$audit_user" -v d="$auditd_user" -v t="$tick" 'BEGIN { exit !(e <= a + d + t) }' ||
    fail "eBPF costs more CPU per 1,000 starts ($ebpf_user) than audit ($audit_user + auditd $auditd_user, tolerance $tick)"
((ebpf_drss <= 5120)) || fail "the eBPF exec phase adds $ebpf_drss kB RSS, over 5,120 kB"

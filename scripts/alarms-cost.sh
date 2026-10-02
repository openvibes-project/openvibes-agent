#!/usr/bin/env bash
# What threat alarms cost (P14, board #86), for the CI job `alarms-cost` on
# a VM runner with sudo. Installs the packaged binary, unit and user from
# the RPM the `rpm` job built, runs it as systemd runs it, and measures the
# agent's RSS and CPU in three phases, with process_events off and then on:
#   idle   no load;
#   exec   ~100 execs/s with varying arguments that match no rule (what
#          every host pays);
#   storm  the same plus 10 new alarms a second.
# The agent has no reachable platform, so it never enrolls: alarms are
# evaluated and queued, not sent. The table goes to stdout and, in CI, to
# the job summary.
# Usage: alarms-cost.sh RPM_DIR   (PHASE_SECONDS, default 120)
set -euo pipefail
cd "$(dirname "$0")/.."
RPMS=$(realpath "$1")
phase=${PHASE_SECONDS:-120}
fail() { echo "FAIL: $*" >&2; exit 1; }
W=$(mktemp -d)

# Install what the RPM installs (Ubuntu has no rpm database to use).
# The RPM of this workspace's version (dist also holds a next-patch build).
version=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)
(cd "$W" && rpm2cpio "$RPMS"/openvibes-agent-"$version"-*.x86_64.rpm | cpio -idm --quiet)
sudo install -m 0755 "$W/usr/bin/openvibes-agent" /usr/bin/openvibes-agent
sudo install -m 0644 "$W/usr/lib/systemd/system/openvibes-agent.service" /etc/systemd/system/
sudo install -m 0644 "$W/usr/lib/sysusers.d/openvibes-agent.conf" /usr/lib/sysusers.d/
sudo systemd-sysusers
sudo install -d -m 0750 -g openvibes_agent /etc/openvibes-agent
sudo auditctl -R "$W/etc/audit/rules.d/openvibes-agent.rules" >/dev/null

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

configure() { # COLLECTORS
    cat > "$W/agent.toml" <<TOML
state_dir = "/var/lib/openvibes-agent"
platform_url = "https://127.0.0.1:9"
platform_ca_file = "/etc/openvibes-agent/platform-ca.crt"
collectors = [$1]
[[rule_sets]]
id = "baseline-alarms"
bundle_file = "/etc/openvibes-agent/bundle.json"
trusted_keys = [{ issuer_key_id = "org.rules", public_key = "$KEY" }]
TOML
    sudo install -m 0640 -g openvibes_agent "$W/agent.toml" /etc/openvibes-agent/agent.toml
}

pid() { systemctl show -p MainPID --value openvibes-agent; }
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

# Measures one phase: prints "RSS_KB CPU_PERCENT USER_PERCENT SYSTEM_PERCENT
# EXECS".
measure() { # SECONDS ALARMS_PER_TENTH (-1: no load, -2: crafted)
    local u0 s0 u1 s1
    read -r u0 s0 <<<"$(ticks)"
    echo 0 > "$W/execs"
    if (($2 == -2)); then crafted "$1"; elif (($2 < 0)); then sleep "$1"; else load "$1" "$2"; fi
    read -r u1 s1 <<<"$(ticks)"
    # USER_HZ is 100: ticks per second = percent of one core.
    awk -v r="$(rss_kb)" -v u=$((u1 - u0)) -v k=$((s1 - s0)) -v s="$1" \
        -v e="$(cat "$W/execs")" \
        'BEGIN { printf "%d %.2f %.2f %.2f %d\n", r, (u + k) / s, u / s, k / s, e }'
}

declare -A result
for mode in off on; do
    if [[ $mode == on ]]; then
        configure '"processes", "packages", "ports", "process_events"'
    else
        configure '"processes", "packages", "ports"'
    fi
    sudo systemctl restart openvibes-agent
    sleep 60 # the start-up scan and first tick settle
    [[ $(pid) != 0 ]] || fail "the agent is not running ($mode)"
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
result[on.crafted]=$(measure "$phase" -2)
log=$(sudo journalctl -u openvibes-agent -o cat --since=-10min)
crafted_lost=$(grep -oE 'lost before evaluation \(([0-9]+) since start\)' <<<"$log" | tail -1 | grep -oE '[0-9]+' || echo 0)
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
    echo
    echo "crafted: ~100 shells a second by \`nobody\`, each with a 64 KiB argument under five parents with ~4 KiB paths, against the real \`baseline-alarms\` rules (worst case 136,068 operations per start). Starts lost: ${crafted_lost:-0}."
    echo 'Budget (spec §2.7): Δ RSS < 5,120 kB, Δ CPU < 1 % of one core.'
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
} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

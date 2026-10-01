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
audit_lines() { sudo wc -l < /var/log/audit/audit.log; }

# ~100 execs a second for $1 seconds, with $2 of every 10 a new alarm.
load() { # SECONDS ALARMS_PER_TENTH
    /tmp/fake-nginx -c "end=\$((SECONDS + $1)); i=0
        while ((SECONDS < end)); do
            for ((j = $2; j < 10; j++)); do /bin/true \$i \$j; done
            for ((j = 0; j < $2; j++)); do sh -c \"true \$i \$j\"; done
            i=\$((i + 1)); sleep 0.1
        done"
}

# Measures one phase: prints "RSS_KB CPU_PERCENT USER_PERCENT SYSTEM_PERCENT".
measure() { # SECONDS ALARMS_PER_TENTH (-1: no load)
    local u0 s0 u1 s1
    read -r u0 s0 <<<"$(ticks)"
    if (($2 < 0)); then sleep "$1"; else load "$1" "$2"; fi
    read -r u1 s1 <<<"$(ticks)"
    # USER_HZ is 100: ticks per second = percent of one core.
    awk -v r="$(rss_kb)" -v u=$((u1 - u0)) -v k=$((s1 - s0)) -v s="$1" \
        'BEGIN { printf "%d %.2f %.2f %.2f\n", r, (u + k) / s, u / s, k / s }'
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
    [[ $mode == on ]] && { threads0=$(thread_ticks); lines0=$(audit_lines); }
    result[$mode.exec]=$(measure "$phase" 0)
    [[ $mode == on ]] && { threads1=$(thread_ticks); lines1=$(audit_lines); }
    result[$mode.storm]=$(measure "$phase" 1)
    if [[ $mode == on ]]; then
        log=$(sudo journalctl -u openvibes-agent -o cat --since=-10min)
        grep -E 'receive buffer|lost before evaluation' <<<"$log" || true
        lost=$(grep -oE '\(([0-9]+) since start\)' <<<"$log" | tail -1 | grep -oE '[0-9]+' || echo 0)
        cap=$(sudo awk '/^CapEff:/ { print $2 }' "/proc/$(pid)/status")
        [[ $cap == 0000002000000000 ]] || fail "CapEff is $cap"
    fi
done
sudo systemctl stop openvibes-agent

row() { # PHASE
    read -r off_rss off_cpu _ _ <<<"${result[off.$1]}"
    read -r on_rss on_cpu on_user on_sys <<<"${result[on.$1]}"
    printf '| %s | %s | %s | %+d | %s | %s (user %s, system %s) | %+.2f |\n' "$1" "$off_rss" \
        "$on_rss" $((on_rss - off_rss)) "$off_cpu" "$on_cpu" "$on_user" "$on_sys" \
        "$(awk -v a="$on_cpu" -v b="$off_cpu" 'BEGIN { print a - b }')"
}
{
    echo "### Alarms cost ($phase s per phase, $(nproc) CPUs, $(uname -r))"
    echo
    echo '| phase | RSS off kB | RSS on kB | Δ kB | CPU off % | CPU on % | Δ % |'
    echo '|---|---|---|---|---|---|---|'
    row idle
    row exec
    row storm
    echo
    echo 'Budget (spec §2.7): Δ RSS < 5,120 kB, Δ CPU < 1 % of one core.'
    echo
    echo "Process starts lost (all phases, alarms on): ${lost:-0}. $(grep -oE 'receive buffer [0-9]+ KiB' <<<"$log" | tail -1)."
    echo
    echo "By thread during the exec phase, alarms on (CPU % of one core; per second: minor faults, context switches):"
    echo
    join <(echo "$threads0") <(echo "$threads1") |
        awk -v s="$phase" '{ printf "- %s: CPU %.2f, faults %.0f/s, switches %.0f/s\n", $1, ($5 - $2) / s, ($6 - $3) / s, ($7 - $4) / s }'
    echo
    echo "Audit records logged during the exec phase: $(((lines1 - lines0) / phase))/s."
} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

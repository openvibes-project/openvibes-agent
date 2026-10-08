#!/usr/bin/env bash
# Threat alarms on a real kernel (P14), for the CI job `alarms-kernel` on a
# VM runner with sudo. First the test `caps_drop` with real capabilities
# (as root, and as nobody with CAP_BPF and CAP_PERFMON ambient as the unit
# grants them): no thread may keep either. Then the test `alarms_kernel` (its own main thread)
# as nobody twice, starting a fake-nginx before and after it, then an exec
# load while the test measures its cost:
#   audit  the packaged audit rule loaded, only CAP_AUDIT_READ;
#   ebpf   Fedora's `-a task,never` and no exec rule, auditd stopped, only
#          CAP_BPF and CAP_PERFMON; once the test is ready no task of it
#          may hold either (decoded with capsh).
# OV_LOAD_SECONDS (default 120; 0 skips the load).
set -euo pipefail
cd "$(dirname "$0")/.."
load_seconds=${OV_LOAD_SECONDS:-120}
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() { # SECONDS FILE
    local end=$((SECONDS + $1))
    until [[ -e $2 ]]; do ((SECONDS < end)) || fail "timed out waiting for $2"; sleep 0.2; done
}

test_bin() { # NAME
    cargo test --locked -p openvibes-agent --test "$1" --no-run --message-format=json |
        jq -r --arg n "$1" 'select(.executable != null and .target.name == $n) | .executable'
}
bin=$(test_bin alarms_kernel)
caps_bin=$(test_bin caps_drop)
[[ -x $bin && -x $caps_bin ]] || fail "no test binary"
# nobody cannot reach the workspace; the binaries and fake-nginx live in /tmp.
sudo install -m 0755 "$bin" /tmp/ov-alarms-kernel
sudo install -m 0755 "$caps_bin" /tmp/ov-caps-drop

echo "== caps_drop as root"
sudo /tmp/ov-caps-drop
echo "== caps_drop as nobody with CAP_BPF and CAP_PERFMON"
sudo systemd-run --wait --pipe --collect --quiet -p User=nobody \
    -p AmbientCapabilities='CAP_BPF CAP_PERFMON' -p NoNewPrivileges=yes /tmp/ov-caps-drop
sudo install -m 0755 /bin/bash /tmp/fake-nginx

# The packaged unit's syscall filter, line by line (bpf and capset must
# get through it).
filter=()
while read -r line; do filter+=(-p "$line"); done < <(grep -E '^SystemCall(Filter|ErrorNumber|Architectures)=' packaging/rpm/openvibes-agent.service)

# Fails when a task of PID holds CAP_BPF or CAP_PERFMON in its effective,
# permitted or ambient set; prints every set decoded.
no_ebpf_caps() { # PID
    local task line set value decoded
    for task in /proc/"$1"/task/*; do
        while read -r line; do
            set=${line%%:*} value=${line##*[[:space:]]}
            decoded=$(capsh --decode="$value")
            echo "task ${task##*/} $set $decoded"
            [[ $set == CapBnd ]] && continue # cannot be cleared without CAP_SETPCAP
            ! grep -qE 'cap_bpf|cap_perfmon' <<<"$decoded" || fail "task ${task##*/} holds them in $set"
        done < <(sudo grep -E '^Cap(Eff|Prm|Amb|Bnd)' "$task/status")
    done
}

phase() { # SOURCE
    local source=$1 caps want unit=ov-alarms-$1
    local ready=/tmp/ov-alarms-ready-$1 log=/tmp/ov-alarms-kernel-$1.log
    echo "== phase $source"
    if [[ $source == audit ]]; then
        # Only the packaged rule: Fedora's `-a task,never` would come first
        # and stop every exec record (%post comments it out on install).
        sudo auditctl -D >/dev/null
        sudo auditctl -R packaging/rpm/openvibes-agent.rules >/dev/null
        sudo auditctl -l | grep -q 'key=openvibes-exec' || fail "the audit rule did not load"
        caps=CAP_AUDIT_READ want='from kernel audit'
    else
        # Nothing from audit may feed the alarms: no exec rule, no auditd,
        # and Fedora's default that disables audit for every new task.
        sudo systemctl stop auditd 2>/dev/null || sudo service auditd stop || true
        sudo auditctl -D >/dev/null
        sudo auditctl -a task,never
        ! sudo auditctl -l | grep -q 'key=openvibes-exec' || fail "the audit rule is still loaded"
        caps='CAP_BPF CAP_PERFMON' want='with eBPF'
    fi
    sudo rm -f "$ready" "$ready.load" "$ready.stop"

    # Started before the agent (as root, so its exe link is unreadable to
    # nobody); it waits for the agent, then starts sh five times. It stays
    # alive until the test is done with it (board #101): the agent reads an
    # unknown parent from /proc when the exec record arrives, and on a busy
    # runner a parent that already exited is gone ("parent none", no alarm).
    sudo /tmp/fake-nginx -c "while [ ! -e $ready ]; do [ -e $ready.stop ] && exit; sleep 0.2; done; for i in 1 2 3 4 5; do sh -c 'true pre'; done
        while [ ! -e $ready.load ] && [ ! -e $ready.stop ]; do sleep 0.2; done" &
    pre=$!
    # Every exit path stops it (a wait_for timeout too, before or after it
    # started its shells), not only the end.
    # shellcheck disable=SC2064 # this phase's file, now
    trap "sudo touch '$ready.stop'" EXIT

    # shellcheck disable=SC2024 # the log is ours, not root's
    sudo systemd-run --wait --pipe --collect --quiet --unit="$unit" "${filter[@]}" \
        -p User=nobody -p AmbientCapabilities="$caps" \
        -p CapabilityBoundingSet="$caps" -p NoNewPrivileges=yes \
        -E OV_READY="$ready" -E OV_LOAD_SECONDS="$load_seconds" \
        -E OV_SOURCE="$source" -E OPENVIBES_TRACE_STARTS=1 \
        /tmp/ov-alarms-kernel >"$log" 2>&1 &
    agent=$!

    (wait_for 60 "$ready") || { cat "$log"; exit 1; }
    if [[ $source == ebpf ]]; then
        # Attached and running its threads: none holds the capabilities.
        no_ebpf_caps "$(systemctl show -p MainPID --value "$unit")"
    fi
    /tmp/fake-nginx -c "for i in 1 2 3 4 5; do sh -c 'true post'; done"

    if ((load_seconds > 0)); then
        # The test writes this only when the alarms were right; if it ends
        # first, skip the load and report below.
        until [[ -e $ready.load ]] || ! ps -p "$agent" >/dev/null; do sleep 0.5; done
    fi
    if [[ -e $ready.load ]]; then
        # About 100 execs a second with varying arguments: 90 that match no
        # rule, 10 alarms (each a new command line) under fake-nginx.
        /tmp/fake-nginx -c "end=\$((SECONDS + $load_seconds)); i=0
            while ((SECONDS < end)); do
                for j in 1 2 3 4 5 6 7 8 9; do /bin/true \$i \$j; done
                sh -c \"true load \$i\"
                i=\$((i + 1)); sleep 0.1
            done"
    fi
    status=0; wait "$agent" || status=$?
    sudo touch "$ready.stop"
    wait "$pre"
    grep -v 'openvibes-agent: start ' "$log"
    # Each sh start and the parent the agent saw (pre and post run first).
    grep -m 20 'openvibes-agent: start .* exe /usr/bin/dash' "$log" || true
    # What the kernel logged for the two fake-nginx runs (every run, so a
    # flake explains itself).
    grep ' /proc ' /proc/mounts || true
    [[ $source == audit ]] && sudo ausearch --input-logs -k openvibes-exec -i 2>/dev/null | grep -E 'proctitle=sh -c true (pre|post)' -B3 | grep -E 'type=SYSCALL' | sed 's/.* ppid=\([0-9]*\) pid=\([0-9]*\).* exe=\([^ ]*\).*/ppid \1 pid \2 exe \3/' | tail -12 || true
    ((status == 0)) || fail "the alarms_kernel test failed ($source)"
    grep -q "reading process starts $want" "$log" || fail "the log does not name $want"
}

phase audit
phase ebpf
echo "alarms-kernel: ok"

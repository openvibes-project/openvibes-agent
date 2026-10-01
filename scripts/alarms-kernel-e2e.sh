#!/usr/bin/env bash
# Threat alarms on a real kernel (P14), for the CI job `alarms-kernel` on a
# VM runner with sudo: loads the packaged audit rule, runs the ignored test
# `alarms_kernel` as nobody with only CAP_AUDIT_READ, starts a fake-nginx
# before and after it, then an exec load while the test measures its cost.
# OV_LOAD_SECONDS (default 120; 0 skips the load).
set -euo pipefail
cd "$(dirname "$0")/.."
load_seconds=${OV_LOAD_SECONDS:-120}
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() { # SECONDS FILE
    local end=$((SECONDS + $1))
    until [[ -e $2 ]]; do ((SECONDS < end)) || fail "timed out waiting for $2"; sleep 0.2; done
}

sudo auditctl -R packaging/rpm/openvibes-agent.rules >/dev/null
sudo auditctl -l | grep -q 'key=openvibes-exec' || fail "the audit rule did not load"

bin=$(cargo test --locked -p openvibes-agent --test alarms_kernel --no-run --message-format=json |
    jq -r 'select(.executable != null and .target.name == "alarms_kernel") | .executable')
[[ -x $bin ]] || fail "no test binary"
# nobody cannot reach the workspace; the binary and fake-nginx live in /tmp.
sudo install -m 0755 "$bin" /tmp/ov-alarms-kernel
sudo install -m 0755 /bin/bash /tmp/fake-nginx
ready=/tmp/ov-alarms-ready
sudo rm -f "$ready" "$ready.load"

# Started before the agent (as root, so its exe link is unreadable to
# nobody); it waits for the agent, then starts sh five times. It stays
# alive until the test is done with it (board #101): the agent reads an
# unknown parent from /proc when the exec record arrives, and on a busy
# runner a parent that already exited is gone ("parent none", no alarm).
sudo rm -f "$ready.stop"
sudo /tmp/fake-nginx -c "while [ ! -e $ready ]; do sleep 0.2; done; for i in 1 2 3 4 5; do sh -c 'true pre'; done
    while [ ! -e $ready.load ] && [ ! -e $ready.stop ]; do sleep 0.2; done" &
pre=$!
# Every exit path stops it (a wait_for timeout too), not only the end.
trap 'sudo touch "$ready.stop"' EXIT

sudo systemd-run --wait --pipe --collect --quiet \
    -p User=nobody -p AmbientCapabilities=CAP_AUDIT_READ \
    -p CapabilityBoundingSet=CAP_AUDIT_READ -p NoNewPrivileges=yes \
    -E OV_READY="$ready" -E OV_LOAD_SECONDS="$load_seconds" \
    -E OPENVIBES_TRACE_STARTS=1 \
    /tmp/ov-alarms-kernel --ignored --nocapture --test-threads=1 >/tmp/ov-alarms-kernel.log 2>&1 &
agent=$!

wait_for 60 "$ready"
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
grep -v 'openvibes-agent: start ' /tmp/ov-alarms-kernel.log
# Each sh start and the parent the agent saw (pre and post run first).
grep -m 20 'openvibes-agent: start .* exe /usr/bin/dash' /tmp/ov-alarms-kernel.log || true
# What the kernel logged for the two fake-nginx runs (every run, so a
# flake explains itself).
grep ' /proc ' /proc/mounts || true
sudo ausearch -k openvibes-exec -i 2>/dev/null | grep -E 'proctitle=sh -c true (pre|post)' -B3 | grep -E 'type=SYSCALL' | sed 's/.* ppid=\([0-9]*\) pid=\([0-9]*\).* exe=\([^ ]*\).*/ppid \1 pid \2 exe \3/' | tail -12 || true
((status == 0)) || fail "the alarms_kernel test failed"
echo "alarms-kernel: ok"

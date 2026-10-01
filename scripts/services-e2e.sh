#!/usr/bin/env bash
# Host services (P15) under the agent's real unit, for the CI job
# `services-kernel` on a VM runner with sudo. A web server runs as nobody in a
# unit with two programs; the probe runs as the agent user inside the
# packaged unit's sandbox:
#   without the drop-in: the port shows its service, but no program (the
#                        unit runs two), and owners is partial;
#   with owners.conf:    the exact program, read from the server's fds.
# Each run's CPU time is printed for the cost budget (< 5 ms per scan).
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { echo "FAIL: $*" >&2; exit 1; }
port=18765
unit=ov-test-web.service

cargo build -q --locked --release -p openvibes-collectors --example services_probe
sudo install -m 0755 target/release/examples/services_probe /usr/local/bin/ov-services-probe
sudo install -m 0644 packaging/rpm/openvibes-agent.sysusers /usr/lib/sysusers.d/openvibes-agent.conf
sudo systemd-sysusers

# The packaged unit with the probe as a one-shot: the same user and
# sandbox; its output goes to the journal-free file below.
out=/run/ov-services-probe.out
sed -e "s|^ExecStart=.*|ExecStart=/usr/local/bin/ov-services-probe|" \
    -e "s|^Type=.*|Type=oneshot|" -e "/^Restart/d" \
    -e "/^\[Service\]/a StandardOutput=truncate:$out" \
    packaging/rpm/openvibes-agent.service | sudo tee /etc/systemd/system/ov-services-probe.service >/dev/null

# Another user's server, in a unit with two programs (python3 and sleep).
sudo systemd-run --unit="$unit" --collect -p User=nobody \
    bash -c "sleep infinity & exec python3 -m http.server $port --bind 0.0.0.0" >/dev/null
for _ in $(seq 50); do ss -ltnH "sport = :$port" | grep -q . && break; sleep 0.2; done
ss -ltnH "sport = :$port" | grep -q . || fail "the test server did not start"

probe() {
    sudo systemctl daemon-reload
    sudo systemctl start ov-services-probe.service || { sudo systemctl status ov-services-probe.service --no-pager; fail "probe failed"; }
    sudo cat "$out"
}
line() { grep -E "^listener Tcp 0\.0\.0\.0 $port " <<<"$1" || fail "port $port not listed: $1"; }

plain=$(probe)
got=$(line "$plain")
echo "without the drop-in: $got; $(grep -E '^(owners|cpu_ms)' <<<"$plain" | tr '\n' ' ')"
[[ $got == *"service=$unit program=-" ]] || fail "without the drop-in: $got"
grep -q '^owners Partial' <<<"$plain" || fail "owners must be partial without the drop-in"

sudo install -D -m 0644 packaging/rpm/owners.conf /etc/systemd/system/ov-services-probe.service.d/owners.conf
exact=$(probe)
got=$(line "$exact")
echo "with owners.conf: $got; $(grep -E '^(owners|cpu_ms)' <<<"$exact" | tr '\n' ' ')"
[[ $got == *"service=$unit program=python3" ]] || fail "with the drop-in: $got"
# Anything still without a program shows why owners is partial: who
# holds it (as root), its cgroup, and the fds the walk had to read.
if grep -E '^listener .* program=-$' <<<"$exact" | sed 's/^/  no program: /'; then
    grep -E '^listener .* program=-$' <<<"$exact" | awk '{print $4}' | sort -u | while read -r p; do
        sudo ss -ltnpH "sport = :$p" | sed 's/^/  holder: /'
        ss -ltnH --cgroup "sport = :$p" | sed 's/^/  cgroup: /'
    done
    count_fds() { while read -r pid; do sudo ls "/proc/$pid/fd" 2>/dev/null | wc -l; done | paste -sd+ | bc; }
    echo "  fds: pid 1 $(echo 1 | count_fds); system services $(sudo find /sys/fs/cgroup/system.slice -name cgroup.procs -exec cat {} + | count_fds)"
fi

sudo systemctl stop "$unit"
echo "services-e2e: all checks passed"

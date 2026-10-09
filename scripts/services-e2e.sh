#!/usr/bin/env bash
# Host services (P15) under the agent's real unit, for the CI job
# `services-kernel` on a VM runner with sudo. A web server runs as nobody in a
# unit with two programs; the probe runs as the agent user inside the
# packaged unit's sandbox:
#   the agent alone:     the port shows its service, but no program (the
#                        unit runs two), and owners is partial;
#   the root helper:     the packaged openvibes-agent-facts unit names the
#                        exact program in its file, which the agent user
#                        can read (no drop-in, no command: spec #229 §4).
# Each run's CPU time is printed for the cost budget (< 5 ms per scan).
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { echo "FAIL: $*" >&2; exit 1; }
port=18765
unit=ov-test-web.service

cargo build -q --locked --release -p openvibes-collectors --example services_probe
cargo build -q --locked --release -p openvibes-agent --no-default-features --bin openvibes-agent-facts
sudo install -m 0755 target/release/examples/services_probe /usr/local/bin/ov-services-probe
sudo install -D -m 0755 target/release/openvibes-agent-facts /usr/libexec/openvibes-agent/openvibes-agent-facts
sudo install -m 0644 packaging/rpm/openvibes-agent-facts.service /etc/systemd/system/openvibes-agent-facts.service
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
echo "the agent alone: $got; $(grep -E '^(owners|cpu_ms)' <<<"$plain" | tr '\n' ' ')"
[[ $got == *"service=$unit program=-" ]] || fail "the agent alone: $got"
grep -q '^owners Partial' <<<"$plain" || fail "owners must be partial for the agent alone"

# The root helper, as packaged: its file names the exact program, and the
# agent's user may read it.
sudo systemctl daemon-reload
sudo systemctl start openvibes-agent-facts.service || { sudo systemctl status openvibes-agent-facts.service --no-pager; fail "helper failed"; }
facts=/run/openvibes-agent-facts/root-facts.json
[[ "$(sudo stat -c '%a %U:%G' "$(dirname "$facts")") $(sudo stat -c '%a %U:%G' "$facts")" == "750 root:openvibes_agent 640 root:openvibes_agent" ]] ||
    fail "helper file modes: $(sudo ls -ld "$(dirname "$facts")" "$facts")"
json=$(sudo -u openvibes_agent cat "$facts") || fail "the agent user cannot read $facts"
got=$(jq -r --argjson p "$port" '.services.listeners[] | select(.port == $p and .protocol == "tcp") | "service=\(.service // "-") program=\(.program // "-")"' <<<"$json")
echo "root helper: $got; owners $(jq -r .services.owners <<<"$json")"
[[ $got == *"service=$unit program=python3" ]] || fail "root helper: $got"
# The unit's sandbox as this systemd sees it.
sudo systemd-analyze security openvibes-agent-facts.service --no-pager | tail -1
sudo rm -f /etc/systemd/system/openvibes-agent-facts.service

sudo systemctl stop "$unit"
echo "services-e2e: all checks passed"

#!/usr/bin/env bash
# The packaged agent under a real systemd (podman, fedora:44, systemd as
# PID 1): install and static checks, a crash-loop check with the shipped
# configuration, a local-only scan under the hardened unit that must still
# see the whole host, then upgrade, downgrade, and uninstall.
# Usage: scripts/systemd-test.sh [RPM_DIR], where RPM_DIR holds
# openvibes-agent 0.1.0 and a 0.1.1 test build of the same code. SIGN_BIN
# names a prebuilt sign_bundle example (CI); otherwise it is built.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
PODMAN=${PODMAN:-podman}
C=ov-agent-systemd-test
IMAGE=ov-systemd:44
W=$ROOT/target/systemd-test
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
in_c() { "$PODMAN" exec "$C" bash -c "$1"; }
# wait_for DESC SECONDS COMMAND: poll COMMAND in the container once a second.
wait_for() {
    local desc=$1 seconds=$2 i
    for ((i = 0; i < seconds; i++)); do
        if in_c "$3" >/dev/null 2>&1; then ok "$desc"; return 0; fi
        sleep 1
    done
    fail "$desc (after ${seconds}s)"
}
cleanup() {
    local status=$?
    if ((status != 0)); then
        "$PODMAN" exec "$C" journalctl -u openvibes-agent --no-pager -n 30 2>/dev/null || true
    fi
    "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

RPMS=${1:-}
if [[ -z "$RPMS" ]]; then
    bash scripts/build-rpm.sh >/dev/null
    # The same code as 0.1.1, for the upgrade and downgrade steps.
    OV_VERSION=0.1.1 bash scripts/build-rpm.sh >/dev/null
    RPMS=$ROOT/target/rpm/RPMS/x86_64
fi
rm -rf "$W"; mkdir -p "$W"
cp "$RPMS"/openvibes-agent-*.rpm "$W/"
cp scripts/check-rpm.sh "$W/"

# Signed local-only rule set. Each rule proves one collector sees the host:
# PID 1 belongs to root, so the sandbox must not hide other users'
# processes; the ports fact exists only if /proc/net was readable.
SIGN=${SIGN_BIN:-}
if [[ -z "$SIGN" ]]; then
    cargo build --quiet --release --locked -p openvibes-rules --example sign_bundle
    SIGN=$ROOT/target/release/examples/sign_bundle
fi
KEY=$("$SIGN" keygen "$W/signing.key" | tail -1)
cat > "$W/rules.json" <<'RULES'
{"schema_version":1,"rules":[
 {"id":"host.sees.systemd","version":1,"title":"PID 1 is visible","severity":"info","confidence":100,
  "expression":"'systemd' in facts['process.names']","finding_message":"systemd is running"},
 {"id":"host.sees.packages","version":1,"title":"Packages are visible","severity":"info","confidence":100,
  "expression":"facts['package.count'] >= 50","finding_message":"packages are installed"},
 {"id":"host.sees.ports","version":1,"title":"Ports are visible","severity":"info","confidence":100,
  "expression":"facts['port.tcp.exposed.count'] >= 0","finding_message":"ports were read"}]}
RULES
"$SIGN" sign "$W/signing.key" "$W/rules.json" baseline 1 org.rules 7 "$W/bundle.json" >/dev/null
cat > "$W/local.toml" <<TOML
state_dir = "/var/lib/openvibes-agent"
[[rule_sets]]
id = "baseline"
bundle_file = "/etc/openvibes-agent/bundle.json"
trusted_keys = [{ issuer_key_id = "org.rules", public_key = "$KEY" }]
TOML

printf 'FROM registry.fedoraproject.org/fedora:44\nRUN dnf -q -y install systemd sqlite procps-ng && dnf clean all\n' |
    "$PODMAN" build -q -t "$IMAGE" -f - "$W" >/dev/null
"$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
# --privileged (rootless: privileged only inside the container's user
# namespace) lets systemd build the unit's mount namespaces, and drops
# podman's masked and read-only /proc paths, which ProtectKernelTunables=
# cannot re-mount. Without it systemd silently ignores the sandbox.
"$PODMAN" run -d --systemd=always --privileged --name "$C" -v "$W:/test:Z" "$IMAGE" /sbin/init >/dev/null
wait_for "systemd is up" 30 'systemctl is-system-running | grep -qE "running|degraded"'
# The unit's sandbox must be enforced here, or the checks below prove
# nothing. check-rpm.sh also refuses the directives that would blind the
# collectors statically.
[[ "$(in_c 'systemd-run --wait -q -p ProtectSystem=strict --pipe bash -c "touch /usr/.probe 2>/dev/null && echo writable || echo blocked"')" == blocked ]] ||
    fail "this container does not enforce systemd sandboxing"
ok "systemd enforces the unit sandbox in this container"

# Install and static checks.
in_c 'dnf -q -y install /test/openvibes-agent-0.1.0-*.rpm' >/dev/null 2>&1 || fail "install"
in_c 'bash /test/check-rpm.sh' | sed 's/^/  /'
ok "installed; static checks passed"

# The shipped configuration (no CA file yet) is refused; systemd retries
# every 30 s rather than looping.
in_c 'systemctl start openvibes-agent' || true
sleep 65
starts=$(in_c 'systemctl show -p NRestarts --value openvibes-agent')
((starts >= 1 && starts <= 3)) || fail "the unconfigured agent restarted $starts times in 65 s, want 1 to 3"
in_c 'journalctl -u openvibes-agent -o cat | grep -q "cannot start"' ||
    fail "the unconfigured agent did not refuse its configuration"
ok "unconfigured agent retries every 30 s ($starts restarts in 65 s)"
in_c 'systemctl stop openvibes-agent; systemctl reset-failed openvibes-agent' || true

# Local-only scan under the hardened unit.
in_c 'install -m 0640 -g openvibes_agent /test/local.toml /etc/openvibes-agent/agent.toml &&
      install -m 0640 -g openvibes_agent /test/bundle.json /etc/openvibes-agent/bundle.json &&
      systemctl enable --now openvibes-agent' >/dev/null || fail "start"
Q=/var/lib/openvibes-agent/queue.sqlite
for rule in host.sees.systemd host.sees.packages host.sees.ports; do
    wait_for "finding from $rule under the unit" 60 \
        "[[ \$(sqlite3 $Q \"SELECT count(*) FROM pending WHERE CAST(body AS TEXT) LIKE '%\\\"$rule\\\"%'\") -ge 1 ]]"
done
in_c 'pid=$(systemctl show -p MainPID --value openvibes-agent);
      [[ $(ps -o user= -p "$pid") == openvibes_agent ]] &&
      grep -q "^CapEff:[[:space:]]*0000000000000000$" /proc/$pid/status' ||
    fail "the agent is not unprivileged"
ok "runs as openvibes_agent with no effective capabilities"
# The seccomp filter and no_new_privs are in force (the probe above covers
# mount namespaces only), and the hostname namespace is the host's, so a
# hostname change reaches the agent's heartbeats without a restart.
in_c 'pid=$(systemctl show -p MainPID --value openvibes-agent);
      grep -q "^Seccomp:[[:space:]]*2$" /proc/$pid/status &&
      grep -q "^NoNewPrivs:[[:space:]]*1$" /proc/$pid/status' ||
    fail "seccomp filter or no_new_privs not in force"
ok "seccomp filter and no_new_privs in force"
uts=$(in_c 'readlink /proc/$(systemctl show -p MainPID --value openvibes-agent)/ns/uts /proc/1/ns/uts')
[[ "$(sort -u <<< "$uts" | wc -l)" == 1 ]] ||
    fail "the agent has its own hostname namespace (hostname changes would not reach it): $(tr '\n' ' ' <<< "$uts")"
ok "the agent sees the host's hostname"
[[ "$(in_c 'stat -c "%a %U" /var/lib/openvibes-agent')" == "700 openvibes_agent" ]] ||
    fail "state directory is not 0700 openvibes_agent"
ok "state directory 0700 openvibes_agent"
[[ "$(in_c "stat -c '%a %U' $Q")" == "600 openvibes_agent" ]] || fail "queue.sqlite is not 0600 openvibes_agent"
ok "queue 0600 openvibes_agent"

# Upgrade, downgrade, uninstall: the edited configuration and the state
# (queue, with its findings) survive each step.
config_hash() { in_c 'sha256sum /etc/openvibes-agent/agent.toml | cut -d" " -f1'; }
queued() { in_c "sqlite3 $Q 'SELECT count(*) FROM pending'"; }
main_pid() { in_c 'systemctl show -p MainPID --value openvibes-agent'; }
HASH=$(config_hash)
QUEUED=$(queued)
# version_step DESC DNF_COMMAND VERSION
version_step() {
    local before
    before=$(main_pid)
    in_c "dnf -q -y $2" >/dev/null 2>&1 || fail "$1"
    [[ "$(in_c 'rpm -q --qf "%{VERSION}" openvibes-agent')" == "$3" ]] || fail "$1: not at $3"
    wait_for "$1: service active again" 30 'systemctl is-active -q openvibes-agent'
    [[ "$(main_pid)" != "$before" ]] || fail "$1: service was not restarted"
    [[ "$(config_hash)" == "$HASH" ]] || fail "$1: edited agent.toml changed"
    (($(queued) >= QUEUED)) || fail "$1: queued findings lost"
    ok "$1 to $3: restarted, config and queue kept"
}
version_step "upgrade" "upgrade /test/openvibes-agent-0.1.1-*.rpm" 0.1.1
version_step "downgrade" "downgrade /test/openvibes-agent-0.1.0-*.rpm" 0.1.0
in_c 'dnf -q -y remove openvibes-agent' >/dev/null 2>&1 || fail "uninstall"
! in_c 'systemctl cat openvibes-agent' >/dev/null 2>&1 || fail "uninstall left the unit"
in_c "test -s $Q" || fail "uninstall deleted the queue"
kept=$(in_c 'for f in /etc/openvibes-agent/agent.toml.rpmsave /etc/openvibes-agent/agent.toml; do
                 [[ -f $f ]] && { sha256sum "$f" | cut -d" " -f1; break; }; done')
[[ "$kept" == "$HASH" ]] || fail "uninstall did not keep the edited configuration"
ok "uninstall: service gone, state and edited configuration kept"
echo "systemd-test: all checks passed"

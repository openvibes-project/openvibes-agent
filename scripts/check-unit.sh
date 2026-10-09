#!/usr/bin/env bash
# Static checks of the packaged unit and audit rule (P14): the agent holds
# exactly CAP_AUDIT_READ, CAP_BPF and CAP_PERFMON (the last two for the
# eBPF watcher, dropped once it is attached), may call bpf() but not
# perf_event_open(), and may open netlink sockets; the rule file asks for
# exactly the exec events the agent reads.
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { echo "FAIL: $*" >&2; exit 1; }
UNIT=packaging/rpm/openvibes-agent.service
RULES=packaging/rpm/openvibes-agent.rules
[[ "$(grep -c '^AmbientCapabilities=' "$UNIT")" == 1 ]] || fail "AmbientCapabilities= must appear once"
CAPS='CAP_AUDIT_READ CAP_BPF CAP_PERFMON'
grep -qx "AmbientCapabilities=$CAPS" "$UNIT" || fail "AmbientCapabilities is not exactly $CAPS"
[[ "$(grep -c '^CapabilityBoundingSet=' "$UNIT")" == 1 ]] || fail "CapabilityBoundingSet= must appear once"
grep -qx "CapabilityBoundingSet=$CAPS" "$UNIT" || fail "CapabilityBoundingSet is not exactly $CAPS"
# Without CAP_SETPCAP the agent cannot clear its bounding set; a non-root
# user and NoNewPrivileges keep the dropped capabilities from coming back.
grep -qx 'NoNewPrivileges=yes' "$UNIT" || fail "NoNewPrivileges=yes is gone"
user=$(sed -n 's/^User=//p' "$UNIT")
[[ -n $user && $user != root && $user != 0 ]] || fail "User= must name a non-root user"
# The filter's lines apply in order: a later allow line re-allows bpf()
# (load) and capset() (the drop after attach) from the denied @privileged
# group; perf_event_open stays denied.
# A whitelist: exactly these allow lines (so nothing else, perf_event_open
# or a group holding it, is allowed) and the one deny line.
allow=$(grep '^SystemCallFilter=[^~]' "$UNIT")
[[ $allow == $'SystemCallFilter=@system-service\nSystemCallFilter=bpf capset' ]] ||
    fail "the SystemCallFilter allow lines are not exactly @system-service and bpf capset: $allow"
[[ "$(grep -c '^SystemCallFilter=' "$UNIT")" == 3 ]] || fail "SystemCallFilter= must appear exactly three times"
grep -qx 'SystemCallFilter=~@privileged @resources' "$UNIT" || fail "the deny line is not ~@privileged @resources"
# A blocked call fails with EPERM (the agent falls back to audit) instead
# of killing the agent with SIGSYS into a restart loop.
grep -qx 'SystemCallErrorNumber=EPERM' "$UNIT" || fail "SystemCallErrorNumber is not EPERM"
# The heap the eBPF load uses for a moment goes back to the system (R25).
grep -qx 'Environment=GLIBC_TUNABLES=glibc.malloc.mmap_threshold=131072:glibc.malloc.trim_threshold=131072' "$UNIT" ||
    fail "the malloc thresholds are not pinned"
grep -q '^RestrictAddressFamilies=.*\bAF_NETLINK\b' "$UNIT" || fail "AF_NETLINK is not allowed"
rules=$(grep -v '^\s*\(#\|$\)' "$RULES")
expected='-a always,exit -F arch=b64 -S execve,execveat -k openvibes-exec
-a always,exit -F arch=b32 -S execve,execveat -k openvibes-exec'
[[ "$rules" == "$expected" ]] || fail "the rules file is not exactly the two openvibes-exec lines"
grep -q '"process_events"' packaging/rpm/agent.toml || fail "the packaged agent.toml does not enable process_events"
grep -q '"services"' packaging/rpm/agent.toml || fail "the packaged agent.toml does not enable services"
# The agent itself never holds an owner capability; the root-facts helper
# (spec #229 §4) holds exactly the two, no network and no input.
! grep -q 'CAP_SYS_PTRACE\|CAP_DAC_READ_SEARCH' "$UNIT" || fail "the agent unit grants an owner capability"
FACTS=packaging/rpm/openvibes-agent-facts.service
grep -qx 'ExecStart=/usr/libexec/openvibes-agent/openvibes-agent-facts' "$FACTS" || fail "facts: ExecStart takes arguments or moved"
grep -qx 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE' "$FACTS" || fail "facts: bounding set"
grep -qx 'AmbientCapabilities=' "$FACTS" || fail "facts: ambient set not empty"
grep -qx 'Group=openvibes_agent' "$FACTS" || fail "facts: the file's group"
grep -qx 'RestrictAddressFamilies=AF_UNIX AF_NETLINK' "$FACTS" || fail "facts: address families"
grep -qx 'IPAddressDeny=any' "$FACTS" || fail "facts: IP traffic not denied"
for setting in NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes PrivateDevices=yes RuntimeDirectoryMode=0750 RuntimeDirectoryPreserve=yes Type=oneshot; do
    grep -qx "$setting" "$FACTS" || fail "facts: $setting missing"
done
# It must see the host's sockets and processes.
for forbidden in PrivateNetwork=yes ProtectProc=invisible ProcSubset=pid PrivateUsers=yes; do
    ! grep -q "^$forbidden" "$FACTS" || fail "facts: unit sets $forbidden"
done
echo "check-unit: ok"

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
grep -qx 'SystemCallFilter=bpf capset' "$UNIT" || fail "no SystemCallFilter line allows exactly bpf and capset"
! grep -E '^SystemCallFilter=[^~].*\bperf_event_open\b' "$UNIT" >/dev/null || fail "a SystemCallFilter line allows perf_event_open"
# A blocked call fails with EPERM (the agent falls back to audit) instead
# of killing the agent with SIGSYS into a restart loop.
grep -qx 'SystemCallErrorNumber=EPERM' "$UNIT" || fail "SystemCallErrorNumber is not EPERM"
grep -q '^RestrictAddressFamilies=.*\bAF_NETLINK\b' "$UNIT" || fail "AF_NETLINK is not allowed"
rules=$(grep -v '^\s*\(#\|$\)' "$RULES")
expected='-a always,exit -F arch=b64 -S execve,execveat -k openvibes-exec
-a always,exit -F arch=b32 -S execve,execveat -k openvibes-exec'
[[ "$rules" == "$expected" ]] || fail "the rules file is not exactly the two openvibes-exec lines"
grep -q '"process_events"' packaging/rpm/agent.toml || fail "the packaged agent.toml does not enable process_events"
grep -q '"services"' packaging/rpm/agent.toml || fail "the packaged agent.toml does not enable services"
# The opt-in owners drop-in (P15) adds exactly the two capabilities.
DROPIN=packaging/rpm/owners.conf
grep -qx 'AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE' "$DROPIN" || fail "owners.conf ambient set"
grep -qx 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE' "$DROPIN" || fail "owners.conf bounding set"
[[ "$(grep -vc '^\s*\(#\|$\)' "$DROPIN")" == 3 ]] || fail "owners.conf holds more than [Service] and the two lines"
echo "check-unit: ok"

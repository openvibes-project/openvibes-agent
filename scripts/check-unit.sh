#!/usr/bin/env bash
# Static checks of the packaged unit and audit rule (P14): the agent holds
# exactly CAP_AUDIT_READ and may open netlink sockets, and the rule file
# asks for exactly the exec events the agent reads.
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { echo "FAIL: $*" >&2; exit 1; }
UNIT=packaging/rpm/openvibes-agent.service
RULES=packaging/rpm/openvibes-agent.rules
[[ "$(grep -c '^AmbientCapabilities=' "$UNIT")" == 1 ]] || fail "AmbientCapabilities= must appear once"
grep -qx 'AmbientCapabilities=CAP_AUDIT_READ' "$UNIT" || fail "AmbientCapabilities is not exactly CAP_AUDIT_READ"
[[ "$(grep -c '^CapabilityBoundingSet=' "$UNIT")" == 1 ]] || fail "CapabilityBoundingSet= must appear once"
grep -qx 'CapabilityBoundingSet=CAP_AUDIT_READ' "$UNIT" || fail "CapabilityBoundingSet is not exactly CAP_AUDIT_READ"
grep -qx 'NoNewPrivileges=yes' "$UNIT" || fail "NoNewPrivileges=yes is gone"
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

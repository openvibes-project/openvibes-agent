#!/usr/bin/env bash
# Fails if BINARY needs a glibc symbol version above MAX: the one agent
# binary goes into the RPM, .deb and Arch packages, and the oldest system
# supported (EL 9) has glibc 2.34 (offline install spec §4).
# Usage: scripts/check-glibc.sh BINARY MAX
set -euo pipefail
[[ $# == 2 && -f $1 ]] || { echo "usage: $0 BINARY MAX" >&2; exit 2; }
need=$(objdump -T "$1" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/^GLIBC_//' | sort -Vu | tail -1)
[[ -n $need ]] || { echo "check-glibc: $1 needs no versioned glibc symbol" >&2; exit 1; }
if [[ $(printf '%s\n%s\n' "$need" "$2" | sort -V | tail -1) != "$2" ]]; then
    echo "check-glibc: $1 needs glibc $need, above $2" >&2; exit 1
fi
echo "check-glibc: $1 needs glibc $need (max $2)"

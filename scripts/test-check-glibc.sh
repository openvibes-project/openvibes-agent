#!/usr/bin/env bash
# Tests scripts/check-glibc.sh against this machine's bash: it needs some
# glibc 2.x, so a floor of 2.0 must fail and 99.0 must pass.
set -euo pipefail
cd "$(dirname "$0")/.."
bin=$(command -v bash)
bash scripts/check-glibc.sh "$bin" 99.0 >/dev/null || { echo "FAIL: 99.0 refused"; exit 1; }
if out=$(bash scripts/check-glibc.sh "$bin" 2.0 2>&1); then echo "FAIL: 2.0 accepted"; exit 1; fi
grep -q 'above 2.0' <<<"$out" || { echo "FAIL: message: $out"; exit 1; }
if bash scripts/check-glibc.sh /nonexistent 2.34 2>/dev/null; then echo "FAIL: missing file accepted"; exit 1; fi
echo "test-check-glibc: ok"

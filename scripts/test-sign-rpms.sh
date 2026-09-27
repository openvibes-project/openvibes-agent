#!/usr/bin/env bash
# Tests scripts/sign-rpms.sh with a throwaway key: signed packages pass,
# an unsigned package or one signed by another key fails the whole run.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export GNUPGHOME=$T/gnupg; mkdir -m 0700 "$GNUPGHOME"
key() { # NAME → armoured secret key on stdout, public key in $T/NAME.pub
    gpg --batch --pinentry-mode loopback --passphrase pw --quick-gen-key "$1 <$1@example.invalid>" rsa2048 sign 1d
    fpr=$(gpg --with-colons --list-secret-keys "$1@example.invalid" | awk -F: '$1=="fpr"{print $10; exit}')
    gpg --armor --export "$fpr" > "$T/$1.pub"
    gpg --batch --pinentry-mode loopback --passphrase pw --armor --export-secret-keys "$fpr"
}
package() { # NAME DIR → a tiny noarch RPM in DIR
    mkdir -p "$T/build/$1"
    printf 'Name: %s\nVersion: 1\nRelease: 1\nSummary: test\nLicense: MIT\nBuildArch: noarch\n%%description\ntest\n%%files\n' "$1" > "$T/build/$1/$1.spec"
    rpmbuild -bb --define "_topdir $T/build/$1" "$T/build/$1/$1.spec" >/dev/null 2>&1
    mkdir -p "$2"; cp "$T/build/$1"/RPMS/noarch/*.rpm "$2/"
}
GOOD=$(key good); OTHER=$(key other); rm -rf "$GNUPGHOME"/*
package one "$T/ok"; package two "$T/ok"
RPM_SIGNING_KEY=$GOOD RPM_SIGNING_PASSPHRASE=pw bash "$ROOT/scripts/sign-rpms.sh" "$T/ok" "$T/good.pub" ||
    { echo "FAIL: signed packages were refused"; exit 1; }
package three "$T/other"
RPM_SIGNING_KEY=$OTHER RPM_SIGNING_PASSPHRASE=pw bash "$ROOT/scripts/sign-rpms.sh" "$T/other" "$T/other.pub"
cp "$T/ok"/*.rpm "$T/other/"   # a mix of keys, checked against "good"
if bash "$ROOT/scripts/sign-rpms.sh" --check-only "$T/other" "$T/good.pub" 2>/dev/null; then
    echo "FAIL: a package signed by another key passed"; exit 1
fi
package four "$T/unsigned"
if bash "$ROOT/scripts/sign-rpms.sh" --check-only "$T/unsigned" "$T/good.pub" 2>/dev/null; then
    echo "FAIL: an unsigned package passed"; exit 1
fi
echo "test-sign-rpms: all checks passed"

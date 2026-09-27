#!/usr/bin/env bash
# Signs every DIR/*.rpm with the OpenVIBES package key and checks each
# against PUBKEY in a clean rpm database; exits non-zero unless all pass.
# Usage: sign-rpms.sh [--check-only] DIR PUBKEY
# Env (not with --check-only): RPM_SIGNING_KEY (armoured secret key),
# RPM_SIGNING_PASSPHRASE. The keyring and passphrase file live in a temp
# directory removed on exit.
set -euo pipefail
check_only=0
[[ ${1:-} == --check-only ]] && { check_only=1; shift; }
[[ $# == 2 ]] || { echo "usage: $0 [--check-only] DIR PUBKEY" >&2; exit 2; }
dir=$1 pubkey=$2
shopt -s nullglob; rpms=("$dir"/*.rpm); shopt -u nullglob
((${#rpms[@]})) || { echo "sign-rpms: no packages in $dir" >&2; exit 1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
if ((!check_only)); then
    export GNUPGHOME=$T/gnupg; mkdir -m 0700 "$GNUPGHOME"
    printf '%s' "$RPM_SIGNING_KEY" | gpg --batch --quiet --import
    fpr=$(gpg --with-colons --list-secret-keys | awk -F: '$1=="fpr"{print $10; exit}')
    printf '%s' "$RPM_SIGNING_PASSPHRASE" > "$T/pass"; chmod 0600 "$T/pass"
    rpmsign --addsign \
        --define "_gpg_name $fpr" \
        --define "_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback --passphrase-file $T/pass" \
        "${rpms[@]}" >/dev/null
fi
rpm --dbpath "$T/rpmdb" --initdb
rpm --dbpath "$T/rpmdb" --import "$pubkey"
status=0
for package in "${rpms[@]}"; do
    out=$(rpm --dbpath "$T/rpmdb" -K "$package" 2>&1) || true
    if [[ $out != *"digests signatures OK"* ]]; then
        echo "sign-rpms: $package: $out" >&2; status=1
    fi
done
exit $status

#!/usr/bin/env bash
# Builds target/msi/openvibes-agent-<version>-x64.msi around a Windows
# release binary (openvibes-agent.exe, built on Windows with the MSVC target).
# Usage: scripts/build-msi.sh EXE [VERSION]. Needs msitools (wixl, msibuild),
# e.g. in registry.fedoraproject.org/fedora:44: dnf install msitools.
set -euo pipefail
# Checks read each table into a string first: `msiinfo | grep -q` fails
# under pipefail when grep exits early and msiinfo gets SIGPIPE.
cd "$(dirname "$0")/.."
[[ $# -ge 1 && -f $1 ]] || { echo "usage: $0 EXE [VERSION]" >&2; exit 2; }
exe=$(realpath "$1")
# A fresh Windows has no Visual C++ redistributable (#127, .cargo/config.toml).
if grep -qai 'vcruntime140' "$exe"; then
    echo "build-msi: $exe imports VCRUNTIME140.dll; build it with +crt-static" >&2
    exit 1
fi
version=${2:-$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)}
W=target/msi/src
rm -rf "$W"; mkdir -p "$W"
cp "$exe" "$W/openvibes-agent.exe"
cp LICENSE "$W/LICENSE.txt"
cp NOTICE "$W/NOTICE.txt"
msi=target/msi/openvibes-agent-$version-x64.msi
(cd "$W" && wixl -a x64 -D Version="$version" -o "../$(basename "$msi")" ../../../packaging/windows/openvibes-agent.wxs)
# The data directory's ACL (wixl has no PermissionEx).
msibuild "$msi" -i packaging/windows/MsiLockPermissionsEx.idt
# A failed upgrade must restore the old version: remove it inside the
# transaction (wixl puts it at 1401, before InstallInitialize 1500).
msibuild "$msi" -q "UPDATE InstallExecuteSequence SET Sequence = 1501 WHERE Action = 'RemoveExistingProducts'"
grep -q $'^RemoveExistingProducts\t\t1501' <<<"$(msiinfo export "$msi" InstallExecuteSequence)" \
  || { echo "build-msi: RemoveExistingProducts is not inside the transaction" >&2; exit 1; }
# msidbCustomActionTypeHideTarget (8192) for the setup action, whose command
# line carries the enrollment token; wixl has no HideTarget.
msibuild "$msi" -q "UPDATE CustomAction SET Type = 11282 WHERE Action = 'WindowsSetup'"
# The install properties pass to the elevated install (wixl ignores Secure).
msibuild "$msi" -q "UPDATE Property SET Value = 'PLATFORM_URL;PLATFORM_CA;PLATFORM_CA_SHA256;ENROLLMENT_TOKEN;WIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTED' WHERE Property = 'SecureCustomProperties'"
grep -q $'^SecureCustomProperties\tPLATFORM_URL;' <<<"$(msiinfo export "$msi" Property)" \
  || { echo "build-msi: the install properties are not secure" >&2; exit 1; }
grep -q $'^WindowsSetup\t11282\t' <<<"$(msiinfo export "$msi" CustomAction)" \
  || { echo "build-msi: the setup action is not hidden" >&2; exit 1; }
echo "$msi"

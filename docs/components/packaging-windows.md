# packaging-windows (MSI, preview)

## Purpose

Installs `openvibes-agent` on Windows (x86_64) as an automatic service,
running as its own virtual account `NT SERVICE\openvibes-agent` (no
password, no administrator rights), with its configuration, token, identity
and queue in a directory only SYSTEM, Administrators and that account can
open (#118, Windows preview #116). The MSI is **unsigned** in the preview
(ruling #115): Windows SmartScreen warns before it runs.

## Interfaces

Install, as an administrator (or through Intune, Group Policy or any tool
that runs `msiexec`):

```text
msiexec /i openvibes-agent-<version>-x64.msi /qn PLATFORM_URL=https://<platform host> PLATFORM_CA=C:\path\root.crt ENROLLMENT_TOKEN=<token>
```

| Property | Meaning |
|---|---|
| `PLATFORM_URL` | The platform, as `platform_url` on Linux. Without it the agent is local-only, or an upgrade keeps the existing `agent.toml` |
| `PLATFORM_CA` | Path to the platform's `/etc/openvibes/pki/root.crt`, copied in; required with `PLATFORM_URL` |
| `ENROLLMENT_TOKEN` | The enrollment token; kept out of the installer log (`MsiHiddenProperties`, and the setup action's command line is hidden) |

| Path | What |
|---|---|
| `C:\Program Files\OpenVIBES\Agent\openvibes-agent.exe` | The agent; `LICENSE.txt` and `NOTICE.txt` beside it |
| `C:\ProgramData\OpenVIBES\Agent\agent.toml` | Written by the installer from the properties |
| `C:\ProgramData\OpenVIBES\Agent\platform-ca.crt`, `token` | Copied and written from `PLATFORM_CA` and `ENROLLMENT_TOKEN` |
| `C:\ProgramData\OpenVIBES\Agent\state\` | The identity and queue databases, created by the agent |
| Event Log, Application, source `openvibes-agent` | The agent's log lines (the MSI registers the source, with the exe as its message file: `build.rs` links the message table into it) |

The service runs `openvibes-agent.exe service "C:\ProgramData\OpenVIBES\Agent\agent.toml"`.

**Never a reboot** (#125): install, upgrade and uninstall finish with the
agent running (or gone) and exit code 0. The service stops within 10
seconds of Stop, even with a request in flight (`STOP_GRACE` in
`winsvc.rs`; Windows Installer waits about 30 seconds), so its exe is never
locked when the MSI replaces it, and the MSI sets `REBOOT=ReallySuppress`,
so `msiexec` never restarts the host even if some other program holds a
file.
Unlike the Linux packages, the MSI starts the service, so a host with the
three properties enrolls with no further step.

## Configuration

`agent.toml` is the agent's usual file (see `openvibes-agent.md`), with
`collectors = ["processes", "packages"]`: process names and the programs
Apps and Features lists (ports and services are Linux-only for now). To
change the platform or the token, install the same or a newer MSI again
with the new properties; an install without `PLATFORM_URL` keeps the file
as it is, edits included.

## How it is built

`scripts/build-msi.sh EXE [VERSION]` (needs msitools: `wixl`, `msibuild`;
Fedora package `msitools`) builds `target/msi/openvibes-agent-<version>-x64.msi`
from `packaging/windows/openvibes-agent.wxs` around a release binary built
on Windows with the MSVC target and the C runtime linked in
(`.cargo/config.toml`, `+crt-static`; the script refuses an exe that
imports `VCRUNTIME140.dll`, which a fresh Windows does not have). `wixl` lacks a few Windows Installer
features, so the script adds them with `msibuild` and checks each:

- the data directory's ACL, `packaging/windows/MsiLockPermissionsEx.idt`
  (Windows Installer 5.0). `C:\ProgramData\OpenVIBES` and `...\Agent` are
  owned by SYSTEM and protected (no inherited entries): SYSTEM and
  Administrators full control, and on `Agent` the service account
  (`S-1-5-80-56041272-1737313161-3215431290-2488084823-2727013164`, the SID
  of `NT SERVICE\openvibes-agent`) modify. Setting the owner matters:
  `C:\ProgramData` lets any user create folders, so a folder made before the
  install must not stay in that user's hands;
- `SecureCustomProperties` for the three properties (`wixl` ignores
  `Secure="yes"`);
- the hidden-target flag on the setup action, whose command line carries
  the token;
- `RemoveExistingProducts` inside the install transaction, so a failed
  upgrade puts the old version back instead of leaving none.

WiX itself was not used: WiX 6 and later need the Open Source Maintenance
Fee EULA accepted, and WiX 5 is no longer current; msitools is LGPL and
builds the MSI in the same Fedora container as the RPM.

## Failure behaviour

- The installer runs `openvibes-agent.exe windows-setup` as SYSTEM
  (`src/winsetup.rs`) before the service is installed. It checks every
  property first (an `https://` URL, a PEM CA, a valid token, no control
  characters) and writes nothing when one is wrong; it then writes the files
  and loads `agent.toml` with the agent's own config check. Any failure
  exits non-zero and Windows Installer rolls the install (or the upgrade)
  back. The reason is in the Event Log (source `openvibes-agent`).
- `windows-setup` runs on a first install, or when an administrator
  installs, upgrades or repairs; a repair a standard user starts
  (`msiexec /fa`, which Windows Installer runs elevated) skips it, so the
  properties cannot point the agent at another platform or CA.
- `windows-setup` and `windows-remove-data` only accept a path ending in
  `OpenVIBES\Agent`, so a wrong property can never point them elsewhere.
- **Uninstall leaves nothing behind**: the service, the program folder,
  the Event Log source, and the whole `C:\ProgramData\OpenVIBES\Agent`
  (configuration, token, identity, queue; `windows-remove-data`). The
  platform still lists the host until it is removed there. An upgrade
  (`UPGRADINGPRODUCTCODE` set) keeps the data directory, so the identity
  and queued findings survive.
- The agent does not check the directory's ACL itself (std cannot read
  ACLs; see `openvibes-storage` `create_private_dir`); the MSI is the
  only supported installer on Windows.

## How to test

`scripts/test-msi.ps1 -Old <older.msi> -New <new.msi>` (Windows PowerShell
5.1, as an administrator, on a host without the agent) installs the older
MSI local-only, checks the service (running, automatic, its virtual
account), the ACL (owner SYSTEM, protected, no other entries), the Event
Log source and the `started` line; then tries a platform without its CA
(must fail and leave the install as it was); then upgrades with a
platform, a test CA and a token and checks `agent.toml`, the token file,
that the token is not in any installer log, that the state files survived
and that one entry is left in Apps; then uninstalls and checks nothing is
left. CI job chain `msi-exe` → `msi-build` → `msi-test` runs it with a
0.0.1 build as the older MSI; the lab runs it on its Windows Server VM,
where enrolling against a real platform is checked too.

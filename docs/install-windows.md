# Installing the agent on Windows (preview)

The Windows agent is a **preview** in 0.3.0: it enrolls, reports its
processes and installed programs, runs the rules that need only those,
and never needs a reboot. What it does not do yet is listed under
[Not in the preview](#not-in-the-preview). How the MSI is built and what
it installs: [components/packaging-windows.md](components/packaging-windows.md).

## Requirements

- **Windows 10 22H2 or 11, or Windows Server 2016, 2019, 2022 or 2025**,
  64-bit (x64). Tested on Windows Server 2022 (CI, every change) and
  Windows Server 2025 (the lab). Windows 7, 8 and 8.1 are not supported.
- An administrator account.
- The host reaches the platform on TCP 18423 (agents) and 18424 (rules).
- Nothing else: no Visual C++ runtime, no .NET, no PowerShell modules.

## 1. Download and check the MSI

From the agent's GitHub release (`openvibes-agent-X.Y.Z-x64.msi`), with
`SHA256SUMS` and the `.msi.sig` beside it. On any machine with the tools:

```sh
sha256sum -c --ignore-missing SHA256SUMS
gpg --import openvibes.gpg      # the website's package key
gpg --verify openvibes-agent-X.Y.Z-x64.msi.sig openvibes-agent-X.Y.Z-x64.msi
```

The preview MSI has **no Authenticode signature**, so Windows SmartScreen
warns when it is opened by hand ("Windows protected your PC": **More info**,
then **Run anyway**). `msiexec` from a script or a deployment tool shows no
such prompt. A signed MSI is planned.

## 2. Get the three values from the platform

| Value | Where |
|---|---|
| Platform address | the host name agents use, e.g. `platform.example.com` |
| Enrollment token | the console, **Enrollment**, or `openvibes-admin agent command` on the platform |
| The platform's CA | `/etc/openvibes/pki/root.crt` on the platform; copy it to the Windows host, e.g. `C:\Temp\root.crt` |

Check the CA you copied against the fingerprint in the platform's install
line (`--ca-sha256`, shown with colons: compare the hex digits), in
PowerShell:

```powershell
(Get-FileHash -Algorithm SHA256 -InputStream ([IO.MemoryStream]::new([Convert]::FromBase64String(((Get-Content C:\Temp\root.crt) -notmatch '-----') -join '')))).Hash
```

## 3. Install

As an administrator (or from Intune, Group Policy or any tool that runs
`msiexec`):

```powershell
msiexec /i openvibes-agent-X.Y.Z-x64.msi /qn PLATFORM_URL=https://platform.example.com PLATFORM_CA=C:\Temp\root.crt ENROLLMENT_TOKEN=<token>
```

The service starts at once and enrolls within a minute; the host appears
in the console under **Hosts**. The token never reaches the installer's
log. A wrong value (an `http://` address, a file that is not a
certificate, an invalid token) fails the install and leaves nothing
behind; the reason is in the Event Log.

Installed without `PLATFORM_URL` (for example by double-clicking the MSI),
the agent runs **local-only**: it scans, but sends nothing until it is
installed again with the three values.

## Upgrading, changing the platform, uninstalling

- **Upgrade:** install the newer MSI the same way; without the three values
  it keeps the configuration, the identity and the queued findings.
- **Another platform or token:** install the same or a newer MSI again with
  the new values.
- **Uninstall:** Settings › Apps, or `msiexec /x openvibes-agent-X.Y.Z-x64.msi /qn`.
  It removes everything: the program, the service, its configuration,
  identity and queue (`C:\ProgramData\OpenVIBES\Agent`) and its Event Log
  source. Remove the host in the console as well.
- **Never a reboot:** install, upgrade and uninstall finish with the agent
  running (or gone); the MSI never restarts the host, and the service stops
  within seconds when Windows Installer asks.

## Where to look

- **Event Viewer**, Windows Logs › Application, source `openvibes-agent`:
  every agent line (started, enrolled, scans, errors).
- **Services:** `OpenVIBES Agent`, running as its own account
  `NT SERVICE\openvibes-agent` with no administrator rights.
- `C:\ProgramData\OpenVIBES\Agent`: readable only by SYSTEM, Administrators
  and the service.

## Not in the preview

- **Vulnerabilities:** no vulnerability feed covers Windows yet; the
  console says so on a Windows host instead of showing 0.
- **Listening ports and services:** collected on Linux only.
- **Threat alarms:** the Linux agent watches program starts (eBPF or
  audit); Windows (ETW) is planned.
- **Windows rules:** the project's rule sets are written for Linux; on a
  Windows host their rules show as unavailable, never as passed.
- **Programs installed for one user only** are not listed (the service
  cannot read other users' registry hives).
- **Authenticode signature:** see step 1.
- **No CA download:** the MSI takes the CA as a file; it does not yet fetch
  it from the platform and check its fingerprint as the Linux install line
  does.

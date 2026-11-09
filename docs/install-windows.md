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

## 2. Install from the console

In the console, **Settings › Enrollment › Add a host**, Windows row:

1. **Agent MSI** opens the latest agent release; save the MSI.
2. **Download CA** saves the platform's CA as `openvibes-platform-ca.crt`;
   save it in the **same folder** as the MSI.
3. **Copy Windows install** copies the install line. Open PowerShell as
   administrator in that folder and paste it:

```powershell
msiexec /i (Get-Item .\openvibes-agent-*-x64.msi).FullName /qn PLATFORM_URL=https://platform.example.com PLATFORM_CA_SHA256=AB:CD:… ENROLLMENT_TOKEN=<token> | Out-Null
```

The MSI takes `openvibes-platform-ca.crt` from its own folder only if the
file matches the fingerprint in the line (`PLATFORM_CA_SHA256`, as the Linux
install line's `--ca-sha256`), so a CA someone else put there is refused.
The line has no paths, so a folder with spaces in its name works.
`openvibes-admin agent command` on the platform prints the same line.

### Without the console, or for a deployment tool

The properties, all on the `msiexec` command line:

| Property | Value |
|---|---|
| `PLATFORM_URL` | `https://` and the host name agents use, e.g. `https://platform.example.com` |
| `PLATFORM_CA` | a path to the platform's `/etc/openvibes/pki/root.crt`; or leave it out and put the file beside the MSI as `openvibes-platform-ca.crt` (then `PLATFORM_CA_SHA256` is required) |
| `PLATFORM_CA_SHA256` | the CA's fingerprint, `--ca-sha256` in the platform's install line; recommended always, required for the file beside the MSI |
| `ENROLLMENT_TOKEN` | the console, **Enrollment**, or `openvibes-admin agent command` |

```powershell
msiexec /i C:\Deploy\openvibes-agent-X.Y.Z-x64.msi /qn PLATFORM_URL=https://platform.example.com PLATFORM_CA=C:\Deploy\root.crt PLATFORM_CA_SHA256=AB:CD:… ENROLLMENT_TOKEN=<token>
```

(A path with a space in it breaks `msiexec` when PowerShell quotes the
`NAME=value`; use a path without spaces, or the file beside the MSI.) If
the platform's rule distribution port is not 18424, the console offers no
Windows line: the MSI has no setting for that port yet.

### After the install

The service starts at once and enrolls within a minute; the host appears
in the console under **Hosts**. The token never reaches the installer's
log. A wrong value (an `http://` address, a file that is not a
certificate, a CA that does not match the fingerprint, an invalid token)
fails the install and leaves nothing behind; the reason is in the Event
Log.

Installed without `PLATFORM_URL` (for example by double-clicking the MSI),
the agent runs **local-only**: it scans, but sends nothing until it is
installed again with the platform's values.

## Upgrading, changing the platform, uninstalling

- **Upgrade:** install the newer MSI the same way; without the platform values
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
- **The CA comes as a file:** the console's download or a copy of
  `root.crt`; the MSI does not fetch it from the platform itself (that
  would need a TLS check bypass, which the agent's security rules forbid).
- **Rule distribution on another port than 18424** has no MSI setting yet.

# Installs, upgrades and uninstalls the agent MSI on a Windows host and
# checks each step. As an administrator, on a host without the agent:
#   powershell -ExecutionPolicy Bypass -File scripts\test-msi.ps1 -Old <older.msi> -New <new.msi>
# CI job "Windows MSI"; the lab runs it on its Windows Server VM.
# Windows PowerShell 5.1 (Get-EventLog).
param(
    [Parameter(Mandatory = $true)][string]$Old,
    [Parameter(Mandatory = $true)][string]$New
)
$ErrorActionPreference = 'Stop'
$Data = Join-Path $env:ProgramData 'OpenVIBES\Agent'
$Program = Join-Path ${env:ProgramFiles} 'OpenVIBES\Agent'
$EventKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\openvibes-agent'
$Token = 'test-token-not-in-the-log-' + [guid]::NewGuid()
$Work = Join-Path $env:TEMP ('ov-msi-' + [guid]::NewGuid())
New-Item -ItemType Directory $Work | Out-Null

function Step($text) { Write-Host "== $text" }
function Fail($text) { throw "test-msi: $text" }

function Msi([string[]]$arguments, [string]$log) {
    $process = Start-Process msiexec.exe -ArgumentList ($arguments + @('/qn', '/l*v', "`"$log`"")) -Wait -PassThru
    return $process.ExitCode
}

function Started-Line($after) {
    foreach ($i in 1..60) {
        $line = Get-EventLog -LogName Application -Source openvibes-agent -After $after -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -like '*started; collectors: *' } | Select-Object -First 1
        if ($line) { return $line }
        Start-Sleep -Seconds 1
    }
    Fail 'no "started" line in the Event Log (or Event Viewer cannot show its text)'
}

function Check-Installed {
    $service = Get-CimInstance Win32_Service -Filter "Name='openvibes-agent'"
    if (-not $service) { Fail 'the service is not installed' }
    if ($service.State -ne 'Running') { Fail "the service is $($service.State)" }
    if ($service.StartName -ne 'NT SERVICE\openvibes-agent') { Fail "the service runs as $($service.StartName)" }
    if ($service.StartMode -ne 'Auto') { Fail "the service starts $($service.StartMode)" }
    $acl = Get-Acl $Data
    if ($acl.Sddl -notmatch '^O:SY' -or $acl.Sddl -notmatch 'D:PAI') { Fail "data directory ACL: $($acl.Sddl)" }
    $others = $acl.Access | Where-Object {
        $_.IdentityReference.Value -notin @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'NT SERVICE\openvibes-agent')
    }
    if ($others) { Fail "the data directory also grants: $($others.IdentityReference -join ', ')" }
    if (-not (Test-Path (Join-Path $Data 'agent.toml'))) { Fail 'no agent.toml' }
    if (-not (Test-Path $EventKey)) { Fail 'the Event Log source is not registered' }
}

if (Get-Service openvibes-agent -ErrorAction SilentlyContinue) { Fail 'the agent is already installed' }

Step 'install the older MSI, local-only'
$t = Get-Date
$code = Msi @('/i', "`"$Old`"") "$Work\install.log"
if ($code -ne 0) { Fail "install exit code $code" }
Check-Installed
Started-Line $t | Out-Null
$state = Get-ChildItem (Join-Path $Data 'state') -File
if (-not $state) { Fail 'the agent created no state' }
$before = $state | ForEach-Object { "$($_.Name) $($_.CreationTimeUtc.Ticks)" }

Step 'a platform without its CA fails and rolls back, leaving the install as it was'
$code = Msi @('/i', "`"$New`"", 'PLATFORM_URL=https://platform.invalid') "$Work\bad.log"
if ($code -eq 0) { Fail 'PLATFORM_URL without PLATFORM_CA was accepted' }
Check-Installed

Step 'upgrade to the new MSI with a platform, CA and token'
$cert = New-SelfSignedCertificate -DnsName 'platform.invalid' -CertStoreLocation Cert:\CurrentUser\My
$ca = "$Work\root.crt"
"-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n" |
    Set-Content -Encoding ascii $ca
Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)"
$t = Get-Date
$code = Msi @('/i', "`"$New`"", 'PLATFORM_URL=https://platform.invalid', "PLATFORM_CA=`"$ca`"", "ENROLLMENT_TOKEN=$Token") "$Work\upgrade.log"
if ($code -ne 0) { Fail "upgrade exit code $code" }
Check-Installed
Started-Line $t | Out-Null
$config = Get-Content -Raw (Join-Path $Data 'agent.toml')
if ($config -notmatch 'platform_url = "https://platform.invalid"') { Fail "agent.toml: $config" }
if ((Get-Content -Raw (Join-Path $Data 'token')).Trim() -ne $Token) { Fail 'the token file is wrong' }
if (Select-String -Path "$Work\*.log" -Pattern $Token -SimpleMatch -Quiet) { Fail 'the token is in the installer log' }
$after = Get-ChildItem (Join-Path $Data 'state') -File | ForEach-Object { "$($_.Name) $($_.CreationTimeUtc.Ticks)" }
foreach ($file in $before) { if ($file -notin $after) { Fail "the upgrade replaced state file $file" } }
$entries = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' |
    Where-Object { $_.GetValue('DisplayName') -eq 'OpenVIBES Agent' }
if (@($entries).Count -ne 1) { Fail "$(@($entries).Count) OpenVIBES Agent entries in Apps" }

Step 'uninstall leaves nothing behind'
$code = Msi @('/x', "`"$New`"") "$Work\uninstall.log"
if ($code -ne 0) { Fail "uninstall exit code $code" }
if (Get-Service openvibes-agent -ErrorAction SilentlyContinue) { Fail 'the service is still there' }
foreach ($path in @((Split-Path $Data), (Split-Path $Program), $EventKey)) {
    if (Test-Path $path) { Fail "left behind: $path" }
}

Remove-Item -Recurse -Force $Work
Write-Host 'test-msi: all checks passed'

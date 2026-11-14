# Stage 19e-3 (SPEC 19e 5.3 item 8, Dopolnenie 1 p.2): smoke test of the Windows INSTALLER (the built file, not a rebuild).
#   pwsh -NoProfile -File scripts/release/smoke-installer-windows.ps1 <release-dir> [<log-dir>]
# <release-dir> holds chervo-release.txt and the release files (artifact release-files of `assemble`).
# First step: the SHA-256 of the installer must equal the manifest line, otherwise the installer is NOT run.
# Then: silent install for the current user, checks of the install directory, shortcut, uninstall key (HKCU yes,
# HKLM no in both views, no Program Files), the Inno log line about the mode without administrator, the installed
# file against the manifest line of the single .exe, --render-check, a sentinel in the DATA directory, silent
# uninstall (waits until the directory and the key disappear), the sentinel is still there byte for byte.
# CI cannot prove "no UAC for an ordinary user": the runner account is an administrator (SPEC 9.1). Logs go to
# <log-dir> (the workflow uploads them as installer-logs-windows; they never enter the release).
param(
    [Parameter(Mandatory = $true)][string]$Rel,
    [string]$LogDir = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:failed = $false
function Say([string]$line) {
    Write-Host $line
    if ($env:GITHUB_STEP_SUMMARY) { Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $line -Encoding utf8 }
}
function Ok([string]$m) { Say "- ok: $m" }
function Bad([string]$m) { Say "- FAIL: $m"; $script:failed = $true }
function Check([bool]$cond, [string]$m) { if ($cond) { Ok $m } else { Bad $m } }
function Done() {
    Say ''
    if ($script:failed) { exit 1 } else { exit 0 }
}
function Sha([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }

$manifest = Join-Path $Rel 'chervo-release.txt'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { Write-Error "no manifest: $manifest"; exit 1 }
$lines = Get-Content -LiteralPath $manifest
$verLine = @($lines | Where-Object { $_ -match '^version ' })
if ($verLine.Count -ne 1) { Write-Error 'the manifest must have exactly one version line'; exit 1 }
$ver = ($verLine[0] -split ' ')[1].Trim()
if ($ver -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { Write-Error "bad version in the manifest: $ver"; exit 1 }
$setupName = "chervotochina-$ver-windows-x86_64-setup.exe"
$exeName = "chervotochina-$ver-windows-x86_64.exe"
function ManifestSha([string]$name) {
    $m = @($lines | Where-Object { $_ -match '^artifact windows-x86_64 ' } | Where-Object { ($_ -split ' ')[4].Trim() -eq $name })
    if ($m.Count -ne 1) { return '' }
    return ($m[0] -split ' ')[2].Trim().ToLowerInvariant()
}
$setupWant = ManifestSha $setupName
$exeWant = ManifestSha $exeName
$setup = Join-Path $Rel $setupName
Say "### installer-smoke: windows-x86_64 (file ``$setupName``)"
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) { Write-Error "no installer: $setup"; exit 1 }
$setupHave = Sha $setup
Say "- manifest sha256: ``$setupWant``"
Say "- file sha256:     ``$setupHave``"
if ($setupWant -eq '' -or $setupWant -ne $setupHave -or $exeWant -eq '') {
    Bad 'the installer SHA-256 differs from the manifest line (or a line is missing); the installer is NOT run'
    Done
}
Ok 'SHA-256 of the installer equals the manifest line'

if (-not $LogDir) { $LogDir = Join-Path ($(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() })) 'installer-logs' }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$log1 = Join-Path $LogDir 'install.log'
$log2 = Join-Path $LogDir 'uninstall.log'

$appId = (Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\packaging\windows\APPID') -Raw).Trim()
if ($appId -notmatch '^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$') { Write-Error "bad APPID: $appId"; exit 1 }
$uninstSub = "Software\Microsoft\Windows\CurrentVersion\Uninstall\{$appId}_is1"
$hkcuKey = "HKCU:\$uninstSub"
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\Chervotochina'
$dataDir = Join-Path $env:LOCALAPPDATA 'Chervotochina'
$lnk = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Червоточина.lnk'
$pf = @((Join-Path $env:ProgramFiles 'Chervotochina'))
if (${env:ProgramFiles(x86)}) { $pf += (Join-Path ${env:ProgramFiles(x86)} 'Chervotochina') }
function HklmHasKey([string]$view) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
    try { $k = $base.OpenSubKey($uninstSub); if ($k) { $k.Dispose(); return $true } else { return $false } } finally { $base.Dispose() }
}

# 1. before the installation
Check (-not (Test-Path -LiteralPath $hkcuKey)) 'before: no uninstall key in HKCU'
Check (-not (Test-Path -LiteralPath $installDir)) 'before: no install directory'
Check (-not (Test-Path -LiteralPath $lnk)) 'before: no Start menu shortcut'
if ($script:failed) { Done }

# 2. silent installation
$p = Start-Process -FilePath $setup -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', "/LOG=`"$log1`"") -Wait -PassThru
Say "- installer exit code: $($p.ExitCode)"
Check ($p.ExitCode -eq 0) 'the installer returned 0'

# 3. install directory: exactly four files; the installed .exe equals the single signed .exe
$names = @()
if (Test-Path -LiteralPath $installDir) { $names = @(Get-ChildItem -LiteralPath $installDir -Force | ForEach-Object { $_.Name.ToLowerInvariant() } | Sort-Object) }
$wantNames = @('chervotochina.exe', 'chervotochina.ico', 'unins000.dat', 'unins000.exe')
Check (($names -join ',') -eq ($wantNames -join ',')) "install directory holds exactly: $($wantNames -join ', ') (found: $($names -join ', '))"
$installedExe = Join-Path $installDir 'chervotochina.exe'
if (Test-Path -LiteralPath $installedExe) {
    $h = Sha $installedExe
    Say "- installed chervotochina.exe sha256: ``$h`` (manifest line of the single .exe: ``$exeWant``)"
    Check ($h -eq $exeWant) 'the installed file equals the manifest line of the single .exe byte for byte'
}

# 4. shortcut
if (Test-Path -LiteralPath $lnk) {
    $target = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk).TargetPath
    Check ($target -ieq $installedExe) "shortcut target is the installed file ($target)"
} else { Bad "no shortcut $lnk" }

# 5. uninstall key in HKCU
if (Test-Path -LiteralPath $hkcuKey) {
    $k = Get-ItemProperty -LiteralPath $hkcuKey
    Check ($k.DisplayVersion -eq $ver) "HKCU uninstall key: DisplayVersion = $($k.DisplayVersion)"
    Check ($k.InstallLocation.TrimEnd('\') -ieq $installDir) "HKCU uninstall key: InstallLocation = $($k.InstallLocation)"
    Check ($k.QuietUninstallString -like '*unins000.exe*') 'HKCU uninstall key: QuietUninstallString names unins000.exe'
} else { Bad 'no uninstall key in HKCU' }

# 6. nothing for all users
Check (-not (HklmHasKey 'Registry64')) 'no uninstall key in HKLM (64-bit view)'
Check (-not (HklmHasKey 'Registry32')) 'no uninstall key in HKLM (32-bit view)'
foreach ($d in $pf) { Check (-not (Test-Path -LiteralPath $d)) "no $d" }

# 7. the Inno log
if (Test-Path -LiteralPath $log1) {
    $logText = Get-Content -LiteralPath $log1 -Raw
    Check ($logText -match 'Administrative install mode: No') 'the install log says: Administrative install mode: No (no administrator mode)'
    Say '<details><summary>install log</summary>'; Say ''; Say '```'; Say $logText; Say '```'; Say '</details>'
} else { Bad "no install log $log1" }

# 8. the installed program starts
if (Test-Path -LiteralPath $installedExe) {
    $r = Start-Process -FilePath $installedExe -ArgumentList '--render-check' -Wait -PassThru
    Say "- installed file --render-check exit code: $($r.ExitCode)"
    Check ($r.ExitCode -eq 0) '--render-check returned 0'
}

# 9. a sentinel in the user data directory (another directory than the install directory)
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$sentinel = Join-Path $dataDir 'sentinel-19e'
$bytes = New-Object byte[] 64
(New-Object Random).NextBytes($bytes)
[IO.File]::WriteAllBytes($sentinel, $bytes)
$sentinelSha = Sha $sentinel

# 10. silent uninstallation (the uninstaller may return before it has finished: wait for the result)
$unins = Join-Path $installDir 'unins000.exe'
if (Test-Path -LiteralPath $unins) {
    $u = Start-Process -FilePath $unins -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$log2`"") -Wait -PassThru
    Say "- uninstaller exit code: $($u.ExitCode)"
    Check ($u.ExitCode -eq 0) 'the uninstaller returned 0'
    $deadline = (Get-Date).AddSeconds(60)
    while (((Test-Path -LiteralPath $installDir) -or (Test-Path -LiteralPath $hkcuKey)) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
} else { Bad 'no unins000.exe to run' }

# 11. after the uninstallation
Check (-not (Test-Path -LiteralPath $installDir)) 'after: no install directory'
Check (-not (Test-Path -LiteralPath $lnk)) 'after: no shortcut'
Check (-not (Test-Path -LiteralPath $hkcuKey)) 'after: no uninstall key'
if (Test-Path -LiteralPath $sentinel) {
    Check ((Sha $sentinel) -eq $sentinelSha) 'after: the user data sentinel is in place, same bytes'
} else { Bad 'after: the user data sentinel is GONE' }
if (Test-Path -LiteralPath $log2) {
    Say '<details><summary>uninstall log</summary>'; Say ''; Say '```'; Say (Get-Content -LiteralPath $log2 -Raw); Say '```'; Say '</details>'
} else { Bad "no uninstall log $log2" }
Remove-Item -LiteralPath $sentinel -Force -ErrorAction SilentlyContinue

# 12. the logs are in $LogDir for the artifact installer-logs-windows
Say "- logs: $LogDir"
Done

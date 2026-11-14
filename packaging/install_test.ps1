# Installation test for the Sentinel X installer (run from the project root).
#   powershell -ExecutionPolicy Bypass -File packaging\install_test.ps1 -Setup dist\SentinelX-0.9.0-setup.exe
# Installs per-user into a temporary folder, checks the installed program, then uninstalls.
# Uses only harmless test data: the EICAR string is assembled at runtime and deleted afterwards.
param(
    [Parameter(Mandatory = $true)][string]$Setup,
    [string]$SignatureDir = "$env:LOCALAPPDATA\SentinelX\clamav-db"
)
$ErrorActionPreference = "Stop"
$results = [ordered]@{}
function Check($name, [bool]$ok, $detail = "") {
    $results[$name] = if ($ok) { "PASS" } else { "FAIL" }
    Write-Output ("[{0}] {1} {2}" -f $results[$name], $name, $detail)
}

$work = Join-Path $env:TEMP ("sx-install-test-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$dir = Join-Path $work "app"
$home_ = Join-Path $work "home"
New-Item -ItemType Directory -Force $work | Out-Null
$appId = "{6D1C4F2A-8B7E-4E5B-9C31-5F0A2D7E9B44}_is1"
$uninstKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$appId"

$userDesktopLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) "Sentinel X.lnk"
$deskBefore = Test-Path $userDesktopLnk

# 1. silent per-user install
$p = Start-Process -FilePath $Setup -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER",
    "/DIR=`"$dir`"", "/TASKS=`"`"", "/LOG=`"$work\install.log`"" -Wait -PassThru
Check "installer exit code 0" ($p.ExitCode -eq 0) "($($p.ExitCode))"
$exe = Join-Path $dir "SentinelX.exe"
foreach ($f in "SentinelX.exe", "clamav\clamscan.exe", "clamav\clamd.exe", "clamav\freshclam.exe", "clamav\SOURCE.txt",
               "clamav\COPYING.txt", "THIRD_PARTY_NOTICES.txt", "unins000.exe") {
    Check "file $f" (Test-Path (Join-Path $dir $f))
}
Check "uninstall entry (per-user registry)" (Test-Path $uninstKey)
$version = (Get-Item $exe).VersionInfo.ProductVersion
Check "version resource" ($version -ne $null -and $version -ne "") "($version)"

# 2. start and stop the installed program (separate data folder)
$env:SENTINELX_HOME = $home_
$env:QT_QPA_PLATFORM = "offscreen"
$p = Start-Process -FilePath $exe -ArgumentList "--smoke-test", "2000" -Wait -PassThru
Check "installed app starts and exits" ($p.ExitCode -eq 0) "($($p.ExitCode))"
Check "data folder created" (Test-Path (Join-Path $home_ "sentinelx.db"))

# 3. second instance refused while the first runs
$first = Start-Process -FilePath $exe -ArgumentList "--smoke-test", "15000" -PassThru
Start-Sleep -Seconds 5
$second = Start-Process -FilePath $exe -ArgumentList "--smoke-test", "500" -Wait -PassThru
Check "second instance refused" ($second.ExitCode -eq 3) "($($second.ExitCode))"
$first.WaitForExit(60000) | Out-Null
Check "first instance exits normally" ($first.ExitCode -eq 0) "($($first.ExitCode))"

# 4. isolated research worker from the windowed executable
$out = Join-Path $work "worker.json"
$p = Start-Process -FilePath $exe -ArgumentList "--research-worker", "`"$exe`"", "524288000" -Wait -PassThru `
    -RedirectStandardOutput $out -NoNewWindow
$w = Get-Content $out -Raw -Encoding UTF8 | ConvertFrom-Json
Check "research worker (JSON, confined)" ($p.ExitCode -eq 0 -and $w.ok -and $w.confined) "($($w.pe.engine_version))"

# 5. bundled ClamAV detects the EICAR test string (signatures from the existing per-user folder)
if (Test-Path $SignatureDir) {
    $eicarDir = Join-Path $work "eicar"
    New-Item -ItemType Directory -Force $eicarDir | Out-Null
    $e = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    [IO.File]::WriteAllText((Join-Path $eicarDir "eicar.txt"), $e)
    $scan = & (Join-Path $dir "clamav\clamscan.exe") "--database=$SignatureDir" "--no-summary" $eicarDir 2>$null
    Check "bundled ClamAV detects EICAR" (($scan -join " ") -match "Eicar.*FOUND") "($($scan -join ' '))"
    Remove-Item -Recurse -Force $eicarDir
} else {
    Check "bundled ClamAV detects EICAR" $false "(no signature folder at $SignatureDir; skipped)"
}

# 5b. a sign-in start entry (as real-time protection writes it) is removed by the uninstaller
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$savedRun = (Get-ItemProperty -Path $runKey -Name SentinelX -ErrorAction SilentlyContinue).SentinelX
$hadRun = $null -ne $savedRun
if (-not $hadRun) { New-ItemProperty -Path $runKey -Name SentinelX -Value "`"$exe`" --background" -PropertyType String | Out-Null }

# 6. uninstall is refused while Sentinel X runs (nothing half-removed), then works after it exits
$running = Start-Process -FilePath $exe -ArgumentList "--smoke-test", "20000" -PassThru
Start-Sleep -Seconds 5
$p = Start-Process -FilePath (Join-Path $dir "unins000.exe") -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -Wait -PassThru
Check "uninstall refused while running" ($p.ExitCode -ne 0 -and (Test-Path $exe) -and (Test-Path $uninstKey)) "($($p.ExitCode))"
$running.WaitForExit(60000) | Out-Null

# 7. silent uninstall: program removed, user data kept
$p = Start-Process -FilePath (Join-Path $dir "unins000.exe") -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -Wait -PassThru
Start-Sleep -Seconds 3
Check "uninstaller exit code 0" ($p.ExitCode -eq 0) "($($p.ExitCode))"
Check "program files removed" (-not (Test-Path $exe))
Check "uninstall entry removed" (-not (Test-Path $uninstKey))
Check "user data kept after uninstall" (Test-Path (Join-Path $home_ "sentinelx.db"))
if (-not $hadRun) {
    Check "sign-in start entry removed" ($null -eq (Get-ItemProperty -Path $runKey -Name SentinelX -ErrorAction SilentlyContinue))
} else {
    # The uninstaller removes the per-user entry; put back the real installation's entry.
    Set-ItemProperty -Path $runKey -Name SentinelX -Value $savedRun
    Check "real sign-in start entry restored" ((Get-ItemProperty -Path $runKey -Name SentinelX).SentinelX -eq $savedRun)
}
$deskAfter = Test-Path $userDesktopLnk
Check "user's desktop shortcut untouched" ($deskAfter -eq $deskBefore) "(before $deskBefore, after $deskAfter)"

Remove-Item Env:SENTINELX_HOME, Env:QT_QPA_PLATFORM
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
$failed = @($results.Values | Where-Object { $_ -eq "FAIL" }).Count
Write-Output ("RESULT: {0} checks, {1} failed" -f $results.Count, $failed)
exit $failed

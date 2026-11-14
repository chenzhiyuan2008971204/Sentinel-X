# Sentinel X trial-run monitor. Runs ONLY inside the disposable sandbox VM (never on the host).
# Starts the sample, watches it for $Seconds, writes what changed as JSON to $OutJson.
param(
    [Parameter(Mandatory = $true)][string]$Sample,
    [int]$Seconds = 120,
    [Parameter(Mandatory = $true)][string]$OutJson,
    [string]$Manifest = "C:\ProgramData\Microsoft\Windows\Caches\cversions.3.db",
    [switch]$NoMouse
)
$ErrorActionPreference = "SilentlyContinue"
$started = Get-Date

function RunKeys {
    $keys = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $out = @()
    foreach ($k in $keys) {
        $p = Get-ItemProperty -Path $k
        if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object { $out += "$k\$($_.Name)=$($_.Value)" } }
    }
    $out
}
function Startup { Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -File | ForEach-Object { $_.FullName } }
function Services { Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name)|$($_.PathName)" } }
function Tasks { Get-ScheduledTask | Where-Object { $_.TaskName -ne $mouseTask } | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" } }
function WmiSubs { Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | ForEach-Object { "$($_.__CLASS)|$($_.Name)" } }
function Files {
    $roots = $env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, "$env:USERPROFILE\Desktop", "C:\Windows\Temp", "C:\Users\Public"
    foreach ($r in $roots) { Get-ChildItem $r -Recurse -File -Force -Depth 4 | ForEach-Object { $_.FullName } }
}
function Detections { Get-MpThreatDetection | ForEach-Object { "$($_.ThreatID)|$($_.DetectionID)" } }
function DetectionNames { Get-MpThreat | ForEach-Object { $_.ThreatName } }

# Decoys: the user's everyday files written by the "lived-in" setup (listed in $Manifest). A
# ransomware-like sample renames, encrypts or deletes them. Without that list (an older sandbox),
# a folder of plain decoy documents is created instead.
$decoys = @{}
$decoyDir = "?"
if (Test-Path $Manifest) {
    foreach ($f in (Get-Content $Manifest -Encoding UTF8)) { if ($f -and (Test-Path $f)) { $decoys[$f] = (Get-FileHash $f).Hash } }
} else {
    $decoyDir = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "Reports"
    New-Item -ItemType Directory -Force $decoyDir | Out-Null
    foreach ($i in 1..40) {
        $ext = @(".docx", ".xlsx", ".jpg", ".pdf", ".txt")[$i % 5]
        $f = Join-Path $decoyDir ("report_{0:D2}{1}" -f $i, $ext)
        Set-Content -Path $f -Value ("Quarterly report draft {0}." -f $i) -Encoding ASCII
        $decoys[$f] = (Get-FileHash $f).Hash
    }
}

# Someone at the keyboard: move the mouse and scroll now and then, in the signed-in user's own
# session (an interactive scheduled task; this script itself runs in a background session).
$mouseTask = "OneDrive Reporting Task-S-1-5-21-" + (Get-Random -Minimum 100000 -Maximum 999999)
if (-not $NoMouse) {
    $mover = @"
Add-Type -Namespace W -Name U -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y); [DllImport("user32.dll")] public static extern void mouse_event(int f,int x,int y,int d,int e);'
`$r = New-Object Random; `$x = 600; `$y = 400; `$end = (Get-Date).AddSeconds($($Seconds + 30))
while ((Get-Date) -lt `$end) {
  `$tx = `$r.Next(50, 1200); `$ty = `$r.Next(50, 700)
  foreach (`$s in 1..25) { `$x += (`$tx - `$x) / 6; `$y += (`$ty - `$y) / 6; [W.U]::SetCursorPos([int]`$x, [int]`$y); Start-Sleep -Milliseconds (`$r.Next(15, 45)) }
  if (`$r.Next(0, 5) -eq 0) { [W.U]::mouse_event(0x0800, 0, 0, -120, 0) }
  Start-Sleep -Milliseconds (`$r.Next(300, 2500))
}
"@
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($mover))
    schtasks /create /tn $mouseTask /tr "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $enc" /sc once /st 23:59 /it /ru $env:USERNAME /f | Out-Null
    schtasks /run /tn $mouseTask | Out-Null
}

$before = @{ run = @(RunKeys); startup = @(Startup); services = @(Services); tasks = @(Tasks); wmi = @(WmiSubs);
             files = @(Files); det = @(Detections); hosts = (Get-FileHash "$env:windir\System32\drivers\etc\hosts").Hash;
             rtp = (Get-MpComputerStatus).RealTimeProtectionEnabled }
$beforeFiles = @{}; foreach ($f in $before.files) { $beforeFiles[$f] = 1 }

# ---- start the sample ----
$ext = [IO.Path]::GetExtension($Sample).ToLower()
$proc = $null; $startError = $null
try {
    switch ($ext) {
        ".ps1" { $proc = Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$Sample`"" -PassThru -ErrorAction Stop }
        ".msi" { $proc = Start-Process msiexec.exe -ArgumentList "/i", "`"$Sample`"", "/qn" -PassThru -ErrorAction Stop }
        { $_ -in ".bat", ".cmd" } { $proc = Start-Process cmd.exe -ArgumentList "/c", "`"$Sample`"" -PassThru -ErrorAction Stop }
        { $_ -in ".js", ".vbs", ".jse", ".vbe", ".wsf" } { $proc = Start-Process wscript.exe -ArgumentList "`"$Sample`"" -PassThru -ErrorAction Stop }
        default { $proc = Start-Process -FilePath $Sample -PassThru -ErrorAction Stop }
    }
} catch { $startError = $_.Exception.Message }

# ---- watch: process tree and connection attempts ----
$tree = @{}; $procInfo = @{}; $net = @{}
if ($proc) { $tree[[int]$proc.Id] = 1 }
$end = (Get-Date).AddSeconds($Seconds)
while ((Get-Date) -lt $end) {
    $all = Get-CimInstance Win32_Process
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($p in $all) {
            if (-not $tree.ContainsKey([int]$p.ProcessId) -and $tree.ContainsKey([int]$p.ParentProcessId) -and $p.CreationDate -ge $started) {
                $tree[[int]$p.ProcessId] = 1; $changed = $true
            }
        }
    }
    foreach ($p in $all) {
        if ($tree.ContainsKey([int]$p.ProcessId) -and -not $procInfo.ContainsKey([int]$p.ProcessId)) {
            $procInfo[[int]$p.ProcessId] = @{ name = $p.Name; cmd = ([string]$p.CommandLine).Substring(0, [Math]::Min(300, ([string]$p.CommandLine).Length)) }
        }
    }
    foreach ($c in (Get-NetTCPConnection)) {
        if ($tree.ContainsKey([int]$c.OwningProcess) -and $c.RemoteAddress -notin "0.0.0.0", "::", "127.0.0.1", "::1") {
            $net["$($c.RemoteAddress):$($c.RemotePort)"] = $procInfo[[int]$c.OwningProcess].name
        }
    }
    Start-Sleep -Milliseconds 800
}

if (-not $NoMouse) { schtasks /delete /tn $mouseTask /f | Out-Null }
$after = @{ run = @(RunKeys); startup = @(Startup); services = @(Services); tasks = @(Tasks); wmi = @(WmiSubs);
            files = @(Files); det = @(Detections); hosts = (Get-FileHash "$env:windir\System32\drivers\etc\hosts").Hash;
            rtp = (Get-MpComputerStatus).RealTimeProtectionEnabled }
function New($a, $b) { @($b | Where-Object { $a -notcontains $_ }) }
$newFiles = @($after.files | Where-Object { -not $beforeFiles.ContainsKey($_) -and $_ -notlike "$decoyDir*" -and $_ -ne $OutJson })
$exeLike = @($newFiles | Where-Object { $_ -match '\.(exe|dll|scr|sys|ps1|bat|cmd|vbs|js|hta|lnk)$' })
$decoyChanged = 0
foreach ($f in $decoys.Keys) { if (-not (Test-Path $f) -or (Get-FileHash $f).Hash -ne $decoys[$f]) { $decoyChanged++ } }
$newDet = New $before.det $after.det
# Defender may catch the sample while it is being copied in, before the baseline above: count those too.
$sampleDir = Split-Path $Sample -Parent
$aboutSample = @(Get-MpThreatDetection | Where-Object { ($_.Resources -join " ") -like "*$sampleDir*" })
$detCount = [Math]::Max($newDet.Count, $aboutSample.Count)

$report = [ordered]@{
    sample = $Sample; started = [bool]$proc; start_error = $startError; seconds = $Seconds
    processes = @($procInfo.Values | Select-Object -First 40)
    persistence = [ordered]@{ run_keys = (New $before.run $after.run); startup = (New $before.startup $after.startup);
                              services = (New $before.services $after.services); tasks = (New $before.tasks $after.tasks);
                              wmi = (New $before.wmi $after.wmi) }
    dropped_files = @($newFiles | Select-Object -First 60); dropped_executables = @($exeLike | Select-Object -First 30)
    decoys_total = $decoys.Count; decoys_changed = $decoyChanged
    defender_new_detections = $detCount; defender_threat_names = @(DetectionNames | Select-Object -First 10)
    defender_disabled = ([bool]$before.rtp -and -not [bool]$after.rtp)
    hosts_changed = ($before.hosts -ne $after.hosts)
    network_attempts = @($net.Keys | ForEach-Object { "$_ ($($net[$_]))" } | Select-Object -First 30)
}
$report | ConvertTo-Json -Depth 5 | Set-Content -Path $OutJson -Encoding UTF8

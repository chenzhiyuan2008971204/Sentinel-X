# Harmless test, run ONLY inside the Sentinel X sandbox VM (it is reset afterwards).
# Renames the monitor's own decoy documents, like ransomware would. Expected: confirmed threat.
$d = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "Reports"  # the folder of decoy documents guest_monitor.ps1 creates
Get-ChildItem $d -File | ForEach-Object { Rename-Item $_.FullName ($_.Name + ".locked") }

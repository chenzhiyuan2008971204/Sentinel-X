# Harmless test, run ONLY inside the Sentinel X sandbox VM. Writes the industry-standard EICAR
# antivirus test string (not malware) so the VM's own Windows Defender should detect it.
# The string is stored base64-encoded here so this script itself is not an EICAR file.
$b = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
[IO.File]::WriteAllText("C:\SX\eicar_test.com", [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($b)))
Start-Sleep 20

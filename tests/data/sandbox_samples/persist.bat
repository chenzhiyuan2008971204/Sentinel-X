@echo off
rem Harmless test, run ONLY inside the Sentinel X sandbox VM (it is reset afterwards).
rem Adds an autostart entry for notepad and copies notepad. Expected: suspicious (persistence).
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SXTest /d "notepad.exe" /f
copy /y "%SystemRoot%\System32\notepad.exe" "%APPDATA%\sxtest.exe"

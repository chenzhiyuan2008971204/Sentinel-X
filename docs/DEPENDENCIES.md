# Dependencies

| Package | Version | License | Used for | Since |
|---|---|---|---|---|
| PySide6 | 6.8.1 | LGPLv3 | GUI | Phase 1 |
| SQLAlchemy | 2.0.36 | MIT | SQLite ORM | Phase 1 |
| pydantic | 2.10.3 | MIT | Config and data models | Phase 1 |
| yara-python | 4.5.1 (libyara 4.5.1) | Apache-2.0 / BSD-3 | YARA engine | Phase 3 |
| pefile | 2024.8.26 | MIT | PE static analysis | Phase 3 |
| psutil | 6.1.0 | BSD-3 | Process and network snapshots | Phase 6 |
| watchdog | 6.0.0 | Apache-2.0 | Folder monitoring | Phase 6 |
| Jinja2 | 3.1.4 | BSD-3 | HTML reports (autoescape) | Phase 7 |
| MarkupSafe | 3.0.4 | BSD-3 | Jinja2 escaping | Phase 7 |
| reportlab | 4.2.5 | BSD-3 | PDF reports | Phase 7 |
| pillow | 13.0.0 | MIT-CMU | ReportLab dependency | Phase 7 |
| chardet | 7.7.0 | LGPLv2.1 | ReportLab dependency | Phase 7 |
| pypdf | 5.1.0 | BSD-3 | Tests: PDF text extraction (dev) | Phase 7 |
| pyinstaller | 6.22.3 | GPLv2 with bootloader exception | Packaging (build only; 6.11 excluded pefile 2024.8.26) | Phase 9 |
| pyinstaller-hooks-contrib | 2026.9 | GPLv2 / Apache-2.0 | Packaging hooks (build only) | Phase 9 |
| pytest | 8.3.4 | MIT | Tests (dev) | Phase 1 |
| pytest-qt | 4.4.0 | MIT | GUI tests (dev) | Phase 1 |
| pytest-cov | 6.0.0 | MIT | Coverage (dev) | Phase 1 |

External engine: ClamAV 1.5.4 (GPLv2), installed on the dev machine with `winget install Cisco.ClamAV`; signatures via `freshclam` into `%LOCALAPPDATA%\SentinelX\clamav-db`. Bundled by the installer since 0.9.0.

Windows APIs used directly via ctypes: `wintrust.dll!WinVerifyTrust` (Authenticode, no UI, no network), `CryptCATAdmin*` / `CryptCATCatalogInfoFromContext` (system catalog signatures), `WTHelperProvDataFromStateData` / `WTHelperGetProv*` and `crypt32!CertGetNameStringW` (signer chain); `kernel32` job objects (`CreateJobObjectW`, `SetInformationJobObject`, `AssignProcessToJobObject`) to confine the research worker; `kernel32` file handles for quarantine; `wevtapi.dll` EvtQuery/EvtNext/EvtRender (event logs, Unicode; chosen over `wevtutil` whose output is lossy ANSI); `shell32!ShellExecuteW "runas"` (user-triggered UAC relaunch); `icacls` / `whoami` (vault ACL).

Real-time protection (0.10.0) also uses `shell32!SHGetKnownFolderPath` (Downloads/Desktop/Documents), `kernel32!CreateMutexW` (installer AppMutex), a kill-on-close job object for clamd, and the per-user `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` value `SentinelX` (stdlib `winreg`). clamd.exe (ClamAV 1.5.4) is bundled.

pywin32 is not needed (replaced by the ctypes bindings above).

PDF font: the first available of the bundled Noto Sans TC (Phase 9), `%WINDIR%\Fonts\msjh.ttc` (Microsoft JhengHei), `mingliu.ttc`, `kaiu.ttf`; ReportLab embeds a subset and refuses fonts whose license forbids embedding.

Build tools (not shipped): Inno Setup 6.7.3 (installer compiler, installed per-user with winget).

Shipped with the installer: ClamAV 1.5.4 runtime (clamscan, freshclam, DLLs, certificates) under GPLv2, unmodified, with `clamav\SOURCE.txt` pointing to the exact source tag; see `THIRD_PARTY_NOTICES.txt`. No font is redistributed: PDF reports embed a subset of Microsoft JhengHei from Windows (a bundled Noto Sans TC is used if placed in `src/sentinelx/resources/fonts/`). External: Sysmon (optional, user-installed; a starting config ships in `src/sentinelx/resources/sysmon-sentinelx.xml`).

Runtime: CPython 3.12 (tested on 3.12.10, Windows 11).

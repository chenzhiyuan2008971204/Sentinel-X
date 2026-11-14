# Changelog

All notable changes to Sentinel X. Dates are UTC.

## [0.16.0] - 2026-11-06 — Whole-drive protection, autostart and ransomware warnings, audit 8 fixes (not yet built or installed)

Requested by the user: protection not limited to a few folders, public YARA rules, running an unknown installer in a virtual machine first, autostart and ransomware protection; then an engineering audit (audit 8) and its fixes.

### Added
- **Whole-drive real-time protection** (option 「全域防護」, on by default): every fixed drive and every removable drive is watched; new or changed files anywhere are scanned. Skipped, to keep the computer responsive: Windows' own folder (its Temp folder is still checked), other antivirus programs' data, the sandbox VM's disk, browser caches, Windows logs and similar constantly changing files (`locations.noisy`).
- **Execution lock** now also covers Desktop, Documents and USB drives (previously only Downloads). Program Files and Temp are deliberately not locked: installers create and start programs there at once.
- **YARA Forge public rules** (`services/rule_update_service.py`, Settings 「YARA 規則」): after consent, the "core" package (about 5,100 rules) is downloaded from the official GitHub release only, its size and SHA-256 are checked against the release, the rules are validated like any rule set (safe modules, no include), and the previous version is removed. Checked weekly. Measured: compiles in 1.1 s, about 18 ms extra per file, 0 hits on 200 Windows system files. The rule-file size limit is now 16 MB.
- **Autostart watch** (`protection/autostart.py`, option 「盯住開機自動執行」, on): Run/RunOnce keys (this user and all users, 32/64-bit), Startup folders and automatic services every 30 s, scheduled tasks every 5 min (Windows' `Get-ScheduledTask`, no administrator rights needed). Read-only. New entries, including ones added while Sentinel X was not running, have their program scanned; confirmed threats are quarantined as usual, suspicious / unsigned / missing programs are reported, validly signed clean ones are only logged. Nothing is ever removed. Not covered: WMI subscriptions, browser extensions, Winlogon/AppInit, drivers. Measured: 177 entries, 2.9 s for the first reading, 0.02 s afterwards.
- **Ransomware warning** (`protection/ransomware.py`, option 「勒索病毒警報」, on): ≥10 documents renamed to an unusual extension in 20 s, or ≥10 "document + extra extension" files created while ≥10 documents are deleted, raise a red alert; ≥150 modified documents a yellow one. The alert names the programs that wrote most (write counters sampled every 15 s); the user can stop one from the protection page (confirmation; Windows' critical processes refused). Never stopped automatically.
- **Ransomware decoys** (option 「放置防勒索誘餌檔」, **off** until the user turns it on): a hidden folder with 4 harmless decoy documents in each user folder; a content change, rename or deletion raises a red alert (attribute-only changes such as OneDrive's are ignored). Turning it off removes only unchanged decoys.
- **Self-check** (`app/self_check.py`): the next start reports when Sentinel X did not close normally, when its settings file was changed while it was not running (SHA-256 kept in the hash-chained audit log), or when the sign-in start entry was removed (restored automatically). Detection only: preventing it needs a service or driver, which this project does not use.
- **Trial-run room** (`sandbox/`, page 「試跑室」): code for running a file in a VirtualBox Windows 11 VM without a network adapter, watching it for 1–30 minutes, and restoring a clean snapshot. **Was not usable at first** (now enabled, see "Trial-run room works" below): building the VM does not complete on a real computer (VirtualBox runs guest commands with a UAC-restricted token). The page says so, its buttons are disabled (`sandbox.FINISHED = False`), the home tile reads 「試跑室（開發中）」, and no automatic build runs.

### Changed (engineering audit 8, see `docs/AUDIT_8_zh-TW.md`)
- **Risk rules 4**: VirusTotal alone is strong evidence only with at least 25 engines and more than half of them; 10–24 engines are moderate (suspicious). ClamAV and VirusTotal no longer count as two independent sources (ClamAV is one of VirusTotal's engines). A VirusTotal-only confirmed threat is never quarantined or terminated automatically by real-time protection; it is locked and reported.
- **Real-time VirusTotal**: only files in Downloads, Desktop, Documents and USB drives are looked up, never waiting for the per-minute limit, at most 350 a day (the rest is left for manual scans). A "0 detections" result analysed more than 180 days ago no longer counts as a full check on its own.
- **Execution lock**: a program that could not be fully checked stays locked and is checked again after 20 s, 1 min and 3 min; then it stays locked and the user is told. Links are never locked; a program already blocked by someone else is left alone.
- With whole-drive protection off, Pictures, Videos, Music and OneDrive are watched as well, so the ransomware warning sees them.
- YARA Forge is downloaded only from `https://github.com/YARAHQ/yara-forge/releases/download/`.
- A file whose content changed while its size and last-write time were set back is scanned again: a moved Windows change time leads to a SHA-256 comparison with the scanned content (`protection/fileid.py`). Attribute-only changes are not rescanned.
- The trial-run room's quarantine button works in the background.
- **Execution lock locks only new programs** (created, moved in, or created in the last 2 minutes). Found on the user's computer: Windows writes information to a program's file when it runs; that change event locked an existing program, so starting it again failed until it had been checked.
- **Trial-run room works (2026-11-08)** and is enabled (`sandbox.FINISHED = True`). Built and verified on the user's computer with the Windows 11 Enterprise evaluation 26300.9457 (SHA-256 matches Microsoft's published value) and VirtualBox 7.2.22. The 4 harmless samples, 60 s each: `quiet.bat` → no findings; `persist.bat` → run key (moderate) + dropped program (weak); `decoys.ps1` → 40 of 40 decoys changed (strong); `eicar_in_vm.ps1` → Defender detection (strong). Fixed on the way, each seen in the real VM:
  - The evaluation reported "grace time expired" and powered off hourly: it must activate online. The VM now has a NAT adapter only during the build (after the WinPE copy, before any sample exists), activates (`slmgr /ato`), and is checked (`slmgr /dli`); the adapter is removed and the build refuses to snapshot if one is still attached. The earlier "expired ISO" diagnosis was wrong.
  - The answer file's account was created in no group, so the first-sign-in Guest Additions install had no rights. `SetupComplete.cmd` (system rights) now runs VirtualBox's post-install script; the first-sign-in command is only a fallback.
  - The Guest Additions service starts only after a restart: the build restarts Windows once after 75 minutes without them.
  - VirtualBox 7.2 does not take the program name after `--`: repeating it made cscript and PowerShell run their own path as a script (`VBox.exec`).
  - After restoring a running snapshot, every guest session was refused (`VERR_NOT_FOUND`): the clean snapshot is now of the shut-down VM; each run boots Windows (about 3-6 minutes).
  - Windows ignored the ACPI power button (hard power-off after 10 minutes): shutdown is now `shutdown /s` inside the VM.
  - PowerShell could start too slowly right after boot ("Starting process failed with rc=VERR_TIMEOUT"): the run waits until PowerShell starts and retries a monitor that never started (the sample has not run then).
  - The newest ISO in the folder is used. Known: one of five real runs timed out once (VirtualBox guest control did not return); a second run passed.
- **Trial-run room is a plain sandbox**: the disguise (laptop hardware identity, everyday user, lived-in files, mouse movement) and the steps that needed administrator rights inside the VM are removed. Samples run under the VM's standard sandbox account in `C:\SX`; 4 GB memory, 64 GB disk. Malware that detects virtual machines may stay quiet, so results never say "safe".
- Fixed two harmless sandbox test samples (`decoys.ps1` targeted the wrong folder; `persist.bat` had a broken path).
- **Memory-saving mode** (option 「省記憶體模式」, off): no resident ClamAV (about 950 MB less); files in Downloads, Desktop, Documents and USB drives are still checked by ClamAV per batch (clamscan), other files by YARA, hash intelligence, PE analysis and VirusTotal. Measured: Sentinel X's own core is about 70 MB plus about 38 MB for the 5,133 YARA Forge rules and stays flat over 10 rounds of 2,000 files (no leak; `packaging/memprobe.py`).
- **Detection-rule files are not auto-quarantined**: YARA rule files and ClamAV text signature files contain the patterns they describe; real-time protection reports them instead of quarantining them (found on the user's computer: YARA Forge's rule file was quarantined). A program merely named `.yar` is not exempt.
- **Locked programs are checked first**: a backlog of other files (an unpacked archive, a build) no longer keeps a locked program waiting.
- Fixed: the ransomware warning's write snapshot failed on every run on the user's computer (a protected process without a name); writers were ranked by their total since start instead of the last half minute.
- `packaging/memwatch.py`: read-only long-term memory/CPU measurement of the running app.
- **VirtualBox version check** (audit 8, M6; `sandbox/vbox_version.py`): before every build and trial run the installed VirtualBox is compared with the newest stable release, read once a day from Oracle's `https://download.virtualbox.org/virtualbox/LATEST-STABLE.TXT` (fixed HTTPS address; a redirect or anything but one version number is not used; nothing about the computer is sent). Older than that, or older than 7.2.22 (the verified release), the VM is not started and the page asks the user to update from virtualbox.org; the buttons are disabled. Offline, the last known newest release (or 7.2.22) is used and the page says it could not be checked. Nothing is downloaded or installed automatically.

### Fixed
- **Process guard CPU** (audit 8, H1): the program path of every process was requested every second, about 180 ms of CPU per second (≈18 % of one core) even with no known threat. Now only new processes are looked at: about 1.6 ms per round, 0 with no known threat.
- **Real-time throughput** (audit 8, M3): at most 100 files a second were handed to scanning (50 per batch, then a fixed pause), and file checks held the lock that new events need. Measured with 20,000 harmless files: before, 61 % after 129 s; after, 100 % after 13.6 s.
- Copying into the VM failed when the target folder already existed (VirtualBox 7 needs a trailing backslash for a folder).
- During first setup the VM can power itself off before the Guest Additions report a signed-in user; the build now starts it again (at most 5 times) instead of waiting for the 5-hour timeout.

### Fixed: quarantine did not start for the built-in Administrator account (2026-11-14)
- Found by the first GitHub build: those machines run as Windows' built-in Administrator (RID 500), whose access entry Windows writes as the SDDL alias `LA`. The vault's "only this user" check compared the text with the full SID, never matched, and the quarantine refused to start (41 tests failed there). Aliases are now resolved with Windows' own conversion (`win32fs.full_sid`); other accounts (Everyone, Administrators, Users, SYSTEM) are still rejected. Tests: `tests/integration/test_vault_acl_aliases.py`.
- Open-source release preparation: GPL-3.0, GitHub Actions build, code signing and privacy policy in README.

### Fixed: a restored false positive kept being blocked (asked by the user, 2026-11-09)
- Marking a copy of a file as a false positive only re-assessed that copy. An older copy of the same content (the quarantined original, an earlier download) kept its "confirmed threat" verdict, and the quarantine entry kept the hash on the process guard's list, so the program was closed every time it started. Now a false positive re-assesses every copy with the same SHA-256 (`ReviewService.review`), and quarantined or deleted files the user has marked as false positives are no longer on the process guard's list (`ProtectionService.threat_hashes`); a copy still judged a confirmed threat by other evidence stays on it.
- Restoring from the quarantine now asks whether to also mark the file as a false positive (whole file, `ReviewService.dismiss_whole_file`). Restoring alone still does not trust the file: the same download is blocked again, as before.
- Tests: `tests/integration/test_restore_false_positive.py` (restore + mark -> the same download passes and is not closed; restore only -> blocked again; marking the new copy clears the quarantined original; per-rule dismissal) and the page's new question.

### Fixed: memory grew with every file event (engineering audit 8, M4)
- The installed app grew from about 235 MB to 784 MB over 36 hours, and from 186 MB to 435 MB in the 10 minutes in which about 30,000 new files appeared; it never went back down. Measured part by part (`packaging/memprobe_realtime.py`, `memprobe_parts.py`, `memprobe_big.py`, `memprobe_gui.py`, `memprobe_events.py`): scanning, the process guard, the ransomware sampler, autostart checks and window refreshes stay flat; a burst of file events through real-time protection reproduced it (20,000 files: 56 → 514 MB).
- Cause: `locations.known_folder()` defined a new ctypes structure class on every call, and ctypes keeps every `POINTER(type)` it creates for good. Every file event asks whether the file is in Downloads, Desktop or Documents about six times. Now the type and the function signature are made once, and the folders are remembered for 30 seconds (users and OneDrive can move them). `fileid.stamp()` had the same per-call pattern (no permanent leak, but wasted CPU). After the fix the same 20,000 files: 56 → 87 MB.

### Found while building the sandbox on the user's computer
- With Windows Memory Integrity on, VirtualBox runs VMs through Hyper-V and a VM with 2 or more CPUs hangs in UEFI start-up; with 1 CPU it starts. Windows 11 Setup refuses 1 CPU, so Windows is installed directly from the installer's mini-system (diskpart, dism, bcdboot). Memory Integrity stays on.

## [0.15.1] - 2026-11-06 — VirusTotal quota day

### Fixed
- The local count of VirusTotal lookups started a new day at local midnight, but VirusTotal resets the free quota at 00:00 UTC (08:00 in Taiwan). Between local midnight and 08:00 Sentinel X could try lookups that VirusTotal then refused (handled as "not looked up this time", never an error). The count now follows the UTC day. 1 new test.

### Notes
- Found while checking the setup on the user's computer: a Sentinel X started from Claude's shell runs inside the Claude app's MSIX container and uses a private copy of `%LOCALAPPDATA%`, so it ran beside the user's own copy on different data. Not a Sentinel X defect; development notes updated so the real app is always started by the user.

## [0.15.0] - 2026-11-06 — VirusTotal hash lookups

Requested by the user to catch more new threats. Off until the user agrees and stores their own free API key.

### Added
- VirusTotal engine (`engines/virustotal.py`): for programs, installers, scripts, archives and documents, the SHA-256 is looked up at VirusTotal (`GET /api/v3/files/{sha256}`); the file is never uploaded. Works in manual scans, real-time protection (so new downloads are looked up before the execution lock is released) and static analysis.
- Evidence and grading (risk rules 2): 10+ engines saying malicious is strong evidence, 3-9 moderate, 1-2 weak (often false positives). The evidence records the counts, detection names, common threat label, public sandbox verdicts, analysis date and a link. A file VirusTotal has never seen is not counted as checked.
- Free-tier limits applied locally (4 per minute, 500 per day; waits at most 20 s per batch); results cached 3 days (1 day for unknown files). When a lookup is not possible (limit, network, wrong key) the file is SKIPPED with the reason: never marked unclean or unassessed.
- Settings 「VirusTotal」: consent, links to sign up and to the API key page, key field (saved encrypted with Windows DPAPI for the current user, cleared from the field, never shown, logged or audited), delete, and a connection test that looks up the harmless EICAR test file's hash. Home page row for it.
- Database schema 7: table `vt_reports` (cache).
- 17 new tests (568 total), with a fake VirusTotal API; nothing contacted the real service.

## [0.14.0] - 2026-11-05 — Permanent delete from the quarantine (user only)

Requested by the user. CLAUDE.md forbids *automatic* permanent deletion; a deletion the user chooses and confirms is allowed.

### Added
- Quarantine page: 「永久刪除…」 for a selected item that is in quarantine. A confirmation explains that it cannot be undone and suggests keeping the file when unsure. Only that item's stored copy is deleted (duplicates keep theirs). The record (path, SHA-256, reason), a `deleted_at` time and the audit entry `QUARANTINE_DELETE` are kept; the research timeline shows the deletion.
- New quarantine status `DELETED`. A deleted threat stays a threat: its SHA-256 still stops copies (process guard) and its file still counts as handled in the threat list.
- Database schema 6: SQLite cannot change a CHECK constraint, so `quarantine_items` is rebuilt with the new status and column (rows copied unchanged; a backup is made before migrating as for every migration). Verified on a copy of the real database: 5 → 6, integrity OK, rows and foreign keys intact.

### Changed
- The test that there is no delete API now checks that permanent delete is never automatic: exactly one delete method, `confirmed=True` required, and only the quarantine page calls it.
- 6 new tests (552 total).

## [0.13.0] - 2026-11-05 — Simpler interface

Requested by the user: an interface that people who are not security experts can understand.

### Added
- Home page (`gui/home_page.py`), shown first: one large status (protected / needs attention / protection off) with one main button, two large actions (quick scan of Downloads, Desktop and Documents; scan a chosen place) and a status list where each row explains in plain words what it means and offers a button only when something needs doing. All states come from the real services; it never says "100 %" or "completely safe".

### Changed
- Menu: everyday pages first (首頁, 掃描, 即時防護, 需要處理的檔案, 隔離區, 設定); research tools (詳細狀態, 研究實驗室, 靜態分析, 行為監控, 威脅情報, 報告) under a 「進階功能」 header that opens and closes (it shows their counts when closed). `MainWindow.go_to(key)` navigates by page key.
- Real-time protection page: every option has a short title and one line explaining what it does; plain-language summary and counts; the page scrolls.
- Settings: 病毒碼 first; the other groups under 「進階設定（不確定的話不用改）」, each with a one-line explanation.
- Status bar: privilege shown only in administrator mode, behavior monitor only while it runs.
- Theme: large rounded status card, primary / secondary / tile button styles.

### Fixed
- The sign-in start entry was written only when a setting changed, so once removed (here by the installation test's uninstall step, which runs as the same user) it never came back. Sentinel X now re-applies it from the saved setting at every start.
- The installer's 「建立桌面捷徑」 option is now checked by default (requested by the user).
- Installation test: it runs as the same user, so its uninstall step removed the real installation's sign-in start entry; it now puts the saved entry back, and checks that the user's desktop shortcut is untouched (24 checks).
- 9 new tests (546 total).

## [0.12.0] - 2026-11-05 — Execution lock for new downloads

### Added
- New programs in the Downloads folder (.exe, .com, .scr, .cpl, .dll, .pif) are locked the moment they appear: Sentinel X adds a "deny execute for Everyone" entry to the file (`icacls`), so Windows refuses to start it (access denied) while reading and scanning still work. After the scan the lock is removed; CONFIRMED_THREAT files are quarantined (or stay locked when auto-quarantine is off) and SUSPICIOUS files stay locked until the user unlocks them on the Real-time protection page (with confirmation). Option 「執行前鎖住」 (on by default). Audit entries `EXEC_LOCK`, `EXEC_LOCK_HELD`, `EXEC_UNLOCK`.
- Locked paths are kept in `exec_locks.json`; files still waiting when the app stopped unexpectedly are checked again at the next start. Turning protection off releases files that were still waiting (threats and suspicious files stay locked).
- Measured: a browser-style download (`.crdownload` renamed to `.exe`) was locked by the watcher in under 2 s; locking takes about 36 ms per file.

### Fixed (found by the new tests)
- Removing the lock changes the file's permissions, which Windows reports as a file change; without a guard the checked file was locked again and never re-checked. Files that were checked or unlocked and whose size and modification time are unchanged are no longer locked again.

### Limits
- Not locked: installers run by another program (.msi, scripts), files outside Downloads, copies of a locked file, and a program started in the moment before the lock is set. The user (file owner) can always change permissions.
- 12 new tests (537 total), with real Windows ACLs and harmless copies of PING.EXE.

## [0.11.0] - 2026-11-05 — Daily automatic signature updates

### Added
- ClamAV signatures update automatically once a day while Sentinel X is running (window open or in the tray), only after the user's consent; option 「每天自動更新病毒碼」 in Settings (on by default, disabled until consent). A failed update is retried after 2 hours and shown as a tray notification; success is silent. Last success and next update are shown in Settings and stored in the config file, so the schedule survives restarts. Manual and automatic updates never run at the same time; closing the app cancels a running update. Audit entries `SIGNATURE_AUTO_UPDATE` and `SIGNATURE_UPDATE_START` with `automatic`.
- The first-run question now says that updates are daily after consent.
- 10 new tests (525 total), with a fake freshclam that never uses the network.

## [0.10.2] - 2026-11-05 — Known limitations hardened

Fixes three limitations listed in ENGINEERING_AUDIT.md. No new features.

### Changed
- R18: real-time scan records are pruned at startup. Real-time batches older than 30 days are removed only when every file was fully assessed, had no detection and got a CLEAN verdict; verdicts stay, so the Threat Center and file history are unchanged. Audit entry `REALTIME_PRUNED`.
- R4: audit-chain verification is incremental. Between full passes (at most 10 minutes apart, and always at startup) only new entries are hashed, after checking that the last verified entry is unchanged and no earlier entry was removed. Measured with 20 000 entries: full pass 297 ms, incremental 5.2 ms. Trade-off: an edit to an older entry's content is found by the next full pass (within 10 minutes), not at once.
- R12: Research Lab YARA test rules are first compiled in the confined worker (job object, time limit = YARA timeout, cancellable); a rule that compiles too slowly is stopped there instead of blocking the app.
- 13 new tests (515 total).

## [0.10.1] - 2026-11-03 — Engineering audit 7 fixes

See ENGINEERING_AUDIT.md (Audit 7). No new features.

### Fixed
- G1: after real-time protection was turned off during a session, closing the window left an invisible process holding the instance lock ("already running" on the next start). A real close now always ends the program.
- G2: a threat that was already running when its file (or a copy elsewhere) was judged CONFIRMED_THREAT was never terminated; the process guard now re-checks every process when the set of threats changes.
- G3: a removable-drive scan could not be cancelled and kept running after protection stopped (and after clamd was stopped). Protection now has one cancel token per session; stopping cancels running scans and suppresses later actions.
- G5: Sentinel X's own reports saved elsewhere (e.g. Documents) were scanned by protection and by manual scans and could be flagged or quarantined, because they quote matched strings; they are now excluded by their recorded hash. Files the user excluded no longer produce "could not fully check" notifications.
- 4 new tests (502 total).

## [0.10.0] - 2026-11-03 — Real-time protection

Requested after the release: system-wide protection, terminating threats taken out of the quarantine, and a download check.

### Added
- Real-time protection (`protection/`, `services/protection_service.py`, page 即時防護): watches Downloads, Desktop, Documents (resolved with SHGetKnownFolderPath), the user's temp folder and removable drives; scans each file once it is completely written, with the same engines, risk rules and records as a manual scan (jobs with origin "realtime", kept out of the Scan Center history).
- Resident ClamAV (`ClamdManager`): clamd started on 127.0.0.1 on a free port with a fixed UTF-8 config, tied to the app by a kill-on-close job object; falls back to clamscan if clamd is not available. Measured: ready in 9.8 s, about 960 MB of memory.
- Automatic quarantine of CONFIRMED_THREAT files (option, on by default; never deletes; audit `AUTO_QUARANTINE`). Measured: 3.6 s from writing the file to quarantine; EICAR caught by the real clamd.
- Process guard (option, on by default): terminates processes whose executable has exactly the SHA-256 of a confirmed or quarantined threat, including a copy taken out of the quarantine; never terminates critical Windows processes, Microsoft-signed programs (reported as a likely false positive), Sentinel X or its children. Measured: 1.0 s from start to termination.
- Vault watch: alerts on changes to the quarantine folder that Sentinel X did not make (verified: no alarm on its own quarantining, an alert for a planted file).
- Download check: new installers and executables in Downloads get a conclusion with reasons (verdict, digital signature, internet origin); it never says "safe".
- Removable drives are scanned when inserted.
- System tray icon and notifications; closing the window keeps protection running; `--background` start at sign-in (per-user Run key, option); the uninstaller removes that entry. clamd.exe is bundled.
- 17 new tests (498 total); installation test 23 checks.

### Not done (and why)
- Blocking a program before it starts, and a sandbox that runs downloads to prove them harmless: the first needs a signed kernel driver; the second is not available on Windows 11 Home, executes unknown code, and cannot prove anything harmless because malware can detect sandboxes.

## [0.9.1] - 2026-11-03 — Engineering audit 6 fixes

See ENGINEERING_AUDIT.md (Audit 6). No new features.

### Fixed
- F1: signature updates failed for every user whose data folder path contains non-ASCII characters (for example a Chinese Windows user name): the freshclam config was written as ASCII. It is now UTF-8, which freshclam 1.5.4 reads correctly (verified with a real Chinese-named folder).
- F2: when ClamAV already works with its own signatures elsewhere, the first-start question no longer appears and Settings no longer claims that ClamAV cannot be used.
- F3: uninstalling (or reinstalling) while Sentinel X runs reported success but left program files behind and removed the uninstall entry. The app now holds a named mutex and the installer uses AppMutex: setup and uninstall ask to close Sentinel X first (silent mode aborts).
- The "signature folder missing" engine message now says how to fix it.
- 4 new tests (481 total); installation test has 21 checks.

## [0.9.0] - 2026-11-03 — Phase 9: Quality assurance and release

### Added
- Windows package: PyInstaller one-folder windowed build (`packaging/sentinelx.spec`, no UPX) with a version resource; `packaging/build.py` copies only the ClamAV 1.5.4 runtime (72 MB: executables, DLLs, certificates, licenses) with `clamav\SOURCE.txt` (GPL source location) and writes `THIRD_PARTY_NOTICES.txt`, then checks the build.
- Installer (Inno Setup 6.7.3, `packaging/installer.iss`): per-user, no administrator rights, `%LOCALAPPDATA%\Programs\SentinelX`; the uninstaller never deletes user data or the quarantine vault and says so.
- Installation test (`packaging/install_test.ps1`, 20 checks): silent install, files and uninstall entry, version resource, start/exit, second instance refused, research worker from the windowed executable, bundled ClamAV detects EICAR, silent uninstall keeps user data.
- First-start question before any signature download (official ClamAV mirror, Cisco Talos); `SignatureService` runs the bundled freshclam with a fixed config into `<data root>\clamav-db`, cancellable, audit-logged; Settings shows signature status, the consent checkbox and "立即更新病毒碼". Nothing is downloaded without consent and nothing updates in the background.
- The packaged app finds its bundled ClamAV first and always uses the per-user signature folder for it.
- QA measurements (`packaging/qa_measure.py`): false positives on harmless Windows files, resource usage, GUI responsiveness during a scan. Results in QUALITY_REPORT.md.
- User manual (docs/USER_MANUAL.md, zh-TW) with ClamAV signature and YARA rule update procedures; release notes; final quality report; product README.
- A test that the app version, pyproject.toml and the newest CHANGELOG entry agree.
- 12 new tests (477 total); full suite passes twice with no skips.

### Fixed
- Showing a finished scan froze the window (4.2 s for 1 500 files in the QA measurement): `job_files()` ran several queries per file. Now a fixed number of queries (1.08 s → 0.01 s, same result) and the Scan Center lists at most 10 000 files, findings first, pointing to the scan report for the rest. Longest GUI stall during a 1 500-file scan: 4 220 ms → 78 ms.
- The research worker writes to the inherited output handle when a windowed build has no `sys.stdout` (audit R14); verified from the packaged executable and the installed copy.
- Version record: the commits for 0.8.0 and 0.8.1 still reported version 0.7.2 in the app and package metadata (the version change had not been applied). Corrected to 0.9.0 here; the new consistency test prevents a repeat.

## [0.8.1] - 2026-11-02 — Engineering audit 5 fixes

See ENGINEERING_AUDIT.md (Audit 5). No new features.

### Fixed
- E1: the 10-second status refresh counts threats with a count query instead of loading every row (0.71 s → 0.002 s with 1 500 threats).
- E2: Settings no longer lowers a stored file limit above 100 000 000 when another setting is saved.
- E3: a database error during the status refresh is shown in the status bar instead of raising an error dialog every 10 seconds.
- 3 new tests (465 total).

## [0.7.2] - 2026-11-02 — Engineering audit 4 fixes

See ENGINEERING_AUDIT.md (Audit 4). No new features.

### Fixed
- D1: scans always skip Sentinel X's own data folder (its rule copies and reports were flagged by its own rules); the vault refuses to quarantine from it or restore into it.
- D2: importing a hash list runs in the background (a 500 000-hash list froze the window for 21 s).
- D3: two Sentinel X processes writing at the same time no longer fork the audit hash chain.
- 4 new tests (443 total).

## [0.7.1] - 2026-11-02 — Engineering audit 3 fixes

See ENGINEERING_AUDIT.md (Audit 3). No new features.

### Fixed
- C1: a long table cell no longer aborts report generation; PDF cells are cut with a pointer to the JSON report, and an unexpected writer error fails only that format.
- C2: the Reports page checks report integrity in the background instead of on the GUI thread.
- C3: "save copy" verifies the copied file's hash and refuses destinations inside the reports folder.
- C4: one unrenderable event no longer leaks event handles or stalls an event-log source.
- C5: AccessDenied on a new process's name no longer drops the whole process poll.
- C6: stopping the monitor after a timeout no longer stops collectors under a running loop or allows a second loop.
- 8 new tests (439 total).

## [0.7.0] - 2026-11-02 — Phase 7: Research Laboratory and Reports

### Added
- Research Lab page (`research/`, `services/lab_service.py`, `gui/lab_page.py`). Nothing is executed; the lab never creates or changes a verdict.
  - Sample facts: MD5 / SHA-1 / SHA-256, type by magic bytes, times, Mark-of-the-Web (Zone.Identifier) shown as untrusted text.
  - PE metadata, sections, imports (tree), version info and structural anomalies, parsed in an isolated worker process (`research/worker.py`): JSON-only result, time limit, 1 GB memory cap and "no child processes" through a Windows job object, killed on timeout or cancel.
  - Digital signature inspector: status, source (embedded or system catalog), catalog file, timestamp, and the certificate chain (subject, issuer, serial, validity, SHA-1/SHA-256 thumbprints). Offline only (no revocation checks, no network).
  - SHA-256 inspector: look up a hash without a file (local intel, current verdict, stored evidence, history).
  - YARA rule tester: write or load rules and test them on chosen harmless files or a folder (first level only, 500 files max). Same module allowlist, no `include`, size limit and timeout as the scanner. Test rules are never registered and never affect verdicts. Results show string ids, offsets, lengths and a 32-byte hex/ASCII excerpt.
  - Detection evidence viewer: every stored engine run and detection for the hash, with engine/rule versions as recorded at scan time and the raw evidence JSON.
  - File comparison: hashes, same-offset byte comparison (labelled as not a similarity algorithm), and PE differences (header fields, sections, imports, version info, signature status).
  - Analysis timeline for a hash: first seen, scans, verdicts, reviews, false-positive decisions, quarantine/restore, monitor events, lab actions and reports.
- Reports (`reporting/`, `services/report_service.py`, `gui/reports_page.py`):
  - One document model rendered as JSON, HTML (Jinja2, autoescape, Content-Security-Policy without scripts) and PDF (ReportLab, embedded CJK font, text extractable).
  - Sample, comparison and scan-job reports. Each contains the source evidence as recorded (engine name, engine and rule versions, rule ids, evidence, timestamps, SHA-256, explanations) and the tool versions at generation time.
  - Files are written atomically under `<data root>\reports` with generated names; each file's SHA-256 is stored in `reports` and in the audit log. The Reports page checks integrity, asks before opening a modified report and refuses to copy one.
- Catalog signature lookup (`CryptCATAdmin*` + `WinVerifyTrust`): the PE engine now reports catalog-signed Windows files as signed (resolves audit item R7).
- `--research-worker` entry point for the frozen build.
- New dependencies: Jinja2 3.1.4, MarkupSafe 3.0.4, ReportLab 4.2.5 (with pillow 13.0.0, chardet 7.7.0); dev: pypdf 5.1.0.
- 71 new tests (431 total): signature chain and catalog on real Windows files, tampered signature, worker timeout/cancel/garbage output/output cap, job object blocks child processes, hostile strings in all three report formats, path control, integrity and copy refusal, missing CJK font, scan-job reports, "the sample is never launched", and GUI tests for both pages.

### Fixed during this phase
- Tool versions appeared in HTML/PDF only when a report builder added them; the writers now always add them (found by a test).
- Dark theme did not style tree widgets and plain-text editors.

### Verified on this machine
- Real data folder: `notepad.exe` inspected (catalog signature VALID, chain to Microsoft Root Certificate Authority 2010, timestamp present, isolated worker ~0.3 s); YARA test, comparison with `calc.exe`; sample and scan-job reports in all three formats; all reports "unchanged"; audit chain intact.
- HTML report checked in a browser, including narrow width.

### Not verified / limits
- The scan engine's PE analysis still runs in-process (the isolated worker is used by the Research Lab only).
- PDF uses Microsoft JhengHei from Windows until Phase 9 bundles Noto Sans TC.
- Report integrity is tamper-evident against the recorded hash, not tamper-proof: someone with the user's rights can change both files and the database, but not without breaking the audit chain.

## [0.6.0] - 2026-11-02 — Phase 6: Windows Behavior Monitoring

### Added
- Passive telemetry (`monitor/`), design in SYSTEM_ARCHITECTURE.md §7:
  - Process creation and outbound network connections via psutil polling (stated limitation: short-lived activity can be missed; access-denied fields recorded as such).
  - Folder monitoring (watchdog) for user-selected folders, persisted in config, own data folder excluded, coalescing and overflow notice.
  - Windows event logs through a ctypes wevtapi binding (Unicode-safe): Sysmon (1/3/11/23/26), Security 4688, Microsoft Defender detections (1116/1117). Each source reports "available", "needs administrator" or "not installed". No history replay.
  - Self-filter: Sentinel X's own child processes are not reported.
- Correlation rules R1–R6 and alerts with facts and analysis stored and displayed separately; alert de-duplication; acknowledge / dismiss; event retention.
- Behavior Monitor page: sources, start/stop, live timeline with source/type/text filters, alerts, watched folders, Sysmon guide (official link + reviewed starting config, never installed by Sentinel X), and "restart as administrator" (confirmation dialog → UAC, fixed arguments).
- Schema v5 migration with backup. New dependencies psutil 6.1.0, watchdog 6.0.0.
- 54 new tests (360 total) using harmless synthetic activity: ping to 127.0.0.1, loopback TCP, file create/modify/rename/delete, and a copied `PING.EXE` listed as malicious only in local test intel to drive the full scan → monitor → R1 alert pipeline.

### Fixed during this phase
- R2 originally reported "known threat modified" when a threat was merely executed, because Windows reports FILE_MODIFY on access; now only creation/move counts unless the path was quarantined.

### Verified on this machine
- Real data folder migrated v4 → v5 (backup `sentinelx.db.bak-v4`).
- Unelevated: psutil sources and Defender available; Security log "needs administrator"; Sysmon "not installed"; folder watch "no folders configured".
- 12 s real monitoring run observed an externally started `PING.EXE` and a real network connection; monitor stopped cleanly on exit.

### Not verified
- The UAC relaunch itself (needs a person to answer the prompt); the argument builder and the confirmation flow are tested.
- Sysmon and Security 4688 ingestion against real logs (Sysmon not installed, Security needs admin); parsing is tested with recorded-format XML.

## [0.5.1] - 2026-11-02 — Engineering audit 2 fixes

See ENGINEERING_AUDIT.md (Audit 2). No new features.

### Fixed
- B1: quarantine verifies the handle's final path after opening (closes a junction-swap race).
- B2: vault reconciliation at startup (own `.part` leftovers removed, missing objects flagged, interrupted intakes marked RETAINED_ERROR), audit-logged.
- B3: restore records RESTORED before removing the vault object.
- B6: the assessor no longer returns CLEAN when only context engines completed; hash intel reports whether it can detect anything.
- B7: Threat Center marks threats whose file is gone; quarantine button explains an unavailable vault.
- 9 new tests (315 total).

## [0.5.0] - 2026-11-02 — Phase 5: Quarantine Manager

### Added
- Quarantine vault (`quarantine/vault.py`, `quarantine/win32fs.py`); design in SECURITY_DESIGN.md §5.
  - Vault DACL restricted to the current user SID, verified as SDDL on every start and re-hardened if changed (including ACEs added for Everyone/Users and on existing objects).
  - Race-free intake through a single locked handle opened without following reparse points; hash must match the verdict; copy fsynced and re-verified; DB + hash-chained audit entry written before the original is deleted by handle.
  - Refuses: non-CONFIRMED verdicts, missing confirmation or reason, stale verdicts, files modified since the scan, files in use, links/junctions in the path, hard-linked files, duplicates (same path + hash). Same hash elsewhere is linked as `duplicate_of`.
  - `.sxq` objects: magic + per-item random XOR key (not executable, not re-detected).
  - Integrity verification on demand and before every restore.
  - Restore only with confirmation, only if the audit entry matches the record, never overwriting, never through links or into the vault, via temp file + hash check + rename; Mark-of-the-Web restored.
  - No permanent-delete API or button exists.
- Quarantine page (list, verify, restore to original or another location) and a "隔離檔案…" action in the Threat Center; both use explicit confirmation dialogs (default button: No) that show path and hash.
- Schema v4 (quarantine metadata) with migration and backup.
- 30 new tests (306 total), including real ACL hardening and tampering, file-in-use, hard link, junction, DB-tampering redirection, tampered vault object, overwrite refusal, 10 MB round trip, MOTW preservation, and GUI flows with cancelled and accepted confirmations.

### Fixed during this phase
- Vault hardening could not remove an Everyone ACE (SDDL `WD` abbreviation not accepted by `icacls /remove`); now resets all explicit ACEs first.

### Verified on this machine
- Real data folder: schema v3 → v4 (backup `sentinelx.db.bak-v3`), vault DACL private.
- Real ClamAV detected EICAR → CONFIRMED_THREAT → quarantined (original removed, no EICAR bytes in the vault object) → integrity verified → restored with matching SHA-256 → test file deleted.

### Known limitations
- Hard-linked files are refused rather than quarantined (removing one name would leave the content reachable).
- An administrator can still take ownership of the vault; the ACL protects against other standard users and accidental access, not against admin-level malware.
- XOR obfuscation is not encryption.

## [0.4.0] - 2026-11-02 — Phase 4: Risk Assessment Engine

### Added
- `core/risk.py`: pure, evidence-based assessor (`risk-rules-1`). Grades each detection STRONG / MODERATE / WEAK / INFO with a stated reason, aggregates across engines, and classifies CLEAN / UNKNOWN / SUSPICIOUS / CONFIRMED_THREAT. Rules are documented in SYSTEM_ARCHITECTURE.md §6.
  - A single weak heuristic (any number from one engine) is never more than an observation.
  - PE evidence is never above WEAK; a missing signature is not evidence.
  - Independent-engine comparison: corroboration across engines, disagreement notes ("YARA found, ClamAV did not"), partial-failure notes.
  - Conflict handling: trusted known-good intelligence lowers a single-source confirmation to SUSPICIOUS for review.
  - Qualitative confidence (高/中/低) and an ordinal score that the explanation states is not a probability.
  - Every verdict carries a full zh-TW explanation listing each piece of evidence and its grade.
- Verdicts stored for every scanned file (excluded files get none; unreadable/limited files get UNKNOWN), linked to contributing detections, superseding the file's previous verdict. Scan summary and history show counts per class.
- False-positive management: suppressions by (hash, rule) or whole hash; suppressed evidence stays stored and visible but is not counted; applied to future scans; removable (deactivated, never deleted) with immediate re-assessment.
- Manual review workflow (`ReviewService`): confirm / mark false positive / escalate, reason required, only on the latest verdict, audit-logged; re-assessment from stored engine results creates a new verdict.
- **Threat Center page**: pending verdicts, full detail (explanation, raw engine results, review log, verdict history), review buttons, false-positive list.
- Dashboard: threat counts from latest verdicts, pending reviews, unassessed files.
- Static Analysis shows the combined assessment (not stored).
- Schema v3 migration (verdict confidence/review fields, `fp_suppressions`), with backup.
- 71 new tests (276 total): 49 risk-rule tests focused on conflicting and partial results, verdict persistence, review workflow, migration from v1 and v2, Threat Center GUI.

### Fixed during this phase
- Threat Center: after a review the selected row looked selected but the review buttons stayed disabled (re-selecting the current row emits no signal).

### Verified on this machine
- Real ClamAV scan of a folder with EICAR and a text file: EICAR → CONFIRMED_THREAT (信心 中, single strong source), text file → CLEAN; real database migrated v2 → v3 with backup `sentinelx.db.bak-v2`.

### Notes
- The verification scan left one CONFIRMED_THREAT record for the (since deleted) test file `eicar.com` in the real database; it is a true EICAR detection and stays as history.
- Risk rules are heuristics designed for transparency, not calibrated against a malware corpus (this project does not download real malware).

## [0.3.1] - 2026-11-02 — Engineering audit fixes

See ENGINEERING_AUDIT.md for details. No new features.

### Fixed
- **A1 (High):** a scan with only context engines (PE structure, hash intel without malicious entries) no longer reports "completed, nothing found"; it fails with an explanation. New `EngineStatus.detection_capable`.
- A2: scan jobs left `RUNNING` by a crash are marked `FAILED` at startup (audited).
- A3: closing the window or page during analysis cancels and joins the worker (no destroyed running `QThread`); static analysis is cancellable.
- A4: labels showing untrusted text are plain text (no rich-text injection).
- A5: YARA module allow-list can no longer be bypassed with a mid-line `import`.
- A6: a scan root that cannot be stat'ed is a skip, not a failed job.
- A7: ClamAV location uses `%ProgramFiles%`.
- A8: unexpected startup errors are shown in a dialog; exception hooks restored; DB closed after the window.
- A9/A10: YARA scan uses a consistent rule snapshot; rule counts cached.
- A11: tests for the real GUI entry point. 14 new tests (205 total).

## [0.3.0] - 2026-11-02 — Phase 3: Multi-Engine Detection

### Added
- Standardized `DetectionResult` model (renamed from `EngineOutcome`): kind FINDINGS / NO_FINDINGS / SKIPPED (not applicable, counts as completed) / ERROR, structured `DetectionRecord`s, plus `info` for non-detection facts.
- **ClamAV `clamd` backend** (`zVERSION`, `zINSTREAM` over loopback TCP; refuses non-loopback hosts). Both backends share one result mapper and pass one contract test suite. Selected with `clamav.backend` in config.
- **YARA engine** (yara-python 4.5.1): rule sets registered from files, copied into the data folder and pinned by SHA-256 (a modified copy is refused); validation rejects syntax errors, unknown modules, disallowed modules (`console`, `tests`) and `include`; invalid sets are kept disabled with the reason; rule set versioning (user value or `date-sha8`); rule ids `<namespace>.<rule>`; meta `severity` and `confirming`; matched string ids and offsets recorded (not bytes).
- **Hash intelligence engine**: import local SHA-256 lists (plain or CSV with label/verdict), per-source trust level; distinguishes MALICIOUS (finding), KNOWN_GOOD and UNKNOWN (both no finding, different `info.reputation`); conflicting sources are flagged.
- **PE static analysis engine** (pefile): identifies PE files (others SKIPPED), extracts architecture, type, .NET, subsystem, timestamp, entry point, sections with entropy and permissions, imports, exports, imphash, version info, overlay; anomaly records (W+X section, high entropy, packer section names, entry point outside sections, no imports, future timestamp, invalid signature, malformed PE) with LOW/MEDIUM/INFO severity only. Authenticode verified with WinVerifyTrust (no UI, no network). Unsigned is recorded as a fact, never a detection.
- Engine toggles in config (`engines.clamav/yara/hash_intel/pe_static`).
- **Threat Intelligence page**: import/remove hash sources, look up a hash, add/enable/disable/remove YARA rule sets with validation messages.
- **Static Analysis page**: analyze one file with all engines in a background thread; report with PE metadata, signature, sections, imports; all file-derived strings HTML-escaped.
- Database schema v2 with a forward-only migration framework and automatic pre-migration backup.
- 64 new tests (191 total), including a fake clamd server, real clamd started by the test (custom harmless signature, CJK paths, EICAR), YARA module/include/tamper tests, PE samples made by modifying a copy of the signed `python.exe` (also proves INVALID signature detection), migration from a v1 database, and HTML-escaping of hostile strings.

### Verified on this machine
- Real clamd 1.5.4: custom-signature detection on a CJK path and EICAR on disk.
- Real WinVerifyTrust: signed `python.exe` VALID, a modified copy INVALID, catalog-signed `notepad.exe` reported UNSIGNED (embedded) as documented.
- Real data folder migrated from schema v1 to v2 with backup `sentinelx.db.bak-v1`.

### Known limitations
- YARA is shown as unavailable until the user adds a rule set; Sentinel X does not ship rules.
- Catalog-signed Windows files show UNSIGNED for the embedded signature (no catalog lookup yet).
- clamd is not started by Sentinel X; the user runs it. `AlertExceedsMax` must be set in clamd.conf for limit alerts.
- pefile runs in-process without a hard timeout; a pathological PE could be slow (size limit still applies).
- A scan with ClamAV unavailable still runs on the other engines; the result screen does not yet warn specifically about the missing signature engine (planned with the Phase 4 risk explanation).

## [0.2.0] - 2026-11-02 — Phase 2: Scanner Engine

### Added
- Engine interface `DetectionEngine` (`availability`, `scan_batch`) and structured evidence model `DetectionRecord` (engine name/version, rule id, evidence, timestamp, SHA-256, confidence explanation).
- ClamAV adapter, `clamscan.exe` backend: locates the executable (config path or `C:\Program Files\ClamAV`), reports engine version, signature DB version and date; treats a missing DB as unavailable; batches files via `--file-list`; hidden subprocess with timeout and cancel-kill; `Heuristics.Limits.Exceeded` is reported as "not fully scanned", not as a finding; missing per-file result, crash, garbage output and timeout are all errors. Non-ASCII paths are passed as 8.3 short names when available.
- Safe walker: single file, directory, recursive; reparse points (symlinks/junctions) not followed by default; when following is enabled, only targets inside the scan root, with loop protection; depth, file-count and size limits; permission and other OS errors recorded per path without aborting.
- Streaming SHA-256 with cancellation between chunks; file metadata (size, mtime, ctime).
- Scan orchestrator with progress callbacks, cooperative cancellation, and job statuses COMPLETED / PARTIAL / CANCELLED / FAILED. No engine available → FAILED, never clean.
- Scan history persistence (jobs, per-file results, engine runs, detections) and exclusions (folder, file, extension, SHA-256) with validation; all scan and exclusion actions audited.
- Scan Center page: engine status with version and signature info, add file/folder targets, async scan on a QThread with progress and cancel, result summary, history and per-file results, exclusion management. Start is disabled with an explanation when no engine is available.
- Dashboard engine card now shows real engine status.
- Theme: distinct disabled-button style, navy tables/inputs/tabs.
- 79 new tests (127 total), including a fake `clamscan` process for crash/timeout/cancel/partial-output cases, Windows junction traversal tests, and a real-ClamAV EICAR test that skips when ClamAV is absent or Defender removes the file.

### Changed
- `files.sha256` and `files.size` are nullable (unreadable files are still recorded). `scan_jobs.status` gains `PARTIAL`. Schema version stays 1 because no database has been released; a Phase 1 dev database must be deleted.

### Fixed during this phase
- QThread could be destroyed while running (process abort) because `quit` was queued behind the finished handler; `quit` is now invoked directly from the worker thread.
- Exclusion type from the combo box arrived as a plain string, so SHA-256 / extension values were validated as paths.

### Verified against real ClamAV 1.5.4 (signatures daily 28171 / main 63 / bytecode 339)
- EICAR via stdin detected (`Eicar-Test-Signature`).
- EICAR on disk detected through the full Sentinel X pipeline (Defender did not remove it during the run; the test still skips if it does).
- Full pipeline with a custom `.hdb` hash signature for a harmless synthetic file: detections in ASCII, CJK and space-containing paths; clean CJK file assessed with no findings.
- Real `clamscan.exe` reads a UTF-8 `--file-list` with CJK paths correctly, so the 8.3 short-name workaround was removed (on zh-TW Windows the short names were not ASCII anyway).
- GUI scan of a real folder with ClamAV completes and shows version and signature date.

### Added (after ClamAV install)
- `clamav.database_dir` setting; default is `%LOCALAPPDATA%\SentinelX\clamav-db` when present, because writing `freshclam.conf` under `Program Files` needs administrator rights. `clamscan --version` reports only the first `--database`, so the adapter passes exactly one.

## [0.1.0] - 2026-11-02 — Phase 1: Core Architecture

### Added
- Project layout under `src/sentinelx` (app / core / services / storage / gui), `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`; editable install via `pip install -e ".[dev]"`.
- Per-user data root `%LOCALAPPDATA%\SentinelX` (override with `SENTINELX_HOME`) with `config.json`, `sentinelx.db`, `logs/`, `vault/`, `reports/`.
- Configuration (`AppConfig`, Pydantic): rejects unknown keys and out-of-range values, never overwrites a corrupt file, atomic save. `clamd_host` accepts loopback addresses only.
- Structured JSON Lines logging with rotation (5 MB × 5).
- SQLite database (SQLAlchemy 2.0): all 17 tables from DATABASE_SCHEMA.md, WAL, foreign keys, enum CHECK constraints, schema version tracking, refusal to open a newer schema.
- Hash-chained audit log with verification; app start/stop recorded.
- Centralized exception hierarchy (`SentinelXError` with zh-TW user messages) and global handlers for the main thread and worker threads; GUI errors are marshalled to the GUI thread.
- Privilege detection (standard / administrator / unknown); failures map to unknown, never to administrator.
- Composition root `bootstrap()` with dependency injection; `StatusService` provides live health data.
- PySide6 main window in Traditional Chinese, dark navy / cyan theme, 10-page navigation. Dashboard shows only live checks (version, privilege, engines, DB integrity, audit chain, data path). Pages not built yet say so and name their planned phase; they contain no controls.
- `--smoke-test MS` flag for automated startup verification.
- 48 tests (unit, integration, security, GUI).

### Not yet implemented
- Any scanning or detection engine (Phase 2+). The dashboard reports engines as not installed.
- Vault ACL hardening (Phase 5); the vault directory exists but has default permissions.
- Admin-mode relaunch and Sysmon guided setup (Phase 6).
- `.ts` translation files; strings are wrapped in `tr()` but only zh-TW exists.

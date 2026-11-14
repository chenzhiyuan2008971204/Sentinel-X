# Sentinel X — Engineering Audit

This file holds every audit, newest first.

---

# Audit 8 — 0.11 to 0.16 additions (0.16.0 in progress)

- Date: 2026-11-06
- Scope: execution lock, VirusTotal, YARA Forge, whole-drive protection, permanent delete, automatic updates, autostart watch, ransomware warning and decoys, trial-run room; risk rules, quarantine, performance and self-protection rechecked. Full report for the user in Traditional Chinese: `docs/AUDIT_8_zh-TW.md`.
- Method: code reading; full suite; harmless measurements (process-guard CPU per round, 20,000-file event burst, memory and CPU of the user's running 0.15.1). Phase 1 changed nothing; fixes were made after the user's approval ("Yes, fix in order"), each with a regression test that fails on the old code.
- Rule followed: no test weakened, skipped or deleted. Tests whose expectations encode the rule the user approved changing were updated (VirusTotal thresholds, risk-rules version, the fake YARA Forge URL, sandbox page tests now state `finished=True`).

## Summary

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| H1 | High | Performance | Process guard requested every process's program path every second: ~180 ms CPU per round, even with no known threat | Fixed (1.6 ms; 0 with no threat) |
| H2 | High | Classification | VirusTotal ≥10 alone was strong evidence → automatic quarantine of grey software; ClamAV + VirusTotal counted as independent | Fixed (risk-rules-4; VirusTotal-only threats never auto-quarantined) |
| H3 | High | Fake feature | Trial-run room build does not complete on a real computer; an unfinished change made every trial run fail (3 tests failing) | Unfinished change reverted; feature clearly disabled (`sandbox.FINISHED = False`) |
| H4 | High | Self-protection | Same-user programs could stop Sentinel X, edit its settings or remove its sign-in start unnoticed | Detection added (`app/self_check.py`); prevention needs a service/driver (out of scope) |
| M1 | Medium | Protection gap | Execution lock released programs that could not be fully checked | Fixed (retries, then held + notification) |
| M2 | Medium | Resources | Real-time protection spent VirusTotal quota on every new file and waited up to 20 s per batch | Fixed (lock areas only, no waiting, 350/day) |
| M3 | Medium | Protection gap | Real-time throughput capped at 100 files/s; file checks held the event lock. 20,000-file burst: 61 % after 129 s | Fixed (100 % after 13.6 s) |
| M4 | Medium | Resources | 0.15.1 after 12 h: app ~610 MB, clamd ~700 MB | Measuring: installed 0.16.0 sampled every 5 min for 12 h (`packaging/memwatch.py`, read-only) |
| M5 | Medium | Coverage | Ransomware warning blind in Pictures/Videos/Music/OneDrive without whole-drive protection | Fixed |
| M6 | Medium | Sandbox | VirtualBox version not checked before running unknown files | Open (with the sandbox) |
| L1 | Low | Exec lock | icacls follows links; unlocking removes every Everyone-deny entry | Fixed (links refused; pre-blocked files left alone). Link test skipped here: no symlink privilege |
| L2 | Low | Exec lock | Same size + mtime after a content change skips rescan/relock | Fixed: a moved Windows change time triggers a SHA-256 comparison with the scanned content (change time alone also moves on a program's first run, so it is not used for the execution lock) |
| L3 | Low | Updates | YARA Forge download URL not checked | Fixed |
| L4 | Low | Classification | Years-old VirusTotal "0 detections" counted as a full check | Fixed (180 days) |
| L5 | Low | GUI | Stop-process waited up to 5 s on the GUI thread; sandbox quarantine on the GUI thread | Fixed (1 s; quarantine in the background) |
| L6 | Low | Quarantine | Hard-linked threats cannot be auto-quarantined | No change (message explains; lock held) |

No critical findings in the reviewed scope. Checked without findings: engine errors never become CLEAN (`FileResult.assessed`); quarantine intake still refuses reparse points and hard links and works by handle; vault ids validated; no `shell=True`, `pickle` or `eval`; SQLite WAL with busy timeout; YARA Forge archive read is limited to the one expected member after the SHA-256 check.

## Remaining issues

M4 (measuring), M6 (with the sandbox) above; earlier R1, R2, R3, R6, R8, R9, R13 unchanged. Not verified: GUI responsiveness during large scans, behaviour on an 8 GB computer, the user's real database (the development shell sees an MSIX-virtualised copy of `%LOCALAPPDATA%`), autostart watch and ransomware warning inside the installed app.

## Test results

- Before fixes: 625 passed, 3 failed (all H3, the unfinished sandbox change).
- Regression tests against the unfixed code failed for H1 (program paths asked for every process) and H2; M3 was measured (61 % of 20,000 files after 129 s). The full suite after the fixes also found a race in the new autostart watch (thread and direct check writing the baseline at once): fixed with a lock, test added.
- After fixes: **642 passed, 0 failed, 1 skipped** (symbolic links need Developer Mode on this computer), 1 deselected (the single-instance test fails whenever the user's own Sentinel X is running); `ruff` clean. Installer not rebuilt yet.

---

# Audit 7 — real-time protection (0.10.0)

- Date: 2026-11-03
- Scope: `protection/` (clamd manager, folder scanner, process guard, vault watch, locations), `services/protection_service.py`, the protection page, tray and close behaviour, autostart, packaging changes; commit `9d8bb8c`
- Method: code reading; ClamAV config parsing of paths with spaces and Chinese (`clamconf`, no network); one minute of real file-event volume in the watched folders; a failing regression test for each suspected defect before fixing; full suite twice; rebuild and installation test.
- Rule followed: no new features; no test weakened, skipped or deleted.

## Summary

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| G1 | Medium | Lifecycle | Started with protection on (quit-on-last-window off), then protection turned off: closing the window left an invisible process holding the instance lock, so the next start said "already running" | Fixed |
| G2 | Medium | Protection gap | The process guard marked every process as seen even when no threats were known; a threat already running when its hash became known (e.g. a copy at another path) was never terminated | Fixed |
| G3 | Medium | Threading / resources | Removable-drive scans used a fresh, never-cancelled token: `stop()` waited 10 s, returned, and the scan went on (against a stopped clamd), writing to the database afterwards | Fixed |
| G5 | Low | Classification | Sentinel X's own reports copied into watched folders quote matched strings and were scanned, and could be quarantined (same in manual scans); files the user excluded produced "could not fully check" notifications | Fixed |

Checked without findings: ClamAV parses configuration paths with spaces and Chinese characters (`clamconf`); clamd and the research worker cannot outlive the app (job objects); the vault watch does not alarm on Sentinel X's own quarantining (real run); real-time batches stay out of the manual scan history; notifications cross threads through a queued signal.

## Remaining issues (new in this audit)

| ID | Severity | Issue | Plan |
|---|---|---|---|
| R18 | Low | Real-time scan records are never pruned. About 2.4 KB per scanned file (Phase 9 measurement); the watched folders produced 0 events in an idle minute here, but busy installers or build tools in Temp can add thousands of files a day. | Retention for realtime jobs (e.g. keep 30 days, always keep files with findings). **Resolved in 0.10.2**: clean batches older than 30 days are pruned at startup (tests in `test_limits_0_10_2.py`). |
| R19 | Info | The tray icon, notifications and sign-in start cannot be shown in the offscreen test environment; covered by logic tests only. | Manual check by the user. |

Earlier remaining issues are unchanged.

## Test results

- Regression tests against the unfixed code: **4 failed** (no quit; process not killed; stop took 10 s and the job was not cancelled; report quarantined).
- After fixes: **502 passed, 0 failed, 0 skipped**, twice; `ruff` clean; rebuilt 0.10.1 installer passes the installation test **23/23**.

---

# Audit 6 — after Phase 9 (0.9.0)

- Date: 2026-11-03
- Scope: Phase 9 code (signature service and first-start question, bundled ClamAV detection, packaging, installer, the rewritten scan list) and how it behaves for the intended users (Traditional Chinese Windows); commit `98c09d7`
- Method: code reading; a Chinese-named data folder (signature update, whole app, vault ACL, real clamscan and freshclam); uninstalling while the app runs; failing regression tests before each fix; full suite twice; rebuild and installation test.
- Rule followed: no new features; no test weakened, skipped or deleted.

## Summary

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| F1 | High | Windows compatibility | Signature updates crashed (`UnicodeEncodeError`) whenever the data folder path has non-ASCII characters — e.g. every user with a Chinese Windows user name, the main audience | Fixed |
| F2 | Low | Honesty | With ClamAV already working from its own signatures, the first-start question said none were downloaded and Settings said ClamAV could not be used | Fixed |
| F3 | Medium | Installer / hidden failure | Uninstalling while the app ran exited 0 but left 50 files and removed the uninstall entry (a half-removed program Windows no longer lists) | Fixed |

Checked without findings: the whole app with a Chinese-named data folder (database, logs, vault ACL with icacls, audit chain); real `clamscan.exe` with a Chinese signature folder (EICAR detected); real `freshclam.exe` with a UTF-8 config naming a Chinese folder; the bulk `job_files()` returns the same rows as before; the build and installer scripts; first-start question shown once and never downloads without a yes.

Disclosure: while probing freshclam (pointed at an unreachable local mirror), freshclam still contacted the official ClamAV servers and downloaded one daily patch into a temporary copy of the signatures, which was then deleted. The user's own signature folder was not changed.

## Findings

### F1 — Non-ASCII data folder broke signature updates (High)
- **Fix:** the freshclam config is written as UTF-8; ClamAV 1.5.4 freshclam reads it (verified with a real folder named 王小明: it read the local version and updated). The 8.3 short-path alternative was rejected: the Chinese folder had no ASCII short name.
- **Test:** `test_F1_update_with_chinese_data_folder`.

### F2 — Misleading signature status (Low)
- **Fix:** the signature service knows whether the ClamAV engine is already available; then no first-start question, and Settings says ClamAV uses signatures from another location.
- **Tests:** `test_F2_working_clamav_is_not_reported_missing`, `test_F2_settings_text_when_clamav_uses_other_signatures`.

### F3 — Uninstall while running (Medium)
- **Fix:** a named mutex is held together with the instance lock; `AppMutex` in the installer makes setup and uninstall refuse while it exists.
- **Tests:** `test_F3_running_mutex_held_with_the_lock`; installation test check "uninstall refused while running".

## Remaining issues

No new ones. Open: R1, R4, R6, R8–R13, R17 (R3 partly addressed).

## Test results

- Regression tests against the unfixed code: **3 failed** (F1, F2 ×2); F3 was reproduced with the real installer (50 files left, exit code 0).
- After fixes: **481 passed, 0 failed, 0 skipped**, twice; `ruff` clean; rebuilt 0.9.1 installer passes the installation test **21/21**, including "uninstall refused while running".

---

# Audit 5 — after Phase 8 (0.8.0)

- Date: 2026-11-02
- Scope: the Phase 8 code (settings, instance lock and restart, dashboard charts, indicators and timer, page transitions, TaskRunner/BusyBar, cancel buttons) and how it touches the older services; commit `f4790c2`
- Method: code reading; timing the indicator queries with 1 500 threat verdicts; a config with an out-of-range value; failing regression tests before each fix; full suite twice.
- Rule followed: no new features; no test weakened, skipped or deleted.

## Summary

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| E1 | Medium | GUI threading / performance | The indicator timer (every 10 s, GUI thread) loaded every threat row to count them: per-row queries plus a file-existence check per row. 1 500 threats froze the window ~0.7 s every 10 s; a threat on an unreachable network path could freeze it for seconds | Fixed |
| E2 | Low | Settings / data integrity | The file-limit box only went to 100 000 000; a larger stored value was shown clipped and written back clipped on any unrelated save (500 000 000 → 100 000 000) | Fixed |
| E3 | Low | Exception handling | A database error inside the timer slot reached the global handler, i.e. an error dialog every 10 s while the database is busy | Fixed |

Checked without findings: the admin relaunch quits the old window after UAC accepts, so the new one gets the lock; the research worker is dispatched before the lock is taken; the lock file lives in the data root, which scans and folder monitoring already skip; closing during a quarantine waits for it to finish; navigating to a busy page does not refresh it under the running task; the fade effect is removed when finished and replaced when interrupted; settings changes keep watched folders; every button is connected (test).

## Findings

### E1 — Indicator refresh loaded every threat row (Medium)
- **Fix:** `attention_counts()` returns both counts with two `COUNT` queries using the same definitions as the Threat Center; the timer and the Dashboard card use it. Measured with 1 500 threats: 0.71 s → 0.002 s.
- **Test:** `test_E1_indicators_use_counts_not_rows` (counts equal the row-based ones; `threats()` is not called).

### E2 — Clipped limit written back (Low)
- **Fix:** the box allows the full QSpinBox range, and a value left unchanged in the form keeps the stored value.
- **Test:** `test_E2_large_limit_not_changed_by_unrelated_save`.

### E3 — Timer errors became repeated dialogs (Low)
- **Fix:** the refresh is wrapped: errors are logged and shown as "狀態暫時無法更新" in the status bar; the next tick retries.
- **Test:** `test_E3_indicator_errors_are_contained`.

## Remaining issues

No new ones. Open from earlier audits: R1, R4, R6, R8–R14, R17 (R3 partly addressed).

## Test results

- Regression tests against the unfixed code: **3 failed** (no count method; 500 000 000 saved as 100 000 000; no count method to fail safely).
- After fixes: **465 passed, 0 failed, 0 skipped**, twice; `ruff` clean (default and F, B, E9, PLE, W605); real-data smoke start exit 0.

---

# Audit 4 — Phase 1–5 code next to the Phase 6–7 features (0.7.1)

- Date: 2026-11-02
- Scope: the older code (scanner, orchestrator, exclusions, audit log, database, quarantine vault, config, GUI pages) re-read for how it behaves now that monitoring, the Research Lab and reports exist: shared state across threads and processes, Sentinel X's own files, long work on the GUI thread; commit `54786c7`
- Method: code reading; reproductions with temporary data folders (scan of the data folder with a registered rule, two processes writing the audit log, a 500 000-hash import, scanning a watched folder); each regression test was run against the unfixed source (stashed) and failed, then against the fix; full suite twice; real-data smoke start and scan.
- Rule followed: no new features; no test weakened, skipped or deleted.

## Summary

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| D1 | Medium | Classification / quarantine safety | Scans did not skip Sentinel X's own data folder. Its YARA rule copies and its reports (which contain matched-string excerpts) were flagged by its own rules — SUSPICIOUS, or CONFIRMED_THREAT for a rule marked confirming, which would then allow quarantining the rule copy and break the YARA engine. Scanning the user profile (which contains `AppData\Local`) is enough. The vault also accepted files from the data folder and restores into it | Fixed |
| D2 | Low | GUI threading | Hash-list import ran on the GUI thread: 500 000 hashes (33 MB) froze the window for 21 s; at the 200 MB limit about 2 minutes "not responding" | Fixed |
| D3 | Medium | Audit integrity / concurrency | The audit log's lock only works within one process. Two Sentinel X processes on the same data (opened twice, or the old window still closing during the admin relaunch) could append at the same time, both chaining to the same previous hash; the Dashboard then reports a broken chain, which looks like tampering. Reproduced: broken at entry 79 of 600 | Fixed |

Checked without findings: thread safety of the audit log within a process (lock covers read + insert + commit); engine status caches (worst case a duplicate version probe); orchestrator (engine errors never clean, cancellation records pending files); config save (atomic); catalog signatures do not change any classification (signature status is a fact, never evidence); scanning a folder that the monitor watches creates no events (reads are not reported); every page that starts a thread is shut down before the database closes.

## Findings

### D1 — Own data folder scanned (Medium)
- **Reproduced:** temporary data folder, YARA rule registered, a lab report exported, scan of the data folder → the rule copy and both reports SUSPICIOUS.
- **Root cause:** no built-in exclusion; the walker only applied user exclusions. Phase 7 made it worse (reports quote matched bytes).
- **Fix:** `ExclusionSet.internal` — the scan service always excludes the data root ("Sentinel X 自己的資料資料夾…，不掃描"); counted as excluded, so the job is still COMPLETED. The vault refuses quarantine sources inside the data root and restore targets inside it (`protected_root`).
- **Tests:** `test_D1_scan_skips_own_data_folder`, `test_D1_vault_refuses_own_data_folder`.

### D2 — Hash import on the GUI thread (Low)
- **Fix:** the import runs in a background worker; the button is disabled meanwhile; closing waits for the single import transaction.
- **Tests:** `test_D2_hash_import_off_gui_thread`; two existing tests (`test_hash_import_lookup_remove`, `test_A4_labels_showing_untrusted_text_are_plain`) now wait for the import, with the same assertions.

### D3 — Audit chain fork across processes (Medium)
- **Root cause:** the "read last hash, insert" pair ran without a database write lock (pysqlite only begins a transaction at the first write), so two processes could read the same last hash.
- **Fix:** the first statement of the transaction is a no-op write, which takes SQLite's write lock before the last hash is read; the in-process lock stays. Reproduction re-run three times: 600/600 entries, chain intact.
- **Test:** `test_D3_two_processes_keep_one_chain` (two real processes).

### Also fixed
- An invalid escape (`"\/"`) introduced while fixing D1 produced a `SyntaxWarning`; corrected, and `W605` added to the audit's ruff check. The value was the same, so behaviour did not change.

## Remaining issues (new in this audit)

| ID | Severity | Issue | Plan |
|---|---|---|---|
| R15 | Low | Quarantine, restore and vault verification still run on the GUI thread; at the default 100 MB limit about a second, at the 4 GB maximum much longer. | Background workers with progress in Phase 8. |
| R16 | Low | Nothing prevents two Sentinel X windows on the same data. The audit chain is now safe (D3), but two monitors would record events twice. | Single-instance guard in Phase 8. |
| R17 | Info | Files created while elevated (admin relaunch) are owned by Administrators; they inherit the folder ACL, so the normal session can still use them. Not verified with a real UAC prompt. | Check during the Phase 9 manual tests. |

Earlier remaining issues are unchanged (R1, R2, R4, R6, R8–R14; R3 partly addressed).

## Test results

- Regression tests against the unfixed source: **4 failed** (D1 own files SUSPICIOUS; vault had no data-folder guard; import not asynchronous; chain broken at entry 8).
- After fixes: **443 passed, 0 failed, 0 skipped**, twice, also with `-W error::SyntaxWarning`; `ruff` clean (default and F, B, E9, PLE, W605).
- Real data: smoke start exit 0; a scan of the real data folder records it as one excluded entry (COMPLETED); audit chain intact; all reports unchanged.

---

# Audit 3 — after Phase 7 (0.7.0)

- Date: 2026-11-02
- Scope: whole codebase at 0.7.0, focus on the code no audit had covered yet: Phase 6 (monitoring: collectors, event-log binding, runner, event repository) and Phase 7 (Research Lab, isolated worker, signatures, reports); commit `387c410`
- Method: same as Audits 1–2 — code reading, `ruff` (default + F, B, E9, PLE), real-data inspection (DB `integrity_check`, FK check, schema version, no file with two latest verdicts, report hashes, audit chain), probes on real files (oversized PDF cell, catalog lookup cost on an unsigned 80 MB PE), one failing regression test per suspected defect before fixing, full suite twice.
- Rule followed: no new features; no test weakened, skipped or deleted.

## Summary

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| C1 | Medium | Reports / exception handling | A long table cell (e.g. a long verdict explanation or many detections) made ReportLab raise `LayoutError`, which escaped `generate()`: JSON was written and recorded, HTML and PDF were never produced, and the whole action reported failure | Fixed |
| C2 | Low | GUI threading / resources | The Reports page hashed every report file on the GUI thread, at startup and on every visit; with many or large reports the window freezes | Fixed |
| C3 | Low | Reports / integrity | "Save copy" checked the report hash, then copied without checking what was copied (a change in between was copied as if verified); it also allowed writing the copy into the reports folder over another recorded report | Fixed |
| C4 | Medium | Monitoring / resources | In the event-log binding, one event that could not be rendered raised out of the batch: the remaining event handles leaked and, because the cursor never advanced, that source failed on every poll from then on | Fixed |
| C5 | Low | Monitoring / exception handling | `AccessDenied` while reading a new process's name was not caught; the whole process poll failed and that cycle's new processes were lost | Fixed |
| C6 | Low | Monitoring / threading | `MonitorRunner.stop()` stopped the collectors and dropped the thread reference even when the loop had not finished within the timeout; the loop could keep using stopped collectors and a second loop could be started | Fixed |

No findings in: broken imports, missing dependencies (all pinned and installed; `pip check`: no broken requirements), Windows paths, fake GUI controls (only Settings is a stated Phase 8 placeholder, without controls), detection classification (the lab creates no verdicts — tested), database consistency (real DB: integrity ok, no FK violations, schema 5, no duplicate latest verdicts, 12 reports all unchanged, audit chain intact), quarantine (unchanged since Audit 2; one RESTORED item), HTML report escaping/CSP, worker isolation (JSON only, job object, timeout/cancel kill), path control of report names.

## Findings

### C1 — PDF layout error aborted report generation (Medium)
- **Reproduced:** a 60 000-character cell → `LayoutError` raised from `ReportService.generate`; only the JSON existed afterwards.
- **Root cause:** ReportLab cannot split one table cell across pages, and `generate()` only caught `ReportError`/`OSError`.
- **Fix:** PDF cells and paragraphs are cut to about 40 lines for their column width, with "（共 N 字，完整內容見 JSON 版報告）"; JSON and HTML keep the full text. Any unexpected writer error now fails only that format, is logged and listed in the result, and its temp file is removed.
- **Tests:** `test_C1_long_cell_does_not_abort_reports[2|10 columns]`, `test_C1_unexpected_writer_error_is_reported_not_raised`.

### C2 — Report hashing on the GUI thread (Low)
- **Fix:** the page lists reports at once ("檢查中…") and hashes them in a background worker; a refresh during hashing schedules one more pass; shutdown waits for it. Copy stays disabled until the report is verified; opening still re-hashes the one file.
- **Tests:** `test_C2_integrity_checked_off_the_gui_thread`; existing page tests now wait for verification (same assertions).

### C3 — Unverified copy and copies into the reports folder (Low)
- **Fix:** the copy's SHA-256 must equal the recorded hash, otherwise it is deleted and the action refused; destinations inside the reports folder are refused.
- **Test:** `test_C3_copy_verified_and_not_into_reports_dir`.

### C4 — One bad event stalled an event-log source (Medium)
- **Fix:** every handle returned by `EvtNext` is closed; an event that cannot be rendered is logged and skipped, later events in the batch still advance the cursor.
- **Test:** `test_C4_bad_event_is_skipped_and_handles_closed` (fake wevtapi).

### C5 — AccessDenied on a process name dropped the poll (Low)
- **Fix:** the name is read like the path and command line: denied fields are recorded in `access_denied`; a process whose parent id cannot be read is skipped alone.
- **Test:** `test_C5_access_denied_name_keeps_other_events` (two real harmless child processes).

### C6 — Runner stop after timeout (Low)
- **Fix:** `stop()` returns False and leaves the collectors and the thread reference alone when the loop is still running; the runner keeps reporting "running", so no second loop starts. A later `stop()` completes normally.
- **Test:** `test_C6_stop_timeout_keeps_runner_consistent`.

## Remaining issues (new in this audit)

| ID | Severity | Issue | Plan |
|---|---|---|---|
| R11 | Info | Since 0.7.0 the PE engine also looks up the system catalog for files without an embedded signature: measured +2.3 ms per unsigned PE and two extra full reads of the file (238 ms for 80 MB). | Accept for now (it removes false "unsigned" reports for Windows files); revisit with a path or size condition if scans of large unsigned PE sets get slow. |
| R12 | Low | YARA test rules have a match timeout but no compile timeout; a pathological rule (up to 1 MB) could keep the lab busy while compiling. Cancel waits for it. | Compile in the isolated worker in Phase 9 hardening. **Resolved in 0.10.2**: compiled first in the confined worker with the YARA timeout and cancel. |
| R13 | Low | Scan-job HTML and JSON reports embed every file's evidence; a scan of hundreds of thousands of files makes very large reports (PDF is capped). | Paged or summary-only HTML for huge jobs in Phase 8/9. |
| R14 | Info | In the frozen build the worker runs as `Sentinel X.exe --research-worker`; a windowed (no console) executable must still get a usable stdout from the parent's handle. | Verify in Phase 9 packaging tests. **Resolved in 0.9.0**: the worker writes to the inherited handle when `sys.stdout` is missing; verified from the packaged and the installed executable. |

Remaining issues R1, R2, R4, R6, R8–R10 are unchanged. R3 is partly addressed (Research Lab isolated; scan engine still in-process). R5 and R7 are resolved.

## Test results

- Before fixes: the 8 new regression tests — **8 failed** (all for the reasons described above, checked one by one).
- After fixes: **439 passed, 0 failed, 0 skipped**, twice in a row; `ruff` clean (default and F, B, E9, PLE); real-data smoke start exit 0; real reports still all "unchanged", audit chain intact.
- Two existing GUI tests were adapted to the now-asynchronous integrity check by waiting for it to finish; no assertion was removed or relaxed.

---

# Audit 2 — after Phase 5 (0.5.0)

- Date: 2026-11-02
- Scope: whole codebase at 0.5.0, focus on Phase 4 (risk, review) and Phase 5 (quarantine); commit `220e46c`
- Method: same as Audit 1 — code reading, `ruff` (F, B, E9, PLE), real-data inspection (DB integrity, FK check, schema, vault contents and DACL, duplicate latest verdicts), one failing regression test per suspected defect before fixing, full suite twice.
- Rule followed: no new features; no test weakened or skipped.

## Summary

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| B1 | Medium | Security / race | Quarantine checked the path for links, then opened it by path; a parent swapped for a junction in between would be followed | Fixed |
| B2 | Medium | Consistency | A crash between "recorded" and "original deleted" left a QUARANTINED item whose original still existed; partial `.part` copies were never cleaned; a missing vault object went unnoticed | Fixed |
| B3 | Low | Consistency | Restore removed the vault object before marking the item RESTORED; a crash in between left a QUARANTINED record without content | Fixed |
| B6 | Medium | Classification | The pure assessor returned CLEAN when only context engines (PE structure, hash intel without malicious hashes) had completed. The scan gate (A1) prevented it in scans, but static analysis and re-assessment call the assessor directly | Fixed |
| B7 | Low | UX / honesty | Threat Center listed threats whose file no longer existed without saying so; the quarantine button gave no reason when the vault was unavailable | Fixed |

No findings in: real database (`integrity_check` ok, no FK violations, no file with two "latest" verdicts), vault (empty after the Phase 5 verification, DACL still private), `ruff`, broken imports, missing dependencies, fake GUI controls, unsafe quarantine deletion (no delete API; reconciliation removes only Sentinel X's own `.part` temporaries).

## Findings

### B1 — Path re-resolution race at intake (Medium)
- **Reproduced:** with the pre-open `realpath` check bypassed (simulating a lost race), a file reached through a junction was quarantined.
- **Fix:** after opening, `GetFinalPathNameByHandleW` on the handle must equal the expected path, otherwise nothing is changed. Hash, copy and delete already used that handle.
- **Test:** `test_B1_handle_final_path_is_verified`.

### B2 — No startup reconciliation (Medium)
- **Fix:** on every start the vault removes its own `*.part` files, flags QUARANTINED items whose object is missing ("隔離檔案遺失"), and marks items whose original still exists with the same hash as RETAINED_ERROR (so they are not shown as contained). Each repair is audit-logged.
- **Tests:** `test_B2_interrupted_intake_reconciled`, `test_B2_missing_vault_object_flagged`.

### B3 — Restore ordering (Low)
- **Fix:** record RESTORED + audit first, then remove the vault object; a failed removal is noted on the item instead of raising after a successful restore.
- **Test:** `test_B3_restore_records_before_removing_vault_object`.

### B6 — Assessor could call a context-only result CLEAN (Medium)
- **Fix:** CLEAN now requires a completed assessment from an engine able to detect something; hash intel reports `detection_capable` in its result info. Otherwise the file is UNKNOWN with an explanation.
- **Note:** the first version of the fix counted only "no findings"; three existing tests (whole-file false-positive suppression) correctly failed, because an engine whose findings were all dismissed still examined the file. The rule was corrected; the tests were not changed.
- **Tests:** `test_B6_*` (4 cases) plus the existing suppression tests.

### B7 — Missing-file and unavailable-vault indications (Low)
- **Fix:** `ThreatRow.file_missing`, shown as "檔案已不在原位置"; the quarantine button carries the vault problem as a tooltip.
- **Test:** `test_B7_missing_file_is_indicated`.

## Remaining issues (new in this audit)

| ID | Severity | Issue | Plan |
|---|---|---|---|
| R8 | Low | Restore validates the target folder, then writes a temp file and renames; a folder swapped for a junction in that window would be followed. Unlike intake, there is no handle to check before data lands. | Open the target directory by handle and create the file relative to it (`NtCreateFile` with a root handle) in Phase 9 hardening. |
| R9 | Info | Reconciliation hashes the original of every QUARANTINED item whose path exists at each start; cost grows with the number of items. | Acceptable for now; revisit with large vaults. |
| R10 | Info | The real database keeps two CONFIRMED_THREAT verdicts for EICAR test files used in Phase 4/5 verification; the files no longer exist and are now labelled as such. | Expected history. |

Remaining issues R1–R7 from Audit 1 are unchanged.

## Test results

- Before fixes: the 9 new regression tests — **8 failed, 1 passed** (the passing one checks behaviour that was already correct).
- After fixes: **315 passed, 0 failed, 0 skipped**, twice in a row; `ruff` clean; real-data smoke start exit 0 with data unchanged.

---

# Audit 1 — after Phase 3 (0.3.0)

- Date: 2026-11-02
- Scope: whole codebase at 0.3.0 (Phases 0–3), commit `3320848`
- Method: read every module; static checks (`ruff` rules F, B, E9, PLE and the `S6xx` subprocess rules; `compileall`); inspected the real user database (`PRAGMA integrity_check`, `foreign_key_check`, constraints); wrote a failing regression test for every suspected defect **before** fixing it; ran the full suite twice.
- Rule followed: no new features; no test weakened or skipped to pass.

## Summary

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| A1 | **High** | Detection classification | A scan made only of context engines (PE structure + empty hash intel) reported "completed, nothing found" | Fixed |
| A2 | Medium | Database consistency | Jobs left `RUNNING` forever after a crash or forced exit | Fixed |
| A3 | Medium | Threading | Closing the window during a long engine call could destroy a running `QThread` (process abort); static analysis was not cancellable | Fixed |
| A4 | Medium | Security (UI) | Labels showing untrusted text (intel labels, paths, compiler messages) used Qt `AutoText` and could render injected rich text | Fixed |
| A5 | Low | Security (YARA) | Module allow-list bypass: `import "console"` placed after a rule on the same line was accepted | Fixed |
| A6 | Low | Exception handling | An `os.stat` error on a scan root failed the whole job instead of skipping that path | Fixed |
| A7 | Low | Windows paths | ClamAV default location hard-coded `C:\Program Files` instead of `%ProgramFiles%` | Fixed |
| A8 | Low | Exception handling | Non-Sentinel startup errors (e.g. `OSError`) exited with no dialog; global hooks not restored; DB closed before window/workers | Fixed |
| A9 | Low | Threading | YARA rule-set list could be swapped by a GUI reload in the middle of a scan (evidence missing rule-set name) | Fixed |
| A10 | Low | Performance | Every rule-set listing recompiled every rule file | Fixed |
| A11 | Low | Missing tests | GUI entry point `app/main.py` had 0 % coverage (smoke-tested manually only) | Fixed |
| A12 | Info | Code quality | Unused import in `tests/conftest.py` | Fixed |

No findings in: broken imports, missing dependencies (all imports map to `requirements.txt`), fake GUI interactions (every visible control is wired; unimplemented pages have no controls), quarantine operations (none exist yet — Phase 5), real database integrity (`ok`, no FK violations, status constraint includes `PARTIAL`).

## Findings

### A1 — Context-only scan reported as clean (High)
- **Symptom (reproduced):** with ClamAV missing, no YARA rules and no malicious hashes, a scan returned `COMPLETED` and the GUI said "引擎未發現已知威脅". Nothing capable of detecting malware had run.
- **Root cause:** Phase 3 added engines that are always "available" (PE structure analysis; hash intel even when empty). The Phase 2 gate "no available engine → FAILED" checked availability only, so these engines silently satisfied it. This was a regression of a stated Phase 2 invariant.
- **Fix:** `EngineStatus.detection_capable`. PE static analysis is never detection-capable; hash intel is only when at least one MALICIOUS hash is loaded; ClamAV/YARA are when available. The orchestrator and the Scan Center button share one gate (`has_detection_engine`); without such an engine the job is `FAILED` with an explanation.
- **Tests:** `test_A1_*` (4 tests).

### A2 — Stale RUNNING jobs (Medium)
- **Root cause:** a job is finished in the orchestrator's final step; a crash or kill before it leaves the row `RUNNING` permanently, shown as "執行中" in history.
- **Fix:** `ScanRepository.mark_interrupted_jobs()` at startup marks them `FAILED` ("程式未正常結束…") and writes an audit entry.
- **Test:** `test_A2_interrupted_jobs_marked_failed`.

### A3 — Running QThread destroyed on close (Medium)
- **Symptom (reproduced):** the regression test aborted the test process (exit code 9) when the static-analysis page was torn down mid-analysis.
- **Root cause:** `shutdown()` waited with a timeout (10 s / 30 s) and then let the `QThread` be destroyed while still running, which Qt treats as fatal. Static analysis had no cancel token at all.
- **Fix:** static analysis takes a `CancelToken` (checked between engines, honoured by ClamAV, `ScanCancelled` no longer swallowed); both pages cancel then wait without timeout; `main()` closes the window (running `closeEvent`) before disposing the database.
- **Test:** `test_A3_static_analysis_can_be_cancelled_on_shutdown`.

### A4 — Rich-text injection in labels (Medium)
- **Symptom (reproduced):** a label `<b>bold</b><img src='x'>` imported from a hash list was rendered as HTML in the lookup result.
- **Root cause:** `QLabel` defaults to `AutoText`, which switches to rich text when the content looks like HTML.
- **Fix:** every label that displays file-, engine- or import-derived text is `PlainText`; the engine-status label (intentionally rich) escapes all values.
- **Test:** `test_A4_labels_showing_untrusted_text_are_plain`.

### A5 — YARA module allow-list bypass (Low)
- **Root cause:** the import check regex was anchored to line start.
- **Fix:** unanchored match; a false match in a comment can only cause a rejection, never an acceptance.
- **Impact if unfixed:** limited (`console` only prints), but the allow-list must hold.
- **Test:** `test_A5_disallowed_module_anywhere_rejected` (2 cases).

### A6 — Root `stat` error failed the job (Low)
- **Fix:** handled like every other path error: a skip entry with a reason.
- **Test:** `test_A6_root_stat_error_is_skip`.

### A7 — Hard-coded `C:\Program Files` (Low)
- **Fix:** `default_locations()` reads `%ProgramFiles%` / `%ProgramFiles(x86)%`.
- **Test:** `test_A7_clamav_location_uses_programfiles`.

### A8 — Startup error handling (Low)
- **Fix:** any exception from `bootstrap()` is shown in a dialog (`show_startup_error`), hooks are uninstalled, exit code 2.
- **Tests:** `tests/gui/test_main_entry.py` (3 tests).

### A9 — YARA reload race (Low)
- **Fix:** `scan_batch` takes a locked snapshot of compiled rules and rule-set list; detections use the snapshot.

### A10 — Repeated YARA compilation (Low)
- **Fix:** rule counts cached per pinned SHA-256.

### A11 — Entry point untested (Low)
- **Fix:** real `python -m sentinelx --smoke-test` in a subprocess (audit log must show `APP_START`…`APP_STOP`), plus in-process startup-error tests.
- **Note:** a first in-process version called `exec()/quit()` on the shared pytest-qt `QApplication`, which put Qt into its closing state and broke later threaded GUI tests. That was a test-design error, not a product defect; the smoke test now runs in its own process.

## Reviewed and accepted (not defects)

- `ruff S603` on `subprocess` calls (`clamav.py` ×2, tests): argument lists, no shell, executables resolved from validated locations or test fixtures. Accepted.
- `walker.py` `pass` on `realpath` failure: a root that cannot be resolved is simply not added to the "inside roots" set, so links are refused — the safe direction.
- SQLite used from worker threads: each operation opens its own short session; verified by threaded GUI tests.

## Remaining issues (not fixed in this audit)

| ID | Severity | Issue | Plan |
|---|---|---|---|
| R1 | Low | A schema-v1 database created during Phase 1 (before `PARTIAL` existed) has a status CHECK without `PARTIAL`; a partial scan would fail to save. Only development databases are affected (the real user DB was checked and is correct). | Rebuild-table migration if a released v1 ever exists; otherwise delete old dev DBs. |
| R2 | Low | A YARA match cannot be interrupted mid-file; close/cancel may wait up to `engine_timeout_s` (default 120 s) for one file. | Consider a lower YARA-specific timeout in Phase 8 settings. |
| R3 | Low | pefile runs in-process without a hard time limit; a pathological PE could be slow (size limit applies). | Evaluate a subprocess sandbox for PE parsing in Phase 7. **Phase 7:** the Research Lab parses in an isolated worker (timeout, 1 GB cap, no child processes). The scan engine is still in-process; moving it costs ~0.3 s per PE file. |
| R4 | Low | Audit-chain verification is O(n) and runs on every dashboard refresh. | Incremental verification with a stored checkpoint in Phase 9. **Resolved in 0.10.2**: incremental between full passes (≤10 min apart, always at start); 20 000 entries: 297 ms full, 5.2 ms incremental. |
| R5 | Info | Quarantine is not implemented yet (Phase 5); the vault folder exists with default permissions and nothing is written to it. | Phase 5. |
| R6 | Info | Coverage of code run inside `QThread`s is under-reported (`static_analysis_service.py` shows 49 %) because coverage does not trace Qt threads by default; the code is exercised by GUI tests and by direct service tests. | Enable coverage's thread tracing or add direct tests in Phase 9. |
| R7 | Info | Catalog-signed Windows files show `UNSIGNED` for the embedded signature. | Catalog lookup (`CryptCATAdmin*`) in Phase 7. **Resolved in 0.7.0.** |

## Test results

- Before fixes: 191 passed; the 11 new regression tests: **10 failed, 1 passed** (the passing one covered already-correct behaviour), and the run ended with a Qt abort (A3).
- After fixes: **205 passed, 0 failed, 0 skipped**, run twice consecutively (≈55 s each), including real ClamAV `clamscan`, real `clamd`, real WinVerifyTrust and the real GUI entry point.
- `ruff check src tests --select F,B,E9,PLE`: all checks passed.
- Coverage: 94 % overall.

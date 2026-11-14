# Sentinel X — System Architecture (Research Edition)

Status: Phase 0 draft, awaiting review. Nothing described here is implemented yet.

## 1. Goals and non-goals

Goals
- A second-layer Windows 10/11 security research tool that sits beside Microsoft Defender.
- Its own orchestration, normalization, risk assessment, evidence correlation, quarantine and reporting. ClamAV, YARA and others are plugged in as engines, not as the product.
- Every verdict is explainable and traceable to engine output.

Non-goals
- Not a replacement for Defender. Not a kernel driver. No real-time blocking in v1.
- No claim of complete detection. Unknown is not clean, and missing signatures are not malware.
- No execution of analyzed files, ever.

## 2. Layered architecture

```
┌──────────────────────────────────────────────────────────┐
│ gui/            PySide6 pages, view-models, Qt workers    │  presentation
├──────────────────────────────────────────────────────────┤
│ services/       use-case facade: ScanService, QuarantineService, │ application
│                 ReportService, MonitorService, IntelService     │
├──────────────────────────────────────────────────────────┤
│ core/           domain: models, DetectionEngine protocol, │  domain
│                 RiskAssessor, Correlator, errors, events  │
├──────────────────────────────────────────────────────────┤
│ engines/        clamav, yara, hash_intel, pe_static       │  adapters
│ collectors/     sysmon, eventlog, psutil, fs_watch        │
│ storage/        SQLAlchemy models, repositories, quarantine vault │
│ reporting/      JSON / HTML / PDF writers                 │
└──────────────────────────────────────────────────────────┘
```

Rules
- Dependencies point downward only. `gui` never imports `engines` or `storage` directly; it talks to `services`.
- `core` has no I/O and no third-party imports except Pydantic. It is fully unit-testable.
- Dependencies are injected through a small composition root (`app/bootstrap.py`). No global singletons.

## 3. Proposed package layout

```
src/sentinelx/
  app/            bootstrap, config, logging, DI container
  core/           models, enums, errors, protocols, risk, correlation
  engines/        base.py, clamav.py, yara_engine.py, hash_intel.py, pe_static.py
  scanner/        walker, limits, orchestrator, cancellation, progress
  quarantine/     vault, integrity, restore
  collectors/     sysmon.py, eventlog.py, procmon.py (psutil), fswatch.py
  intel/          local intel store, import/export, rule sets
  reporting/      document (model + tool versions), builders, writers (JSON/HTML/PDF), templates/
  research/       sample facts, isolated PE/signature worker, YARA tester, comparison (Phase 7)
  storage/        db.py, orm.py, repositories/
  services/       facades used by the GUI
  gui/            main_window, pages/, widgets/, theme/, workers/
tests/            unit/, integration/, security/, gui/
rules/            versioned YARA rule sets (harmless)
docs/             user + developer manuals
```

## 4. Core contracts

Engine interface (all four detection adapters implement it):

```python
class DetectionEngine(Protocol):
    name: str
    def availability(self, refresh: bool = False) -> EngineStatus: ...   # installed? version? signature date?
    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken) -> dict[ScanTarget, EngineOutcome]: ...
```

Engines take batches (changed in Phase 2) because `clamscan` reloads its whole signature database on every start, which makes one process per file unusable. An engine must return one outcome per target; a missing outcome is treated as an error.

`EngineOutcome.kind` is one of `FINDINGS`, `NO_FINDINGS`, `ERROR`, `SKIPPED`. An engine error is never converted into "clean". The orchestrator records it and the file is marked as not fully assessed; the job becomes `PARTIAL`.

`Detection` (the "structured evidence" record):
- engine_name, engine_version, rule_id, evidence (typed payload), timestamp (UTC), file_sha256, confidence_explanation (text), severity_hint (INFO/LOW/MEDIUM/HIGH).

## 5. Scan flow

1. GUI/service creates a `ScanJob` (targets, exclusions, limits) and persists it.
2. `Walker` enumerates files lazily. It skips reparse points (symlinks and junctions) by default, enforces exclusions, size caps and depth caps.
3. For each file the `Orchestrator` opens it once read-only with shared-read access, computes SHA-256 in streaming mode, then fans out to enabled engines in a bounded thread pool.
4. Results go to the `RiskAssessor`, which produces a `Verdict` (CLEAN / UNKNOWN / SUSPICIOUS / CONFIRMED_THREAT) plus a written explanation, and preserves every raw engine result.
5. Repositories persist the file record, detections and verdict. Progress events are emitted to the GUI over Qt signals through a thin adapter.
6. Cancellation is cooperative: a `CancelToken` is checked between files and inside long engine calls (subprocess is terminated on cancel).

## 6. Risk assessment rules (implemented in Phase 4, `core/risk.py`, version `risk-rules-1`)

Each detection is graded STRONG / MODERATE / WEAK / INFO:
- STRONG: ClamAV signature (not PUA/heuristic); hash MALICIOUS in a HIGH-trust source; YARA rule with meta `confirming`.
- MODERATE: ClamAV PUA/heuristic; MEDIUM-trust hash; YARA high/medium severity; HIGH hit from an unrated engine.
- WEAK: PE anomalies (never more), LOW-trust hash, low YARA. INFO is shown but never counted.
- A hash source that conflicts with a known-good listing is graded one level lower.

Classification:
- CONFIRMED_THREAT: ≥1 STRONG, or MODERATE from ≥2 independent engines.
- SUSPICIOUS: ≥1 MODERATE, or WEAK from ≥2 independent engines (a single weak heuristic is only an observation).
- UNKNOWN: otherwise, if the file was not fully assessed.
- CLEAN: otherwise; "nothing known was found by these engines", never "safe".
- A HIGH-trust known-good listing lowers CONFIRMED to SUSPICIOUS (needs review) unless STRONG evidence comes from ≥2 engines.
- A missing signature is a fact in PE `info`, never evidence.
- The ordinal score (0–399) only sorts lists; it is never a probability.

Verdicts are stored per file and superseded, never edited. Manual review (confirm / false positive / escalate) requires a reason, is audit-logged, and creates suppressions plus a new verdict; evidence is never deleted.

## 7. Behavior monitoring (passive, implemented in Phase 6, `monitor/`)

Collectors (all read-only):
- `ProcessCollector`, `NetworkCollector` (psutil, polling every `poll_interval_s`; very short-lived processes/connections can be missed).
- `FolderWatchCollector` (watchdog, user-selected folders only, Sentinel X's own data folder excluded, bounded queue with overflow notice).
- `EventLogCollector` via wevtapi: Sysmon (1, 3, 11, 23, 26), Security 4688 (needs admin and process-creation auditing), Defender detections 1116/1117 (readable unelevated). Starts at the newest record (no history replay); unavailable channels report "not installed" or "needs administrator".
- Sentinel X's own child processes are ignored so the monitor does not report itself.

`MonitorRunner` (plain thread) polls → stores `security_events` → `Correlator` → `alerts` (deduplicated by key for 10 minutes, retention-pruned events). Correlation rules R1–R6 (threat executed, threat path written, encoded PowerShell, Office spawning shells, Temp/Downloads program connecting out, Defender detection compared with Sentinel X's verdict). Every alert has `observed_facts` (recorded data only) and `analysis` (interpretation incl. innocent explanations), shown in separate sections. Nothing is ever killed, blocked or changed.

Elevation: a button relaunches through UAC (`ShellExecuteW "runas"`) with fixed arguments `-m sentinelx --elevated`; the current instance then quits. Sysmon is never installed by Sentinel X: a guide links to the official page and saves a reviewed starting config.

## 8. Concurrency model

- GUI thread only renders. Long work runs in `QThreadPool` workers wrapping service calls.
- Scanner uses a bounded `ThreadPoolExecutor` (file-level parallelism); engine subprocesses have timeouts.
- SQLite in WAL mode, one writer through a repository layer, short transactions.

## 9. Windows-specific compatibility issues (to resolve before coding)

| # | Issue | Impact | Planned handling |
|---|---|---|---|
| W1 | ClamAV on Windows has no Linux-style on-access scanning (clamonacc) | No real-time scanning via ClamAV | On-demand scans only plus Watchdog-triggered scans of selected folders. Documented as a limitation. |
| W2 | ClamAV is bundled by the installer, but the signature DB comes from `freshclam` and may be missing or stale; users may also point to their own install | Engine may be absent or stale | Availability check shows version and DB age; never reports clean if absent or if the DB is missing. Two backends: `clamscan.exe` subprocess (default) and `clamd` over loopback TCP (see §11). |
| W3 | "Standalone YARA" | Rule engine availability | **Resolved in Phase 3:** `yara-python` 4.5.1 (libyara 4.5.1) wheel works on CPython 3.12 / Windows 11; no `yara64.exe` fallback needed. Rules are compiled from source text (not paths) and files are matched from memory, avoiding libyara's non-ASCII path handling. |
| W4 | Microsoft Defender will quarantine or delete EICAR and some test files as they are written | Tests flake or vanish | EICAR is assembled at runtime from split strings, written only into a dedicated test folder, and tests tolerate "file removed by AV". Document an optional Defender exclusion for the test dir that the user adds manually; Sentinel X never edits Defender settings. |
| W5 | Sysmon cannot be redistributed and needs admin rights to install; Security/Sysmon logs need elevation to read | Monitoring may be unavailable | Unelevated by default with an optional user-triggered admin restart (§11). Guided Sysmon setup, never a silent install. Features degrade per source with a clear status; no silent failure. `pywin32` (`win32evtlog`) evaluated for event reads. |
| W15 | UAC elevation from a Python/PyInstaller app | Admin mode | Relaunch via `ShellExecuteW` with `runas`; pass only a fixed flag, never user-controlled arguments; detect elevation with `IsUserAnAdmin`/token check. |
| W16 | CJK fonts in Qt and in PDF output | zh-TW UI and reports | Qt uses `Microsoft JhengHei UI` with fallbacks; ReportLab must embed a CJK-capable TTF (Noto Sans TC, SIL OFL licensed, bundled) because the built-in PDF fonts have no Chinese glyphs. |
| W6 | Reparse points: symlinks, junctions, mount points; NTFS alternate data streams; 8.3 names; case-insensitive paths | Traversal and path-confusion attacks | Use `os.lstat` plus `FILE_ATTRIBUTE_REPARSE_POINT` checks, resolve with `Path.resolve(strict=True)` and compare against allowed roots; ignore ADS by default and report it as a finding for later phases. |
| W7 | Path length over 260 chars and reserved names (CON, NUL) | Walker errors | Use `\\?\` extended paths internally, normalize and validate, treat reserved names as errors, not crashes. |
| W8 | File locking: in-use files cannot be moved or read exclusively | Quarantine move fails | Open with share-read; quarantine uses copy, verify hash, then remove original; on failure report and leave the original untouched. |
| W9 | NTFS ACLs, not POSIX modes | Vault protection | Create the vault under `%LOCALAPPDATA%\SentinelX\vault` with an inherited-ACL reset granting only the current user. Store content under random IDs with a non-executable extension (`.sxq`). Use `icacls` via subprocess or `pywin32` security APIs; verify in tests. |
| W10 | Mark-of-the-Web (Zone.Identifier ADS) | Restored files lose or keep origin info | Record the stream in metadata; decide at Phase 5 whether to preserve it on restore. |
| W11 | PySide6 and PyInstaller on Windows: large bundles, Qt plugin collection, occasional AV false positives on frozen executables | Packaging at Phase 9 | Use `--onedir` first; document false-positive risk. |
| W12 | `watchdog` ReadDirectoryChangesW can overflow its buffer under bursts | Missed events | Handle overflow by rescanning the directory; surface a "possible missed events" notice. |
| W13 | PDF reporting libraries need pure-Python or bundled binaries | Packaging weight | Use ReportLab (pure Python) for PDF. HTML reports use Jinja2 templates with autoescaping. |
| W14 | Console encoding and non-ASCII paths (this machine already has CJK path names) | Subprocess output mangled | Always pass argument lists, decode subprocess output as UTF-8 with replacement, test with CJK paths. |

## 10. Dependency list (planned)

PySide6, SQLAlchemy 2.x, Pydantic 2.x, pefile, yara-python (decision pending, W3), psutil, watchdog, pywin32 (event log, ACLs, elevation), ReportLab, Jinja2, pytest, pytest-qt, pytest-cov, PyInstaller. Bundled at packaging time: ClamAV Windows build (GPLv2, with license and source link) and Noto Sans TC font (OFL). External, user-installed: Sysmon. Installer tool for Phase 9: Inno Setup (decision recorded then).

## 11. Review decisions (2026-11-02)

1. **ClamAV: both modes.** `ClamAVAdapter` has two backends behind one interface: `ClamscanBackend` (subprocess `clamscan.exe`, default, simplest isolation) and `ClamdBackend` (talks to a running `clamd` over TCP). Selectable in Settings. `clamd` must listen on `127.0.0.1` only; the adapter refuses a non-loopback address. Both backends share one output parser and the same rule that errors are never clean. `clamscan` ships in Phase 2, `clamd` lands in Phase 3 after the shared tests exist.
2. **Optional administrator mode.** The app always starts unelevated. A "Restart as administrator" action in Settings and on the Behavior Monitor page relaunches the app through `ShellExecuteW(..., "runas", ...)`, which shows the normal Windows UAC prompt. The app never elevates silently and never stays elevated across restarts by default. The title bar and status bar show the current privilege level. Admin-only features (Sysmon channel, Security log) show "requires administrator mode" when unavailable.
3. **Bundle into the installer: ClamAV yes, Sysmon no (needs reconfirmation).**
   - ClamAV is GPLv2. Redistributing the unmodified official Windows build is allowed if the installer ships the license text and a source offer or link. The Phase 9 installer bundles ClamAV, its licenses, and runs `freshclam` on first launch only after the user agrees (it downloads signatures from the Internet).
   - Sysmon is a Microsoft Sysinternals tool. Its license does not allow redistribution, and installing it adds a system driver and service, which the security design forbids doing automatically. So the installer will not bundle Sysmon. Instead, the app detects Sysmon and offers a guided setup: it opens the official Microsoft download page and shows the install steps and a recommended harmless config. The user installs it themselves.
4. **Traditional Chinese UI.** All UI strings are zh-TW. Technical terms that have no common translation (SHA-256, YARA, PE, Sysmon, CONFIRMED_THREAT codes in exports) stay in English. Strings still go through Qt's `tr()` and `.ts` files so English can be added later without code changes. Reports default to zh-TW; JSON exports keep English keys and enum values for machine use.

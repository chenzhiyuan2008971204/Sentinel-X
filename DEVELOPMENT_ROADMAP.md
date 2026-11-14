# Sentinel X — Development Roadmap

Rule: one phase at a time. A phase is done only when its exit criteria are met by passing tests. After each phase: update CHANGELOG.md, docs, and report done / not done.

| Phase | Name | Key deliverables | Exit criteria (evidence required) |
|---|---|---|---|
| 0 | Architecture | 5 design documents | User review and approval |
| 1 | Core architecture | Project layout, pyproject/requirements, config, structured logging, DB init + models, exception handling, bootstrap, minimal zh-TW PySide6 window with `tr()` setup, privilege-level detection | `pytest` green; app window opens on Windows with Chinese text rendered; DB created and migrated |
| 2 | Scanner engine | Walker, hashing, progress, cancel, exclusions, scan history, ClamAV adapter (`clamscan` backend) with availability check | EICAR detected via ClamAV when installed; engine-missing and engine-error never reported clean; symlink and size-limit tests pass |
| 3 | Multi-engine detection | `clamd` backend, YARA, hash intelligence, PE static analysis, `DetectionResult` model | Both ClamAV backends pass the same contract tests; `clamd` refuses non-loopback; each engine independently tested |
| 4 | Risk assessment | Evidence aggregation, 4-class verdicts, explanations, manual review | Conflict-matrix tests pass; weak heuristic alone never yields CONFIRMED_THREAT |
| 5 | Quarantine | Vault, integrity-checked restore, audit trail, duplicate handling | Round-trip hash test; traversal/symlink/race tests; no auto-delete |
| 6 | Behavior monitoring | Sysmon + Event Log + psutil + folder watch, timeline, alerts (passive), optional admin-mode relaunch, guided Sysmon setup | Synthetic harmless activity appears in timeline; degraded-source handling tested; elevation relaunch tested manually and documented |
| 7 | Research Lab | PE/hash/signature viewers, YARA tester, comparison, exportable reports | Reports contain source evidence and tool versions; nothing executed |
| 8 | Full GUI | All 10 pages wired to real data, progress, cancellation | Every nav item and control exercised by pytest-qt; no placeholder stats |
| 9 | QA and release | Full test passes, security tests, PyInstaller + installer bundling ClamAV (with GPL license and source link) and CJK font, first-run `freshclam` consent, zh-TW manuals, release notes | Final quality report; installer installs and launches clean on a fresh Windows 11; bundled ClamAV detected with correct version |
| Opt | AI Threat Analyst | Offline-capable evidence explainer | Cannot trigger quarantine or deletion; consent required for any upload |

## Cross-phase tracks
- Security review at the end of every phase (checklist in SECURITY_DESIGN.md).
- `/audit` after phases 3, 5, 8 and 9.
- Dependency list kept current in `docs/DEPENDENCIES.md`.

## Risks
1. Defender interferes with EICAR tests (see SYSTEM_ARCHITECTURE W4).
2. ClamAV/Sysmon not installed on the dev machine; tests must skip with explicit reasons rather than pass silently.
3. Scope size: GUI polish (Phase 8) is the likeliest to slip; core correctness takes priority.

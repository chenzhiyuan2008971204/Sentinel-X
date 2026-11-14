# Sentinel X — Test Strategy

## 1. Principles
- A feature is complete only with passing tests as evidence.
- Tests never use real malware. Allowed samples: the EICAR string (built at runtime) and harmless synthetic files (random bytes, fake PE headers, text with YARA-triggering marker strings).
- Missing external tools (ClamAV, Sysmon, admin rights) cause an explicit `skip` with a reason, and a summary of skips is printed. Skips are never counted as passes in the release report.
- Tests are never weakened to make them pass.

## 2. Tooling
pytest, pytest-qt (GUI), pytest-cov, pytest-timeout, hypothesis (path and parser fuzzing), `tmp_path` for all file work. Markers: `unit`, `integration`, `security`, `gui`, `windows`, `needs_clamav`, `needs_sysmon`, `slow`.

## 3. Layers

| Layer | Scope | Examples |
|---|---|---|
| Unit | `core`, risk rules, parsers, repositories (in-memory SQLite) | classification matrix; ClamAV output parser; hash chain |
| Integration | scanner + real engines + DB | EICAR through ClamAV into verdict and history; YARA + PE + hash combined |
| Security | hostile inputs and misuse | path traversal, symlink/junction, oversize, malformed PE, zip bomb handed to ClamAV with limits, ACL on vault, shell-injection via filenames |
| GUI | pytest-qt, offscreen platform | every nav item opens; scan start/cancel; no placeholder text |
| Windows compatibility | `windows` marker | CJK and long paths, locked file, reserved names, ADS, CRLF output |
| Performance / resource | bounded | scan 10k small files within memory cap; cancel latency; UI thread never blocked |
| Packaging | Phase 9 | PyInstaller build launches; clean-VM install |

## 4. Defender interaction (important)
EICAR files are often removed by Defender within seconds. Strategy:
1. Build EICAR bytes from split constants at test time; never commit it.
2. Tests that need the file on disk write it to a dedicated folder under the temp directory and expect that it may disappear; the test treats "file vanished" as `skip(reason="removed by real-time protection")`, not a failure and not a pass.
3. Where possible, test engines through in-memory/stream interfaces or via engine mocks that return recorded real outputs (fixtures stored as text, not as samples).
4. The user may manually add a Defender exclusion for the test folder. Sentinel X never modifies Defender.

## 5. Critical behavior tests (must exist before the related phase closes)

Scanner
- Engine missing → result is `UNKNOWN`/not assessed, never CLEAN.
- Engine crash/timeout/garbled output → `EngineError` recorded, scan marked partial.
- Cancellation stops within a bounded time and kills child processes.
- Permission-denied file → recorded as not assessed.
- Symlink/junction pointing outside the root is not followed.
- File over size limit is skipped with a recorded reason.

ClamAV backends
- `clamscan` and `clamd` backends pass one shared contract test suite (same inputs, same normalized outputs).
- `clamd` backend refuses a non-loopback host; `clamd` down mid-scan → `EngineError`, not clean.
- Missing signature DB → engine reported unavailable.

Privilege and localization
- Privilege detection reports the correct level; the admin relaunch builds a fixed argument list (unit test on the command builder; the UAC prompt itself is a documented manual test).
- zh-TW strings load through `tr()`; GUI test asserts Chinese labels render (no tofu boxes check via font coverage).
- PDF report with Chinese text embeds the CJK font and the text is extractable.

Risk
- Weak heuristic alone ≠ CONFIRMED_THREAT.
- Unsigned PE alone ≠ SUSPICIOUS-as-malware (at most an informational note).
- Two engines disagree (one signature hit, one clean) → verdict keeps both results and explains.
- Manual dismissal is audit-logged and does not delete evidence.

Quarantine
- Round-trip: quarantine → restore yields identical SHA-256.
- Tampered vault object → restore refused.
- Restore onto existing file refused; restore target traversal refused.
- Vault ACL is user-only.
- No code path removes a vault object (static check plus test).

Monitoring
- Synthetic harmless activity (spawning `cmd /c echo`, creating a temp file) appears as events with correct fields.
- Missing admin/Sysmon → source reported unavailable, others still work.

Reporting
- Reports escape hostile strings (`<script>` in filename).
- Reports include engine versions and rule versions.

AI module (optional)
- Cannot call quarantine/delete APIs (enforced by interface; test with a spy).

## 6. Coverage and gates
- Target ≥ 85% line coverage on `core`, `scanner`, `quarantine`, `engines`; GUI measured but not gated.
- CI-style gate command (local script): lint (ruff), type check (mypy on `core` and `services`), pytest all non-skipped, then a skip summary.
- Each phase report lists: tests added, pass/fail/skip counts, skip reasons.

## 7. Test data management
- `tests/data/` holds only harmless text fixtures and recorded tool outputs.
- Generators in `tests/factories.py` create synthetic PE headers, large sparse files, deep directory trees and hostile filenames at runtime.

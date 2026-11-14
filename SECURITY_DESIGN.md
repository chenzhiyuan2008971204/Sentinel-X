# Sentinel X — Security Design

## 1. Threat model

Assets: the user's files, the quarantine vault, the evidence database, the application itself.

Adversaries and inputs
- Malicious files being scanned (parser exploits in our own code, resource exhaustion, zip bombs, path tricks).
- Malicious or tampered rule/intel files imported by the user.
- Local unprivileged processes trying to tamper with the vault, DB or config.
- Attacker-controlled strings inside files, event logs and process names that end up in the GUI, reports or AI prompts.

Out of scope: kernel-level adversaries, a fully compromised admin account, physical access.

## 2. Hard rules (mirrored from CLAUDE.md)

1. Never execute, load or import analyzed files. Static, read-only handling only.
2. Never disable or modify Windows Defender or system settings.
3. Never permanently delete a suspicious file automatically. Quarantine is a move into the vault, and the vault never auto-purges.
4. Never download real malware. Tests use EICAR (assembled at runtime) and synthetic harmless files.
5. Behavior monitoring is passive. No process termination, no blocking.
6. Quarantine, restore and any destructive-looking action require explicit user confirmation, and are audit-logged.
7. AI output is advisory only and can never trigger an action.

## 3. File handling

- Open files read-only with share-read; never follow reparse points unless explicitly enabled and then only inside allowed roots.
- Path validation: normalize, resolve, compare against the scan root; reject reserved device names, ADS syntax in user-supplied paths, and `..` escapes.
- Limits (configurable, with defaults): max file size per engine, max directory depth, max files per job, per-engine timeout, max archive expansion ratio and depth (archives are scanned by ClamAV only; we do not unpack them ourselves in v1).
- Streaming hashing with a fixed chunk size. No whole-file reads into memory for large files.
- Permission errors are recorded per file and surface as "not assessed", never as clean.

## 4. Subprocess and engine isolation

- Engines that shell out (`clamscan.exe`, optional `yara64.exe`) are launched with argument lists (no shell), absolute resolved executable paths, a timeout, and captured stdout/stderr decoded as UTF-8 with replacement.
- Output is parsed with strict parsers; unexpected output is an `EngineError`.
- Engine paths come from config and are validated (file exists, expected name, optional Authenticode check displayed to the user).

## 5. Quarantine vault (implemented in Phase 5, `quarantine/`)

- Location `%LOCALAPPDATA%\SentinelX\vault`. On every start the DACL is read back as SDDL and, unless it is protected with a single ACE for the current user SID, reset (`icacls /reset /T`, then `/inheritance:r /grant:r *SID:(OI)(CI)F`). If that fails, quarantine is disabled and the reason is shown.
- Objects are `<uuid>.sxq`: a 4-byte magic and the content XORed with a random 32-byte per-item key. Not executable, not re-detected by other AV. Obfuscation is accident prevention, not a security control.
- Only the latest `CONFIRMED_THREAT` verdict can be quarantined, with a reason and an explicit confirmation dialog showing the file and hash.
- Intake is race-free: the file is opened once (`GENERIC_READ|DELETE`, share READ only, `FILE_FLAG_OPEN_REPARSE_POINT`), refused if it is a reparse point, a directory, has more than one hard link, or its path resolves through a link. Hash, copy and delete use that same handle; the hash must equal the verdict's hash ("modified since scan" otherwise). The copy is fsynced, renamed into place and re-verified. The DB record and the audit entry are written before the original is deleted by handle; if deletion fails the item is `RETAINED_ERROR` and the original is untouched.
- Restore requires: explicit confirmation; the item's hash-chained audit entry must be intact and match path, hash and vault id (editing the DB cannot redirect a restore); target absolute, no ADS/wildcards/reserved names, folder not reached through a link, not inside the vault, never overwriting; decode to a temp file, verify SHA-256, then rename. Mark-of-the-Web is restored if it existed. The vault object is removed only after a verified restore.
- VirusTotal (0.15.0): only SHA-256 values leave the computer, only after consent, over HTTPS to www.virustotal.com. The API key is stored with DPAPI (current user), never logged, audited or shown.
- Permanent delete of vault content exists only as a user action (0.14.0): one service method that requires `confirmed=True`, called only by the quarantine page after a confirmation dialog. The record and audit entry are kept, and the deleted file's hash still counts as a threat. Nothing deletes automatically.
- Duplicates: same path + same hash is refused; same hash at another path is quarantined and linked (`duplicate_of`).

## 6. Data protection and integrity

- SQLite in WAL mode under the user profile; foreign keys on; migrations versioned.
- Audit log is append-only at the application level (hash-chained entries: each row stores the hash of the previous row) so tampering is detectable. This detects tampering; it does not prevent it.
- No telemetry. No network access in v1 except where the user explicitly enables something, off by default. The one planned case is ClamAV signature updates (`freshclam`), which run only after the user agrees on first launch and can be turned off in Settings.
- Secrets (future API keys) are stored with Windows DPAPI, never in plain config.

## 7. Untrusted text handling

- All strings that originate from files, events or engines are escaped before rendering in Qt rich text, HTML reports (Jinja2 autoescape on) and PDFs.
- No `eval`, no `pickle` on external data, no YAML `load` (use `safe_load`), no `shell=True`.
- Import of rule/intel files is validated against a schema; YARA rules are compiled in a restricted context (no external modules beyond the allowed set) before activation.

## 8. Privilege model

- Starts unelevated every time. Optional administrator mode is entered only by an explicit user action that relaunches the app through the Windows UAC prompt. The relaunch passes a fixed internal flag only; no user- or file-derived arguments.
- In admin mode the same hard rules apply: no Defender changes, no auto-deletion, passive monitoring only. Admin mode is shown permanently in the title bar and status bar, and entering/leaving it is audit-logged.
- Sentinel X itself installs no services, drivers or scheduled tasks in v1. `clamd`, if the user enables it, is started as a normal user process bound to 127.0.0.1, not as a Windows service.
- Sysmon is never installed by Sentinel X; setup is guided and performed by the user.
- Bundled ClamAV binaries are verified by hash at install time and their path is fixed under the install directory; the user can override with an external install.

## 9. Per-phase security checklist

- [ ] New inputs validated; new subprocess calls use arg lists and timeouts.
- [ ] Errors never turn into "clean".
- [ ] No new auto-destructive path.
- [ ] Security tests added (traversal, symlink, oversize, malformed input).
- [ ] Logs contain no file contents and no secrets.
- [ ] Dependencies reviewed and pinned.

## 10. Known limitations (to be published in user docs)

- Real-time protection (0.10.0) adds opt-in active responses, both on by default once protection is enabled and
  both switchable: automatic quarantine of CONFIRMED_THREAT files (never deletion) and termination of processes whose
  executable hash exactly matches a confirmed or quarantined threat. Excluded from termination: critical Windows
  processes, Microsoft-signed programs, Sentinel X and its children. Behaviour monitoring itself stays passive.
  No kernel driver: nothing is blocked before it starts; processes are found by polling (1 s).
- Detection quality is bounded by the engines and rule sets installed; undetected malware will be reported as CLEAN or UNKNOWN.
- No real-time protection; Defender remains the primary defense.
- Hash-chained audit logs detect tampering only if an external copy of the latest hash is kept.
- Frozen PyInstaller builds may be flagged by some AV products.

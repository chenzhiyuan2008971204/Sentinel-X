"""Real-time protection: ties the resident ClamAV scanner, folder watching, removable drives,
the process guard and the vault watch to the existing scan, verdict and quarantine services.

Every file goes through the same orchestrator and risk rules as a manual scan (recorded as
scan jobs with origin "realtime"), so verdicts and evidence look the same everywhere.
Automatic actions are limited to what the user enabled: quarantining CONFIRMED_THREAT files
(never deleting) and terminating processes started from a confirmed or quarantined threat.
"""

from __future__ import annotations

import collections
import logging
import os
import re
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from sentinelx.app.config import AppConfig, ConfigStore
from sentinelx.app.paths import AppPaths
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import AuditActor, Classification, QuarantineStatus, SignatureStatus
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.engines.base import DetectionEngine
from sentinelx.engines.virustotal import RealtimeVirusTotal, VirusTotalEngine
from sentinelx.protection import locations
from sentinelx.protection.autostart import AutostartEntry, AutostartWatch, read_entries
from sentinelx.protection import ransomware as ransomware_mod
from sentinelx.protection.ransomware import Alert, Decoys, RansomwareDetector, stop_process
from sentinelx.protection.clamd_manager import ClamdManager
from sentinelx.protection.process_guard import ProcessGuard, Termination
from sentinelx.protection import exec_lock
from sentinelx.protection.exec_lock import HELD, PENDING, LockEntry, LockRegistry
from sentinelx.protection.realtime import FolderScanner, VaultWatch
from sentinelx.quarantine.win32fs import QuarantineError
from sentinelx.research.sample import read_motw
from sentinelx.scanner.exclusions import norm_path
from sentinelx.scanner.orchestrator import ScanOrchestrator
from sentinelx.services.quarantine_service import QuarantineService
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.scan_repository import ExclusionRepository, FileRow, ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

log = logging.getLogger(__name__)
GATE_SUFFIXES = frozenset({".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle", ".bat", ".cmd", ".ps1",
                           ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr", ".com", ".jar", ".lnk", ".iso", ".img",
                           ".zip", ".7z", ".rar"})
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "SentinelX"
BACKGROUND_FLAG = "--background"
CLAMD_WAIT_S = 120.0
RETRY_DELAYS_S = (20.0, 60.0, 180.0)  # programs that could not be fully checked (audit 8, M1)

Notifier = Callable[[str, str, str], None]  # (level: info|warn|bad, title, message)


EXTERNAL_ENGINES = frozenset({"VirusTotal"})
NEW_FILE_S = 120.0
RULE_SUFFIXES = frozenset({".yar", ".yara", ".rule", ".rules"})
SIGNATURE_SUFFIXES = frozenset({".ndb", ".ldb", ".hdb", ".hsb", ".mdb", ".msb", ".cdb"})  # ClamAV text signatures


def is_rule_source(path: str) -> bool:
    """A detection-rule text file (YARA rules, ClamAV text signatures). Such files contain the
    very byte patterns they describe, so engines match them; they are never quarantined or
    acted on automatically (found on the user's computer: YARA Forge's rule file was
    auto-quarantined). Only plain text qualifies: no NUL bytes, and YARA files must look like
    rules."""
    suffix = Path(path).suffix.lower()
    if suffix not in RULE_SUFFIXES | SIGNATURE_SUFFIXES:
        return False
    try:
        with open(path, "rb") as f:
            head = f.read(256 * 1024)
    except OSError:
        return False
    if b"\x00" in head:
        return False
    if suffix in SIGNATURE_SUFFIXES:
        return True
    text = head.decode("utf-8", "replace")
    return bool(re.search(r"^\s*(private\s+|global\s+)*rule\s+\w+", text, re.M)) and "condition:" in text


def _created_recently(path: str) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False
    born = getattr(st, "st_birthtime", None) or st.st_ctime  # Windows: creation time
    return time.time() - born < NEW_FILE_S


def _only_external(f: FileRow) -> bool:
    """True when every detection comes from another vendor's verdict (no local engine agreed)."""
    engines = {d.split(":", 1)[0].strip() for d in f.detections}
    return bool(engines) and engines <= EXTERNAL_ENGINES


@dataclass(frozen=True)
class Activity:
    at: str
    path: str
    result: str  # zh-TW text of the outcome
    action: str
    level: str  # info | warn | bad


@dataclass(frozen=True)
class ProtectionStatus:
    enabled: bool
    running: bool
    engine_state: str
    engine_detail: str
    folders: tuple[str, ...]
    drives: tuple[str, ...]
    guard_running: bool
    queue: int
    scanned: int
    blocked: int
    terminated: int


def _key(p: Path) -> str:
    """Same normalization as FolderScanner.watched()."""
    return os.path.normcase(str(p))


def autostart_command(executable: str, frozen: bool) -> str:
    if frozen:
        return f'"{executable}" {BACKGROUND_FLAG}'
    pyw = Path(executable).with_name("pythonw.exe")
    return f'"{pyw if pyw.is_file() else executable}" -m sentinelx {BACKGROUND_FLAG}'


class ProtectionService:
    def __init__(self, paths: AppPaths, config: AppConfig, store: ConfigStore, engines: Sequence[DetectionEngine],
                 scans: ScanRepository, exclusions: ExclusionRepository, verdicts: VerdictRepository,
                 quarantine: QuarantineService, audit: AuditLog, *, clamd: ClamdManager | None = None,
                 removable: Callable[[], list[Path]] = locations.removable_drives,
                 folders: Callable[[], list[tuple[str, Path]]] | None = None,
                 vault_dir: Path | None = None, own_change_age: Callable[[], float] = lambda: 1e9,
                 registry: object | None = None, internal_hashes: Callable[[], set[str]] = set,
                 downloads: Callable[[], Path | None] | None = None,
                 locker: tuple[Callable[[Path], bool], Callable[[Path], bool]] | None = None,
                 drives: Callable[[], list[Path]] = locations.fixed_drives,
                 lock_areas: Callable[[], list[Path]] | None = None,
                 autostart_reader: Callable[[], list[AutostartEntry]] | None = None,
                 ransomware: RansomwareDetector | None = None, decoys: Decoys | None = None,
                 user_folders: Callable[[], list[Path]] | None = None) -> None:
        self._paths = paths
        self._config = config
        self._store = store
        # VirusTotal: only for files people bring in, never waiting (audit 8, M2)
        self._other_engines = [RealtimeVirusTotal(e, lambda p: self._in_lock_area(str(p)))
                               if isinstance(e, VirusTotalEngine) else e
                               for e in engines if e.name != "ClamAV"]
        self._fallback_clamav = next((e for e in engines if e.name == "ClamAV"), None)
        self._scans = scans
        self._exclusions = exclusions
        self._verdicts = verdicts
        self._quarantine = quarantine
        self._audit = audit
        self.clamd = clamd
        self._removable = removable
        self._folders = folders
        self._vault_dir = vault_dir
        self._own_change_age = own_change_age
        self._registry = registry
        self._internal_hashes = internal_hashes  # Sentinel X's own reports, wherever they were copied
        self._downloads = downloads or (lambda: locations.downloads())  # looked up late (tests patch it)
        self._drives_fn = drives
        self._lock_areas = lock_areas
        self._autostart_reader = autostart_reader or read_entries
        self.autostart: AutostartWatch | None = None
        self._user_folders = user_folders or (lambda: ransomware_mod.user_folders())  # looked up late (tests patch it)
        self.decoys = decoys or Decoys()
        self.ransomware = ransomware or RansomwareDetector(decoys=self.decoys.paths, decoy_changed=self.decoys.changed)
        self._deny, self._allow = locker or (exec_lock.deny_execute, exec_lock.allow_execute)
        self.locks = LockRegistry(paths.root / "exec_locks.json")
        self._cleared: dict[str, tuple[int, int] | None] = {}  # checked/unlocked files: path -> (size, mtime)
        self._retries: dict[str, tuple[int, float]] = {}  # unchecked locked programs: key -> (tries, due)
        self._cancel = CancelToken()
        self.notifier: Notifier = lambda _l, _t, _m: None
        self._activity: collections.deque[Activity] = collections.deque(maxlen=500)
        self._counts = {"scanned": 0, "blocked": 0, "terminated": 0}
        self._scanner: FolderScanner | None = None
        self._guard: ProcessGuard | None = None
        self._vault_watch: VaultWatch | None = None
        self._drives: set[str] = set()
        self._stop = threading.Event()
        self._drive_thread: threading.Thread | None = None
        self._hash_cache: tuple[float, set[str]] = (0.0, set())
        self._lock = threading.Lock()

    # ---------- settings ----------
    @property
    def settings(self):  # type: ignore[no-untyped-def]
        return self._config.protection

    def update(self, **changes: bool) -> None:
        p = self._config.protection
        for k, v in changes.items():
            if not hasattr(p, k):
                raise ValueError(f"unknown protection setting {k}")
            setattr(p, k, bool(v))
        self._store.save(self._config)
        self._audit.record("PROTECTION_SETTINGS", actor=AuditActor.USER, detail=changes)
        if "start_at_login" in changes or "enabled" in changes:
            self.apply_autostart()
        if self.running and any(k.startswith("watch_") for k in changes):
            self._apply_folders()
        if self.running and "kill_known_threats" in changes:
            self._apply_guard()
        if self.running and "low_memory" in changes and self.clamd is not None:
            # Memory-saving mode: no resident ClamAV (about 950 MB); see _scan_files.
            if self.settings.low_memory:
                self.clamd.stop()
            else:
                self.clamd.start()
        if self.running and "watch_autostart" in changes:
            self._apply_autostart_watch()
        if "ransomware_decoys" in changes:
            if self.settings.ransomware_decoys and self.running:
                self.decoys.place()
            elif not self.settings.ransomware_decoys:
                self.decoys.remove()

    def set_enabled(self, on: bool) -> None:
        self.update(enabled=on)
        if on:
            self.start()
        else:
            self.stop()

    # ---------- autostart (per-user Run key; no administrator rights) ----------
    def _reg(self):  # type: ignore[no-untyped-def]
        if self._registry is not None:
            return self._registry
        import winreg

        return winreg

    def autostart_enabled(self) -> bool:
        reg = self._reg()
        try:
            with reg.OpenKey(reg.HKEY_CURRENT_USER, RUN_KEY) as k:
                reg.QueryValueEx(k, RUN_VALUE)
            return True
        except OSError:
            return False

    def apply_autostart(self) -> bool:
        """Create or remove the sign-in start value from the setting. True when it was wanted
        but missing, i.e. it had to be restored."""
        want = self.settings.enabled and self.settings.start_at_login
        restored = want and not self.autostart_enabled()
        reg = self._reg()
        with reg.CreateKey(reg.HKEY_CURRENT_USER, RUN_KEY) as k:
            if want:
                reg.SetValueEx(k, RUN_VALUE, 0, reg.REG_SZ,
                               autostart_command(sys.executable, bool(getattr(sys, "frozen", False))))
            else:
                try:
                    reg.DeleteValue(k, RUN_VALUE)
                except OSError:
                    pass
        return restored

    # ---------- lifecycle ----------
    @property
    def running(self) -> bool:
        return self._scanner is not None

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self._stop.clear()
            self._cancel = CancelToken()
            if self.clamd is not None and not self.settings.low_memory:
                self.clamd.start()
            self._scanner = FolderScanner(self._scan_batch, exclude=[self._paths.root], on_locked=self._locked,
                                          on_overflow=self._overflow, on_seen=self._seen, skip=self._skip_noise,
                                          on_event=self._file_event, first=lambda p: self.locks.get(p) is not None)
            self._scanner.start()
            self._apply_folders()
            for e in self.locks.entries(PENDING):  # locked when the app last stopped: check them again
                if Path(e.path).exists():
                    self._scanner.notify(e.path)
                else:
                    self.locks.remove(e.path)
            self._drives = set()
            self._drive_thread = threading.Thread(target=self._drive_loop, name="sentinelx-drives", daemon=True)
            self._drive_thread.start()
            self._apply_guard()
            self._apply_autostart_watch()
            if self.settings.ransomware_decoys:
                self.decoys.place()
            if self._vault_dir is not None:
                self._vault_watch = VaultWatch(self._vault_dir, self._own_change_age, self._vault_tamper)
                self._vault_watch.start()
        self._audit.record("PROTECTION_START", actor=AuditActor.SYSTEM,
                           detail={"folders": self.status().folders, "auto_quarantine": self.settings.auto_quarantine,
                                   "kill_known_threats": self.settings.kill_known_threats})

    def stop(self) -> None:
        with self._lock:
            if not self.running:
                return
            self._stop.set()
            self._cancel.cancel()  # running scans (e.g. a whole USB drive) stop at the next file (audit G3)
            if self._drive_thread is not None:
                self._drive_thread.join(10)
                self._drive_thread = None
            if self._scanner is not None:
                self._scanner.stop()
                self._scanner = None
            if self._guard is not None:
                self._guard.stop()
                self._guard = None
            if self.autostart is not None:
                self.autostart.stop()
                self.autostart = None
            if self._vault_watch is not None:
                self._vault_watch.stop()
                self._vault_watch = None
            if self.clamd is not None:
                self.clamd.stop()
        # Protection is off: files still waiting for their scan must not stay unusable.
        # Threats and suspicious files (HELD) stay locked until the user unlocks them.
        for e in self.locks.entries(PENDING):
            self._release(e.path, "防護已停止，未完成檢查")
        self._audit.record("PROTECTION_STOP", actor=AuditActor.SYSTEM, detail=dict(self._counts))

    def _skip_noise(self, path: str) -> bool:
        return self.settings.watch_all_drives and self._folders is None and locations.noisy(path)

    def _fixed_folders(self) -> list[tuple[str, Path]]:
        if self._folders is not None:
            return self._folders()
        s = self.settings
        if s.watch_all_drives:
            # Whole drives cover Downloads, Desktop, Documents and Temp; watching those too would
            # only deliver every event twice.
            return [(f"磁碟 {d.drive}", d) for d in self._drives_fn()]
        folders = locations.watched_folders(downloads_=s.watch_downloads, desktop_documents=s.watch_desktop_documents,
                                            temp=s.watch_temp)
        if s.ransomware_watch:
            # The ransomware warning needs file events from all the user's folders (audit 8, M5).
            covered = [_key(p).rstrip("\\/") + os.sep for _l, p in folders]
            for p in self._user_folders():
                k = _key(p).rstrip("\\/") + os.sep
                if p.is_dir() and not any(k.startswith(c) for c in covered):
                    folders.append((f"勒索病毒警報：{p.name}", p))
                    covered.append(k)
        return folders

    def _apply_folders(self) -> None:
        assert self._scanner is not None
        wanted = {_key(p): p for _l, p in self._fixed_folders()}
        drives = {_key(Path(d)) for d in self._drives}
        for key in list(self._scanner.watched()):
            if key not in wanted and key not in drives:
                self._scanner.unwatch(Path(key))
        for p in wanted.values():
            self._scanner.watch(p)

    def _apply_guard(self) -> None:
        if self.settings.kill_known_threats and self._guard is None:
            self._guard = ProcessGuard(self.threat_hashes, self._terminated)
            self._guard.start()
        elif not self.settings.kill_known_threats and self._guard is not None:
            self._guard.stop()
            self._guard = None

    # ---------- autostart watch ----------
    def _apply_autostart_watch(self) -> None:
        if self.settings.watch_autostart and self.autostart is None:
            self.autostart = AutostartWatch(self._paths.root / "autostart_baseline.json", self._autostart_new,
                                            read=self._autostart_reader)
            self.autostart.start()
        elif not self.settings.watch_autostart and self.autostart is not None:
            self.autostart.stop()
            self.autostart = None

    def _own_entry(self, e: AutostartEntry) -> bool:
        """Sentinel X's own start-at-login value (set and removed by apply_autostart)."""
        return e.name == RUN_VALUE and "目前使用者" in e.location and BACKGROUND_FLAG in e.command

    def _autostart_new(self, e: AutostartEntry) -> None:
        """A program newly set to start with Windows: record it, scan its file, tell the user
        unless it is a clean file with a valid digital signature. Nothing is removed."""
        if self._own_entry(e) or self._cancel.cancelled:
            return
        program = e.program()
        where = f"{e.location}「{e.name}」"
        self._audit.record("AUTOSTART_ADDED", actor=AuditActor.SYSTEM, subject=str(program or e.command),
                           detail={"location": e.location, "name": e.name, "command": e.command[:500]})
        if program is None or not program.is_file():
            self._record(str(program or ""), "新增開機自動執行", f"{where}：找不到它要啟動的程式檔，無法檢查", "warn")
            self.notifier("warn", "新增開機自動執行", f"{where}：找不到它要啟動的程式檔，無法檢查。指令：{e.command[:160]}")
            return
        rows = self._scan_files([program])
        f = next((r for r in rows if r.classification is not None), None)
        if f is None:
            self._record(str(program), "新增開機自動執行", f"{where}：已排除，未檢查", "info")
            return
        if f.classification in (Classification.CONFIRMED_THREAT, Classification.SUSPICIOUS):
            self._act(f)  # same notification and (for confirmed threats) quarantine as any file
            self._record(str(program), "新增開機自動執行", f"{where}：" + ("確認威脅" if f.classification is Classification.CONFIRMED_THREAT else "可疑"), "bad")
            return
        from sentinelx.engines.authenticode import inspect_signature

        sig = inspect_signature(program)
        if f.classification is Classification.CLEAN and sig.status is SignatureStatus.VALID and sig.chain:
            self._record(str(program), "新增開機自動執行",
                         f"{where}：未發現已知威脅；有效數位簽章：{sig.chain[0].subject}", "info")
            return
        why = "無法完整檢查" if f.classification is Classification.UNKNOWN else "未發現已知威脅"
        sig_text = "數位簽章無效（檔案可能被修改）" if sig.status is SignatureStatus.INVALID else "沒有有效的數位簽章"
        text = f"{program.name} 會在每次開機時自動執行（{where}）。{why}，但{sig_text}。如果不是你剛裝的軟體，請小心。"
        self._record(str(program), "新增開機自動執行", text, "warn")
        self.notifier("warn", "新增開機自動執行", text)

    def autostart_entries(self) -> list[AutostartEntry]:
        return self.autostart.entries() if self.autostart is not None else []

    # ---------- ransomware warning ----------
    def _file_event(self, kind: str, path: str, dest: str | None) -> None:
        if not self.settings.ransomware_watch or self._cancel.cancelled:
            return
        alert = self.ransomware.event(kind, path, dest)
        if alert is not None:
            self._ransomware_alert(alert)

    def _ransomware_alert(self, a: Alert) -> None:
        names = "、".join(f"{w.name}（寫入 {w.written_mb:g} MB）" for w in a.writers) or "找不到（可能以系統管理員身分執行）"
        self._audit.record("RANSOMWARE_ALERT", actor=AuditActor.SYSTEM, subject=a.examples[0] if a.examples else "",
                           detail={"level": a.level, "reason": a.reason, "examples": a.examples,
                                   "writers": [{"pid": w.pid, "name": w.name, "exe": w.exe, "mb": w.written_mb}
                                               for w in a.writers]})
        self._record(a.examples[0] if a.examples else "", "勒索病毒警報" if a.level == "bad" else "大量文件被修改",
                     f"{a.reason} 寫入最多的程式：{names}", a.level)
        title = "可能有勒索病毒正在加密檔案！" if a.level == "bad" else "大量文件在短時間內被修改"
        self.notifier(a.level, title, f"{a.reason} 寫入最多的程式：{names}。到 Sentinel X「即時防護」可以停止它。")
        for w in a.writers:  # check the writers' program files too (a confirmed threat is quarantined)
            if w.exe and self._scanner is not None:
                self._scanner.notify(w.exe)

    def stop_writer(self, pid: int, name: str) -> str:
        """The user chose to stop a program named in a ransomware warning."""
        msg = stop_process(pid, name)
        self._audit.record("RANSOMWARE_STOP_PROCESS", actor=AuditActor.USER, subject=name,
                           detail={"pid": pid, "result": msg})
        self._record("", "停止程式", msg, "info")
        return msg

    def dismiss_ransomware_alert(self) -> None:
        self.ransomware.alert = None

    def _drive_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.check_drives()
            except Exception:  # noqa: BLE001
                log.exception("removable drive check failed")
            if self.settings.ransomware_watch:
                self.ransomware.tick()
            try:
                self.retry_unchecked()
            except Exception:  # noqa: BLE001
                log.exception("retrying unchecked programs failed")
            self._stop.wait(3.0)

    def check_drives(self) -> list[Path]:
        """Watch newly inserted removable drives and scan what is already on them."""
        if self._scanner is None:
            return []
        current = {str(d): d for d in (self._removable() if self.settings.watch_removable else [])}
        new = [d for k, d in current.items() if k not in self._drives]
        for k in list(self._drives):
            if k not in current:
                self._scanner.unwatch(Path(k))
        self._drives = set(current)
        for d in new:
            self._scanner.watch(d)
            self._record(str(d), "偵測到卸除式磁碟", "掃描整個磁碟", "info")
            self.notifier("info", "偵測到卸除式磁碟", f"正在掃描 {d}")
            self._scan_batch([d])
        return new

    # ---------- threats ----------
    def threat_hashes(self) -> set[str]:
        ts, cached = self._hash_cache
        if time.monotonic() - ts < 5.0:
            return cached
        hashes = {sha for _p, sha, cls, _v, _q in self._verdicts.threat_index_rows()
                  if sha and cls is Classification.CONFIRMED_THREAT}
        # A quarantined (or deleted) file the user has since marked as a false positive is not
        # stopped: its re-downloaded copy must be able to run. A copy still judged a confirmed
        # threat (other evidence than the dismissed one) stays on the list above.
        dismissed = {s.sha256 for s in self._verdicts.active_suppressions()}
        hashes |= {q.sha256 for q in self._quarantine.items()
                   if q.status in (QuarantineStatus.QUARANTINED, QuarantineStatus.DELETED)
                   and q.sha256 not in dismissed}
        self._hash_cache = (time.monotonic(), hashes)
        return hashes

    def _terminated(self, t: Termination) -> None:
        if t.killed:
            self._counts["terminated"] += 1
        self._audit.record("THREAT_PROCESS_TERMINATED" if t.killed else "THREAT_PROCESS_FOUND", actor=AuditActor.SYSTEM,
                           subject=t.path, detail={"pid": t.pid, "sha256": t.sha256, "result": t.detail})
        level = "bad" if t.killed else "warn"
        self._record(t.path, "威脅程序正在執行", f"{t.detail}（PID {t.pid}）", level)
        self.notifier(level, "已終止威脅程序" if t.killed else "發現威脅程序",
                      f"{t.name}（PID {t.pid}）：{t.detail}")

    def _vault_tamper(self, kind: str, path: str) -> None:
        self._audit.record("VAULT_CHANGED_EXTERNALLY", actor=AuditActor.SYSTEM, subject=path, detail={"event": kind})
        self._record(path, "隔離區被其他程式變更", f"事件：{kind}；請到「隔離區」驗證完整性", "bad")
        self.notifier("bad", "隔離區被其他程式變更", f"{Path(path).name}（{kind}）。請到「隔離區」驗證完整性。")

    # ---------- scanning ----------
    def _engines(self) -> list[DetectionEngine]:
        c = self.clamd
        if c is not None:
            waited = time.monotonic()
            while c.state == ClamdManager.STARTING and time.monotonic() - waited < CLAMD_WAIT_S and not self._stop.is_set():
                time.sleep(0.5)
            engine = c.engine()
            if engine is not None:
                return [engine, *self._other_engines]
        # clamd not available: the slower clamscan engine, so files are still checked
        return [e for e in (self._fallback_clamav, *self._other_engines) if e is not None]

    def _scan_files(self, paths: list[Path]) -> list[FileRow]:
        """Scan with the same engines, exclusions and suppressions as real-time protection.

        Memory-saving mode: ClamAV is not resident. Files people bring in (Downloads, Desktop,
        Documents, USB drives) are still checked by ClamAV, started for the batch (slower);
        everything else by the other engines only (YARA, hash intelligence, PE, VirusTotal)."""
        if self.settings.low_memory:
            brought_in = [p for p in paths if self._in_lock_area(str(p))]
            rest = [p for p in paths if not self._in_lock_area(str(p))]
            rows: list[FileRow] = []
            if brought_in:
                rows += self._scan_with(brought_in, [e for e in (self._fallback_clamav, *self._other_engines) if e])
            if rest:
                rows += self._scan_with(rest, list(self._other_engines))
            return rows
        return self._scan_with(paths, self._engines())

    def _scan_with(self, paths: list[Path], engines: list[DetectionEngine]) -> list[FileRow]:
        exclusions = self._exclusions.active_set()
        exclusions.internal.append(norm_path(self._paths.root).rstrip("\\/"))
        exclusions.hashes |= self._internal_hashes()
        cancel = self._cancel
        orch = ScanOrchestrator(engines, self._scans, self._config.scan,
                                suppressions=self._verdicts.active_suppressions())
        summary = orch.run(paths, exclusions, cancel, origin="realtime")
        self._counts["scanned"] += summary.files_seen
        return [] if cancel.cancelled else list(self._scans.job_files(summary.job_id))

    def _scan_batch(self, paths: list[Path]) -> None:
        if self._cancel.cancelled:
            return
        # empty when protection was stopped meanwhile: no actions or notifications afterwards
        for f in self._scan_files(paths):
            if self._scanner is not None:
                self._scanner.remember_content(f.path, f.sha256)
            # Excluded files have no verdict: the user (or Sentinel X for its own files) chose not
            # to assess them, so they are neither acted on nor reported (audit G5).
            if f.classification is not None:
                self._act(f)
            elif self.locks.get(f.path) is not None:
                self._settle_lock(f)  # excluded by the user: no verdict, just unlock

    # ---------- execution lock (new programs in Downloads) ----------
    def _seen(self, path: str, kind: str = "created") -> None:
        """First event for a file: lock a new program before it can be started.

        Only new files: created, moved in (a finished download is renamed into place), or created
        in the last NEW_FILE_S seconds. Windows also writes information to an existing program
        when it runs; locking it then made the next start fail until it was checked again."""
        if not (self.settings.exec_lock and exec_lock.lockable(path) and self._in_lock_area(path)):
            return
        if kind not in ("created", "moved") and not _created_recently(path):
            return
        if self.locks.get(path) is not None or not os.path.isfile(path):
            return
        # Removing the lock changes the file's permissions, which Windows reports as a change.
        # A file already checked (or unlocked by the user) whose content is unchanged stays unlocked.
        if self._cleared.get(LockRegistry.key(path)) == self._stamp(path):
            return
        if self._deny is exec_lock.deny_execute and not exec_lock.can_execute(Path(path)):
            # Already blocked by someone else (e.g. the user's own permission): never "unlock" it
            # later, because removing our entry removes every deny entry for Everyone (audit 8, L1).
            return
        if self._deny(Path(path)):
            self.locks.put(LockEntry(path, PENDING, "等待檢查", utc_now_iso()))
            self._audit.record("EXEC_LOCK", actor=AuditActor.SYSTEM, subject=path)
        # else: still being written (no permission change possible yet); the next event retries

    @staticmethod
    def _stamp(path: str) -> tuple[int, int] | None:
        # Size and last-write time: Windows' change time also moves when a program first runs,
        # which must not lock it again. Faked times are caught by the real-time content check.
        try:
            st = os.stat(path)
        except OSError:
            return None
        return st.st_size, st.st_mtime_ns

    def _mark_cleared(self, path: str) -> None:
        if len(self._cleared) >= 5000:
            self._cleared.pop(next(iter(self._cleared)))
        self._cleared[LockRegistry.key(path)] = self._stamp(path)
        if self._scanner is not None:
            self._scanner.mark_checked(path)  # the permission change is not new content (audit 8, L2)

    def _release(self, path: str, why: str) -> bool:
        ok = self._allow(Path(path)) if Path(path).exists() else True
        if ok:
            self._mark_cleared(path)
            self.locks.remove(path)
            self._audit.record("EXEC_UNLOCK", actor=AuditActor.SYSTEM, subject=path, detail={"reason": why})
        return ok

    def _hold(self, path: str, reason: str) -> None:
        self.locks.put(LockEntry(path, HELD, reason, utc_now_iso()))
        self._audit.record("EXEC_LOCK_HELD", actor=AuditActor.SYSTEM, subject=path, detail={"reason": reason})

    def unlock(self, path: str) -> bool:
        """User action on the protection page: allow a held file to run again."""
        e = self.locks.get(path)
        if e is None:
            return False
        ok = self._allow(Path(path)) if Path(path).exists() else True
        if ok:
            self._mark_cleared(path)
            self.locks.remove(path)
            self._audit.record("EXEC_UNLOCK", actor=AuditActor.USER, subject=path, detail={"reason": "使用者解鎖"})
        return ok

    def _settle_lock(self, f: FileRow) -> str:
        """After the scan: unlock, or keep the lock for threats and suspicious files. Returns a note."""
        if self.locks.get(f.path) is None:
            return ""
        cls = f.classification
        if not Path(f.path).exists():  # quarantined (moved away) or deleted
            self.locks.remove(f.path)
            return ""
        if cls is Classification.CONFIRMED_THREAT:
            self._hold(f.path, "確認威脅")
            return "；已鎖住，不能執行"
        if cls is Classification.SUSPICIOUS:
            self._hold(f.path, "可疑")
            return "；已鎖住，確認安全後可在「即時防護」頁面解鎖"
        if cls is Classification.UNKNOWN:
            # Audit 8 (M1): a program that could not be fully checked is not unlocked as if it were.
            key = LockRegistry.key(f.path)
            tries = self._retries.get(key, (0, 0.0))[0]
            if tries < len(RETRY_DELAYS_S):
                self._retries[key] = (tries + 1, time.monotonic() + RETRY_DELAYS_S[tries])
                self.locks.put(LockEntry(f.path, PENDING, "無法完整檢查，稍後重試", utc_now_iso()))
                return "；無法完整檢查，保持鎖住並稍後重試"
            self._retries.pop(key, None)
            self._hold(f.path, "無法完整檢查")
            self.notifier("warn", "新程式無法完整檢查", f"{Path(f.path).name}：重試後仍無法完整檢查，已保持鎖住。"
                          "確認來源可信後，可在「即時防護」頁面解鎖。")
            return "；重試後仍無法完整檢查，已鎖住，確認安全後可在「即時防護」頁面解鎖"
        self._retries.pop(LockRegistry.key(f.path), None)
        self._release(f.path, "檢查完成" if cls is not None else "已排除")
        return ""

    def retry_unchecked(self, now: float | None = None) -> int:
        """Scan again the locked programs whose check failed, once their retry time has come."""
        now = time.monotonic() if now is None else now
        due = [k for k, (_n, at) in self._retries.items() if at <= now]
        paths = [Path(e.path) for e in self.locks.entries(PENDING) if LockRegistry.key(e.path) in due]
        for k in due:
            if not any(LockRegistry.key(p) == k for p in paths):
                self._retries.pop(k, None)  # unlocked or removed meanwhile
        if paths and not self._cancel.cancelled:
            self._scan_batch(paths)
        return len(paths)

    def _act(self, f: FileRow) -> None:
        try:
            self._act_verdict(f)
        finally:
            note = self._settle_lock(f)
            if note:
                self._record(f.path, "執行鎖", note.lstrip("；"), "warn")

    def _act_verdict(self, f: FileRow) -> None:
        name = Path(f.path).name
        gate = self.settings.download_gate and self._in_downloads(f.path) and Path(f.path).suffix.lower() in GATE_SUFFIXES
        cls = f.classification
        if cls in (Classification.CONFIRMED_THREAT, Classification.SUSPICIOUS) and is_rule_source(f.path):
            self._record(f.path, "偵測規則檔（未自動處理）：" + "、".join(f.detections[:2]),
                         "這是病毒偵測規則的文字檔，本來就含有病毒特徵文字；沒有自動隔離", "warn")
            self.notifier("warn", "偵測到規則檔", f"{name}：看起來是 YARA／病毒碼規則的文字檔，裡面本來就有病毒特徵，"
                          "所以沒有自動隔離。如果不是你下載的，請到「需要處理的檔案」確認。")
        elif cls is Classification.CONFIRMED_THREAT and _only_external(f):
            # Audit 8 (H2): another vendor's verdict alone never moves or stops the user's file.
            self._record(f.path, "確認威脅（只有 VirusTotal）：" + "、".join(f.detections[:2]),
                         "已通知；沒有自動隔離，請到「需要處理的檔案」確認", "bad")
            locked = "已鎖住不能執行；" if self.locks.get(f.path) is not None else ""
            self.notifier("bad", "VirusTotal 多家判定有危險",
                          f"{name}：{locked}本機引擎沒有發現，所以沒有自動隔離。請到「需要處理的檔案」確認。")
        elif cls is Classification.CONFIRMED_THREAT:
            self._hash_cache = (0.0, set())  # the process guard must know this hash at once
            terminated = self._guard.kill_path(f.path) if self._guard is not None else []
            action = "已通知（自動隔離已關閉）"
            if self.settings.auto_quarantine and f.verdict_id is not None:
                try:
                    self._quarantine.quarantine_verdict(f.verdict_id, "即時防護自動隔離：" + "、".join(f.detections[:3]),
                                                        confirmed=True)
                    action = "已自動隔離"
                    self._counts["blocked"] += 1
                    self._audit.record("AUTO_QUARANTINE", actor=AuditActor.SYSTEM, subject=f.path,
                                       detail={"verdict_id": f.verdict_id, "sha256": f.sha256,
                                               "terminated": [t.pid for t in terminated if t.killed]})
                except QuarantineError as exc:
                    action = f"自動隔離失敗：{exc.user_message}"
            self._record(f.path, "確認威脅：" + "、".join(f.detections[:2]), action, "bad")
            self.notifier("bad", "已攔截威脅" if action == "已自動隔離" else "發現威脅", f"{name}：{action}")
        elif cls is Classification.SUSPICIOUS:
            self._record(f.path, "可疑：" + "、".join(f.detections[:2]), "已通知，請到威脅中心審查", "warn")
            locked = "已鎖住不能執行；" if self.locks.get(f.path) is not None else ""
            self.notifier("warn", "可疑檔案" + ("（不建議安裝）" if gate else ""),
                          f"{name}：{locked}請到威脅中心查看依據。")
        elif cls is Classification.UNKNOWN:
            reason = f.not_assessed_reason or "、".join(f.engine_errors[:1]) or "部分引擎無法評估"
            self._record(f.path, "無法完整檢查", reason, "warn")
            if gate:
                self.notifier("warn", "下載檢查：無法完整檢查", f"{name}：{reason}。不代表安全。")
        elif gate:
            text, level = self.gate_verdict(f)
            self._record(f.path, "下載檢查：未發現已知威脅", text, level)
            self.notifier(level, "下載檢查完成", f"{name}：{text}")

    def gate_verdict(self, f: FileRow) -> tuple[str, str]:
        """Conclusion for a new installer that no engine flagged. Never claims "safe"."""
        from sentinelx.engines.authenticode import inspect_signature

        sig = inspect_signature(Path(f.path))
        motw = read_motw(Path(f.path)) or {}
        internet = motw.get("ZoneId") in ("3", "4")
        if sig.status is SignatureStatus.VALID and sig.chain:
            return f"未發現已知威脅；有效數位簽章：{sig.chain[0].subject}。仍請確認是你要的軟體。", "info"
        if sig.status is SignatureStatus.INVALID:
            return "未發現已知威脅，但數位簽章無效（檔案可能被修改）：不建議安裝。", "warn"
        where = "來自網際網路、" if internet else ""
        return f"未發現已知威脅，但{where}沒有可驗證的數位簽章：請確認來源可信再安裝。", "warn"

    def _in_lock_area(self, path: str) -> bool:
        """Where files the user brings in arrive: Downloads, Desktop, Documents, USB drives.
        Not Temp or Program Files: installers create and start programs there at once, and a lock
        would break them."""
        if self._lock_areas is not None:
            areas = self._lock_areas()
        else:
            areas = [p for p in (self._downloads(), locations.desktop(), locations.documents()) if p]
            areas += [Path(d) for d in self._drives]
        k = _key(Path(path))
        return any(k.startswith(_key(a).rstrip("\\/") + os.sep) for a in areas)

    def _in_downloads(self, path: str) -> bool:
        d = self._downloads()
        return d is not None and _key(Path(path)).startswith(_key(d).rstrip("\\/") + os.sep)

    def _locked(self, path: Path) -> None:
        self._record(str(path), "無法完整檢查", "檔案一直被其他程式使用，無法讀取", "warn")

    def _overflow(self, n: int) -> None:
        self._record("", "事件過多", f"{n} 個檔案事件未處理（短時間內大量變動）", "warn")

    def _record(self, path: str, result: str, action: str, level: str) -> None:
        self._activity.appendleft(Activity(utc_now_iso(), path, result, action, level))

    # ---------- reading ----------
    def activity(self) -> list[Activity]:
        return list(self._activity)

    def status(self) -> ProtectionStatus:
        c = self.clamd
        if self.settings.low_memory:
            state, detail = "low_memory", "ClamAV 不常駐；下載、桌面、文件與 USB 的檔案逐批用 clamscan 檢查"
        elif c is None:
            state, detail = "clamscan", "使用 clamscan（較慢）"
        else:
            state, detail = c.state, c.detail
        return ProtectionStatus(
            self.settings.enabled, self.running, state, detail,
            tuple(f"{label}：{p}" for label, p in self._fixed_folders()) if self.running else (),
            tuple(sorted(self._drives)), self._guard is not None and self._guard.running,
            self._scanner.queue_length() if self._scanner else 0,
            self._counts["scanned"], self._counts["blocked"], self._counts["terminated"])

    # ---------- used by tests and the page ----------
    def scan_now(self, paths: list[Path]) -> None:
        self._scan_batch(paths)

    def notify_file(self, path: str) -> None:
        if self._scanner is not None:
            self._scanner.notify(path)

    def process_pending(self, now: float | None = None) -> int:
        return self._scanner.process_ready(now) if self._scanner is not None else 0

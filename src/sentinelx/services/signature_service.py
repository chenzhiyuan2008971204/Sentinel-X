"""ClamAV signature updates with `freshclam`, only with the user's consent.

Nothing is downloaded without consent. On first start Sentinel X asks once whether it may
download ClamAV signatures from the official ClamAV mirror (database.clamav.net, run by
Cisco Talos); the answer is stored and can be changed in Settings. With consent (and the
"daily automatic update" option, on by default) it updates once a day while it is running,
retrying a failed update after two hours. Signatures go to
`<data root>\\clamav-db`, so no administrator rights are needed. The freshclam
configuration is written by Sentinel X with fixed content.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinelx.app.config import AppConfig, ConfigStore
from sentinelx.app.paths import AppPaths
from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.enums import AuditActor
from sentinelx.engines.clamav import locate_clamscan
from sentinelx.storage.audit import AuditLog

log = logging.getLogger(__name__)

MIRROR = "database.clamav.net"
SIGNATURE_SUFFIXES = (".cvd", ".cld")
UPDATE_TIMEOUT_S = 45 * 60
OUTPUT_TAIL = 30
CREATE_NO_WINDOW = 0x08000000
AUTO_INTERVAL = timedelta(hours=24)
AUTO_RETRY = timedelta(hours=2)
AUTO_CHECK_S = 600.0  # how often the background thread looks whether an update is due
AUTO_FIRST_DELAY_S = 60.0  # let the app finish starting first
TS = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class SignatureStatus:
    freshclam: Path | None
    database_dir: Path
    files: tuple[str, ...]
    newest: str | None  # UTC time of the newest signature file
    engine_ready: bool = False  # ClamAV already works (e.g. with its own signatures elsewhere)

    @property
    def present(self) -> bool:
        return bool(self.files)


@dataclass(frozen=True)
class UpdateResult:
    ok: bool
    exit_code: int | None
    output_tail: tuple[str, ...]
    duration_s: float


class SignatureService:
    def __init__(self, paths: AppPaths, config: AppConfig, store: ConfigStore, audit: AuditLog,
                 *, on_updated: Callable[[Path], None] = lambda _d: None,
                 launcher: list[str] | None = None, engine_ready: Callable[[], bool] = lambda: False) -> None:
        """`launcher` replaces the freshclam invocation (tests use a fake script)."""
        self._paths = paths
        self._config = config
        self._store = store
        self._audit = audit
        self._on_updated = on_updated
        self._launcher = launcher
        self._engine_ready = engine_ready
        self._running = threading.Lock()  # one update at a time (manual or automatic)
        self._auto_thread: threading.Thread | None = None
        self._auto_stop = threading.Event()
        self._auto_cancel = CancelToken()
        self.on_auto_result: Callable[[UpdateResult], None] = lambda _r: None

    # ---- state ----
    @property
    def consented(self) -> bool:
        return self._config.signature_updates_consented

    def database_dir(self) -> Path:
        d = self._config.clamav.database_dir
        return Path(d) if d else self._paths.root / "clamav-db"

    def freshclam(self) -> Path | None:
        clamscan = locate_clamscan(self._config.clamav.clamscan_path)
        if clamscan is None:
            return None
        f = clamscan.with_name("freshclam.exe")
        return f if f.is_file() else None

    def status(self) -> SignatureStatus:
        d = self.database_dir()
        files: list[Path] = []
        if d.is_dir():
            files = sorted(p for p in d.iterdir() if p.suffix.lower() in SIGNATURE_SUFFIXES and p.is_file())
        newest = None
        if files:
            ts = max(p.stat().st_mtime for p in files)
            newest = datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return SignatureStatus(self.freshclam() if self._launcher is None else Path("freshclam.exe"), d,
                               tuple(p.name for p in files), newest, self._engine_ready())

    def needs_prompt(self) -> bool:
        """Ask on first start, only if an update is possible and ClamAV has no signatures yet
        (neither in Sentinel X's folder nor anywhere ClamAV already uses)."""
        if self._config.signature_updates_prompted:
            return False
        st = self.status()
        return st.freshclam is not None and not st.present and not st.engine_ready

    def set_consent(self, consent: bool) -> None:
        self._config.signature_updates_consented = consent
        self._config.signature_updates_prompted = True
        self._store.save(self._config)
        self._audit.record("SIGNATURE_UPDATE_CONSENT", actor=AuditActor.USER, detail={"consent": consent,
                                                                                    "mirror": MIRROR})

    # ---- update ----
    def config_text(self) -> str:
        return f"DatabaseDirectory {self.database_dir()}\nDatabaseMirror {MIRROR}\n"

    def command(self, conf: Path) -> list[str]:
        if self._launcher is not None:
            return [*self._launcher, f"--config-file={conf}"]
        exe = self.freshclam()
        if exe is None:
            raise ValueError("找不到 freshclam.exe（ClamAV 尚未安裝，或 clamscan 路徑設定錯誤）。")
        return [str(exe), f"--config-file={conf}"]

    @property
    def auto_update(self) -> bool:
        return self._config.signature_auto_update

    @property
    def last_attempt(self) -> str | None:
        return self._config.signature_last_attempt

    @property
    def last_success(self) -> str | None:
        return self._config.signature_last_success

    @property
    def updating(self) -> bool:
        return self._running.locked()

    def set_auto_update(self, on: bool) -> None:
        self._config.signature_auto_update = on
        self._store.save(self._config)
        self._audit.record("SIGNATURE_AUTO_UPDATE", actor=AuditActor.USER, detail={"enabled": on})

    @staticmethod
    def _parse(s: str | None) -> datetime | None:
        try:
            return datetime.strptime(s, TS).replace(tzinfo=UTC) if s else None
        except ValueError:
            return None

    def _wait_after_last(self) -> tuple[datetime | None, timedelta]:
        last = self._parse(self.last_attempt)
        ok = self._parse(self.last_success)
        return last, (AUTO_INTERVAL if last is not None and ok is not None and ok >= last else AUTO_RETRY)

    def auto_due(self, now: datetime | None = None) -> bool:
        """Whether the daily automatic update should run now."""
        if not (self.consented and self.auto_update) or self.status().freshclam is None:
            return False
        now = now or datetime.now(UTC)
        last, wait = self._wait_after_last()
        if last is None or last > now:  # never tried, or the clock was moved back
            return True
        return now - last >= wait

    def next_auto(self) -> str | None:
        """UTC time of the next automatic update; None when off or not tried yet."""
        if not (self.consented and self.auto_update):
            return None
        last, wait = self._wait_after_last()
        return (last + wait).strftime(TS) if last is not None else None

    def run_auto_once(self, now: datetime | None = None) -> UpdateResult | None:
        """Run the automatic update if it is due and no other update is running."""
        if not self.auto_due(now):
            return None
        try:
            res = self.update(self._auto_cancel, actor=AuditActor.SYSTEM)
        except (ValueError, ScanCancelled):
            return None
        self.on_auto_result(res)
        return res

    def start_auto(self, *, check_s: float = AUTO_CHECK_S, first_delay_s: float = AUTO_FIRST_DELAY_S) -> None:
        if self._auto_thread is not None:
            return
        self._auto_stop.clear()
        self._auto_cancel = CancelToken()

        def loop() -> None:
            delay = first_delay_s
            while not self._auto_stop.wait(delay):
                try:
                    self.run_auto_once()
                except Exception:  # noqa: BLE001 - never let the background thread die
                    log.exception("automatic signature update failed")
                delay = check_s

        self._auto_thread = threading.Thread(target=loop, name="sentinelx-signature-auto", daemon=True)
        self._auto_thread.start()

    def stop_auto(self) -> None:
        self._auto_stop.set()
        self._auto_cancel.cancel()
        if self._auto_thread is not None:
            self._auto_thread.join(15)
            self._auto_thread = None

    def update(self, cancel: CancelToken | None = None, *, actor: AuditActor = AuditActor.USER) -> UpdateResult:
        if not self.consented:
            raise ValueError("尚未同意下載病毒碼。請先在設定中勾選「允許從 ClamAV 官方伺服器下載病毒碼」。")
        if not self._running.acquire(blocking=False):
            raise ValueError("病毒碼正在更新中，請稍候。")
        try:
            return self._update(cancel or CancelToken(), actor)
        finally:
            self._running.release()

    def _update(self, cancel: CancelToken, actor: AuditActor) -> UpdateResult:
        self._config.signature_last_attempt = datetime.now(UTC).strftime(TS)
        self._store.save(self._config)
        db = self.database_dir()
        db.mkdir(parents=True, exist_ok=True)
        conf = self._paths.root / "freshclam.conf"
        # UTF-8: the data folder contains the Windows user name, which may be Chinese; freshclam
        # reads UTF-8 paths (verified with ClamAV 1.5.4). ASCII failed for such users (audit F1).
        conf.write_text(self.config_text(), encoding="utf-8")
        cmd = self.command(conf)
        self._audit.record("SIGNATURE_UPDATE_START", actor=actor, detail={"database_dir": str(db), "mirror": MIRROR,
                                                                        "automatic": actor == AuditActor.SYSTEM})
        started = time.monotonic()
        with tempfile.TemporaryFile() as out:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                    creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0)
            try:
                while True:
                    try:
                        proc.wait(timeout=0.2)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    if cancel.cancelled:
                        raise ScanCancelled()
                    if time.monotonic() - started > UPDATE_TIMEOUT_S:
                        break
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
            out.seek(0)
            text = out.read().decode("utf-8", "replace")
        lines = tuple(ln for ln in text.splitlines() if ln.strip())[-OUTPUT_TAIL:]
        res = UpdateResult(proc.returncode == 0, proc.returncode, lines, round(time.monotonic() - started, 1))
        self._audit.record("SIGNATURE_UPDATE_FINISH", actor=AuditActor.SYSTEM,
                           detail={"ok": res.ok, "exit_code": res.exit_code, "duration_s": res.duration_s,
                                   "files": list(self.status().files)})
        if res.ok:
            self._config.signature_last_success = datetime.now(UTC).strftime(TS)
            self._store.save(self._config)
            self._on_updated(db)
        return res

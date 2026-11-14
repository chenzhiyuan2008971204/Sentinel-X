"""Trial-run room for the GUI: status, building/rebuilding the VM, running one file.

A trial run is recorded like a scan (origin "sandbox"): the file is checked by the normal
engines plus the sandbox behaviour engine, so the verdict, evidence, Threat Center and
quarantine work exactly as for any scan. The sample only ever runs inside the VM.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import AuditActor, Classification
from sentinelx.engines.base import DetectionEngine
from sentinelx.sandbox.engine import SandboxEngine, findings
from sentinelx.sandbox.trial import DEFAULT_SECONDS, Sandbox, SandboxStatus
from sentinelx.sandbox.vbox import VBoxError
from sentinelx.scanner.exclusions import ExclusionSet
from sentinelx.scanner.orchestrator import ScanOrchestrator
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.scan_repository import FileRow, ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

log = logging.getLogger(__name__)
Notifier = Callable[[str, str, str], None]


@dataclass(frozen=True)
class TrialResult:
    path: str
    file: FileRow | None
    report: dict[str, Any]
    behaviours: list[str]  # plain-language findings
    classification: Classification | None
    seconds: int

    @property
    def summary(self) -> str:
        if not self.report.get("started") and not self.behaviours:
            err = self.report.get("start_error") or "原因不明"
            return f"檔案在虛擬機裡沒有成功執行（{err}），所以沒有觀察到行為。"
        if self.classification is Classification.CONFIRMED_THREAT:
            return "試跑結果：確定有危險。不要安裝或執行它。"
        if self.behaviours:
            return "試跑結果：觀察到可疑行為，建議不要安裝。"
        return (f"試跑 {self.seconds} 秒內沒有看到可疑行為。這不代表一定安全："
                "有些病毒會發現自己在虛擬機裡就裝乖，或等更久才發作。")


class SandboxService:
    def __init__(self, sandbox: Sandbox, engines: Sequence[DetectionEngine], scans: ScanRepository,
                 verdicts: VerdictRepository, limits: ScanLimits, audit: AuditLog) -> None:
        self.sandbox = sandbox
        self._engines = list(engines)
        self._scans = scans
        self._verdicts = verdicts
        self._limits = limits
        self._audit = audit
        self._busy = threading.Lock()
        self.notifier: Notifier = lambda _l, _t, _m: None
        self._rebuild_thread: threading.Thread | None = None

    @property
    def busy(self) -> bool:
        return self._busy.locked()

    def status(self) -> SandboxStatus:
        return self.sandbox.status()

    # ---- building ----
    def build(self, progress: Callable[[str], None] = lambda _m: None, cancel: CancelToken | None = None,
              *, automatic: bool = False) -> None:
        if not self._busy.acquire(blocking=False):
            raise VBoxError("試跑室正在使用中")
        try:
            self._audit.record("SANDBOX_BUILD_START", actor=AuditActor.SYSTEM if automatic else AuditActor.USER,
                               detail={"iso": str(self.sandbox.iso())})
            self.sandbox.build(progress, cancel)
            self._audit.record("SANDBOX_BUILD_DONE", actor=AuditActor.SYSTEM)
        finally:
            self._busy.release()

    def rebuild_if_due(self) -> bool:
        """Start a background rebuild when the evaluation is about to expire. Returns True if started."""
        st = self.status()
        if not (st.ready and st.rebuild_due) or self.busy or (self._rebuild_thread and self._rebuild_thread.is_alive()):
            return False

        def work() -> None:
            try:
                self.notifier("info", "試跑室自動重建", "Windows 試用期快到了，正在用已下載的映像檔重建（約 1 小時）。")
                self.build(automatic=True)
                self.notifier("info", "試跑室重建完成", "可以繼續使用試跑室。")
            except Exception as exc:  # noqa: BLE001 - reported to the user, never crashes the app
                log.exception("sandbox rebuild failed")
                self.notifier("warn", "試跑室重建失敗", str(getattr(exc, "reason", exc)))

        self._rebuild_thread = threading.Thread(target=work, name="sentinelx-sandbox-rebuild", daemon=True)
        self._rebuild_thread.start()
        return True

    # ---- trial run ----
    def trial(self, path: Path, *, seconds: int = DEFAULT_SECONDS, progress: Callable[[str], None] = lambda _m: None,
              cancel: CancelToken | None = None) -> TrialResult:
        cancel = cancel or CancelToken()
        if not path.is_file():
            raise VBoxError("請選擇一個檔案")
        if not self._busy.acquire(blocking=False):
            raise VBoxError("試跑室正在使用中")
        try:
            engine = SandboxEngine(lambda p, c: self.sandbox.run_file(p, seconds, progress, c), seconds)
            others = [e for e in self._engines if e.availability().available]
            # Installers are often larger than the scan size limit; a trial run is for exactly those.
            limits = self._limits.model_copy(update={"max_file_size_mb": 4096})
            orch = ScanOrchestrator([*others, engine], self._scans, limits,
                                    suppressions=self._verdicts.active_suppressions())
            summary = orch.run([path], ExclusionSet(), cancel, origin="sandbox")
            rows = self._scans.job_files(summary.job_id)
            row = rows[0] if rows else None
            rep = engine.last_report or {}
            behaviours = [text for _r, _s, text, _e in findings(rep)]
            res = TrialResult(str(path), row, rep, behaviours, row.classification if row else None, seconds)
            self._audit.record("SANDBOX_TRIAL", actor=AuditActor.USER, subject=str(path),
                               detail={"sha256": row.sha256 if row else None, "seconds": seconds,
                                       "started": bool(rep.get("started")), "behaviours": len(behaviours),
                                       "classification": res.classification.value if res.classification else None})
            return res
        finally:
            self._busy.release()

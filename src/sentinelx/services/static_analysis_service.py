"""Single-file static analysis: PE structure, hash reputation and YARA, without a scan job."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.enums import AuditActor, EngineOutcomeKind
from sentinelx.core.models import DetectionResult, FileResult, ScanTarget
from sentinelx.core.risk import Assessment, Suppression, assess, unassessed
from sentinelx.engines.base import DetectionEngine
from sentinelx.scanner.hashing import sha256_file
from sentinelx.scanner.orchestrator import has_detection_engine
from sentinelx.scanner.walker import is_reparse_point
from sentinelx.storage.audit import AuditLog


@dataclass(frozen=True)
class StaticReport:
    path: Path
    size: int
    sha256: str
    results: tuple[DetectionResult, ...]
    assessment: Assessment | None = None


class StaticAnalysisService:
    def __init__(self, engines: Sequence[DetectionEngine], audit: AuditLog, limits: ScanLimits,
                 suppressions: Callable[[], Sequence[Suppression]] = lambda: ()) -> None:
        self._engines = list(engines)
        self._audit = audit
        self._limits = limits
        self._suppressions = suppressions

    def analyze(self, path: Path, cancel: CancelToken | None = None) -> StaticReport:
        cancel = cancel or CancelToken()
        st = os.lstat(path)
        if is_reparse_point(st):
            raise ValueError("這是符號連結或交接點，為了安全不會跟隨分析。")
        if not path.is_file():
            raise ValueError("請選擇一般檔案。")
        if st.st_size > self._limits.max_file_size_mb * 1024 * 1024:
            raise ValueError(f"檔案超過大小上限 {self._limits.max_file_size_mb} MB。")
        sha = sha256_file(path, cancel)
        target = ScanTarget(path, sha, st.st_size)
        results = []
        for eng in self._engines:
            cancel.raise_if_cancelled()
            st_eng = eng.availability()
            if not st_eng.available:
                results.append(DetectionResult(eng.name, EngineOutcomeKind.ERROR, st_eng.version, st_eng.rules_version,
                                               error=st_eng.detail))
                continue
            try:
                res = eng.scan_batch([target], cancel).get(target)
            except ScanCancelled:
                raise
            except Exception as exc:  # noqa: BLE001 - shown as engine error
                res = DetectionResult(eng.name, EngineOutcomeKind.ERROR, st_eng.version, st_eng.rules_version,
                                      error=f"{type(exc).__name__}: {exc}")
            results.append(res or DetectionResult(eng.name, EngineOutcomeKind.ERROR, error="引擎沒有回傳結果"))
        fr = FileResult(path, st.st_size, None, None, sha, tuple(results))
        assessment = assess(fr, self._suppressions())
        if not has_detection_engine(self._engines):
            # Same rule as scanning: structure analysis alone cannot classify a file.
            assessment = replace(unassessed("沒有可用的偵測引擎（ClamAV、YARA 規則或含惡意雜湊的情報）"),
                                 evidence=assessment.evidence)
        self._audit.record("STATIC_ANALYSIS", actor=AuditActor.USER, subject=str(path),
                           detail={"sha256": sha, "classification": assessment.classification.value})
        return StaticReport(path, st.st_size, sha, tuple(results), assessment)

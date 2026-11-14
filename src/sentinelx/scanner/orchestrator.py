"""Scan orchestration: walk -> limits -> hash -> batch to engines -> persist.

Invariants:
- A file is "assessed" only if every available engine completed on it.
- An engine exception or a missing outcome becomes an ERROR outcome; it is never "no findings".
- Without an available detection-capable engine, no scan runs and the job is FAILED
  (context engines such as PE structure analysis alone are not enough).
- Any non-excluded file left unassessed makes the job PARTIAL, not COMPLETED.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.enums import Classification, EngineOutcomeKind, ScanStatus
from sentinelx.core.risk import Suppression, assess, unassessed
from sentinelx.core.models import DetectionResult, FileResult, ScanProgress, ScanSummary, ScanTarget
from sentinelx.engines.base import DetectionEngine
from sentinelx.scanner.exclusions import ExclusionSet
from sentinelx.scanner.hashing import sha256_file
from sentinelx.scanner.walker import Walker, WalkEntry
from sentinelx.storage.scan_repository import ScanRepository

log = logging.getLogger(__name__)

ProgressCallback = Callable[[ScanProgress], None]
NO_ENGINE_MESSAGE = "沒有可用的偵測引擎（需要 ClamAV、已啟用的 YARA 規則，或含惡意雜湊的情報），未執行掃描。"


def has_detection_engine(engines: Sequence[DetectionEngine]) -> bool:
    """A scan is only meaningful if at least one available engine can detect malicious content."""
    return any((st := e.availability()).available and st.detection_capable for e in engines)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Pending:
    def __init__(self, target: ScanTarget, mtime: str, ctime: str) -> None:
        self.target = target
        self.mtime = mtime
        self.ctime = ctime


class ScanOrchestrator:
    def __init__(
        self,
        engines: Sequence[DetectionEngine],
        repo: ScanRepository,
        limits: ScanLimits,
        *,
        batch_size: int = 64,
        suppressions: Sequence[Suppression] = (),
    ) -> None:
        self._engines = list(engines)
        self._repo = repo
        self._limits = limits
        self._batch_size = batch_size
        self._suppressions = list(suppressions)

    def run(
        self,
        roots: Sequence[Path],
        exclusions: ExclusionSet,
        cancel: CancelToken,
        on_progress: ProgressCallback | None = None,
        *,
        origin: str = "manual",
    ) -> ScanSummary:
        engines = [e for e in self._engines if e.availability().available]
        options = {
            "origin": origin,  # "manual" (Scan Center) or "realtime" (real-time protection)
            "limits": self._limits.model_dump(),
            "engines": [
                {"name": s.name, "version": s.version, "rules_version": s.rules_version}
                for s in (e.availability() for e in engines)
            ],
        }
        job_id = self._repo.create_job([str(r) for r in roots], options)

        if not has_detection_engine(engines):
            self._repo.finish_job(job_id, ScanStatus.FAILED, seen=0, assessed=0, not_assessed=0,
                                  error_summary=NO_ENGINE_MESSAGE)
            return ScanSummary(job_id, ScanStatus.FAILED.value, 0, 0, 0, 0, NO_ENGINE_MESSAGE)

        progress = ScanProgress()
        counts = {"assessed": 0, "not_assessed": 0, "excluded": 0, "with_detections": 0}
        by_class: Counter[Classification] = Counter()
        pending: list[_Pending] = []

        def emit() -> None:
            if on_progress is not None:
                on_progress(ScanProgress(**vars(progress)))

        def record(r: FileResult) -> None:
            # Excluded files get no verdict (the user chose not to assess them).
            assessment = None
            if not r.excluded:
                assessment = (assess(r, self._suppressions) if r.outcomes
                              else unassessed(r.not_assessed_reason or "未掃描"))
                by_class[assessment.classification] += 1
            self._repo.record_file(job_id, r, assessment)
            progress.files_done += 1
            if r.assessed:
                counts["assessed"] += 1
            else:
                counts["not_assessed"] += 1
                progress.files_skipped += 1
                if r.excluded:
                    counts["excluded"] += 1
            if r.detections:
                counts["with_detections"] += 1
                progress.detections += len(r.detections)
            emit()

        def flush() -> None:
            if not pending:
                return
            batch = list(pending)
            pending.clear()
            targets = [p.target for p in batch]
            per_engine: list[dict[ScanTarget, DetectionResult]] = []
            for eng in engines:
                cancel.raise_if_cancelled()
                try:
                    per_engine.append(eng.scan_batch(targets, cancel))
                except ScanCancelled:
                    pending.extend(batch)  # recorded as cancelled by the caller
                    raise
                except Exception as exc:  # noqa: BLE001 - engine bugs must not look clean
                    log.exception("engine crashed", extra={"ctx": {"engine": eng.name}})
                    st = eng.availability()
                    per_engine.append({
                        t: DetectionResult(eng.name, EngineOutcomeKind.ERROR, st.version, st.rules_version,
                                         error=f"引擎發生例外：{type(exc).__name__}: {exc}")
                        for t in targets
                    })
            for p in batch:
                outcomes = []
                for eng, res in zip(engines, per_engine, strict=True):
                    o = res.get(p.target)
                    if o is None:
                        st = eng.availability()
                        o = DetectionResult(eng.name, EngineOutcomeKind.ERROR, st.version, st.rules_version,
                                          error="引擎沒有回傳此檔案的結果")
                    outcomes.append(o)
                record(FileResult(p.target.path, p.target.size, p.mtime, p.ctime, p.target.sha256, tuple(outcomes)))

        def skip(entry: WalkEntry, reason: str, sha: str | None = None, excluded: bool = False) -> None:
            st = entry.stat
            record(FileResult(
                entry.path, st.st_size if st else None,
                _iso(st.st_mtime) if st else None, _iso(st.st_ctime) if st else None,
                sha, (), reason, excluded,
            ))

        status = ScanStatus.COMPLETED
        error_summary: str | None = None
        try:
            for entry in Walker(self._limits, exclusions).walk(roots, cancel):
                progress.files_seen += 1
                progress.current_path = str(entry.path)
                if not entry.is_file:
                    skip(entry, entry.skip_reason or "未掃描", excluded=entry.excluded)
                    continue
                try:
                    sha = sha256_file(entry.path, cancel)
                except OSError as exc:
                    reason = "權限不足，無法讀取" if isinstance(exc, PermissionError) else f"無法讀取：{exc.strerror or exc}"
                    skip(entry, reason)
                    continue
                if exclusions.match_hash(sha):
                    skip(entry, "符合排除的 SHA-256", sha, excluded=True)
                    continue
                assert entry.stat is not None
                pending.append(_Pending(
                    ScanTarget(entry.path, sha, entry.stat.st_size),
                    _iso(entry.stat.st_mtime), _iso(entry.stat.st_ctime),
                ))
                if len(pending) >= self._batch_size:
                    flush()
            flush()
        except ScanCancelled:
            status = ScanStatus.CANCELLED
            error_summary = "使用者取消掃描。"
            for p in pending:
                record(FileResult(p.target.path, p.target.size, p.mtime, p.ctime, p.target.sha256, (), "掃描已取消"))
        except Exception as exc:  # noqa: BLE001 - recorded as FAILED, then surfaced to the caller
            log.exception("scan failed", extra={"ctx": {"job_id": job_id}})
            status = ScanStatus.FAILED
            error_summary = f"掃描發生錯誤：{type(exc).__name__}: {exc}"

        failures = counts["not_assessed"] - counts["excluded"]
        if status is ScanStatus.COMPLETED and failures > 0:
            status = ScanStatus.PARTIAL
            error_summary = f"有 {failures} 個檔案未完成評估（權限、大小上限、連結或引擎錯誤），結果不完整。"

        self._repo.finish_job(job_id, status, seen=progress.files_seen, assessed=counts["assessed"],
                              not_assessed=counts["not_assessed"], error_summary=error_summary)
        log.info("scan finished", extra={"ctx": {"job_id": job_id, "status": status.value, **counts}})
        return ScanSummary(job_id, status.value, progress.files_seen, counts["assessed"],
                           counts["not_assessed"], counts["with_detections"], error_summary,
                           confirmed=by_class[Classification.CONFIRMED_THREAT],
                           suspicious=by_class[Classification.SUSPICIOUS],
                           unknown=by_class[Classification.UNKNOWN],
                           clean=by_class[Classification.CLEAN])

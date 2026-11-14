"""Scan use cases for the GUI: engine status, running scans, history, exclusions."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import AuditActor, ExclusionKind
from sentinelx.core.models import EngineStatus, ScanSummary
from sentinelx.engines.base import DetectionEngine
from sentinelx.scanner.exclusions import norm_path, validate_exclusion
from sentinelx.scanner.orchestrator import ProgressCallback, ScanOrchestrator, has_detection_engine
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.db import Database
from sentinelx.storage.verdict_repository import VerdictRepository
from sentinelx.storage.scan_repository import (
    DayActivity,
    ExclusionRepository,
    ExclusionRow,
    FileRow,
    JobRow,
    ScanRepository,
)


class ScanService:
    def __init__(self, engines: Sequence[DetectionEngine], db: Database, audit: AuditLog, limits: ScanLimits,
                 *, internal_root: Path | None = None, internal_hashes: Callable[[], set[str]] = set) -> None:
        self._engines = list(engines)
        self._internal_root = internal_root
        self._internal_hashes = internal_hashes
        self._audit = audit
        self._limits = limits
        self._scans = ScanRepository(db)
        self._exclusions = ExclusionRepository(db)
        self._verdicts = VerdictRepository(db)

    # engines
    def engine_statuses(self, refresh: bool = False) -> list[EngineStatus]:
        return [e.availability(refresh=refresh) for e in self._engines]

    def any_engine_available(self) -> bool:
        """Same gate the orchestrator applies: at least one available detection-capable engine."""
        return has_detection_engine(self._engines)

    # scanning
    def run_scan(self, roots: Sequence[Path], cancel: CancelToken, on_progress: ProgressCallback | None = None) -> ScanSummary:
        targets = [str(r) for r in roots]
        self._audit.record("SCAN_START", actor=AuditActor.USER, subject="; ".join(targets))
        orch = ScanOrchestrator(self._engines, self._scans, self._limits,
                                suppressions=self._verdicts.active_suppressions())
        exclusions = self._exclusions.active_set()
        if self._internal_root is not None:
            # Its own rule copies and reports contain the strings its rules look for.
            exclusions.internal.append(norm_path(self._internal_root).rstrip("\\/"))
        # Sentinel X's own reports quote matched strings; copies saved elsewhere are skipped by hash.
        exclusions.hashes |= self._internal_hashes()
        summary = orch.run(roots, exclusions, cancel, on_progress)
        self._audit.record(
            "SCAN_FINISH", actor=AuditActor.SYSTEM, subject=f"job {summary.job_id}",
            detail={"status": summary.status, "seen": summary.files_seen, "assessed": summary.files_assessed,
                    "not_assessed": summary.files_not_assessed, "with_detections": summary.files_with_detections,
                    "confirmed": summary.confirmed, "suspicious": summary.suspicious, "unknown": summary.unknown},
        )
        return summary

    def daily_activity(self, days: int = 14) -> list[DayActivity]:
        return self._scans.daily_activity(days)

    def history(self, limit: int = 100) -> list[JobRow]:
        return self._scans.list_jobs(limit)

    def job_files(self, job_id: int) -> list[FileRow]:
        return self._scans.job_files(job_id)

    # exclusions
    def exclusions(self) -> list[ExclusionRow]:
        return self._exclusions.list_all()

    def add_exclusion(self, kind: ExclusionKind, value: str, reason: str | None = None) -> int:
        canonical = validate_exclusion(kind, value)  # raises ValueError with a zh-TW message
        eid = self._exclusions.add(kind, canonical, reason)
        self._audit.record("EXCLUSION_ADD", actor=AuditActor.USER, subject=canonical, detail={"kind": kind.value, "reason": reason})
        return eid

    def remove_exclusion(self, exclusion_id: int) -> bool:
        row = self._exclusions.remove(exclusion_id)
        if row is None:
            return False
        self._audit.record("EXCLUSION_REMOVE", actor=AuditActor.USER, subject=row.value, detail={"kind": row.kind.value})
        return True

"""Persistence for scan jobs, per-file results, engine runs, detections and exclusions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import case, delete, func, select, true
from sqlalchemy.orm import Session

from sentinelx.core.enums import Classification, EngineOutcomeKind, ExclusionKind, ScanStatus
from sentinelx.core.models import FileResult
from sentinelx.core.risk import Assessment
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.scanner.exclusions import ExclusionSet, norm_path
from sentinelx.storage.db import Database
from sentinelx.storage.orm import Detection, EngineRun, Exclusion, FileRecord, FileScan, ScanJob, Verdict


@dataclass(frozen=True)
class JobRow:
    id: int
    started_at: str
    finished_at: str | None
    status: str
    targets: list[str]
    files_seen: int
    files_assessed: int
    files_not_assessed: int
    detections: int
    error_summary: str | None
    confirmed: int = 0  # verdicts assigned during this scan
    suspicious: int = 0
    unknown: int = 0


REALTIME_LIKE = '%"origin": "realtime"%'  # batches of real-time protection, not listed as manual scans
REALTIME_KEEP_DAYS = 30  # clean real-time batches older than this are pruned (audit R18)


@dataclass(frozen=True)
class DayActivity:
    day: date
    jobs: int
    files_assessed: int
    files_not_assessed: int


@dataclass(frozen=True)
class FileRow:
    path: str
    sha256: str | None
    size: int | None
    assessed: bool
    not_assessed_reason: str | None
    detections: list[str]  # "Engine: rule_id"
    engine_errors: list[str]  # "Engine: message"
    classification: Classification | None = None  # verdict at scan time; None = excluded
    confidence: str | None = None
    verdict_id: int | None = None


@dataclass(frozen=True)
class ExclusionRow:
    id: int
    kind: ExclusionKind
    value: str
    reason: str | None
    created_at: str
    enabled: bool


def insert_verdict(s: Session, file_id: int, a: Assessment, detection_ids: list[int]) -> int:
    """Insert a verdict for `file_id` and mark the previous latest verdict as superseded."""
    contributing = [detection_ids[e.index] for e in a.contributing if e.index < len(detection_ids)]
    v = Verdict(
        file_id=file_id, classification=a.classification.value, ordinal_score=a.ordinal_score,
        explanation=a.explanation, contributing_detection_ids=json.dumps(contributing),
        confidence=a.confidence, needs_review=1 if a.needs_review else 0, assessor_version=a.assessor_version,
    )
    s.add(v)
    s.flush()
    for old in s.scalars(select(Verdict).where(Verdict.file_id == file_id, Verdict.superseded_by.is_(None),
                                               Verdict.id != v.id)):
        old.superseded_by = v.id
    return v.id


class ScanRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def create_job(self, targets: list[str], options: dict[str, Any]) -> int:
        with self._db.session() as s:
            job = ScanJob(
                status=ScanStatus.RUNNING.value,
                targets_json=json.dumps(targets, ensure_ascii=False),
                options_json=json.dumps(options, ensure_ascii=False, default=str),
            )
            s.add(job)
            s.flush()
            return job.id

    def record_file(self, job_id: int, r: FileResult, assessment: Assessment | None = None) -> None:
        """Store the file, every engine result and detection, and (if given) its verdict,
        all in one transaction. The verdict supersedes the file's previous latest verdict."""
        pnorm = norm_path(r.path)
        now = utc_now_iso()
        with self._db.session() as s:
            q = select(FileRecord).where(FileRecord.path_norm == pnorm)
            q = q.where(FileRecord.sha256.is_(None) if r.sha256 is None else FileRecord.sha256 == r.sha256)
            rec = s.scalars(q.limit(1)).first()
            if rec is None:
                rec = FileRecord(
                    sha256=r.sha256, size=r.size, path=str(r.path), path_norm=pnorm,
                    mtime=r.mtime, ctime=r.ctime, first_seen_at=now, last_seen_at=now,
                )
                s.add(rec)
                s.flush()
            else:
                rec.last_seen_at = now
            fs = FileScan(
                job_id=job_id, file_id=rec.id, assessed=1 if r.assessed else 0,
                not_assessed_reason=r.not_assessed_reason or self._error_reason(r),
            )
            s.add(fs)
            s.flush()
            detection_ids: list[int] = []  # same order as FileResult.detections
            for o in r.outcomes:
                run = EngineRun(
                    file_scan_id=fs.id, engine_name=o.engine_name, engine_version=o.engine_version,
                    rules_version=o.rules_version, outcome=o.kind.value, error_detail=o.error,
                    duration_ms=o.duration_ms,
                    info_json=json.dumps(o.info, ensure_ascii=False, default=str),
                )
                s.add(run)
                s.flush()
                for d in o.detections:
                    row = Detection(
                        engine_run_id=run.id, rule_id=d.rule_id, severity_hint=d.severity_hint.value,
                        evidence_json=json.dumps(d.evidence, ensure_ascii=False, default=str),
                        confidence_explanation=d.confidence_explanation, detected_at=d.timestamp,
                        file_sha256=d.file_sha256,
                    )
                    s.add(row)
                    s.flush()
                    detection_ids.append(row.id)
            if assessment is not None:
                fs.verdict_id = insert_verdict(s, rec.id, assessment, detection_ids)

    @staticmethod
    def _error_reason(r: FileResult) -> str | None:
        if r.assessed:
            return None
        errs = [f"{o.engine_name}: {o.error}" for o in r.outcomes if not o.completed]
        return "；".join(errs) if errs else None

    def finish_job(self, job_id: int, status: ScanStatus, *, seen: int, assessed: int,
                   not_assessed: int, error_summary: str | None) -> None:
        with self._db.session() as s:
            job = s.get(ScanJob, job_id)
            assert job is not None
            job.status = status.value
            job.finished_at = utc_now_iso()
            job.files_seen = seen
            job.files_assessed = assessed
            job.files_not_assessed = not_assessed
            job.error_summary = error_summary

    def mark_interrupted_jobs(self) -> int:
        """Close jobs left RUNNING by a crash or forced exit. Called once at startup."""
        with self._db.session() as s:
            jobs = s.scalars(select(ScanJob).where(ScanJob.status == ScanStatus.RUNNING.value)).all()
            for j in jobs:
                j.status = ScanStatus.FAILED.value
                j.finished_at = utc_now_iso()
                j.error_summary = "程式未正常結束，此次掃描中斷，結果不完整。"
            return len(jobs)

    def prune_realtime(self, *, keep_days: int = REALTIME_KEEP_DAYS, now: datetime | None = None) -> int:
        """Delete old real-time batches that found nothing (audit R18). Returns the number of jobs removed.

        A batch is kept when any of its files has a detection, was not fully assessed, or got a
        verdict other than CLEAN. Verdicts stay (they belong to the file), so the Threat Center
        and file history are unchanged; only the per-batch scan records of clean files go.
        """
        cutoff = ((now or datetime.now(UTC)) - timedelta(days=keep_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._db.session() as s:
            has_finding = (
                select(FileScan.job_id)
                .outerjoin(EngineRun, EngineRun.file_scan_id == FileScan.id)
                .outerjoin(Detection, Detection.engine_run_id == EngineRun.id)
                .outerjoin(Verdict, Verdict.id == FileScan.verdict_id)
                .where((Detection.id.is_not(None)) | (FileScan.assessed == 0)
                       | (Verdict.classification.is_not(None) & (Verdict.classification != Classification.CLEAN.value)))
            )
            ids = list(s.scalars(
                select(ScanJob.id).where(
                    ScanJob.options_json.like(REALTIME_LIKE),
                    ScanJob.finished_at.is_not(None),
                    ScanJob.finished_at < cutoff,
                    ScanJob.id.not_in(has_finding),
                )
            ))
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                # file_scans → engine_runs → detections are removed by ON DELETE CASCADE.
                s.execute(delete(ScanJob).where(ScanJob.id.in_(chunk)))
            return len(ids)

    def list_jobs(self, limit: int = 100, *, include_realtime: bool = False) -> list[JobRow]:
        det_count = (
            select(FileScan.job_id, func.count(Detection.id).label("n"))
            .join(EngineRun, EngineRun.file_scan_id == FileScan.id)
            .join(Detection, Detection.engine_run_id == EngineRun.id)
            .group_by(FileScan.job_id)
            .subquery()
        )
        def cls_count(c: Classification):  # type: ignore[no-untyped-def]
            return func.sum(case((Verdict.classification == c.value, 1), else_=0)).label(c.value)

        class_counts = (
            select(FileScan.job_id, cls_count(Classification.CONFIRMED_THREAT), cls_count(Classification.SUSPICIOUS),
                   cls_count(Classification.UNKNOWN))
            .join(Verdict, Verdict.id == FileScan.verdict_id)
            .group_by(FileScan.job_id)
            .subquery()
        )
        with self._db.session() as s:
            rows = s.execute(
                select(ScanJob, func.coalesce(det_count.c.n, 0),
                       func.coalesce(class_counts.c.CONFIRMED_THREAT, 0),
                       func.coalesce(class_counts.c.SUSPICIOUS, 0),
                       func.coalesce(class_counts.c.UNKNOWN, 0))
                .outerjoin(det_count, det_count.c.job_id == ScanJob.id)
                .outerjoin(class_counts, class_counts.c.job_id == ScanJob.id)
                .where(true() if include_realtime else ScanJob.options_json.not_like(REALTIME_LIKE))
                .order_by(ScanJob.id.desc())
                .limit(limit)
            ).all()
            return [
                JobRow(
                    id=j.id, started_at=j.started_at, finished_at=j.finished_at, status=j.status,
                    targets=json.loads(j.targets_json), files_seen=j.files_seen,
                    files_assessed=j.files_assessed, files_not_assessed=j.files_not_assessed,
                    detections=int(n), error_summary=j.error_summary,
                    confirmed=int(nc), suspicious=int(ns), unknown=int(nu),
                )
                for j, n, nc, ns, nu in rows
            ]

    def daily_activity(self, days: int = 14) -> list[DayActivity]:
        """Per local calendar day, oldest first, including days without scans (zeros)."""
        today = datetime.now().astimezone().date()
        first = today - timedelta(days=days - 1)
        cutoff = (datetime.combine(first, datetime.min.time()).astimezone().astimezone(UTC)
                  .strftime("%Y-%m-%dT%H:%M:%SZ"))
        out = {first + timedelta(days=i): [0, 0, 0] for i in range(days)}
        with self._db.session() as s:
            for started, assessed, not_assessed in s.execute(
                    select(ScanJob.started_at, ScanJob.files_assessed, ScanJob.files_not_assessed)
                    .where(ScanJob.started_at >= cutoff)):
                try:
                    day = datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).astimezone().date()
                except ValueError:
                    continue
                if day in out:
                    out[day][0] += 1
                    out[day][1] += assessed or 0
                    out[day][2] += not_assessed or 0
        return [DayActivity(d, *v) for d, v in out.items()]

    def job_files(self, job_id: int) -> list[FileRow]:
        """All files of a job. A fixed number of queries (not several per file): a scan of many
        thousands of files is shown on the GUI thread right after it finishes."""
        with self._db.session() as s:
            scans = s.execute(
                select(FileScan.id, FileScan.assessed, FileScan.not_assessed_reason, FileRecord.path,
                       FileRecord.sha256, FileRecord.size, Verdict.id, Verdict.classification, Verdict.confidence)
                .join(FileRecord, FileRecord.id == FileScan.file_id)
                .outerjoin(Verdict, Verdict.id == FileScan.verdict_id)
                .where(FileScan.job_id == job_id).order_by(FileScan.id)
            ).all()
            errs: dict[int, list[str]] = {}
            dets: dict[int, list[str]] = {}
            for fs_id, engine, detail in s.execute(
                    select(EngineRun.file_scan_id, EngineRun.engine_name, EngineRun.error_detail)
                    .join(FileScan, FileScan.id == EngineRun.file_scan_id)
                    .where(FileScan.job_id == job_id, EngineRun.outcome == EngineOutcomeKind.ERROR.value)
                    .order_by(EngineRun.id)):
                errs.setdefault(fs_id, []).append(f"{engine}: {detail}")
            for fs_id, engine, rule in s.execute(
                    select(EngineRun.file_scan_id, EngineRun.engine_name, Detection.rule_id)
                    .join(Detection, Detection.engine_run_id == EngineRun.id)
                    .join(FileScan, FileScan.id == EngineRun.file_scan_id)
                    .where(FileScan.job_id == job_id).order_by(EngineRun.id, Detection.id)):
                dets.setdefault(fs_id, []).append(f"{engine}: {rule}")
        return [
            FileRow(path=path, sha256=sha, size=size, assessed=bool(assessed), not_assessed_reason=reason,
                    detections=dets.get(fs_id, []), engine_errors=errs.get(fs_id, []),
                    classification=Classification(cls) if cls else None, confidence=conf if vid else None,
                    verdict_id=vid)
            for fs_id, assessed, reason, path, sha, size, vid, cls, conf in scans
        ]


class ExclusionRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def list_all(self) -> list[ExclusionRow]:
        with self._db.session() as s:
            return [
                ExclusionRow(e.id, ExclusionKind(e.kind), e.value, e.reason, e.created_at, bool(e.enabled))
                for e in s.scalars(select(Exclusion).order_by(Exclusion.id))
            ]

    def add(self, kind: ExclusionKind, value: str, reason: str | None) -> int:
        with self._db.session() as s:
            dup = s.scalars(
                select(Exclusion).where(Exclusion.kind == kind.value, Exclusion.value == value)
            ).first()
            if dup is not None:
                dup.enabled = 1
                return dup.id
            e = Exclusion(kind=kind.value, value=value, reason=reason, enabled=1)
            s.add(e)
            s.flush()
            return e.id

    def remove(self, exclusion_id: int) -> ExclusionRow | None:
        with self._db.session() as s:
            e = s.get(Exclusion, exclusion_id)
            if e is None:
                return None
            row = ExclusionRow(e.id, ExclusionKind(e.kind), e.value, e.reason, e.created_at, bool(e.enabled))
            s.delete(e)
            return row

    def active_set(self) -> ExclusionSet:
        return ExclusionSet.from_pairs((r.kind, r.value) for r in self.list_all() if r.enabled)

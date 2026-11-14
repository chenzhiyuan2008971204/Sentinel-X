"""Read-only queries for the Research Lab and reports: stored evidence and the history of a hash."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from sentinelx.core.enums import Classification, EngineOutcomeKind, Severity
from sentinelx.core.models import DetectionRecord, DetectionResult
from sentinelx.storage.db import Database
from sentinelx.storage.orm import (
    AuditEntry,
    Detection,
    EngineRun,
    FileRecord,
    FileScan,
    FpSuppression,
    ManualReview,
    QuarantineItem,
    Report,
    ScanJob,
    SecurityEvent,
    Verdict,
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_SCANS = 50
MAX_EVENTS = 200

AUDIT_TEXT = {
    "STATIC_ANALYSIS": "靜態分析", "LAB_INSPECT": "研究實驗室檢視", "LAB_COMPARE": "檔案比較",
    "YARA_TEST": "YARA 規則測試", "REPORT_CREATE": "產生報告", "REPORT_EXPORT": "匯出報告複本",
    "QUARANTINE_ERROR": "隔離失敗", "FP_SUPPRESSION_REMOVE": "停用誤判排除",
}


@dataclass(frozen=True)
class EvidenceRun:
    """One engine run on a file in one scan, with its detections, as stored."""

    job_id: int
    scanned_at: str
    path: str
    file_scan_id: int
    result: DetectionResult


@dataclass(frozen=True)
class TimelineEvent:
    at: str
    category: str
    title: str
    detail: str = ""


@dataclass(frozen=True)
class StoredVerdict:
    id: int
    classification: Classification
    confidence: str
    explanation: str
    assessor_version: str | None
    created_at: str


@dataclass(frozen=True)
class JobFileEvidence:
    path: str
    sha256: str | None
    size: int | None
    assessed: bool
    not_assessed_reason: str | None
    verdict: StoredVerdict | None
    results: tuple[DetectionResult, ...]


@dataclass(frozen=True)
class JobEvidence:
    id: int
    started_at: str
    finished_at: str | None
    status: str
    targets: list[str]
    options: dict[str, Any]
    files_seen: int
    files_assessed: int
    files_not_assessed: int
    error_summary: str | None
    files: tuple[JobFileEvidence, ...]


def normalize_sha(text: str) -> str:
    sha = text.strip().lower()
    if not SHA256_RE.match(sha):
        raise ValueError("SHA-256 必須是 64 個十六進位字元。")
    return sha


def _results(s: Any, file_scan_id: int) -> tuple[DetectionResult, ...]:
    out = []
    for run in s.scalars(select(EngineRun).where(EngineRun.file_scan_id == file_scan_id).order_by(EngineRun.id)):
        dets = tuple(
            DetectionRecord(run.engine_name, run.engine_version, d.rule_id, Severity(d.severity_hint),
                            json.loads(d.evidence_json or "{}"), d.file_sha256, d.confidence_explanation, d.detected_at)
            for d in s.scalars(select(Detection).where(Detection.engine_run_id == run.id).order_by(Detection.id))
        )
        out.append(DetectionResult(run.engine_name, EngineOutcomeKind(run.outcome), run.engine_version,
                                   run.rules_version, dets, run.error_detail, run.duration_ms,
                                   json.loads(run.info_json or "{}")))
    return tuple(out)


def _verdict(v: Verdict | None) -> StoredVerdict | None:
    if v is None:
        return None
    return StoredVerdict(v.id, Classification(v.classification), v.confidence, v.explanation, v.assessor_version,
                         v.created_at)


class ResearchRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def evidence_for_sha(self, sha256: str) -> list[EvidenceRun]:
        """Engine runs from the most recent scans of files with this hash, newest first."""
        sha = normalize_sha(sha256)
        with self._db.session() as s:
            rows = s.execute(
                select(FileScan.id, ScanJob.id, ScanJob.started_at, FileRecord.path)
                .join(FileRecord, FileRecord.id == FileScan.file_id)
                .join(ScanJob, ScanJob.id == FileScan.job_id)
                .where(FileRecord.sha256 == sha).order_by(FileScan.id.desc()).limit(MAX_SCANS)
            ).all()
            return [EvidenceRun(job_id, started, path, fs_id, r)
                    for fs_id, job_id, started, path in rows for r in _results(s, fs_id)]

    def latest_verdict(self, sha256: str) -> tuple[str, StoredVerdict] | None:
        """(path, verdict) of the newest current verdict for any file with this hash."""
        sha = normalize_sha(sha256)
        with self._db.session() as s:
            row = s.execute(
                select(FileRecord.path, Verdict).join(Verdict, Verdict.file_id == FileRecord.id)
                .where(FileRecord.sha256 == sha, Verdict.superseded_by.is_(None)).order_by(Verdict.id.desc()).limit(1)
            ).first()
            return (row[0], _verdict(row[1])) if row else None  # type: ignore[return-value]

    def timeline_for_sha(self, sha256: str) -> list[TimelineEvent]:
        sha = normalize_sha(sha256)
        ev: list[TimelineEvent] = []
        with self._db.session() as s:
            recs = list(s.scalars(select(FileRecord).where(FileRecord.sha256 == sha)))
            ids = [r.id for r in recs]
            for r in recs:
                ev.append(TimelineEvent(r.first_seen_at, "掃描", "首次在掃描中看到此檔案", r.path))
            if ids:
                for fs, job in s.execute(select(FileScan, ScanJob).join(ScanJob, ScanJob.id == FileScan.job_id)
                                         .where(FileScan.file_id.in_(ids)).order_by(FileScan.id)):
                    state = "已完整評估" if fs.assessed else f"未完成評估：{fs.not_assessed_reason or '部分引擎無法評估'}"
                    ev.append(TimelineEvent(job.started_at, "掃描", f"掃描 #{job.id}", state))
                for v in s.scalars(select(Verdict).where(Verdict.file_id.in_(ids)).order_by(Verdict.id)):
                    ev.append(TimelineEvent(v.created_at, "判定", f"判定 #{v.id}：{v.classification}",
                                            f"信心 {v.confidence}；規則 {v.assessor_version or '—'}"))
                for r, v in s.execute(select(ManualReview, Verdict).join(Verdict, Verdict.id == ManualReview.verdict_id)
                                      .where(Verdict.file_id.in_(ids)).order_by(ManualReview.id)):
                    ev.append(TimelineEvent(r.reviewed_at, "審查", f"人工審查：{r.decision}（判定 #{v.id}）", r.reason))
            for f in s.scalars(select(FpSuppression).where(FpSuppression.sha256 == sha)):
                state = "啟用中" if f.active else "已停用"
                ev.append(TimelineEvent(f.created_at, "審查", f"誤判排除（{state}）：{f.rule_id or '全部規則'}", f.reason))
            for q in s.scalars(select(QuarantineItem).where(QuarantineItem.sha256 == sha)):
                ev.append(TimelineEvent(q.confirmed_by_user_at, "隔離", "移入隔離區", q.original_path))
                if q.restored_at:
                    ev.append(TimelineEvent(q.restored_at, "隔離", "從隔離區還原", q.restore_target or q.original_path))
                if q.deleted_at:
                    ev.append(TimelineEvent(q.deleted_at, "隔離", "從隔離區永久刪除", q.original_path))
            for e in s.scalars(select(SecurityEvent).where(SecurityEvent.sha256 == sha)
                               .order_by(SecurityEvent.id.desc()).limit(MAX_EVENTS)):
                ev.append(TimelineEvent(e.occurred_at, "行為監控", f"{e.kind}（{e.source}）",
                                        " ".join(x for x in (e.process_path, e.target_path) if x)))
            for a in s.scalars(select(AuditEntry).where(AuditEntry.detail_json.like(f"%{sha}%"))
                               .order_by(AuditEntry.id.desc()).limit(MAX_EVENTS)):
                if a.action in ("QUARANTINE", "RESTORE", "REPORT_CREATE") or a.action.startswith("REVIEW_"):
                    continue  # already shown from their own tables
                ev.append(TimelineEvent(a.at, "研究", AUDIT_TEXT.get(a.action, a.action), a.subject))
            for rep in s.scalars(select(Report).where(Report.subject_ref.like(f"%{sha}%"))):
                ev.append(TimelineEvent(rep.created_at, "報告", f"產生 {rep.kind} 報告（{rep.subject_type}）", rep.path))
        ev.sort(key=lambda e: e.at or "")
        return ev

    def job_evidence(self, job_id: int) -> JobEvidence | None:
        with self._db.session() as s:
            job = s.get(ScanJob, job_id)
            if job is None:
                return None
            files = []
            for fs, rec in s.execute(select(FileScan, FileRecord).join(FileRecord, FileRecord.id == FileScan.file_id)
                                     .where(FileScan.job_id == job_id).order_by(FileScan.id)):
                v = s.get(Verdict, fs.verdict_id) if fs.verdict_id else None
                files.append(JobFileEvidence(rec.path, rec.sha256, rec.size, bool(fs.assessed), fs.not_assessed_reason,
                                             _verdict(v), _results(s, fs.id)))
            return JobEvidence(job.id, job.started_at, job.finished_at, job.status, json.loads(job.targets_json or "[]"),
                               json.loads(job.options_json or "{}"), job.files_seen, job.files_assessed,
                               job.files_not_assessed, job.error_summary, tuple(files))

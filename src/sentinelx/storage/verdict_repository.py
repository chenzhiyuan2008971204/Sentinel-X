"""Verdicts, manual reviews and false-positive suppressions.

Nothing here deletes evidence: a review adds a row, a false-positive decision adds a
suppression, and re-assessment adds a new verdict that supersedes the old one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import exists, func, select

from sentinelx.core.enums import Classification, EngineOutcomeKind, ReviewDecision, Severity
from sentinelx.core.models import DetectionRecord, DetectionResult, FileResult
from sentinelx.core.risk import Assessment, Suppression
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.storage.db import Database
from sentinelx.storage.orm import (
    Detection,
    EngineRun,
    FileRecord,
    FileScan,
    FpSuppression,
    ManualReview,
    Verdict,
)
from sentinelx.storage.scan_repository import insert_verdict

ATTENTION = (Classification.CONFIRMED_THREAT.value, Classification.SUSPICIOUS.value)


@dataclass(frozen=True)
class ThreatRow:
    verdict_id: int
    file_id: int
    path: str
    sha256: str | None
    classification: Classification
    confidence: str
    ordinal_score: int
    needs_review: bool
    created_at: str
    last_review: ReviewDecision | None
    last_review_reason: str | None
    summary: str  # first contributing rule ids
    file_missing: bool = False  # the file is no longer at its scanned path


@dataclass(frozen=True)
class VerdictDetail:
    row: ThreatRow
    explanation: str
    results: tuple[DetectionResult, ...]
    reviews: tuple[tuple[str, ReviewDecision, str], ...]  # (time, decision, reason)
    history: tuple[tuple[int, str, Classification], ...]  # (verdict id, time, classification) oldest first


@dataclass(frozen=True)
class SuppressionRow:
    id: int
    sha256: str
    rule_id: str | None
    reason: str
    created_at: str
    active: bool


class VerdictRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    # ---------- suppressions ----------
    def active_suppressions(self) -> list[Suppression]:
        with self._db.session() as s:
            return [Suppression(r.sha256, r.rule_id, r.reason)
                    for r in s.scalars(select(FpSuppression).where(FpSuppression.active == 1))]

    def add_suppression(self, sha256: str, rule_id: str | None, reason: str, review_id: int | None) -> int:
        with self._db.session() as s:
            row = FpSuppression(sha256=sha256, rule_id=rule_id, reason=reason, created_at=utc_now_iso(),
                                active=1, review_id=review_id)
            s.add(row)
            s.flush()
            return row.id

    def list_suppressions(self, include_inactive: bool = False) -> list[SuppressionRow]:
        with self._db.session() as s:
            q = select(FpSuppression).order_by(FpSuppression.id.desc())
            if not include_inactive:
                q = q.where(FpSuppression.active == 1)
            return [SuppressionRow(r.id, r.sha256, r.rule_id, r.reason, r.created_at, bool(r.active))
                    for r in s.scalars(q)]

    def deactivate_suppression(self, sid: int) -> SuppressionRow | None:
        """Deactivate (never delete) so the decision history is kept."""
        with self._db.session() as s:
            r = s.get(FpSuppression, sid)
            if r is None or not r.active:
                return None
            r.active = 0
            return SuppressionRow(r.id, r.sha256, r.rule_id, r.reason, r.created_at, False)

    # ---------- verdicts ----------
    def _threat_row(self, s, v: Verdict, rec: FileRecord) -> ThreatRow:  # type: ignore[no-untyped-def]
        rev = s.scalars(select(ManualReview).where(ManualReview.verdict_id == v.id)
                        .order_by(ManualReview.id.desc()).limit(1)).first()
        ids = json.loads(v.contributing_detection_ids or "[]")
        rules = [r for (r,) in s.execute(select(Detection.rule_id).where(Detection.id.in_(ids)))] if ids else []
        return ThreatRow(
            v.id, rec.id, rec.path, rec.sha256, Classification(v.classification), v.confidence, v.ordinal_score,
            bool(v.needs_review), v.created_at,
            ReviewDecision(rev.decision) if rev else None, rev.reason if rev else None,
            "、".join(rules[:3]) + (" …" if len(rules) > 3 else ""),
            not Path(rec.path).exists(),
        )

    def threats(self, include_resolved: bool = False) -> list[ThreatRow]:
        """Latest verdicts that need attention (confirmed, suspicious, or flagged for review)."""
        with self._db.session() as s:
            q = (select(Verdict, FileRecord).join(FileRecord, FileRecord.id == Verdict.file_id)
                 .where(Verdict.superseded_by.is_(None)))
            if not include_resolved:
                q = q.where((Verdict.classification.in_(ATTENTION)) | (Verdict.needs_review == 1))
            q = q.order_by(Verdict.ordinal_score.desc(), Verdict.id.desc())
            return [self._threat_row(s, v, rec) for v, rec in s.execute(q)]

    def attention_counts(self) -> tuple[int, int]:
        """(verdicts needing attention, of which waiting for a first review) — counts only, no rows.
        Same definitions as `threats()` and `ThreatRow.needs_review / last_review`."""
        latest = Verdict.superseded_by.is_(None)
        reviewed = exists().where(ManualReview.verdict_id == Verdict.id)
        with self._db.session() as s:
            attention = s.scalar(select(func.count()).select_from(Verdict).where(
                latest, (Verdict.classification.in_(ATTENTION)) | (Verdict.needs_review == 1)))
            pending = s.scalar(select(func.count()).select_from(Verdict).where(
                latest, Verdict.needs_review == 1, ~reviewed))
        return int(attention or 0), int(pending or 0)

    def get(self, verdict_id: int) -> ThreatRow | None:
        with self._db.session() as s:
            v = s.get(Verdict, verdict_id)
            if v is None:
                return None
            return self._threat_row(s, v, s.get(FileRecord, v.file_id))

    def latest_for_file(self, file_id: int) -> int | None:
        with self._db.session() as s:
            return s.scalars(select(Verdict.id).where(Verdict.file_id == file_id, Verdict.superseded_by.is_(None))
                             .order_by(Verdict.id.desc()).limit(1)).first()

    def is_latest(self, verdict_id: int) -> bool:
        with self._db.session() as s:
            v = s.get(Verdict, verdict_id)
            return v is not None and v.superseded_by is None

    def detail(self, verdict_id: int) -> VerdictDetail | None:
        row = self.get(verdict_id)
        if row is None:
            return None
        fr, _ = self.load_latest_result(row.file_id)
        with self._db.session() as s:
            v = s.get(Verdict, verdict_id)
            reviews = tuple((r.reviewed_at, ReviewDecision(r.decision), r.reason) for r in s.scalars(
                select(ManualReview).where(ManualReview.verdict_id == verdict_id).order_by(ManualReview.id)))
            history = tuple((h.id, h.created_at, Classification(h.classification)) for h in s.scalars(
                select(Verdict).where(Verdict.file_id == row.file_id).order_by(Verdict.id)))
            return VerdictDetail(row, v.explanation, fr.outcomes if fr else (), reviews, history)

    def add_review(self, verdict_id: int, decision: ReviewDecision, reason: str) -> int:
        with self._db.session() as s:
            r = ManualReview(verdict_id=verdict_id, decision=decision.value, reason=reason, reviewed_at=utc_now_iso())
            s.add(r)
            s.flush()
            return r.id

    def add_verdict(self, file_id: int, a: Assessment, detection_ids: list[int]) -> int:
        with self._db.session() as s:
            return insert_verdict(s, file_id, a, detection_ids)

    def threat_index_rows(self) -> list[tuple[str, str | None, Classification, int, bool]]:
        """(path, sha256, classification, verdict id, quarantined) for latest CONFIRMED/SUSPICIOUS verdicts."""
        from sentinelx.core.enums import QuarantineStatus
        from sentinelx.storage.orm import QuarantineItem

        with self._db.session() as s:
            q_paths = {p.lower() for (p,) in s.execute(select(QuarantineItem.original_path).where(
                QuarantineItem.status.in_((QuarantineStatus.QUARANTINED.value, QuarantineStatus.DELETED.value))))}
            rows = s.execute(select(FileRecord.path, FileRecord.sha256, Verdict.classification, Verdict.id)
                             .join(Verdict, Verdict.file_id == FileRecord.id)
                             .where(Verdict.superseded_by.is_(None), Verdict.classification.in_(ATTENTION))).all()
        return [(p, sha, Classification(c), vid, p.lower() in q_paths) for p, sha, c, vid in rows]

    def files_with_sha(self, sha256: str) -> list[int]:
        with self._db.session() as s:
            return [i for (i,) in s.execute(select(FileRecord.id).where(FileRecord.sha256 == sha256))]

    def class_counts(self) -> dict[Classification, int]:
        """Counts over each file's latest verdict."""
        with self._db.session() as s:
            rows = s.execute(select(Verdict.classification, func.count())
                             .where(Verdict.superseded_by.is_(None)).group_by(Verdict.classification)).all()
        out = {c: 0 for c in Classification}
        for c, n in rows:
            out[Classification(c)] = int(n)
        return out

    def load_latest_result(self, file_id: int) -> tuple[FileResult | None, list[int]]:
        """Rebuild the stored FileResult of the file's most recent scan (for re-assessment).
        Returns the detection row ids in the same order as FileResult.detections."""
        with self._db.session() as s:
            rec = s.get(FileRecord, file_id)
            fs = s.scalars(select(FileScan).where(FileScan.file_id == file_id)
                           .order_by(FileScan.id.desc()).limit(1)).first()
            if rec is None or fs is None:
                return None, []
            outcomes: list[DetectionResult] = []
            ids: list[int] = []
            for run in s.scalars(select(EngineRun).where(EngineRun.file_scan_id == fs.id).order_by(EngineRun.id)):
                dets = []
                for d in s.scalars(select(Detection).where(Detection.engine_run_id == run.id).order_by(Detection.id)):
                    dets.append(DetectionRecord(run.engine_name, run.engine_version, d.rule_id, Severity(d.severity_hint),
                                                json.loads(d.evidence_json or "{}"), d.file_sha256,
                                                d.confidence_explanation, d.detected_at))
                    ids.append(d.id)
                outcomes.append(DetectionResult(run.engine_name, EngineOutcomeKind(run.outcome), run.engine_version,
                                                run.rules_version, tuple(dets), run.error_detail, run.duration_ms,
                                                json.loads(run.info_json or "{}")))
            reason = None if outcomes else (fs.not_assessed_reason or "未掃描")
            return FileResult(Path(rec.path), rec.size, rec.mtime, rec.ctime,
                              rec.sha256, tuple(outcomes), reason), ids

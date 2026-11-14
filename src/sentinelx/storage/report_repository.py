"""Generated report records (`reports` table). Rows are never deleted by the application."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from sentinelx.core.enums import ReportKind
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.storage.db import Database
from sentinelx.storage.orm import Report


@dataclass(frozen=True)
class ReportRow:
    id: int
    kind: ReportKind
    created_at: str
    subject_type: str
    subject_ref: str
    path: str
    sha256: str | None
    tool_versions: dict[str, Any]


def _row(r: Report) -> ReportRow:
    return ReportRow(r.id, ReportKind(r.kind), r.created_at, r.subject_type, r.subject_ref, r.path, r.sha256,
                     json.loads(r.tool_versions_json or "{}"))


class ReportRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def add(self, kind: ReportKind, subject_type: str, subject_ref: str, path: str, sha256: str,
            tool_versions: dict[str, Any]) -> ReportRow:
        with self._db.session() as s:
            r = Report(kind=kind.value, created_at=utc_now_iso(), subject_type=subject_type, subject_ref=subject_ref,
                       path=path, sha256=sha256, tool_versions_json=json.dumps(tool_versions, ensure_ascii=False))
            s.add(r)
            s.flush()
            return _row(r)

    def list(self, limit: int = 500) -> list[ReportRow]:
        with self._db.session() as s:
            return [_row(r) for r in s.scalars(select(Report).order_by(Report.id.desc()).limit(limit))]

    def hashes(self) -> set[str]:
        """SHA-256 of every report Sentinel X wrote (copies anywhere have the same hash)."""
        with self._db.session() as s:
            return {h for (h,) in s.execute(select(Report.sha256)) if h}

    def get(self, report_id: int) -> ReportRow | None:
        with self._db.session() as s:
            r = s.get(Report, report_id)
            return _row(r) if r else None

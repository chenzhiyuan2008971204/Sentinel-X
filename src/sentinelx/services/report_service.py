"""Write report documents to disk, record them, check their integrity, export copies.

Reports are written only inside `<data root>\\reports` under names Sentinel X generates
(no user-supplied path component), atomically (temp file + rename). Each file's SHA-256 is
stored in the `reports` table and in the hash-chained audit log, so later changes to a
report file are detectable.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from sentinelx.core.enums import AuditActor, ReportKind
from sentinelx.core.models import EngineStatus
from sentinelx.reporting.builders import scan_job_report
from sentinelx.reporting.document import tool_versions
from sentinelx.reporting.writers import ReportError, to_html, to_json, to_pdf
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.report_repository import ReportRepository, ReportRow
from sentinelx.storage.research_repository import ResearchRepository
from sentinelx.storage.scan_repository import JobRow, ScanRepository

log = logging.getLogger(__name__)
EXT = {ReportKind.JSON: "json", ReportKind.HTML: "html", ReportKind.PDF: "pdf"}
SUBJECT_TEXT = {"SAMPLE": "樣本研究", "COMPARISON": "檔案比較", "SCAN_JOB": "掃描"}


class Integrity(StrEnum):
    OK = "OK"
    MODIFIED = "MODIFIED"
    MISSING = "MISSING"


@dataclass(frozen=True)
class GenerateResult:
    rows: tuple[ReportRow, ...]
    errors: tuple[str, ...]  # formats that could not be written, with the reason


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class ReportService:
    def __init__(self, reports_dir: Path, repo: ReportRepository, research: ResearchRepository,
                 scans: ScanRepository, audit: AuditLog, engine_statuses: Callable[[], Sequence[EngineStatus]]) -> None:
        self._dir = reports_dir
        self._repo = repo
        self._research = research
        self._scans = scans
        self._audit = audit
        self._statuses = engine_statuses

    @property
    def reports_dir(self) -> Path:
        return self._dir

    def tool_versions(self) -> dict[str, Any]:
        return tool_versions(list(self._statuses()))

    def generate(self, doc: dict[str, Any], kinds: Sequence[ReportKind]) -> GenerateResult:
        if not kinds:
            raise ValueError("請至少選擇一種報告格式。")
        self._dir.mkdir(parents=True, exist_ok=True)
        subject_type, ref = doc["subject"]["type"], doc["subject"]["ref"]
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        base = f"{subject_type.lower()}-{stamp}-{uuid.uuid4().hex[:8]}"
        rows: list[ReportRow] = []
        errors: list[str] = []
        for kind in dict.fromkeys(kinds):  # keep order, drop duplicates
            dest = self._dir / f"{base}.{EXT[kind]}"
            tmp = self._dir / f".{base}.{EXT[kind]}.tmp"
            try:
                if kind is ReportKind.PDF:
                    to_pdf(doc, tmp)
                else:
                    tmp.write_bytes(to_json(doc) if kind is ReportKind.JSON else to_html(doc))
                os.replace(tmp, dest)
            except (ReportError, OSError) as exc:
                tmp.unlink(missing_ok=True)
                errors.append(f"{kind.value}：{exc}")
                continue
            except Exception as exc:  # noqa: BLE001 - a writer bug must fail this format only, visibly
                log.exception("report writer failed", extra={"ctx": {"kind": kind.value}})
                tmp.unlink(missing_ok=True)
                errors.append(f"{kind.value}：{type(exc).__name__}: {exc}")
                continue
            sha = _sha256(dest)
            row = self._repo.add(kind, subject_type, ref, str(dest), sha, doc["tool_versions"])
            self._audit.record("REPORT_CREATE", actor=AuditActor.USER, subject=str(dest),
                               detail={"report_id": row.id, "kind": kind.value, "subject_type": subject_type,
                                       "subject_ref": ref, "sha256": sha, "title": doc["title"]})
            rows.append(row)
        return GenerateResult(tuple(rows), tuple(errors))

    def reports(self) -> list[ReportRow]:
        return self._repo.list()

    def integrity(self, row: ReportRow) -> Integrity:
        p = Path(row.path)
        if not p.is_file():
            return Integrity.MISSING
        try:
            return Integrity.OK if _sha256(p) == row.sha256 else Integrity.MODIFIED
        except OSError:
            return Integrity.MISSING

    def export_copy(self, row: ReportRow, dest: Path) -> Path:
        """Copy a report elsewhere. Refused if the stored file no longer matches its recorded hash."""
        state = self.integrity(row)
        if state is not Integrity.OK:
            raise ValueError("報告檔不存在。" if state is Integrity.MISSING else "報告檔已被修改，與產生時記錄的雜湊不符，不提供複製。")
        target = dest.resolve()
        if target == Path(row.path).resolve() or self._dir.resolve() in target.parents:
            raise ValueError("不能另存到報告資料夾內（會覆蓋或混入已記錄的報告）。")
        shutil.copyfile(row.path, dest)
        # The source could change between the check above and the copy: verify what was written.
        if _sha256(dest) != row.sha256:
            dest.unlink(missing_ok=True)
            raise ValueError("複製後的內容與產生時記錄的雜湊不符，已刪除複本。")
        self._audit.record("REPORT_EXPORT", actor=AuditActor.USER, subject=str(dest),
                           detail={"report_id": row.id, "sha256": row.sha256})
        return dest

    # ---- scan job reports ----
    def scan_jobs(self, limit: int = 200) -> list[JobRow]:
        return self._scans.list_jobs(limit)

    def scan_report(self, job_id: int, kinds: Sequence[ReportKind]) -> GenerateResult:
        job = self._research.job_evidence(job_id)
        if job is None:
            raise ValueError(f"找不到掃描 #{job_id}。")
        return self.generate(scan_job_report(job, self.tool_versions()), kinds)

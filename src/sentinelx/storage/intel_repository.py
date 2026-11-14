"""Local hash intelligence (SHA-256 reputation lists).

Import format (UTF-8 text/CSV, one entry per line, `#` comments allowed, optional header):
    sha256
    sha256,label
    sha256,label,verdict        verdict = malicious | known_good

Lines that are not valid are counted and reported, never silently accepted.
A hash absent from every source is UNKNOWN; absence never means clean.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import func, select

from sentinelx.core.enums import IntelVerdict, TrustLevel
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.storage.db import Database
from sentinelx.storage.orm import IntelHash, IntelSource

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_IMPORT_BYTES = 200 * 1024 * 1024
_VERDICT_ALIASES = {
    "malicious": IntelVerdict.MALICIOUS, "malware": IntelVerdict.MALICIOUS, "bad": IntelVerdict.MALICIOUS,
    "known_good": IntelVerdict.KNOWN_GOOD, "known-good": IntelVerdict.KNOWN_GOOD,
    "good": IntelVerdict.KNOWN_GOOD, "trusted": IntelVerdict.KNOWN_GOOD,
}


@dataclass(frozen=True)
class ImportResult:
    source_id: int
    imported: int
    duplicates: int
    invalid_lines: list[int]  # 1-based line numbers (first 50)
    invalid_count: int


@dataclass(frozen=True)
class SourceRow:
    id: int
    name: str
    version: str | None
    trust: TrustLevel
    imported_at: str
    malicious: int
    known_good: int
    origin_note: str | None


@dataclass(frozen=True)
class IntelMatch:
    sha256: str
    source: str
    source_version: str | None
    trust: TrustLevel
    verdict: IntelVerdict
    label: str | None


def parse_intel_lines(text: str, default_verdict: IntelVerdict) -> tuple[list[tuple[str, str | None, IntelVerdict]], list[int]]:
    entries: list[tuple[str, str | None, IntelVerdict]] = []
    invalid: list[int] = []
    reader = csv.reader(io.StringIO(text))
    for lineno, row in enumerate(reader, start=1):
        cells = [c.strip() for c in row]
        if not cells or not cells[0] or cells[0].startswith("#"):
            continue
        if lineno == 1 and cells[0].lower() in ("sha256", "hash"):
            continue
        if not _SHA256.fullmatch(cells[0]):
            invalid.append(lineno)
            continue
        label = cells[1] if len(cells) > 1 and cells[1] else None
        verdict = default_verdict
        if len(cells) > 2 and cells[2]:
            v = _VERDICT_ALIASES.get(cells[2].lower())
            if v is None:
                invalid.append(lineno)
                continue
            verdict = v
        entries.append((cells[0].lower(), label, verdict))
    return entries, invalid


class IntelStore:
    def __init__(self, db: Database) -> None:
        self._db = db

    def import_file(
        self,
        path: Path,
        *,
        source_name: str,
        trust: TrustLevel,
        default_verdict: IntelVerdict = IntelVerdict.MALICIOUS,
        version: str | None = None,
    ) -> ImportResult:
        if not path.is_file():
            raise ValueError("找不到情報檔案。")
        if path.stat().st_size > MAX_IMPORT_BYTES:
            raise ValueError("情報檔案超過 200 MB 上限。")
        try:
            text = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("情報檔案必須是 UTF-8 文字檔。") from exc
        name = source_name.strip()
        if not name:
            raise ValueError("請輸入來源名稱。")
        entries, invalid = parse_intel_lines(text, default_verdict)
        if not entries:
            raise ValueError(f"檔案中沒有有效的 SHA-256（無效行數：{len(invalid)}）。")
        return self._store(name, trust, version, f"匯入自 {path.name}", entries, invalid)

    def _store(self, name: str, trust: TrustLevel, version: str | None, note: str,
               entries: Iterable[tuple[str, str | None, IntelVerdict]], invalid: list[int]) -> ImportResult:
        with self._db.session() as s:
            if s.scalars(select(IntelSource).where(IntelSource.name == name)).first() is not None:
                raise ValueError(f"已有名為「{name}」的情報來源，請先刪除或換一個名稱。")
            src = IntelSource(name=name, version=version, imported_at=utc_now_iso(), trust_level=trust.value,
                              origin_note=note)
            s.add(src)
            s.flush()
            seen: set[str] = set()
            dup = 0
            rows = []
            for sha, label, verdict in entries:
                if sha in seen:
                    dup += 1
                    continue
                seen.add(sha)
                rows.append({"source_id": src.id, "sha256": sha, "label": label, "category": verdict.value,
                             "added_at": utc_now_iso()})
            s.execute(IntelHash.__table__.insert(), rows)
            return ImportResult(src.id, len(rows), dup, invalid[:50], len(invalid))

    def sources(self) -> list[SourceRow]:
        with self._db.session() as s:
            counts = dict(
                ((sid, cat), n) for sid, cat, n in s.execute(
                    select(IntelHash.source_id, IntelHash.category, func.count()).group_by(IntelHash.source_id, IntelHash.category)
                )
            )
            return [
                SourceRow(src.id, src.name, src.version, TrustLevel(src.trust_level), src.imported_at,
                          counts.get((src.id, IntelVerdict.MALICIOUS.value), 0),
                          counts.get((src.id, IntelVerdict.KNOWN_GOOD.value), 0), src.origin_note)
                for src in s.scalars(select(IntelSource).order_by(IntelSource.id))
            ]

    def remove_source(self, source_id: int) -> SourceRow | None:
        row = next((r for r in self.sources() if r.id == source_id), None)
        if row is None:
            return None
        with self._db.session() as s:
            s.execute(IntelHash.__table__.delete().where(IntelHash.source_id == source_id))
            src = s.get(IntelSource, source_id)
            if src is not None:
                s.delete(src)
        return row

    def lookup_many(self, hashes: Iterable[str]) -> dict[str, list[IntelMatch]]:
        wanted = sorted({h.lower() for h in hashes})
        out: dict[str, list[IntelMatch]] = {h: [] for h in wanted}
        with self._db.session() as s:
            for i in range(0, len(wanted), 500):
                chunk = wanted[i:i + 500]
                q = (select(IntelHash, IntelSource).join(IntelSource, IntelSource.id == IntelHash.source_id)
                     .where(IntelHash.sha256.in_(chunk)))
                for h, src in s.execute(q):
                    out[h.sha256].append(IntelMatch(h.sha256, src.name, src.version, TrustLevel(src.trust_level),
                                                    IntelVerdict(h.category), h.label))
        return out

    def malicious_count(self) -> int:
        with self._db.session() as s:
            return int(s.scalar(select(func.count()).select_from(IntelHash)
                                .where(IntelHash.category == IntelVerdict.MALICIOUS.value)) or 0)

    def stamp(self) -> str:
        """Version string for the whole local intel set (changes whenever it changes)."""
        with self._db.session() as s:
            n_src = s.scalar(select(func.count()).select_from(IntelSource)) or 0
            n_hash = s.scalar(select(func.count()).select_from(IntelHash)) or 0
            last = s.scalar(select(func.max(IntelSource.imported_at)))
        return f"{n_src} sources/{n_hash} hashes/{last or '-'}"

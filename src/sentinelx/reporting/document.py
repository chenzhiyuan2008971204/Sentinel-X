"""The report document: a JSON-safe dict that every writer renders the same way.

Shape (schema "sentinelx-report/1"):
  report_type, title, generated_at, subject {type, ref}, tool_versions, disclaimer,
  sections: [{type: fields|table|text|code, title, ...}], evidence: {...raw source data...}

`sections` is the human-readable view. `evidence` keeps the source data exactly as the
engines and the database recorded it (engine versions, rule ids, raw evidence, timestamps),
so a reader can check every statement in the sections against it.
"""

from __future__ import annotations

import json
import platform
from collections.abc import Iterable, Sequence
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from sentinelx import __version__
from sentinelx.core.models import EngineStatus
from sentinelx.core.risk import ASSESSOR_VERSION
from sentinelx.core.timeutil import utc_now_iso

SCHEMA = "sentinelx-report/1"
DISCLAIMER = (
    "本報告記錄 Sentinel X 在產生當下觀察到的事實、各引擎的結果與判定規則的結論。"
    "偵測能力受限於已安裝的引擎與規則：沒有發現不代表檔案安全，分類也不是機率。"
    "所有檔案只被讀取，沒有被執行。"
)
_PACKAGES = ("pefile", "yara-python", "PySide6", "SQLAlchemy", "Jinja2", "reportlab", "psutil", "watchdog")


def _pkg(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def tool_versions(engines: Sequence[EngineStatus] = ()) -> dict[str, Any]:
    import yara

    return {
        "sentinelx": __version__,
        "python": platform.python_version(),
        "os": platform.platform(),
        "libyara": yara.YARA_VERSION,
        "risk_assessor": ASSESSOR_VERSION,
        "packages": {p: _pkg(p) for p in _PACKAGES},
        "engines": [
            {"name": e.name, "available": e.available, "version": e.version, "rules_version": e.rules_version,
             "rules_date": e.rules_date, "detail": e.detail}
            for e in engines
        ],
    }


def fields(title: str, rows: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    return {"type": "fields", "title": title, "rows": [[k, v] for k, v in rows]}


def table(title: str, columns: Sequence[str], rows: Iterable[Sequence[Any]], note: str | None = None) -> dict[str, Any]:
    return {"type": "table", "title": title, "columns": list(columns), "rows": [list(r) for r in rows], "note": note}


def text(title: str, paragraphs: Iterable[str]) -> dict[str, Any]:
    return {"type": "text", "title": title, "paragraphs": list(paragraphs)}


def code(title: str, body: Any) -> dict[str, Any]:
    content = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False, indent=2, default=str)
    return {"type": "code", "title": title, "text": content}


def new_document(report_type: str, title: str, subject_type: str, subject_ref: str, versions: dict[str, Any],
                 sections: list[dict[str, Any]], evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "report_type": report_type, "title": title, "generated_at": utc_now_iso(),
        "subject": {"type": subject_type, "ref": subject_ref}, "tool_versions": versions,
        "disclaimer": DISCLAIMER, "sections": sections, "evidence": evidence,
    }


def fmt(v: Any) -> str:
    """Display text for a value in HTML/PDF. Escaping is the writer's job, not this one's."""
    if v is None or v == "":
        return "—"
    if isinstance(v, bool):
        return "是" if v else "否"
    if isinstance(v, (list, tuple)):
        return "、".join(fmt(x) for x in v) if v else "—"
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False, default=str)
    return str(v)


def versions_section(v: dict[str, Any]) -> dict[str, Any]:
    rows: list[tuple[str, Any]] = [("Sentinel X", v.get("sentinelx")), ("Python", v.get("python")),
                                   ("作業系統", v.get("os")), ("libyara", v.get("libyara")),
                                   ("判定規則", v.get("risk_assessor"))]
    rows += [(k, x) for k, x in (v.get("packages") or {}).items()]
    for e in v.get("engines", []):
        state = "可用" if e.get("available") else f"不可用：{e.get('detail') or ''}"
        rows.append((f"引擎 {e.get('name')}", f"{e.get('version') or '—'}；規則／病毒碼 {e.get('rules_version') or '—'}；{state}"))
    return fields("工具版本（產生報告時）", rows)

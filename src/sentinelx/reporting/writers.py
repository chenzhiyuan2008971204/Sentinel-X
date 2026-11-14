"""JSON, HTML and PDF writers for report documents.

Every string in a report may come from an analyzed file or an event log, so:
- HTML: Jinja2 with autoescape on, and a Content-Security-Policy that allows no scripts.
- PDF: ReportLab paragraphs parse a small markup language, so text is XML-escaped and
  control characters are removed before it reaches a Paragraph; code blocks use
  Preformatted, which does not parse markup.
"""

from __future__ import annotations

import json
import os
import re
import threading
from importlib.resources import files
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from sentinelx.reporting.document import fmt, versions_section

CJK_FONT_NAME = "SentinelCJK"
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_font_lock = threading.Lock()
_font_registered: str | None = None
CODE_WRAP = 110
MAX_PDF_CODE_LINES = 4000
# A table cell cannot span pages in ReportLab; taller text raises LayoutError. Cells are cut
# to about PDF_CELL_LINES lines at the widest glyph (CJK, ~8 pt at 8 pt font size).
PDF_CELL_LINES = 40
PDF_GLYPH_PT = 8.0


class ReportError(Exception):
    pass


def to_json(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, ensure_ascii=False, indent=2, default=str).encode("utf-8")


def _env() -> Environment:
    tpl_dir = str(files("sentinelx.reporting") / "templates")
    env = Environment(loader=FileSystemLoader(tpl_dir), autoescape=True, undefined=StrictUndefined,
                      trim_blocks=True, lstrip_blocks=True)
    env.globals["fmt"] = fmt
    return env


def rendered_sections(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The document's sections plus the tool versions, which every rendered report carries."""
    return [*doc["sections"], versions_section(doc["tool_versions"])]


def to_html(doc: dict[str, Any]) -> bytes:
    evidence = json.dumps(doc.get("evidence", {}), ensure_ascii=False, indent=2, default=str)
    return _env().get_template("report.html.j2").render(doc=doc, sections=rendered_sections(doc),
                                                        evidence_json=evidence).encode("utf-8")


# ---------------- PDF ----------------

def font_candidates() -> list[tuple[Path, int]]:
    """CJK TrueType fonts to embed, in order. Phase 9 bundles Noto Sans TC (OFL) first."""
    bundled = Path(str(files("sentinelx") / "resources" / "fonts" / "NotoSansTC-Regular.ttf"))
    windir = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
    return [(bundled, 0), (windir / "msjh.ttc", 0), (windir / "mingliu.ttc", 0), (windir / "kaiu.ttf", 0)]


def register_cjk_font() -> str:
    """Register the first usable CJK font with ReportLab; returns the font file used."""
    global _font_registered
    with _font_lock:
        if _font_registered:
            return _font_registered
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont, TTFError

        problems = []
        for path, index in font_candidates():
            if not path.is_file():
                continue
            try:
                pdfmetrics.registerFont(TTFont(CJK_FONT_NAME, str(path), subfontIndex=index))
            except (TTFError, OSError) as exc:  # e.g. a font whose license forbids embedding
                problems.append(f"{path.name}：{exc}")
                continue
            _font_registered = str(path)
            return _font_registered
        raise ReportError("找不到可以嵌入 PDF 的中文字型，無法產生 PDF。" + ("；".join(problems) if problems else ""))


def _cell(v: Any, width_pt: float) -> str:
    s = fmt(v)
    cap = max(120, int(width_pt / PDF_GLYPH_PT) * PDF_CELL_LINES)
    if len(s) > cap:
        s = s[:cap] + f"…（共 {len(s):,} 字，完整內容見 JSON 版報告）"
    return _p(s)


def _p(text: Any) -> str:
    s = _CTRL.sub("", fmt(text) if not isinstance(text, str) else text)
    return escape(s).replace("\n", "<br/>")


def _wrap_code(text: str) -> str:
    out: list[str] = []
    for line in _CTRL.sub("", text).splitlines():
        while len(line) > CODE_WRAP:
            out.append(line[:CODE_WRAP])
            line = "  " + line[CODE_WRAP:]
        out.append(line)
        if len(out) >= MAX_PDF_CODE_LINES:
            out.append(f"…（PDF 只列出前 {MAX_PDF_CODE_LINES} 行，完整內容見 JSON 版報告）")
            break
    return "\n".join(out)


def to_pdf(doc: dict[str, Any], dest: Path) -> str:
    """Write the PDF to `dest`. Returns the embedded font file."""
    font_file = register_cjk_font()
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

    base = ParagraphStyle("base", fontName=CJK_FONT_NAME, fontSize=9, leading=13, wordWrap="CJK")
    small = ParagraphStyle("small", parent=base, fontSize=8, leading=11)
    muted = ParagraphStyle("muted", parent=small, textColor=colors.HexColor("#475569"))
    h1 = ParagraphStyle("h1", parent=base, fontSize=16, leading=22, textColor=colors.HexColor("#0e7490"))
    h2 = ParagraphStyle("h2", parent=base, fontSize=12, leading=17, spaceBefore=10, spaceAfter=4)
    mono = ParagraphStyle("mono", parent=base, fontSize=6.5, leading=8.5)
    grid = TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ])
    width = A4[0] - 30 * mm

    story: list[Any] = [
        Paragraph(_p(doc["title"]), h1),
        Paragraph(_p(f"報告類型：{doc['report_type']}　主題：{doc['subject']['type']} {doc['subject']['ref']}　"
                     f"產生時間（UTC）：{doc['generated_at']}　格式 {doc['schema']}"), muted),
        Spacer(1, 4), Paragraph(_p(doc["disclaimer"]), small), Spacer(1, 6),
    ]
    for s in rendered_sections(doc):
        story.append(Paragraph(_p(s["title"]), h2))
        if s["type"] == "fields":
            rows = [[Paragraph(_p(k), muted), Paragraph(_cell(v, width * 0.72), small)] for k, v in s["rows"]]
            if rows:
                story.append(Table(rows, colWidths=[width * 0.28, width * 0.72], style=grid))
        elif s["type"] == "table":
            if s["rows"]:
                n = len(s["columns"])
                head = [Paragraph(_p(c), muted) for c in s["columns"]]
                body = [[Paragraph(_cell(v, width / n), small) for v in r] for r in s["rows"]]
                t = Table([head, *body], colWidths=[width / n] * n, repeatRows=1, style=grid)
                t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0"))]))
                story.append(t)
            else:
                story.append(Paragraph("（無資料）", muted))
            if s.get("note"):
                story.append(Paragraph(_p(s["note"]), muted))
        elif s["type"] == "text":
            story += [Paragraph(_cell(x, width), base) for x in s["paragraphs"]]
        elif s["type"] == "code":
            story.append(Preformatted(_wrap_code(s["text"]), mono))
    story.append(Paragraph("原始證據（JSON）", h2))
    story.append(Paragraph("引擎與資料庫記錄的原始資料，可用來核對上方各節。", muted))
    story.append(Preformatted(_wrap_code(json.dumps(doc.get("evidence", {}), ensure_ascii=False, indent=2,
                                                    default=str)), mono))

    footer = f"Sentinel X {doc['tool_versions'].get('sentinelx', '')}　{doc['generated_at']}"

    def on_page(canvas: Any, d: Any) -> None:
        canvas.saveState()
        canvas.setFont(CJK_FONT_NAME, 7)
        canvas.drawString(15 * mm, 8 * mm, f"{footer}　第 {d.page} 頁")
        canvas.restoreState()

    SimpleDocTemplate(str(dest), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm,
                      bottomMargin=14 * mm, title=_CTRL.sub("", doc["title"]), author="Sentinel X",
                      creator=f"Sentinel X {doc['tool_versions'].get('sentinelx', '')}").build(
        story, onFirstPage=on_page, onLaterPages=on_page)
    return font_file

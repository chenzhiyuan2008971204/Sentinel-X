"""Report generation (JSON/HTML/PDF) and the Research Lab service, on harmless files."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import pypdf
import pytest
from fakes import MALWARE_MARKER, SignatureAV
from sqlalchemy import text

from sentinelx import __version__
from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.enums import ReportKind
from sentinelx.engines.base import DetectionEngine
from sentinelx.reporting import writers
from sentinelx.reporting.document import fields, new_document, table, tool_versions
from sentinelx.services.report_service import Integrity

pytestmark = pytest.mark.integration

ALL = [ReportKind.JSON, ReportKind.HTML, ReportKind.PDF]
HOSTILE = "<script>alert('x')</script> & <font color=red>紅</font> <b>粗</b>\x07\x1b"
PY_EXE = Path(sys.executable)


def pdf_text(path: str) -> str:
    return "".join(p.extract_text() or "" for p in pypdf.PdfReader(path).pages)


def hostile_doc() -> dict:  # type: ignore[type-arg]
    return new_document("SAMPLE", f"研究報告 {HOSTILE}", "SAMPLE", "a" * 64, tool_versions(),
                        [fields("欄位", [("名稱", HOSTILE), ("清單", ["x", HOSTILE])]),
                         table("表格", ["欄 A", "欄 B"], [[HOSTILE, 1], ["中文內容", None]])],
                        {"raw": HOSTILE})


@pytest.mark.security
def test_hostile_strings_escaped_in_every_format(container: AppContainer) -> None:
    res = container.reports.generate(hostile_doc(), ALL)
    assert not res.errors and [r.kind for r in res.rows] == ALL
    by = {r.kind: Path(r.path) for r in res.rows}
    assert json.loads(by[ReportKind.JSON].read_text(encoding="utf-8"))["evidence"]["raw"] == HOSTILE
    page = by[ReportKind.HTML].read_text(encoding="utf-8")
    assert "<script>alert" not in page and "<font color" not in page and "<b>粗" not in page
    assert "&lt;script&gt;" in page and "Content-Security-Policy" in page and "default-src 'none'" in page
    t = pdf_text(str(by[ReportKind.PDF]))
    assert "<script>alert" in t.replace("\n", "")  # rendered as literal text, not markup
    assert "中文內容" in t and "研究報告" in t


def test_tool_versions_in_every_format(container: AppContainer) -> None:
    doc = hostile_doc()
    doc["tool_versions"] = container.reports.tool_versions()
    res = container.reports.generate(doc, ALL)
    by = {r.kind: Path(r.path) for r in res.rows}
    doc = json.loads(by[ReportKind.JSON].read_text(encoding="utf-8"))
    tv = doc["tool_versions"]
    assert tv["sentinelx"] == __version__ and tv["libyara"] and tv["risk_assessor"] and tv["packages"]["pefile"]
    assert tv["engines"][0]["name"] == "FakeAV" and tv["engines"][0]["version"] == "9.9"
    html_page = by[ReportKind.HTML].read_text(encoding="utf-8")
    assert f"Sentinel X {__version__}" in html_page and tv["libyara"] in html_page
    assert __version__ in pdf_text(str(by[ReportKind.PDF]))
    assert all(r.tool_versions["sentinelx"] == __version__ for r in res.rows)


def test_reports_recorded_with_hash_and_audit(container: AppContainer) -> None:
    res = container.reports.generate(hostile_doc(), [ReportKind.JSON])
    [row] = res.rows
    p = Path(row.path)
    assert p.parent == container.paths.reports_dir and p.name.startswith("sample-") and p.suffix == ".json"
    assert container.reports.integrity(row) is Integrity.OK
    with container.db.engine.connect() as c:
        detail = c.execute(text("SELECT detail_json FROM audit_log WHERE action='REPORT_CREATE'")).scalar_one()
    assert json.loads(detail)["sha256"] == row.sha256
    assert container.audit.verify().ok
    assert not list(container.paths.reports_dir.glob(".*.tmp"))


@pytest.mark.security
def test_title_cannot_choose_the_path(container: AppContainer) -> None:
    doc = hostile_doc()
    doc["title"] = "..\\..\\evil"
    doc["subject"]["ref"] = "..\\..\\evil"
    [row] = container.reports.generate(doc, [ReportKind.HTML]).rows
    assert Path(row.path).parent == container.paths.reports_dir and "evil" not in Path(row.path).name


@pytest.mark.security
def test_integrity_modified_missing_and_copy(container: AppContainer, tmp_path: Path) -> None:
    rows = container.reports.generate(hostile_doc(), [ReportKind.JSON, ReportKind.HTML]).rows
    j, h = rows
    dest = tmp_path / "copy.json"
    container.reports.export_copy(j, dest)
    assert dest.read_bytes() == Path(j.path).read_bytes()
    Path(j.path).write_text("tampered", encoding="utf-8")
    assert container.reports.integrity(j) is Integrity.MODIFIED
    with pytest.raises(ValueError, match="已被修改"):
        container.reports.export_copy(j, tmp_path / "copy2.json")
    Path(h.path).unlink()
    assert container.reports.integrity(h) is Integrity.MISSING
    with pytest.raises(ValueError, match="不存在"):
        container.reports.export_copy(h, tmp_path / "copy3.html")
    with pytest.raises(ValueError, match="至少"):
        container.reports.generate(hostile_doc(), [])


def test_missing_cjk_font_fails_only_pdf(container: AppContainer, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(writers, "_font_registered", None)
    monkeypatch.setattr(writers, "font_candidates", lambda: [(tmp_path / "none.ttf", 0)])
    res = container.reports.generate(hostile_doc(), ALL)
    assert [r.kind for r in res.rows] == [ReportKind.JSON, ReportKind.HTML]
    assert len(res.errors) == 1 and "中文字型" in res.errors[0]
    assert not list(container.paths.reports_dir.glob("*.pdf")) and not list(container.paths.reports_dir.glob(".*"))


def test_scan_job_report(make_container: Callable[[Sequence[DetectionEngine]], AppContainer], tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    root = tmp_path / "scan"
    root.mkdir()
    (root / "bad.bin").write_bytes(b"x " + MALWARE_MARKER)
    (root / "ok.txt").write_text("fine")
    from sentinelx.core.cancel import CancelToken

    summary = c.scans.run_scan([root], CancelToken())
    res = c.reports.scan_report(summary.job_id, ALL)
    assert not res.errors
    doc = json.loads(Path(res.rows[0].path).read_text(encoding="utf-8"))
    assert doc["report_type"] == "SCAN_JOB" and doc["subject"]["ref"] == str(summary.job_id)
    files = {Path(f["path"]).name: f for f in doc["evidence"]["files"]}
    assert files["bad.bin"]["verdict"]["classification"] in ("CONFIRMED_THREAT", "SUSPICIOUS")
    det = files["bad.bin"]["results"][0]["detections"][0]
    assert det["engine_name"] == "ClamAV" and det["rule_id"] and det["file_sha256"] and det["timestamp"]
    assert files["ok.txt"]["verdict"] is not None  # clean files kept in the JSON evidence
    attention = next(s for s in doc["sections"] if s["title"].startswith("需要注意"))
    assert [Path(r[0]).name for r in attention["rows"]] == ["bad.bin"]
    t = pdf_text(res.rows[2].path)
    assert "掃描報告" in t and "bad.bin" in t
    with pytest.raises(ValueError, match="找不到"):
        c.reports.scan_report(99999, ALL)


# ---------------- Research Lab service ----------------

def test_lab_inspect_and_sample_report(container: AppContainer, tmp_path: Path) -> None:
    sample = tmp_path / "copy.exe"
    shutil.copyfile(PY_EXE, sample)
    insp = container.lab.inspect(sample)
    assert insp.worker_error is None and insp.worker_confined and not insp.sha_changed
    assert insp.pe is not None and insp.pe.info["is_pe"] and insp.signature is not None
    run = container.lab.yara_test('rule mz { strings: $m = "This program" condition: $m }', [sample])
    res = container.lab.export_sample(insp.facts.sha256, insp, [run], ALL)
    assert not res.errors
    doc = json.loads(Path(res.rows[0].path).read_text(encoding="utf-8"))
    ev = doc["evidence"]
    assert ev["file"]["sha256"] == insp.facts.sha256 and ev["pe_result"]["engine_version"].startswith("1.0 (pefile")
    assert ev["signature"]["status"] == insp.signature.status.value
    assert ev["yara_tests"][0]["results"][0]["hits"][0]["rule"] == "mz"
    titles = [e["title"] for e in ev["timeline"]]
    assert "研究實驗室檢視" in titles and "YARA 規則測試" in titles
    assert doc["tool_versions"]["sentinelx"] == __version__
    assert "工具版本" in Path(res.rows[1].path).read_text(encoding="utf-8")
    assert container.lab.lookup(insp.facts.sha256).latest is None  # the lab never creates a verdict
    with container.db.engine.connect() as c:
        assert c.execute(text("SELECT COUNT(*) FROM verdicts")).scalar_one() == 0


def test_lab_lookup_validates_hash(container: AppContainer) -> None:
    with pytest.raises(ValueError, match="64"):
        container.lab.lookup("not-a-hash")
    lk = container.lab.lookup("A" * 64)
    assert lk.sha256 == "a" * 64 and lk.intel == () and lk.latest is None and lk.stored_runs == 0


def test_lab_evidence_and_timeline_from_scan(make_container: Callable[[Sequence[DetectionEngine]], AppContainer],
                                             tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    root = tmp_path / "s"
    root.mkdir()
    bad = root / "bad.bin"
    bad.write_bytes(b"x " + MALWARE_MARKER)
    from sentinelx.core.cancel import CancelToken

    c.scans.run_scan([root], CancelToken())
    insp = c.lab.inspect(bad)
    sha = insp.facts.sha256
    ev = c.lab.evidence(sha)
    assert ev and ev[0].result.engine_name == "ClamAV" and ev[0].result.detections
    cats = {e.category for e in c.lab.timeline(sha)}
    assert {"掃描", "判定", "研究"} <= cats
    lk = c.lab.lookup(sha)
    assert lk.latest is not None and lk.stored_runs >= 1


def test_lab_compare(container: AppContainer, tmp_path: Path) -> None:
    a = tmp_path / "a.exe"
    shutil.copyfile(PY_EXE, a)
    b = tmp_path / "b.exe"
    data = bytearray(a.read_bytes())
    data[-1] ^= 0xFF
    b.write_bytes(bytes(data))
    cmp, ia, ib = container.lab.compare(a, b)
    assert not cmp.identical and cmp.bytes.differing_bytes == 1 and cmp.bytes.first_difference == len(data) - 1
    assert cmp.pe is not None
    res = container.lab.export_comparison(cmp, ia, ib, [ReportKind.JSON])
    doc = json.loads(Path(res.rows[0].path).read_text(encoding="utf-8"))
    assert doc["report_type"] == "COMPARISON" and doc["evidence"]["comparison"]["bytes"]["differing_bytes"] == 1


@pytest.mark.security
def test_lab_never_executes_the_sample(container: AppContainer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = tmp_path / "sample.exe"
    shutil.copyfile(PY_EXE, sample)
    launched: list[list[str]] = []
    real_popen = subprocess.Popen

    def spy(cmd, *a, **kw):  # type: ignore[no-untyped-def]
        launched.append(list(cmd))
        return real_popen(cmd, *a, **kw)

    monkeypatch.setattr(subprocess, "Popen", spy)
    monkeypatch.setattr("os.startfile", lambda *a, **k: pytest.fail("startfile called"), raising=False)
    insp = container.lab.inspect(sample)
    container.lab.yara_test("rule r { condition: true }", [sample])
    container.lab.compare(sample, PY_EXE)
    container.lab.export_sample(insp.facts.sha256, insp, [], ALL)
    assert launched, "the worker should have been started"
    for cmd in launched:
        assert Path(cmd[0]).resolve() == PY_EXE.resolve()  # only the interpreter itself, never the sample
        assert cmd[1:4] == ["-I", "-m", "sentinelx.research.worker"]

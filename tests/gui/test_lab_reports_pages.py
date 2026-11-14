"""Research Lab and Reports pages (pytest-qt, offscreen), on harmless files."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, SignatureAV
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.gui.lab_page import ResearchLabPage
from sentinelx.gui.reports_page import ReportsPage
from sentinelx.services.report_service import Integrity

pytestmark = pytest.mark.gui
PY_EXE = Path(sys.executable)


def lab_page(qtbot: QtBot, c: AppContainer) -> ResearchLabPage:
    p = ResearchLabPage(c.lab)
    qtbot.addWidget(p)
    return p


def wait_idle(qtbot: QtBot, p: ResearchLabPage) -> None:
    qtbot.waitUntil(lambda: not p.busy, timeout=60000)


def inspect(qtbot: QtBot, p: ResearchLabPage, path: Path) -> None:
    p.path_edit.setText(str(path))
    p.inspect_button.click()
    assert p.busy and not p.inspect_button.isEnabled()
    wait_idle(qtbot, p)


def test_buttons_need_a_sample(qtbot: QtBot, container: AppContainer) -> None:
    p = lab_page(qtbot, container)
    assert not p.export_button.isEnabled() and not p.compare_button.isEnabled()
    assert not p.yara_sample_button.isEnabled() and not p.compare_export_button.isEnabled()
    p.inspect_button.click()
    assert "請先選擇" in p.status_label.text() and not p.busy


def test_inspect_pe_fills_every_tab(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    sample = tmp_path / "copy.exe"
    shutil.copyfile(PY_EXE, sample)
    p = lab_page(qtbot, container)
    inspect(qtbot, p, sample)
    assert p.inspection is not None and p.sha256 == p.inspection.facts.sha256
    assert p.sha256 in p.overview.toPlainText() and "隔離分析程序：是" in p.overview.toPlainText()
    assert p.sections_table.rowCount() >= 3 and p.imports_tree.topLevelItemCount() >= 1
    assert "PEStatic" in p.pe_header.toPlainText()
    assert p.inspection.signature is not None and p.inspection.signature.status.value in p.sig_view.toPlainText()
    assert p.chain_table.rowCount() == len(p.inspection.signature.chain)
    assert p.timeline_table.rowCount() >= 1  # the inspection itself is in the audit log
    assert p.export_button.isEnabled() and p.compare_button.isEnabled() and p.yara_sample_button.isEnabled()


@pytest.mark.security
@pytest.mark.skipif(sys.platform != "win32", reason="NTFS alternate data streams")
def test_hostile_motw_shown_as_text(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    sample = tmp_path / "dl.txt"
    sample.write_text("hello", encoding="utf-8")
    with open(f"{sample}:Zone.Identifier", "w", encoding="utf-8") as f:
        f.write("[ZoneTransfer]\nZoneId=3\nHostUrl=<img src=x onerror=alert(1)><b>bold</b>\n")
    p = lab_page(qtbot, container)
    inspect(qtbot, p, sample)
    plain = p.overview.toPlainText()
    assert "<img src=x onerror=alert(1)><b>bold</b>" in plain  # literal text, not parsed markup
    assert "不是 PE" in p.pe_header.toPlainText()


def test_yara_tab(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    a = tmp_path / "a.txt"
    a.write_bytes(b"xx SX-LAB-MARKER yy")
    b = tmp_path / "b.txt"
    b.write_bytes(b"clean")
    p = lab_page(qtbot, container)
    p.rule_edit.setPlainText('rule lab { strings: $m = "SX-LAB-MARKER" condition: $m }')
    p.run_yara([a, b])
    wait_idle(qtbot, p)
    assert len(p.yara_runs) == 1 and p.yara_runs[0].matched == 1
    rows = {p.yara_table.item(r, 0).text(): p.yara_table.item(r, 1).text() for r in range(p.yara_table.rowCount())}
    assert rows[str(a)] == "lab" and "未命中" in rows[str(b)]
    assert p.yara_table.item(0, 3).text() == "3"  # offset
    assert "1 個命中" in p.yara_label.text()


def test_yara_bad_rule_reports_error(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    f = tmp_path / "a.txt"
    f.write_text("x")
    p = lab_page(qtbot, container)
    p.rule_edit.setPlainText('import "console" rule r { condition: true }')
    p.run_yara([f])
    wait_idle(qtbot, p)
    assert "不允許" in p.status_label.text() and p.yara_runs == []


def test_load_rule_file(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    f = tmp_path / "r.yar"
    f.write_text("rule from_file { condition: true }", encoding="utf-8")
    p = lab_page(qtbot, container)
    p.load_rule_file(f)
    assert "from_file" in p.rule_edit.toPlainText()


def test_hash_lookup_and_bad_hash(qtbot: QtBot, container: AppContainer) -> None:
    p = lab_page(qtbot, container)
    p.hash_edit.setText("zz")
    p.lookup_button.click()
    wait_idle(qtbot, p)
    assert "64" in p.status_label.text() and p.sha256 is None
    p.hash_edit.setText("ab" * 32)
    p.lookup_button.click()
    wait_idle(qtbot, p)
    assert p.sha256 == "ab" * 32 and p.inspection is None
    assert "只依雜湊查詢" in p.overview.toPlainText() and p.export_button.isEnabled()
    assert not p.compare_button.isEnabled()


def test_evidence_tab_from_scan(qtbot: QtBot, make_container, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    c = make_container([SignatureAV()])
    root = tmp_path / "s"
    root.mkdir()
    bad = root / "bad.bin"
    bad.write_bytes(b"x " + MALWARE_MARKER)
    c.scans.run_scan([root], CancelToken())
    p = lab_page(qtbot, c)
    inspect(qtbot, p, bad)
    assert p.evidence_table.rowCount() >= 1
    p.evidence_table.selectRow(0)
    assert "ClamAV" in p.evidence_detail.toPlainText() or "引擎" in p.evidence_detail.toPlainText()
    assert any(p.timeline_table.item(r, 1).text() == "判定" for r in range(p.timeline_table.rowCount()))


def test_compare_and_export(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    a = tmp_path / "a.exe"
    shutil.copyfile(PY_EXE, a)
    p = lab_page(qtbot, container)
    inspect(qtbot, p, a)
    p.compare_edit.setText(str(PY_EXE))
    p.compare_button.click()
    wait_idle(qtbot, p)
    assert p.comparison is not None and "內容完全相同" in p.compare_view.toPlainText()
    p.fmt_pdf.setChecked(False)
    p.compare_export_button.click()
    wait_idle(qtbot, p)
    assert p.last_export is not None and len(p.last_export.rows) == 2 and not p.last_export.errors
    p.fmt_pdf.setChecked(True)
    p.export_button.click()
    wait_idle(qtbot, p)
    assert p.last_export is not None and len(p.last_export.rows) == 3 and "已產生" in p.export_label.text()
    assert any(p.timeline_table.item(r, 1).text() == "報告" for r in range(p.timeline_table.rowCount()))


def test_shutdown_cancels_running_inspection(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    sample = tmp_path / "copy.exe"
    shutil.copyfile(PY_EXE, sample)
    p = lab_page(qtbot, container)
    p.path_edit.setText(str(sample))
    p.inspect_button.click()
    p.shutdown()
    assert not p.busy


# ---------------- Reports page ----------------

class Opener:
    def __init__(self) -> None:
        self.opened: list[Path] = []

    def __call__(self, path: Path) -> bool:
        self.opened.append(path)
        return True


def reports_page(qtbot: QtBot, c: AppContainer, answer: bool = False) -> tuple[ReportsPage, Opener, list[str]]:
    asked: list[str] = []
    opener = Opener()

    def confirm(_parent, _title: str, message: str) -> bool:  # type: ignore[no-untyped-def]
        asked.append(message)
        return answer

    p = ReportsPage(c.reports, confirm=confirm, opener=opener)
    qtbot.addWidget(p)
    verified(qtbot, p)
    return p, opener, asked


def verified(qtbot: QtBot, p: ReportsPage) -> None:
    """Integrity is checked in the background (Audit 3, C2); wait until it is done."""
    qtbot.waitUntil(lambda: not p.verifying, timeout=30000)


def _scan(c: AppContainer, tmp_path: Path) -> int:
    root = tmp_path / "scan"
    root.mkdir()
    (root / "bad.bin").write_bytes(b"x " + MALWARE_MARKER)
    return c.scans.run_scan([root], CancelToken()).job_id


def test_reports_generate_scan_report(qtbot: QtBot, make_container, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    c = make_container([SignatureAV()])
    job = _scan(c, tmp_path)
    p, _, _ = reports_page(qtbot, c)
    assert p.job_combo.count() == 1 and p.job_combo.currentData() == job and p.generate_button.isEnabled()
    p.generate_scan_report()
    qtbot.waitUntil(lambda: p.table.rowCount() == 3, timeout=60000)
    verified(qtbot, p)
    assert {p.table.item(r, 2).text() for r in range(3)} == {"JSON", "HTML", "PDF"}
    assert all(p.table.item(r, 5).text() == "未變更" for r in range(3)) and "已產生 3 份" in p.status_label.text()


def test_reports_integrity_open_and_copy(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    from sentinelx.core.enums import ReportKind

    doc = container.lab.sample_document("cd" * 32, None)
    [row] = container.reports.generate(doc, [ReportKind.HTML]).rows
    p, opener, asked = reports_page(qtbot, container, answer=False)
    assert p.generate_button.isEnabled() is False  # no scan jobs yet
    p.table.selectRow(0)
    assert p.copy_button.isEnabled()
    p.open_selected()
    assert opener.opened == [Path(row.path)] and asked == []
    dest = tmp_path / "copy.html"
    p.save_copy_to(dest)
    assert dest.read_bytes() == Path(row.path).read_bytes()

    Path(row.path).write_text("<script>changed</script>", encoding="utf-8")
    p.refresh()
    verified(qtbot, p)
    assert p.integrity[row.id] is Integrity.MODIFIED and p.table.item(0, 5).text() == "已被修改"
    p.table.selectRow(0)
    assert not p.copy_button.isEnabled()
    p.open_selected()
    assert len(asked) == 1 and "不符" in asked[0] and len(opener.opened) == 1  # declined: not opened
    p.save_copy_to(tmp_path / "copy2.html")
    assert "已被修改" in p.status_label.text() and not (tmp_path / "copy2.html").exists()

    Path(row.path).unlink()
    p.refresh()
    verified(qtbot, p)
    p.table.selectRow(0)
    p.open_selected()
    assert "不存在" in p.status_label.text() and len(opener.opened) == 1


def test_reports_open_modified_after_confirm(qtbot: QtBot, container: AppContainer) -> None:
    from sentinelx.core.enums import ReportKind

    [row] = container.reports.generate(container.lab.sample_document("ef" * 32, None), [ReportKind.JSON]).rows
    Path(row.path).write_text("{}", encoding="utf-8")
    p, opener, asked = reports_page(qtbot, container, answer=True)
    p.table.selectRow(0)
    p.open_selected()
    assert len(asked) == 1 and opener.opened == [Path(row.path)]
    p.open_folder()
    assert opener.opened[-1] == container.paths.reports_dir

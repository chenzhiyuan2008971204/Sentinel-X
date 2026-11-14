from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.enums import EngineOutcomeKind, Severity
from sentinelx.core.models import DetectionRecord, DetectionResult
from sentinelx.engines.base import DetectionEngine
from sentinelx.engines.pe_static import PEStaticEngine
from sentinelx.gui.intel_page import ThreatIntelPage
from sentinelx.gui.static_page import StaticAnalysisPage, render_report
from sentinelx.services.static_analysis_service import StaticReport

pytestmark = pytest.mark.gui
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
GOOD = 'rule T { meta: severity = "low" strings: $a = "x-test" condition: $a }'


def intel_page(qtbot: QtBot, c: AppContainer) -> ThreatIntelPage:
    p = ThreatIntelPage(c.intel)
    qtbot.addWidget(p)
    return p


def test_hash_import_lookup_remove(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    p = intel_page(qtbot, container)
    f = tmp_path / "list.txt"
    f.write_text(f"{'a' * 64},Evil\nbad-line\n", encoding="utf-8")

    p.import_hashes(f)  # no name yet
    qtbot.waitUntil(lambda: not p.importing, timeout=30000)  # runs in the background (Audit 4, D2)
    assert "來源名稱" in p.hash_msg.text() and p.src_table.rowCount() == 0

    p.src_name.setText("TestList")
    p.import_hashes(f)
    qtbot.waitUntil(lambda: not p.importing, timeout=30000)
    assert "已匯入 1 筆" in p.hash_msg.text() and "無效 1 行" in p.hash_msg.text()
    assert p.src_table.rowCount() == 1 and p.src_table.item(0, 1).text() == "TestList"

    p.lookup_edit.setText("A" * 64)
    qtbot.mouseClick(p.lookup_button, Qt.MouseButton.LeftButton)
    assert "TestList" in p.lookup_result.text() and "惡意" in p.lookup_result.text()
    p.lookup_edit.setText("b" * 64)
    p.lookup()
    assert "未知" in p.lookup_result.text() and "不代表安全" in p.lookup_result.text()
    p.lookup_edit.setText("nope")
    p.lookup()
    assert "64" in p.lookup_result.text()

    p.src_table.selectRow(0)
    qtbot.mouseClick(p.remove_src_button, Qt.MouseButton.LeftButton)
    assert p.src_table.rowCount() == 0


def test_yara_add_toggle_remove(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    p = intel_page(qtbot, container)
    good = tmp_path / "good.yar"
    good.write_text(GOOD, encoding="utf-8")
    bad = tmp_path / "bad.yar"
    bad.write_text('import "cuckoo"\nrule c { condition: true }', encoding="utf-8")

    p.add_rule_file(good)
    assert "已加入並啟用" in p.rule_msg.text() and p.rule_table.item(0, 4).text() == "有效"
    p.add_rule_file(bad)
    assert "驗證失敗" in p.rule_msg.text() and p.rule_table.item(1, 5).text() == "否"

    p.rule_table.selectRow(1)
    qtbot.mouseClick(p.toggle_rule_button, Qt.MouseButton.LeftButton)
    assert "不能啟用" in p.rule_msg.text()

    p.rule_table.selectRow(0)
    qtbot.mouseClick(p.toggle_rule_button, Qt.MouseButton.LeftButton)
    assert p.rule_table.item(0, 5).text() == "否"
    p.rule_table.selectRow(0)
    qtbot.mouseClick(p.remove_rule_button, Qt.MouseButton.LeftButton)
    assert p.rule_table.rowCount() == 1


def test_static_analysis_real_pe(qtbot: QtBot, make_container: MakeContainer) -> None:
    c = make_container([PEStaticEngine()])
    p = StaticAnalysisPage(c.static)
    qtbot.addWidget(p)
    p.path_edit.setText(sys.executable)
    qtbot.mouseClick(p.analyze_button, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: not p.busy, timeout=20000)
    assert p.last_report is not None
    assert p.last_report.sha256 == hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    html_text = p.report.toHtml()
    assert "PEStatic" in html_text and "區段" in html_text and "數位簽章" in html_text


def test_static_analysis_errors_shown(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    p = StaticAnalysisPage(container.static)
    qtbot.addWidget(p)
    p.start_analysis()
    assert "請先選擇" in p.status_label.text()
    p.path_edit.setText(str(tmp_path / "missing.exe"))
    p.start_analysis()
    qtbot.waitUntil(lambda: not p.busy, timeout=10000)
    assert "無法分析" in p.status_label.text()


@pytest.mark.security
def test_report_escapes_hostile_strings() -> None:
    evil = "<script>alert(1)</script>"
    det = DetectionRecord("PEStatic", "1", evil, Severity.LOW, {}, "a" * 64, evil)
    res = DetectionResult("PEStatic", EngineOutcomeKind.FINDINGS, "1", "r", (det,), info={
        "is_pe": True, "sections": [{"name": evil, "virtual_size": 1, "raw_size": 1, "entropy": 1.0,
                                     "writable": False, "executable": True}],
        "imports": {evil: [evil]}, "version_info": {evil: evil}, "signature": {"status": "UNSIGNED", "message": evil},
    })
    out = render_report(StaticReport(Path(f"C:/x/{evil}.exe"), 1, "a" * 64, (res,)))
    assert "<script>" not in out and "&lt;script&gt;" in out

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, FakeEngine
from PySide6.QtCore import Qt
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.engines.base import DetectionEngine
from sentinelx.gui.pages import DashboardPage
from sentinelx.gui.threat_page import ThreatCenterPage

pytestmark = pytest.mark.gui
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


@pytest.fixture
def scanned(make_container: MakeContainer, tmp_path: Path) -> AppContainer:
    c = make_container([FakeEngine()])
    (tmp_path / "bad.bin").write_bytes(MALWARE_MARKER)
    (tmp_path / "ok.txt").write_text("fine")
    c.scans.run_scan([tmp_path], CancelToken())
    return c


def page(qtbot: QtBot, c: AppContainer) -> ThreatCenterPage:
    p = ThreatCenterPage(c.reviews)
    qtbot.addWidget(p)
    p.show()
    return p


def test_lists_and_shows_detail(qtbot: QtBot, scanned: AppContainer) -> None:
    p = page(qtbot, scanned)
    assert p.table.rowCount() == 1 and p.table.item(0, 1).text() == "可疑"
    assert not p.confirm_button.isEnabled()
    p.table.selectRow(0)
    html_text = p.detail.toPlainText()
    assert "判定說明" in html_text and "FakeAV" in html_text and "不是機率" in html_text
    assert p.confirm_button.isEnabled()
    p.include_resolved.setChecked(True)
    assert p.table.rowCount() == 2


def test_review_requires_reason_then_dismisses(qtbot: QtBot, scanned: AppContainer) -> None:
    p = page(qtbot, scanned)
    p.table.selectRow(0)
    qtbot.mouseClick(p.fp_button, Qt.MouseButton.LeftButton)
    assert "原因" in p.msg.text() and p.table.rowCount() == 1

    p.reason_edit.setText("測試檔")
    qtbot.mouseClick(p.fp_button, Qt.MouseButton.LeftButton)
    assert "標記誤判" in p.msg.text()
    assert p.table.rowCount() == 0
    assert p.fp_table.rowCount() == 1

    p.tabs.setCurrentIndex(1)
    p.fp_table.selectRow(0)
    qtbot.mouseClick(p.remove_fp_button, Qt.MouseButton.LeftButton)
    assert p.fp_table.rowCount() == 0 and p.table.rowCount() == 1


def test_escalate_and_confirm(qtbot: QtBot, scanned: AppContainer) -> None:
    p = page(qtbot, scanned)
    p.table.selectRow(0)
    p.reason_edit.setText("需要逆向")
    qtbot.mouseClick(p.escalate_button, Qt.MouseButton.LeftButton)
    assert p.table.item(0, 4).text() == "待進一步分析"
    # The reviewed item stays selected and actionable without re-clicking it.
    assert p.confirm_button.isEnabled() and p.table.currentRow() == 0
    p.reason_edit.setText("確認惡意")
    qtbot.mouseClick(p.confirm_button, Qt.MouseButton.LeftButton)
    assert p.table.item(0, 1).text() == "確認威脅", p.msg.text()
    assert p.table.item(0, 2).text() == "人工確認"


@pytest.mark.security
def test_detail_escapes_hostile_paths(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    d = tmp_path / "x&lt;b&gt;"  # literal entity-like name; Windows forbids < > in names
    d.mkdir()
    (d / "bad.bin").write_bytes(MALWARE_MARKER)
    c.scans.run_scan([d], CancelToken())
    p = page(qtbot, c)
    p.table.selectRow(0)
    assert "x&lt;b&gt;" in p.detail.toPlainText()  # shown literally, not decoded to <b>


def test_dashboard_counts(qtbot: QtBot, scanned: AppContainer) -> None:
    dash = DashboardPage(scanned.status, scanned.reviews)
    qtbot.addWidget(dash)
    assert "可疑 1" in dash.cards["threats"].value.text()
    assert dash.cards["review"].value.text() == "1 個"

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import FakeEngine, make_tree
from PySide6.QtCore import Qt
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.engines.base import DetectionEngine
from sentinelx.gui.scan_page import ScanCenterPage

pytestmark = pytest.mark.gui

MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


def page_for(qtbot: QtBot, c: AppContainer) -> ScanCenterPage:
    p = ScanCenterPage(c.scans)
    qtbot.addWidget(p)
    p.show()
    return p


def wait_done(qtbot: QtBot, p: ScanCenterPage, timeout: int = 15000) -> None:
    qtbot.waitUntil(lambda: not p.scanning, timeout=timeout)


def test_start_disabled_without_targets(qtbot: QtBot, container: AppContainer) -> None:
    p = page_for(qtbot, container)
    assert not p.start_button.isEnabled()
    assert "FakeAV 9.9" in p.engine_label.text()


def test_no_engine_blocks_scan_and_explains(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path) -> None:
    p = page_for(qtbot, make_container([FakeEngine(available=False)]))
    p.add_target(tmp_path)
    assert not p.start_button.isEnabled()
    assert "無法使用" in p.engine_label.text()
    assert "沒有可用的偵測引擎" in p.progress_label.text()


def test_scan_runs_async_and_shows_results(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    make_tree(tmp_path / "t")
    p = page_for(qtbot, container)
    p.add_target(tmp_path / "t")
    p.add_target(tmp_path / "t")  # duplicates ignored
    assert p.targets.count() == 1
    qtbot.mouseClick(p.start_button, Qt.MouseButton.LeftButton)
    assert p.scanning and p.cancel_button.isEnabled() and not p.start_button.isEnabled()
    wait_done(qtbot, p)

    s = p.last_summary
    assert s is not None and s.status == "COMPLETED"
    # FakeAV is an unrated engine: its HIGH hit is graded MODERATE -> SUSPICIOUS, not confirmed.
    assert (s.confirmed, s.suspicious, s.clean) == (0, 1, 3)
    assert "掃描完成" in p.result_label.text() and "可疑 1" in p.result_label.text()
    assert "威脅中心" in p.result_label.text()
    assert p.jobs_table.rowCount() == 1 and p.jobs_table.item(0, 6).text() == "0 / 1"
    statuses = [p.files_table.item(r, 0).text() for r in range(p.files_table.rowCount())]
    assert sum(st.startswith("可疑") for st in statuses) == 1
    assert sum(st.startswith("未發現威脅") for st in statuses) == 3


def test_cancel_from_gui(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path) -> None:
    for i in range(30):
        (tmp_path / f"{i}.txt").write_text(str(i))
    eng = FakeEngine(delay_per_file_s=0.2)
    p = page_for(qtbot, make_container([eng]))
    p.add_target(tmp_path)
    p.start_scan()
    assert eng.started.wait(10)
    qtbot.mouseClick(p.cancel_button, Qt.MouseButton.LeftButton)
    wait_done(qtbot, p)
    assert p.last_summary is not None and p.last_summary.status == "CANCELLED"
    assert "已取消" in p.result_label.text()


def test_partial_result_is_flagged(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a")
    p = page_for(qtbot, make_container([FakeEngine(raise_on_scan=RuntimeError("x"))]))
    p.add_target(tmp_path)
    p.start_scan()
    wait_done(qtbot, p)
    assert "部分完成" in p.result_label.text() and "未完成評估" in p.result_label.text()


def test_remove_target(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    p = page_for(qtbot, container)
    p.add_target(tmp_path)
    p.targets.setCurrentRow(0)
    qtbot.mouseClick(p.remove_target_button, Qt.MouseButton.LeftButton)
    assert p.targets.count() == 0 and not p.start_button.isEnabled()


def test_exclusion_management(qtbot: QtBot, container: AppContainer) -> None:
    p = page_for(qtbot, container)
    p.excl_kind.setCurrentIndex(p.excl_kind.findText("SHA-256"))
    p.excl_value.setText("not-a-hash")
    qtbot.mouseClick(p.add_excl_button, Qt.MouseButton.LeftButton)
    assert "64" in p.excl_error.text() and p.excl_table.rowCount() == 0

    p.excl_kind.setCurrentIndex(p.excl_kind.findText("副檔名"))
    p.excl_value.setText("log")
    qtbot.mouseClick(p.add_excl_button, Qt.MouseButton.LeftButton)
    assert p.excl_table.rowCount() == 1 and p.excl_table.item(0, 2).text() == ".log"

    p.excl_table.selectRow(0)
    qtbot.mouseClick(p.remove_excl_button, Qt.MouseButton.LeftButton)
    assert p.excl_table.rowCount() == 0


def test_refresh_engines_button(qtbot: QtBot, container: AppContainer) -> None:
    p = page_for(qtbot, container)
    qtbot.mouseClick(p.refresh_engines_button, Qt.MouseButton.LeftButton)
    assert "FakeAV" in p.engine_label.text()

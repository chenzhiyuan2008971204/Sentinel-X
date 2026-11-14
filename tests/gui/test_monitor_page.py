from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import FakeCollector
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QPushButton
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.enums import EventSource, PrivilegeLevel
from sentinelx.engines.base import DetectionEngine
from sentinelx.gui.monitor_page import BehaviorMonitorPage
from sentinelx.monitor.events import EventKind, SecurityEventIn
from sentinelx.services.monitor_service import SYSMON_URL, MonitorService
from sentinelx.storage.event_repository import EventRepository

pytestmark = pytest.mark.gui
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


@pytest.fixture
def env(make_container: MakeContainer):  # type: ignore[no-untyped-def]
    c = make_container([])
    good = FakeCollector("程序（測試）")
    admin = FakeCollector("Sysmon", available=False, requires_admin=True, source=EventSource.SYSMON)
    svc = MonitorService(c.paths, c.config, c.config_store, EventRepository(c.db), c.quarantine._verdicts, c.audit,
                         PrivilegeLevel.STANDARD, collector_factory=lambda cfg: [good, admin])
    yield c, svc, good
    svc.stop()


class Answer:
    def __init__(self, v: bool) -> None:
        self.v = v
        self.asked = 0

    def __call__(self, *_a) -> bool:  # type: ignore[no-untyped-def]
        self.asked += 1
        return self.v


def page(qtbot: QtBot, svc: MonitorService, **kw) -> BehaviorMonitorPage:  # type: ignore[no-untyped-def]
    p = BehaviorMonitorPage(svc, **kw)
    qtbot.addWidget(p)
    p.show()
    return p


def test_sources_and_start_stop(qtbot: QtBot, env) -> None:  # type: ignore[no-untyped-def]
    _, svc, good = env
    p = page(qtbot, svc)
    assert p.sources.rowCount() == 2 and p.sources.item(1, 1).text() == "需要系統管理員"
    assert not p.stop_button.isEnabled()
    qtbot.mouseClick(p.start_button, Qt.MouseButton.LeftButton)
    assert svc.running and good.started and p.stop_button.isEnabled() and not p.start_button.isEnabled()
    assert "程序（測試）" in p.msg.text()
    qtbot.mouseClick(p.stop_button, Qt.MouseButton.LeftButton)
    assert not svc.running and good.stopped


def test_timeline_filters_and_alerts(qtbot: QtBot, env) -> None:  # type: ignore[no-untyped-def]
    _, svc, good = env
    p = page(qtbot, svc)
    p.start()
    good.pending = [
        SecurityEventIn(EventSource.PSUTIL, EventKind.PROCESS_CREATE, "2026-11-02T07:00:00Z", "powershell.exe",
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 77, 1,
                        "powershell.exe -enc SQBFAFgA"),
        SecurityEventIn(EventSource.FSWATCH, EventKind.FILE_CREATE, "2026-11-02T07:00:01Z", target_path="C:\\d\\<b>x</b>.txt"),
    ]
    svc.run_once()
    p.refresh_all()
    assert p.timeline.rowCount() == 2
    p.kind_filter.setCurrentIndex(p.kind_filter.findData(EventKind.FILE_CREATE.value))
    qtbot.mouseClick(p.apply_filter_button, Qt.MouseButton.LeftButton)
    assert p.timeline.rowCount() == 1 and p.timeline.item(0, 6).text() == "C:\\d\\<b>x</b>.txt"
    p.kind_filter.setCurrentIndex(0)
    p.text_filter.setText("powershell")
    p.refresh_timeline()
    assert p.timeline.rowCount() == 1

    assert p.alert_table.rowCount() == 1
    p.alert_table.selectRow(0)
    text = p.alert_detail.toPlainText()
    assert "觀察到的事實" in text and "分析推論" in text and "不會對此警示採取任何自動動作" in text
    assert text.index("觀察到的事實") < text.index("分析推論")
    qtbot.mouseClick(p.ack_button, Qt.MouseButton.LeftButton)
    assert p.alert_table.rowCount() == 0
    p.show_closed.setChecked(True)
    assert p.alert_table.item(0, 3).text() == "已讀"


def test_watch_folders(qtbot: QtBot, env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    _, svc, _ = env
    p = page(qtbot, svc)
    p.add_folder(tmp_path)
    assert p.folder_list.count() == 1
    p.add_folder(tmp_path)
    assert "已在監看清單" in p.msg.text()
    p.folder_list.setCurrentRow(0)
    qtbot.mouseClick(p.remove_folder_button, Qt.MouseButton.LeftButton)
    assert p.folder_list.count() == 0


def test_elevation_requires_confirmation(qtbot: QtBot, env) -> None:  # type: ignore[no-untyped-def]
    _, svc, _ = env
    calls: list[str] = []
    svc._relauncher = lambda: calls.append("relaunch") or True
    quits: list[int] = []
    no = Answer(False)
    p = page(qtbot, svc, confirm=no, quit_app=lambda: quits.append(1))
    assert p.elevate_button.isVisible()
    qtbot.mouseClick(p.elevate_button, Qt.MouseButton.LeftButton)
    assert no.asked == 1 and calls == [] and quits == []
    p.confirm = Answer(True)
    qtbot.mouseClick(p.elevate_button, Qt.MouseButton.LeftButton)
    assert calls == ["relaunch"] and quits == [1]


def test_elevation_declined_by_uac(qtbot: QtBot, env) -> None:  # type: ignore[no-untyped-def]
    _, svc, _ = env
    svc._relauncher = lambda: False
    quits: list[int] = []
    p = page(qtbot, svc, confirm=Answer(True), quit_app=lambda: quits.append(1))
    p.request_elevation()
    assert quits == [] and "UAC" in p.msg.text()


def test_sysmon_guide(qtbot: QtBot, env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    _, svc, _ = env
    opened: list[str] = []
    p = page(qtbot, svc, open_url=opened.append)
    assert "已偵測到 Sysmon" in p.sysmon_state.text()  # the fake Sysmon source "needs admin" = installed
    qtbot.mouseClick(p.sysmon_page_button, Qt.MouseButton.LeftButton)
    assert opened == [SYSMON_URL]
    p.save_sysmon_config(tmp_path / "s.xml")
    assert (tmp_path / "s.xml").exists() and "已儲存" in p.msg.text()


def test_no_process_control_buttons(qtbot: QtBot, env) -> None:  # type: ignore[no-untyped-def]
    _, svc, _ = env
    p = page(qtbot, svc)
    labels = " ".join(b.text() for b in p.findChildren(QPushButton))
    for word in ("終止", "結束程序", "封鎖", "阻擋", "Kill", "kill"):
        assert word not in labels


def test_admin_hides_elevation(qtbot: QtBot, env) -> None:  # type: ignore[no-untyped-def]
    _, svc, _ = env
    svc.privilege = PrivilegeLevel.ADMINISTRATOR
    p = page(qtbot, svc)
    assert not p.elevate_button.isVisible()

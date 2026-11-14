"""Phase 8: settings, dashboard charts, indicators, transitions, cancellation, and the rule
that every visible button does something."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, SignatureAV
from PySide6.QtCore import QMetaMethod, QPointF
from PySide6.QtWidgets import QPushButton
from pytestqt.qtbot import QtBot
from sqlalchemy import text

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import PrivilegeLevel
from sentinelx.engines.base import DetectionEngine
from sentinelx.gui.charts import Bar, CategoryBars, DailyColumns
from sentinelx.gui.main_window import MainWindow, Services
from sentinelx.gui.pages import PAGE_SPECS, DashboardPage
from sentinelx.gui.settings_page import SettingsPage
from sentinelx.gui.workers import TaskRunner

pytestmark = pytest.mark.gui
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


def window(qtbot: QtBot, c: AppContainer) -> MainWindow:
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor,
                            c.reports, c.lab, c.settings, c.signatures, c.protection), PrivilegeLevel.STANDARD)
    qtbot.addWidget(w)
    w.show()
    return w


# ---------------- settings ----------------

class Answers:
    def __init__(self, value: bool) -> None:
        self.value = value
        self.asked: list[str] = []

    def __call__(self, _p, _t: str, message: str) -> bool:  # type: ignore[no-untyped-def]
        self.asked.append(message)
        return self.value


def settings_page(qtbot: QtBot, c: AppContainer, answer: bool = True) -> tuple[SettingsPage, Answers, list[Path], list[int]]:
    ans, opened, restarts = Answers(answer), [], []
    p = SettingsPage(c.settings, confirm=ans, opener=lambda path: opened.append(path) or True,
                     restarter=lambda: restarts.append(1) or True)
    qtbot.addWidget(p)
    return p, ans, opened, restarts


def test_settings_show_current_values(qtbot: QtBot, container: AppContainer) -> None:
    p, *_ = settings_page(qtbot, container)
    cfg = container.config
    assert p.max_size.value() == cfg.scan.max_file_size_mb and p.yara_timeout.value() == cfg.scan.yara_timeout_s
    assert p.backend.currentData() == cfg.clamav.backend and p.log_level.currentData() == cfg.log_level
    assert not p.restart_button.isEnabled()


def test_settings_save_persists_audits_and_asks_restart(qtbot: QtBot, container: AppContainer) -> None:
    p, ans, _, restarts = settings_page(qtbot, container)
    p.max_size.setValue(250)
    p.yara_timeout.setValue(15)
    p.use_pe.setChecked(False)
    p.poll.setValue(5.0)
    p.save_button.click()
    assert "已儲存 4 項變更" in p.status_label.text() and "重新啟動" in p.status_label.text()
    disk = json.loads(container.paths.config_file.read_text(encoding="utf-8"))
    assert disk["scan"]["max_file_size_mb"] == 250 and disk["scan"]["yara_timeout_s"] == 15
    assert disk["engines"]["pe_static"] is False and disk["monitor"]["poll_interval_s"] == 5.0
    assert container.config.scan.max_file_size_mb == 250  # shared object kept in step
    with container.db.engine.connect() as c:
        detail = json.loads(c.execute(text("SELECT detail_json FROM audit_log WHERE action='SETTINGS_CHANGE'")).scalar_one())
    assert detail["scan.max_file_size_mb"] == [100, 250]
    assert p.restart_button.isEnabled()
    p.restart_button.click()
    assert ans.asked and restarts == [1]
    p.save_button.click()
    assert "沒有變更" in p.status_label.text()


def test_settings_keep_watch_dirs_set_on_monitor_page(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    p, *_ = settings_page(qtbot, container)
    container.monitor.add_watch_dir(tmp_path)  # after the settings page was loaded
    p.retention.setValue(5000)
    p.save_button.click()
    disk = json.loads(container.paths.config_file.read_text(encoding="utf-8"))
    assert disk["monitor"]["watch_dirs"] == [str(tmp_path)] and disk["monitor"]["retention_events"] == 5000


@pytest.mark.security
def test_settings_reject_invalid_values(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    p, *_ = settings_page(qtbot, container)
    before = container.paths.config_file.read_text(encoding="utf-8")
    p.clamd_host.setText("10.0.0.5")
    p.save_button.click()
    assert "只能是本機位址" in p.status_label.text()
    p.clamd_host.setText("127.0.0.1")
    p.clamscan_path.setText(str(tmp_path / "missing.exe"))
    p.save_button.click()
    assert "找不到這個檔案" in p.status_label.text()
    p.clamscan_path.clear()
    p.db_dir.setText(str(tmp_path / "nope"))
    p.save_button.click()
    assert "資料夾不存在" in p.status_label.text()
    assert container.paths.config_file.read_text(encoding="utf-8") == before


def test_settings_defaults_discard_follow_links_and_folders(qtbot: QtBot, container: AppContainer) -> None:
    p, ans, opened, _ = settings_page(qtbot, container, answer=False)
    p.max_size.setValue(7)
    p.discard_button.click()
    assert p.max_size.value() == container.config.scan.max_file_size_mb
    p.max_size.setValue(7)
    p.defaults_button.click()
    assert p.max_size.value() == 100 and "預設值" in p.status_label.text()
    p.follow_links.setChecked(True)
    p.save_button.click()
    assert ans.asked and not p.follow_links.isChecked() and not container.config.scan.follow_reparse_points
    p.open_data_button.click()
    p.open_logs_button.click()
    assert opened == [container.paths.root, container.paths.log_dir]


def test_yara_timeout_reaches_the_engine(make_container: MakeContainer) -> None:
    c = make_container([])
    c.settings.save(c.settings.current().model_copy(update={"scan": c.config.scan.model_copy(update={"yara_timeout_s": 9})}))
    c2 = make_container_with_real_engines(c)
    from sentinelx.engines.yara_engine import YaraEngine

    try:
        [y] = [e for e in c2.engines if isinstance(e, YaraEngine)]
        assert y._timeout == 9
    finally:
        c2.shutdown()


def make_container_with_real_engines(c: AppContainer) -> AppContainer:
    from sentinelx.app.bootstrap import bootstrap

    return bootstrap(c.paths, console_log=False, privilege=PrivilegeLevel.STANDARD)


# ---------------- dashboard ----------------

def test_dashboard_charts_show_real_data(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    d = DashboardPage(c.status, c.reviews, c.scans)
    qtbot.addWidget(d)
    assert sum(b.value for b in d.class_chart.bars) == 0
    assert sum(b.value for b in d.activity_chart.bars) == 0 and len(d.activity_chart.bars) == 14
    root = tmp_path / "s"
    root.mkdir()
    (root / "bad.bin").write_bytes(MALWARE_MARKER)
    (root / "ok.txt").write_text("fine")
    c.scans.run_scan([root], CancelToken())
    d.refresh_button.click()
    values = {b.label: b.value for b in d.class_chart.bars}
    assert sum(values.values()) == 2 and values["未發現威脅"] == 1
    assert d.activity_chart.bars[-1].value == 2 and "2 個檔案完整評估" in d.activity_chart.bars[-1].tip


def test_dashboard_reflows_with_width(qtbot: QtBot, container: AppContainer) -> None:
    d = DashboardPage(container.status, container.reviews, container.scans)
    qtbot.addWidget(d)
    d.show()
    for width, cols in ((1200, 3), (800, 2), (500, 1)):
        d.resize(width, 700)
        qtbot.waitUntil(lambda c=cols: d.columns == c, timeout=3000)


def test_charts_tooltips_and_empty_state(qtbot: QtBot) -> None:
    bars = CategoryBars("空")
    qtbot.addWidget(bars)
    bars.resize(400, 200)
    bars.set_bars([Bar("甲", 3, "#f87171", "甲：3"), Bar("乙", 0, "#34d399", "乙：0")])
    bars.show()
    bars.grab()  # paints and records hit areas
    assert bars.tip_at(QPointF(200, 4 + 15)) == (0, "甲：3")
    cols = DailyColumns("最近 14 天沒有掃描")
    qtbot.addWidget(cols)
    cols.resize(400, 180)
    cols.set_bars([Bar("1/1", 0, "#22d3ee")] * 3)
    cols.show()
    cols.grab()
    assert cols.tip_at(QPointF(10, 10)) is None  # empty data: no marks, only the message


# ---------------- main window ----------------

def test_badges_and_status_bar(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    f = tmp_path / "bad.bin"
    f.write_bytes(MALWARE_MARKER)
    c.scans.run_scan([f], CancelToken())
    w = window(qtbot, c)
    row = [s.key for s in PAGE_SPECS].index("threats")
    assert w.badges["threats"] == 1 and w.nav.item(row).text().endswith("(1)")
    assert "未啟動" in w.monitor_label.text() and "1/1 可用" in w.engines_label.text()
    w.close()


def test_page_fade_finishes_and_removes_effect(qtbot: QtBot, container: AppContainer) -> None:
    w = window(qtbot, container)
    w.nav.setCurrentRow(1)
    page = w.stack.currentWidget()
    assert page.graphicsEffect() is not None
    qtbot.waitUntil(lambda: page.graphicsEffect() is None, timeout=3000)
    w.close()


def test_every_visible_button_is_connected(qtbot: QtBot, container: AppContainer) -> None:
    """CLAUDE.md: no fake buttons. Walk every page and check each button's clicked signal."""
    w = window(qtbot, container)
    unconnected = []
    for row, spec in enumerate(PAGE_SPECS):
        w.nav.setCurrentRow(row)
        for b in w.pages[spec.key].findChildren(QPushButton):
            if not b.isSignalConnected(QMetaMethod.fromSignal(b.clicked)):
                unconnected.append(f"{spec.key}: {b.text()}")
    assert unconnected == []
    w.close()


# ---------------- background tasks ----------------

def test_task_runner_cancel_and_shutdown(qtbot: QtBot) -> None:
    r = TaskRunner()
    errors: list[str] = []
    started = threading.Event()

    def slow(cancel: CancelToken) -> object:
        started.set()
        while True:
            cancel.raise_if_cancelled()
            time.sleep(0.01)

    assert r.run(slow, lambda _x: None, errors.append, "t")
    assert not r.run(slow, lambda _x: None, errors.append, "t")  # one task at a time
    started.wait(5)
    r.cancel()
    qtbot.waitUntil(lambda: not r.busy, timeout=5000)
    assert errors == ["已取消。"]
    r.run(slow, lambda _x: None, errors.append, "t")
    r.shutdown()
    assert not r.busy


def test_static_analysis_cancel_button(qtbot: QtBot, container: AppContainer, tmp_path: Path) -> None:
    from sentinelx.gui.static_page import StaticAnalysisPage

    p = StaticAnalysisPage(container.static)
    qtbot.addWidget(p)
    assert not p.cancel_button.isEnabled()
    f = tmp_path / "a.txt"
    f.write_text("x")
    p.path_edit.setText(str(f))
    p.analyze_button.click()
    assert p.cancel_button.isEnabled()
    p.cancel_button.click()
    qtbot.waitUntil(lambda: not p.busy, timeout=30000)
    assert not p.cancel_button.isEnabled()
    assert "取消" in p.status_label.text() or "分析完成" in p.status_label.text()  # may finish first


def test_lab_cancel_kills_worker(qtbot: QtBot, container: AppContainer, monkeypatch: pytest.MonkeyPatch,
                                 tmp_path: Path) -> None:
    import sys

    from sentinelx.gui.lab_page import ResearchLabPage
    from sentinelx.research import isolation

    real = isolation.run_worker
    monkeypatch.setattr(container.lab, "_worker", lambda path, mb, **kw: real(
        path, mb, command=[sys.executable, "-c", "import time; time.sleep(30)"], **kw))
    p = ResearchLabPage(container.lab)
    qtbot.addWidget(p)
    f = tmp_path / "a.txt"
    f.write_text("x")
    p.path_edit.setText(str(f))
    p.inspect_button.click()
    assert not p.cancel_button.isHidden() and not p.progress.isHidden()
    t0 = time.monotonic()
    p.cancel_button.click()
    qtbot.waitUntil(lambda: not p.busy, timeout=10000)
    assert time.monotonic() - t0 < 10 and "已取消" in p.status_label.text()
    assert p.cancel_button.isHidden() and p.inspection is None

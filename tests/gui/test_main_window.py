from __future__ import annotations

from collections.abc import Callable, Sequence

import pytest
from fakes import FakeEngine
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QPushButton
from pytestqt.qtbot import QtBot
from sqlalchemy import text

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.enums import PrivilegeLevel
from sentinelx.engines.base import DetectionEngine
from sentinelx.gui.intel_page import ThreatIntelPage
from sentinelx.gui.lab_page import ResearchLabPage
from sentinelx.gui.main_window import MainWindow, Services
from sentinelx.gui.pages import PAGE_SPECS, DashboardPage, NotImplementedPage
from sentinelx.gui.protection_page import ProtectionPage
from sentinelx.gui.reports_page import ReportsPage
from sentinelx.gui.settings_page import SettingsPage
from sentinelx.gui.scan_page import ScanCenterPage
from sentinelx.gui.static_page import StaticAnalysisPage

pytestmark = pytest.mark.gui


def make_window(qtbot: QtBot, c: AppContainer, privilege: PrivilegeLevel = PrivilegeLevel.STANDARD) -> MainWindow:
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor,
                            c.reports, c.lab, c.settings, c.signatures, c.protection), privilege)
    qtbot.addWidget(w)
    w.show()
    return w


@pytest.fixture
def window(qtbot: QtBot, container: AppContainer) -> MainWindow:
    return make_window(qtbot, container)


def dashboard(w: MainWindow) -> DashboardPage:
    d = w.pages["dashboard"]
    assert isinstance(d, DashboardPage)
    return d


def test_title_is_chinese(window: MainWindow) -> None:
    assert window.windowTitle().startswith("Sentinel X 研究版")
    assert "系統管理員" not in window.windowTitle()


def test_admin_title_marker(qtbot: QtBot, container: AppContainer) -> None:
    assert "系統管理員模式" in make_window(qtbot, container, PrivilegeLevel.ADMINISTRATOR).windowTitle()


def test_all_pages_navigable(window: MainWindow) -> None:
    # 13 pages (home + the 10 original + 即時防護 + 試跑室) and the 「進階功能」 header
    assert window.nav.count() == len(PAGE_SPECS) + 1 == 14
    assert window.current_page_key() == "home"
    for spec in PAGE_SPECS:
        window.go_to(spec.key)
        assert window.current_page_key() == spec.key
        assert window.stack.currentWidget() is window.pages[spec.key]


def test_everyday_pages_first_research_tools_folded(window: MainWindow) -> None:
    from sentinelx.gui.main_window import ADVANCED_HEADER

    keys = [window.nav.item(r).data(Qt.ItemDataRole.UserRole) for r in range(window.nav.count())]
    assert keys[:7] == ["home", "scan", "sandbox", "protection", "threats", "quarantine", "settings"]
    assert keys[7] == ADVANCED_HEADER
    advanced = [window.nav.item(r) for r in range(8, window.nav.count())]
    assert advanced and all(it.isHidden() for it in advanced)
    window._nav_clicked(window.advanced_header)  # open
    assert all(not it.isHidden() for it in advanced) and window.advanced_header.text().startswith("▾")
    window._nav_clicked(window.advanced_header)  # close again
    assert all(it.isHidden() for it in advanced)
    window.go_to("lab")  # going to a research page opens the section
    assert window.advanced_open and window.current_page_key() == "lab"


def test_implemented_pages_are_real(window: MainWindow) -> None:
    assert isinstance(window.pages["scan"], ScanCenterPage)
    assert isinstance(window.pages["intel"], ThreatIntelPage)
    assert isinstance(window.pages["static"], StaticAnalysisPage)
    assert isinstance(window.pages["lab"], ResearchLabPage)
    assert isinstance(window.pages["reports"], ReportsPage)
    assert isinstance(window.pages["settings"], SettingsPage)
    assert isinstance(window.pages["protection"], ProtectionPage)
    # Phase 8: no placeholder page is left.
    assert [s.key for s in PAGE_SPECS if s.planned_phase is not None] == []


def test_unimplemented_pages_are_honest_and_have_no_controls(window: MainWindow) -> None:
    for spec in PAGE_SPECS:
        if spec.planned_phase is None:
            continue
        page = window.pages[spec.key]
        assert isinstance(page, NotImplementedPage)
        assert f"Phase {spec.planned_phase}" in page.note.text()
        assert page.findChildren(QPushButton) == []


def test_dashboard_shows_live_status(window: MainWindow, container: AppContainer) -> None:
    d = dashboard(window)
    assert d.cards["root"].value.text() == str(container.paths.root)
    assert "1 筆" in d.cards["audit"].value.text()
    assert d.cards["engines"].value.text() == "FakeAV 9.9"
    assert d.cards["privilege"].value.text() == "一般使用者"


def test_dashboard_reports_unavailable_engine(
    qtbot: QtBot, make_container: Callable[[Sequence[DetectionEngine]], AppContainer]
) -> None:
    w = make_window(qtbot, make_container([FakeEngine(available=False)]))
    assert "無可用引擎" in dashboard(w).cards["engines"].value.text()


def test_refresh_reflects_new_data(window: MainWindow, container: AppContainer, qtbot: QtBot) -> None:
    container.audit.record("TEST_EVENT")
    qtbot.mouseClick(dashboard(window).refresh_button, Qt.MouseButton.LeftButton)
    assert "2 筆" in dashboard(window).cards["audit"].value.text()


@pytest.mark.security
def test_dashboard_reports_broken_audit_chain(window: MainWindow, container: AppContainer) -> None:
    with container.db.engine.begin() as c:
        c.execute(text("UPDATE audit_log SET action='TAMPERED' WHERE id=1"))
    dashboard(window).refresh()
    assert "中斷" in dashboard(window).cards["audit"].value.text()

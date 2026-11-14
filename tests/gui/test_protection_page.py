"""Real-time protection in the GUI: page controls, notifications across threads, window close."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, SignatureAV
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.enums import PrivilegeLevel
from sentinelx.engines.base import DetectionEngine
from sentinelx.gui.main_window import MainWindow, Services
from sentinelx.gui.protection_page import ProtectionPage
from sentinelx.services.protection_service import ProtectionService
from sentinelx.storage.scan_repository import ExclusionRepository, ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

pytestmark = pytest.mark.gui
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


class Reg:
    HKEY_CURRENT_USER, REG_SZ = 1, 1

    def __init__(self) -> None:
        self.v: dict[str, str] = {}

    class K:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *a) -> None:  # type: ignore[no-untyped-def]
            pass

    def CreateKey(self, *_a):  # type: ignore[no-untyped-def]  # noqa: N802
        return self.K()

    OpenKey = CreateKey  # noqa: N815

    def SetValueEx(self, _k, n, _r, _t, v) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
        self.v[n] = v

    def DeleteValue(self, _k, n) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
        self.v.pop(n, None)

    def QueryValueEx(self, _k, n):  # type: ignore[no-untyped-def]  # noqa: N802
        if n not in self.v:
            raise OSError(2, "missing")
        return self.v[n], 1


def protection(c: AppContainer, folder: Path) -> ProtectionService:
    return ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db),
                             ExclusionRepository(c.db), VerdictRepository(c.db), c.quarantine, c.audit, clamd=None,
                             removable=lambda: [], folders=lambda: [("測試", folder)], registry=Reg())


def test_page_toggle_options_and_activity(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([SignatureAV()])
    s = protection(c, tmp_path)
    asked: list[str] = []
    page = ProtectionPage(s, confirm=lambda _p, _t, m: asked.append(m) or True)
    qtbot.addWidget(page)
    assert "已關閉" in page.state_label.text() and page.toggle_button.text() == "開啟即時防護"
    page.toggle_button.click()
    try:
        assert s.running and "防護中" in page.state_label.text() and "測試" in page.where_label.text()
        assert json.loads(c.paths.config_file.read_text(encoding="utf-8"))["protection"]["enabled"] is True
        page.options["download_gate"].setChecked(False)
        assert s.settings.download_gate is False
        bad = tmp_path / "bad.bin"
        bad.write_bytes(MALWARE_MARKER)
        s.notify_file(str(bad))
        s.process_pending(time.monotonic() + 10)
        s.process_pending(time.monotonic() + 20)
        page.refresh()
        assert page.activity.rowCount() >= 1 and page.activity.item(0, 2).text() == "已自動隔離"
        assert "擋下 1 個" in page.counts_label.text()
    finally:
        page.toggle_button.click()  # off, after confirmation
    assert asked and not s.running and "已關閉" in page.state_label.text()


def test_notifications_reach_the_window_from_other_threads(qtbot: QtBot, make_container: MakeContainer,
                                                           tmp_path: Path) -> None:
    c = make_container([])
    s = protection(c, tmp_path)
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor, c.reports,
                            c.lab, c.settings, c.signatures, s), PrivilegeLevel.STANDARD)
    qtbot.addWidget(w)
    threading.Thread(target=lambda: s.notifier("bad", "已攔截威脅", "x.exe：已自動隔離")).start()
    qtbot.waitUntil(lambda: w.notifications == [("bad", "已攔截威脅", "x.exe：已自動隔離")], timeout=5000)
    assert "即時防護：關閉" in w.protection_label.text()
    w.close()


def test_window_closes_normally_without_tray(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path) -> None:
    """Offscreen there is no system tray: closing must really close (never leave a hidden window)."""
    c = make_container([])
    s = protection(c, tmp_path)
    s.update(enabled=True)
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor, c.reports,
                            c.lab, c.settings, c.signatures, s), PrivilegeLevel.STANDARD)
    qtbot.addWidget(w)
    w.show()
    assert not w.has_tray
    w.close()
    assert not w.isVisible()

from __future__ import annotations

import threading

import pytest
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget
from pytestqt.qtbot import QtBot

from sentinelx.gui.error_bridge import ErrorBridge

pytestmark = pytest.mark.gui


def _boxes() -> list[QMessageBox]:
    return [w for w in QApplication.topLevelWidgets() if isinstance(w, QMessageBox) and w.isVisible()]


def test_error_from_worker_thread_shows_dialog_on_gui_thread(qtbot: QtBot) -> None:
    parent = QWidget()
    qtbot.addWidget(parent)
    bridge = ErrorBridge(parent)
    t = threading.Thread(target=bridge.notify, args=("資料庫發生錯誤。", "DatabaseError: x"))
    t.start()
    t.join()
    qtbot.waitUntil(lambda: len(_boxes()) == 1, timeout=2000)
    box = _boxes()[0]
    assert box.text() == "資料庫發生錯誤。"
    assert box.detailedText() == "DatabaseError: x"
    box.close()

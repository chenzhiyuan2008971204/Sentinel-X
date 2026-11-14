"""Marshals error notifications from any thread onto the GUI thread."""

from __future__ import annotations

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtWidgets import QMessageBox, QWidget


class ErrorBridge(QObject):
    raised = Signal(str, str)

    def __init__(self, parent_window: QWidget | None = None) -> None:
        super().__init__()
        self._parent = parent_window
        self.raised.connect(self._show, Qt.ConnectionType.QueuedConnection)

    def notify(self, user_message: str, detail: str) -> None:
        """Thread-safe: emitting a queued signal is the only thing done off the GUI thread."""
        self.raised.emit(user_message, detail)

    def set_parent_window(self, w: QWidget) -> None:
        self._parent = w

    @Slot(str, str)
    def _show(self, user_message: str, detail: str) -> None:
        box = QMessageBox(self._parent)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle(self.tr("Sentinel X 錯誤"))
        box.setText(user_message)
        box.setDetailedText(detail)
        box.open()

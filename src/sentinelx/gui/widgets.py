"""Small shared widgets and helpers."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from sentinelx.gui.workers import TaskRunner


def item(text: str, color: str | None = None) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if color:
        it.setForeground(QColor(color))
    return it


def table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    t.horizontalHeader().setStretchLastSection(True)
    return t


def title(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("pageTitle")
    return lbl


def muted(text: str = "") -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("muted")
    lbl.setWordWrap(True)
    return lbl


class BusyBar(QWidget):
    """Shown only while the runner is busy: what is happening, an indeterminate progress bar,
    and a cancel button when the task can be cancelled."""

    def __init__(self, runner: TaskRunner) -> None:
        super().__init__()
        self.setObjectName("busyBar")
        self._runner = runner
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.label = QLabel()
        self.label.setObjectName("muted")
        self.label.setTextFormat(Qt.TextFormat.PlainText)
        self.bar = QProgressBar()
        self.bar.setRange(0, 0)  # indeterminate: these tasks cannot report a fraction honestly
        self.bar.setTextVisible(False)
        self.bar.setFixedWidth(160)
        self.cancel_button = QPushButton(self.tr("取消"))
        self.cancel_button.clicked.connect(runner.cancel)
        lay.addWidget(self.label, 1)
        lay.addWidget(self.bar)
        lay.addWidget(self.cancel_button)
        runner.busy_changed.connect(self._on_busy)
        runner.message.connect(self.label.setText)
        self.setVisible(False)

    def _on_busy(self, busy: bool) -> None:
        self.setVisible(busy)
        self.cancel_button.setVisible(busy and self._runner.cancellable)
        self.cancel_button.setEnabled(True)

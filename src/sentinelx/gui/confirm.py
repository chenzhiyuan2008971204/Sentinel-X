"""Explicit confirmation for destructive-looking actions. Pages take a `Confirm` callable so
tests can answer without a modal dialog; the default asks the user with No as the default button."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox, QWidget

Confirm = Callable[[QWidget, str, str], bool]  # (parent, title, plain-text message) -> accepted


def ask_yes_no(parent: QWidget, title: str, message: str) -> bool:
    """A neutral question (not a warning): Yes is the default button."""
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Question)
    box.setWindowTitle(title)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setText(message)
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    box.setDefaultButton(QMessageBox.StandardButton.Yes)
    return box.exec() == QMessageBox.StandardButton.Yes


def ask(parent: QWidget, title: str, message: str) -> bool:
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle(title)
    box.setTextFormat(Qt.TextFormat.PlainText)  # message contains file paths
    box.setText(message)
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    box.setDefaultButton(QMessageBox.StandardButton.No)
    return box.exec() == QMessageBox.StandardButton.Yes

from __future__ import annotations

import threading


class ScanCancelled(Exception):
    """Raised inside long operations when the user cancelled."""


class CancelToken:
    """Cooperative cancellation flag shared between the GUI thread and workers."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise ScanCancelled()

"""Background workers. Long operations never run on the GUI thread."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot

from sentinelx.core.cancel import CancelToken
from sentinelx.core.models import ScanProgress
from sentinelx.services.scan_service import ScanService

log = logging.getLogger(__name__)


class ScanWorker(QObject):
    progress = Signal(object)  # ScanProgress
    finished = Signal(object)  # ScanSummary
    failed = Signal(str)

    PROGRESS_INTERVAL_S = 0.1

    def __init__(self, service: ScanService, roots: Sequence[Path], cancel: CancelToken) -> None:
        super().__init__()
        self._service = service
        self._roots = list(roots)
        self._cancel = cancel
        self._last_emit = 0.0

    def _on_progress(self, p: ScanProgress) -> None:
        now = time.monotonic()
        if now - self._last_emit >= self.PROGRESS_INTERVAL_S:
            self._last_emit = now
            self.progress.emit(p)

    @Slot()
    def run(self) -> None:
        try:
            summary = self._service.run_scan(self._roots, self._cancel, self._on_progress)
        except Exception as exc:  # noqa: BLE001 - reported to the GUI, never swallowed
            log.exception("scan worker failed")
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        self.finished.emit(summary)


class CallWorker(QObject):
    """Runs one callable off the GUI thread and reports its return value or error."""

    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, fn: Callable[[], object]) -> None:
        super().__init__()
        self._fn = fn

    @Slot()
    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001 - reported to the GUI, never swallowed
            if not isinstance(exc, ValueError):
                log.exception("background call failed")
            self.failed.emit(str(exc) if isinstance(exc, ValueError) else f"{type(exc).__name__}: {exc}")
            return
        self.finished.emit(result)


def start_worker(worker: QObject, run_slot_name: str = "run") -> QThread:
    """Move `worker` to a new QThread and start it.

    The thread's event loop is stopped from the worker thread itself (DirectConnection;
    QThread.quit is thread-safe) so that by the time the GUI handles `finished`, `wait()`
    returns promptly. The caller keeps Python references to both objects until then;
    no deleteLater is used, so ownership stays with Python (no double delete).
    """
    thread = QThread()
    worker.moveToThread(thread)
    thread.started.connect(getattr(worker, run_slot_name))
    for sig_name in ("finished", "failed"):
        sig = getattr(worker, sig_name, None)
        if sig is not None:
            sig.connect(thread.quit, Qt.ConnectionType.DirectConnection)
    thread.start()
    return thread


class TaskRunner(QObject):
    """Runs one background task at a time for a page, with cancellation.

    `fn` receives a CancelToken. Results come back on the GUI thread through bound slots of
    this object (queued connections). `shutdown()` cancels and waits, so a page can be
    closed safely while a task runs.
    """

    busy_changed = Signal(bool)
    message = Signal(str)  # text shown while busy

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: CallWorker | None = None
        self._cancel: CancelToken | None = None
        self._on_done: Callable[[object], None] | None = None
        self._on_error: Callable[[str], None] | None = None
        self.cancellable = False

    @property
    def busy(self) -> bool:
        return self._thread is not None

    def run(self, fn: Callable[[CancelToken], object], on_done: Callable[[object], None],
            on_error: Callable[[str], None], text: str, *, cancellable: bool = True) -> bool:
        if self.busy:
            return False
        self._cancel = CancelToken()
        cancel = self._cancel
        self._on_done, self._on_error, self.cancellable = on_done, on_error, cancellable
        self._worker = CallWorker(lambda: fn(cancel))
        self._worker.finished.connect(self._finished)
        self._worker.failed.connect(self._failed)
        self._thread = start_worker(self._worker)
        self.message.emit(text)
        self.busy_changed.emit(True)
        return True

    def cancel(self) -> None:
        if self._cancel is not None and self.cancellable:
            self._cancel.cancel()
            self.message.emit("正在取消…")

    def _end(self) -> tuple[Callable[[object], None] | None, Callable[[str], None] | None]:
        if self._thread is not None:
            self._thread.wait()
        cbs = (self._on_done, self._on_error)
        self._thread = self._worker = self._cancel = None
        self._on_done = self._on_error = None
        self.busy_changed.emit(False)
        return cbs

    @Slot(object)
    def _finished(self, result: object) -> None:
        on_done, _ = self._end()
        if on_done is not None:
            on_done(result)

    @Slot(str)
    def _failed(self, msg: str) -> None:
        _, on_error = self._end()
        if on_error is not None:
            on_error("已取消。" if msg == "ScanCancelled: " or msg.startswith("ScanCancelled") else msg)

    def shutdown(self) -> None:
        if self._cancel is not None:
            self._cancel.cancel()
        if self._thread is not None:
            self._thread.wait()
            self._thread = self._worker = self._cancel = None

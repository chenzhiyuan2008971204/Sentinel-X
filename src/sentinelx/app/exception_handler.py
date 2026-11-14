"""Global exception handling.

Uncaught exceptions on any thread are logged with a traceback and forwarded to an optional
notifier (the GUI installs one that shows a dialog). The handler never swallows the fact
that something failed.
"""

from __future__ import annotations

import logging
import sys
import threading
from collections.abc import Callable
from types import TracebackType

from sentinelx.core.errors import SentinelXError

log = logging.getLogger("sentinelx.unhandled")

Notifier = Callable[[str, str], None]  # (user_message, technical_detail)


def user_message_for(exc: BaseException) -> str:
    if isinstance(exc, SentinelXError):
        return exc.user_message
    return "發生未預期的錯誤，詳細資訊已寫入記錄檔。"


class ExceptionHandler:
    def __init__(self, notifier: Notifier | None = None) -> None:
        self._notifier = notifier
        self._prev_sys = sys.excepthook
        self._prev_thread = threading.excepthook

    def set_notifier(self, notifier: Notifier | None) -> None:
        self._notifier = notifier

    def handle(
        self,
        exc_type: type[BaseException],
        exc: BaseException,
        tb: TracebackType | None,
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            self._prev_sys(exc_type, exc, tb)
            return
        log.critical("unhandled exception", exc_info=(exc_type, exc, tb))
        if self._notifier is not None:
            try:
                self._notifier(user_message_for(exc), f"{exc_type.__name__}: {exc}")
            except Exception:  # noqa: BLE001 - notifier failure must not recurse
                log.exception("exception notifier failed")

    def _thread_hook(self, args: threading.ExceptHookArgs) -> None:
        if args.exc_value is not None:
            self.handle(args.exc_type, args.exc_value, args.exc_traceback)

    def install(self) -> None:
        sys.excepthook = self.handle
        threading.excepthook = self._thread_hook

    def uninstall(self) -> None:
        sys.excepthook = self._prev_sys
        threading.excepthook = self._prev_thread

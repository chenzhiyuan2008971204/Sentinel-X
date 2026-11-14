"""GUI entry point: `python -m sentinelx` or the `sentinelx` script."""

from __future__ import annotations

import argparse
import logging
import sys

from sentinelx.app.exception_handler import ExceptionHandler, user_message_for
from sentinelx.core.errors import SentinelXError

log = logging.getLogger(__name__)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="sentinelx")
    p.add_argument(
        "--smoke-test",
        type=int,
        metavar="MS",
        help="start the GUI, quit after MS milliseconds, exit 0 if startup succeeded",
    )
    # Marker added by the user-triggered UAC relaunch; informational only (logged).
    p.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    # Marker added by the restart after a settings change; waits for the old instance to close.
    p.add_argument("--restarted", action="store_true", help=argparse.SUPPRESS)
    # Started at Windows sign-in: no window, protection keeps running in the tray.
    p.add_argument("--background", action="store_true", help=argparse.SUPPRESS)
    return p.parse_args(argv)


def show_startup_error(message: str) -> None:
    from PySide6.QtWidgets import QMessageBox

    QMessageBox.critical(None, "Sentinel X", message)


def main(argv: list[str] | None = None) -> int:
    raw = sys.argv[1:] if argv is None else argv
    if raw[:1] == ["--research-worker"]:
        # Frozen builds have no `python -m`; the isolated PE worker is started this way.
        from sentinelx.research.worker import main as worker_main

        return worker_main(raw[1:])
    args = _parse_args(raw)

    handler = ExceptionHandler()
    handler.install()

    # Imports kept local so a missing Qt install produces a clear error, not an import crash.
    from PySide6.QtCore import QTimer
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication

    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.app.instance import HANDOVER_WAIT_MS, InstanceLock
    from sentinelx.app.paths import AppPaths
    from sentinelx.gui import theme
    from sentinelx.gui.error_bridge import ErrorBridge
    from sentinelx.gui.main_window import MainWindow, Services

    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("Sentinel X")
    font = QFont()
    font.setFamilies(theme.FONT_FAMILIES)
    app.setFont(font)
    app.setStyleSheet(theme.STYLESHEET)

    paths = AppPaths.default()
    try:
        paths.ensure()
        # Sentinel X's own temporary files go to its data folder, which protection never scans.
        import tempfile

        (paths.root / "tmp").mkdir(exist_ok=True)
        tempfile.tempdir = str(paths.root / "tmp")
    except OSError as exc:
        show_startup_error(f"無法建立資料資料夾 {paths.root}：{exc}")
        handler.uninstall()
        return 2
    lock = InstanceLock(paths.root)
    if not lock.acquire(HANDOVER_WAIT_MS if (args.elevated or args.restarted) else 0):
        log.warning("another instance is running", extra={"ctx": {"root": str(paths.root)}})
        if args.smoke_test is None:
            show_startup_error("Sentinel X 已經在執行中（同一個資料資料夾只能開啟一個視窗）。")
        handler.uninstall()
        return 3

    try:
        container = bootstrap(paths)
    except Exception as exc:  # noqa: BLE001 - any startup failure must be shown, not just logged
        log.critical("startup failed", exc_info=True)
        detail = str(exc) if isinstance(exc, SentinelXError) else f"{type(exc).__name__}: {exc}"
        show_startup_error(f"{user_message_for(exc)}\n\n{detail}")
        lock.release()
        handler.uninstall()
        return 2

    if args.elevated:
        log.info("started via elevation relaunch", extra={"ctx": {"privilege": container.privilege.value}})
    window = MainWindow(
        Services(container.status, container.scans, container.intel, container.static, container.reviews,
                 container.quarantine, container.monitor, container.reports, container.lab,
                 container.settings, container.signatures, container.protection, container.virustotal,
                 container.sandbox, container.rule_updates),
        container.privilege,
    )
    bridge = ErrorBridge(window)
    handler.set_notifier(bridge.notify)
    app.aboutToQuit.connect(window.prepare_quit)
    protecting = container.config.protection.enabled and args.smoke_test is None
    if args.smoke_test is None:
        try:
            # Re-create (or remove) the sign-in start entry from the saved setting: it can be missing
            # after an update, an uninstall of another copy, or if the program folder moved.
            restored = container.protection.apply_autostart()
            sc = container.self_check
            if restored and sc is not None and not sc.first_run:
                sc.autostart_restored()
        except OSError:
            log.warning("could not update the sign-in start entry", exc_info=True)
        if container.self_check is not None:  # audit 8 (H4): tell the user what happened while away
            for title, message in container.self_check.warnings:
                QTimer.singleShot(3000, lambda t=title, m=message: window.bridge.notified.emit("warn", t, m))
    if protecting:
        app.setQuitOnLastWindowClosed(False)  # the tray keeps protection running
        QTimer.singleShot(0, container.protection.start)
    if not (args.background and protecting and window.has_tray):
        window.show()

    if args.smoke_test is not None:
        QTimer.singleShot(args.smoke_test, app.quit)
    else:
        QTimer.singleShot(0, window.ask_signature_consent)  # first start only; it asks, never downloads by itself
        container.signatures.start_auto()  # daily update, only after consent (checked each time)
        container.rule_updates.start_auto()  # weekly YARA Forge check, only after consent
        # Trial-run room: rebuild from the saved ISO before the 90-day evaluation runs out.
        QTimer.singleShot(120_000, window.check_sandbox_rebuild)
        sandbox_timer = QTimer(window)
        sandbox_timer.setInterval(6 * 3600 * 1000)
        sandbox_timer.timeout.connect(window.check_sandbox_rebuild)
        sandbox_timer.start()

    try:
        code = app.exec()
    finally:
        window.close()  # runs closeEvent: cancels and joins background workers before the DB closes
        container.shutdown()
        lock.release()
        handler.uninstall()
    return int(code)


if __name__ == "__main__":
    sys.exit(main())

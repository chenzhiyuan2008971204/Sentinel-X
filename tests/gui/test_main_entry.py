"""The real GUI entry point (`python -m sentinelx`), run in-process on the offscreen platform."""

from __future__ import annotations

import os
import subprocess
import sys
import threading

import pytest
from pytestqt.qtbot import QtBot
from sqlalchemy import text

from sentinelx.app import main as main_mod
from sentinelx.app.paths import HOME_ENV, AppPaths
from sentinelx.storage.db import Database

pytestmark = pytest.mark.gui


def test_smoke_start_and_clean_exit(app_paths: AppPaths) -> None:
    # Separate process: calling exec()/quit() on the shared pytest-qt QApplication would put
    # Qt into its "closing" state and break every later threaded GUI test.
    env = {**os.environ, HOME_ENV: str(app_paths.root), "QT_QPA_PLATFORM": "offscreen"}
    cp = subprocess.run([sys.executable, "-m", "sentinelx", "--smoke-test", "300"], env=env,
                        capture_output=True, timeout=120)
    assert cp.returncode == 0, cp.stderr.decode("utf-8", "replace")[-2000:]
    db = Database(app_paths.database_file)
    with db.engine.connect() as c:
        actions = [r[0] for r in c.execute(text("SELECT action FROM audit_log ORDER BY id"))]
    db.dispose()
    assert actions[0] == "APP_START" and actions[-1] == "APP_STOP"


def test_unexpected_startup_error_is_shown(qtbot: QtBot, app_paths: AppPaths,
                                           monkeypatch: pytest.MonkeyPatch) -> None:
    shown: list[str] = []
    monkeypatch.setattr(main_mod, "show_startup_error", shown.append)

    def broken(*_a, **_k):  # type: ignore[no-untyped-def]
        raise OSError("disk unavailable")

    monkeypatch.setattr("sentinelx.app.bootstrap.bootstrap", broken)
    hooks = (sys.excepthook, threading.excepthook)
    assert main_mod.main([]) == 2
    assert shown and "OSError: disk unavailable" in shown[0]
    assert (sys.excepthook, threading.excepthook) == hooks


def test_corrupt_config_is_shown(qtbot: QtBot, app_paths: AppPaths, monkeypatch: pytest.MonkeyPatch) -> None:
    app_paths.ensure()
    app_paths.config_file.write_text("{broken", encoding="utf-8")
    shown: list[str] = []
    monkeypatch.setattr(main_mod, "show_startup_error", shown.append)
    assert main_mod.main([]) == 2
    assert "設定檔" in shown[0]

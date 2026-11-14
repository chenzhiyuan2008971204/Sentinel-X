"""Audit 5 regression tests (after Phase 8)."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, SignatureAV
from pytestqt.qtbot import QtBot
from sqlalchemy.exc import OperationalError

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import PrivilegeLevel, ReviewDecision
from sentinelx.engines.base import DetectionEngine
from sentinelx.gui.main_window import MainWindow, Services
from sentinelx.gui.settings_page import SettingsPage

pytestmark = pytest.mark.gui
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]


def window(qtbot: QtBot, c: AppContainer) -> MainWindow:
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor,
                            c.reports, c.lab, c.settings), PrivilegeLevel.STANDARD)
    qtbot.addWidget(w)
    return w


# ---- E1: the 10 s indicator refresh loaded every threat row on the GUI thread ----
def test_E1_indicators_use_counts_not_rows(qtbot: QtBot, make_container: MakeContainer, tmp_path: Path,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    c = make_container([SignatureAV()])
    for i in range(3):
        (tmp_path / f"m{i}.bin").write_bytes(MALWARE_MARKER + bytes([i]))
    c.scans.run_scan([tmp_path], CancelToken())
    vid = c.reviews.threats()[0].verdict_id
    c.reviews.review(vid, ReviewDecision.ESCALATE, "check")
    attention, pending = c.reviews.attention_counts()
    assert attention == len(c.reviews.threats())
    assert pending == sum(1 for r in c.reviews.threats() if r.needs_review and r.last_review is None)
    w = window(qtbot, c)

    def no_rows(*_a, **_k):  # type: ignore[no-untyped-def]
        raise AssertionError("threats() must not run on every indicator refresh")

    monkeypatch.setattr(c.reviews, "threats", no_rows)
    w.update_indicators()
    assert w.badges["threats"] == attention
    w.close()


# ---- E2: Settings silently lowered a larger file limit to the spin box maximum ----
def test_E2_large_limit_not_changed_by_unrelated_save(qtbot: QtBot, app_paths, make_container: MakeContainer) -> None:  # type: ignore[no-untyped-def]
    app_paths.ensure()
    cfg = json.loads(json.dumps({"scan": {"max_files_per_job": 500_000_000}}))
    app_paths.config_file.write_text(json.dumps(cfg), encoding="utf-8")
    c = make_container([])
    p = SettingsPage(c.settings, confirm=lambda *a: True, opener=lambda _p: True, restarter=lambda: True)
    qtbot.addWidget(p)
    p.max_size.setValue(200)
    p.save_button.click()
    disk = json.loads(app_paths.config_file.read_text(encoding="utf-8"))
    assert disk["scan"]["max_files_per_job"] == 500_000_000 and disk["scan"]["max_file_size_mb"] == 200


# ---- E3: a database error in the timer showed an error dialog every 10 s ----
def test_E3_indicator_errors_are_contained(qtbot: QtBot, container: AppContainer,
                                           monkeypatch: pytest.MonkeyPatch) -> None:
    w = window(qtbot, container)

    def locked(*_a, **_k):  # type: ignore[no-untyped-def]
        raise OperationalError("SELECT", {}, Exception("database is locked"))

    monkeypatch.setattr(container.reviews, "attention_counts", locked)
    w.update_indicators()  # must not raise into the Qt event loop
    assert "無法更新" in w.monitor_label.text()
    w.close()


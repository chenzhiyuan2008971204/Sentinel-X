"""0.11.0: daily automatic ClamAV signature updates (fake freshclam, never touches the network)."""

from __future__ import annotations

import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinelx.app.bootstrap import AppContainer
from sentinelx.services.signature_service import TS, SignatureService

pytestmark = pytest.mark.gui
FAKE = [sys.executable, "-I", str(Path(__file__).parent.parent / "data" / "fake_freshclam.py")]


def svc(c: AppContainer) -> SignatureService:
    return SignatureService(c.paths, c.config, c.config_store, c.audit, launcher=FAKE)


def actions(c: AppContainer) -> list[str]:
    from sqlalchemy import select

    from sentinelx.storage.orm import AuditEntry

    with c.db.session() as s:
        return list(s.scalars(select(AuditEntry.action).order_by(AuditEntry.id)))


def test_never_runs_without_consent(container: AppContainer) -> None:
    s = svc(container)
    assert not s.consented and s.auto_update  # option on by default, but no consent
    assert not s.auto_due()
    assert s.run_auto_once() is None
    assert not s.status().present
    assert "SIGNATURE_UPDATE_START" not in actions(container)


def test_runs_when_due_and_records_times(container: AppContainer) -> None:
    s = svc(container)
    s.set_consent(True)
    assert s.auto_due()  # never tried
    res = s.run_auto_once()
    assert res is not None and res.ok
    assert s.status().present and s.last_success and s.last_attempt
    assert not s.auto_due()  # just updated
    now = datetime.now(UTC)
    assert not s.auto_due(now + timedelta(hours=23))
    assert s.auto_due(now + timedelta(hours=24, minutes=1))
    assert s.next_auto() is not None
    # stored in the config file, so the schedule survives a restart
    again = container.config_store.load()
    assert again.signature_last_success == s.last_success
    a = actions(container)
    assert "SIGNATURE_UPDATE_START" in a and "SIGNATURE_UPDATE_FINISH" in a


def test_failed_update_retries_after_two_hours(container: AppContainer, monkeypatch: pytest.MonkeyPatch) -> None:
    s = svc(container)
    s.set_consent(True)
    monkeypatch.setenv("FAKE_FRESHCLAM_MODE", "fail")
    results = []
    s.on_auto_result = results.append
    res = s.run_auto_once()
    assert res is not None and not res.ok and results == [res]
    assert s.last_success is None
    now = datetime.now(UTC)
    assert not s.auto_due(now + timedelta(hours=1))
    assert s.auto_due(now + timedelta(hours=2, minutes=1))


def test_option_off_stops_automatic_updates(container: AppContainer) -> None:
    s = svc(container)
    s.set_consent(True)
    s.set_auto_update(False)
    assert not s.auto_due() and s.run_auto_once() is None and s.next_auto() is None
    assert "SIGNATURE_AUTO_UPDATE" in actions(container)


def test_clock_moved_back_does_not_block_updates(container: AppContainer) -> None:
    s = svc(container)
    s.set_consent(True)
    container.config.signature_last_attempt = (datetime.now(UTC) + timedelta(days=30)).strftime(TS)
    assert s.auto_due()


def test_manual_and_automatic_update_never_overlap(container: AppContainer, monkeypatch: pytest.MonkeyPatch) -> None:
    s = svc(container)
    s.set_consent(True)
    monkeypatch.setenv("FAKE_FRESHCLAM_MODE", "slow")
    from sentinelx.core.cancel import CancelToken, ScanCancelled

    cancel = CancelToken()
    errors: list[BaseException] = []

    def manual() -> None:
        try:
            s.update(cancel)
        except ScanCancelled:
            pass
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=manual)
    t.start()
    deadline = time.monotonic() + 10
    while not s.updating and time.monotonic() < deadline:
        time.sleep(0.05)
    assert s.updating
    with pytest.raises(ValueError, match="正在更新中"):
        s.update()
    container.config.signature_last_attempt = None  # make the automatic one due
    assert s.run_auto_once() is None  # skipped, not run twice
    cancel.cancel()
    t.join(15)
    assert not errors and not s.updating


def test_background_thread_runs_and_stops(container: AppContainer) -> None:
    s = svc(container)
    s.set_consent(True)
    done = threading.Event()
    s.on_auto_result = lambda _r: done.set()
    s.start_auto(check_s=0.2, first_delay_s=0.1)
    try:
        assert done.wait(30)
        assert s.status().present
    finally:
        s.stop_auto()
    assert s._auto_thread is None


def test_stop_cancels_a_running_automatic_update(container: AppContainer, monkeypatch: pytest.MonkeyPatch) -> None:
    s = svc(container)
    s.set_consent(True)
    monkeypatch.setenv("FAKE_FRESHCLAM_MODE", "slow")
    s.start_auto(check_s=0.2, first_delay_s=0.0)
    deadline = time.monotonic() + 10
    while not s.updating and time.monotonic() < deadline:
        time.sleep(0.05)
    assert s.updating
    started = time.monotonic()
    s.stop_auto()
    assert time.monotonic() - started < 10 and not s.updating


def test_settings_page_shows_and_toggles_auto_update(qtbot, container: AppContainer) -> None:  # type: ignore[no-untyped-def]
    from sentinelx.gui.settings_page import SettingsPage

    s = svc(container)
    p = SettingsPage(container.settings, confirm=lambda *a: True, opener=lambda _p: True, restarter=lambda: True,
                     signatures=s)
    qtbot.addWidget(p)
    assert not p.sig_auto.isEnabled() and "尚未同意" in p.sig_schedule.text()
    p.sig_consent.setChecked(True)
    assert p.sig_auto.isEnabled() and p.sig_auto.isChecked() and "開啟" in p.sig_schedule.text()
    p.sig_auto.setChecked(False)
    assert not s.auto_update and "已關閉" in p.sig_schedule.text()
    assert not container.config_store.load().signature_auto_update


def test_failed_automatic_update_notifies(qtbot, container: AppContainer) -> None:  # type: ignore[no-untyped-def]
    from sentinelx.core.enums import PrivilegeLevel
    from sentinelx.gui.main_window import MainWindow, Services
    from sentinelx.services.signature_service import UpdateResult

    c = container
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor,
                            c.reports, c.lab, c.settings, c.signatures, c.protection), PrivilegeLevel.STANDARD)
    qtbot.addWidget(w)
    assert c.signatures.on_auto_result == w._signature_auto_result
    # from a background thread, as in real use
    t = threading.Thread(target=w._signature_auto_result, args=(UpdateResult(False, 1, ("x",), 1.0),))
    t.start()
    t.join()
    qtbot.waitUntil(lambda: any("病毒碼自動更新失敗" in n[1] for n in w.notifications), timeout=5000)
    n = len(w.notifications)
    w._signature_auto_result(UpdateResult(True, 0, ("ok",), 1.0))  # success: no notification
    qtbot.wait(200)
    assert len(w.notifications) == n

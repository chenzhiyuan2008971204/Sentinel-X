"""Signature updates: consent first, fake freshclam (no network), bundled ClamAV location."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot
from sqlalchemy import text

from sentinelx.app.bootstrap import AppContainer, clamav_database_dir
from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.engines import clamav
from sentinelx.gui.settings_page import SettingsPage
from sentinelx.services.signature_service import MIRROR, SignatureService

pytestmark = pytest.mark.gui
FAKE = [sys.executable, "-I", str(Path(__file__).parent.parent / "data" / "fake_freshclam.py")]


def service(c: AppContainer, updated: list[Path] | None = None) -> SignatureService:
    sink = updated if updated is not None else []
    return SignatureService(c.paths, c.config, c.config_store, c.audit, on_updated=sink.append, launcher=FAKE)


def actions(c: AppContainer) -> list[str]:
    with c.db.engine.connect() as con:
        return [a for (a,) in con.execute(text("SELECT action FROM audit_log ORDER BY id"))]


def test_prompt_once_and_consent_is_recorded(container: AppContainer) -> None:
    s = service(container)
    assert s.needs_prompt() and not s.consented
    s.set_consent(False)
    assert not s.needs_prompt() and not s.consented
    disk = json.loads(container.paths.config_file.read_text(encoding="utf-8"))
    assert disk["signature_updates_prompted"] is True and disk["signature_updates_consented"] is False
    assert "SIGNATURE_UPDATE_CONSENT" in actions(container)


@pytest.mark.security
def test_no_download_without_consent(container: AppContainer) -> None:
    s = service(container)
    with pytest.raises(ValueError, match="尚未同意"):
        s.update()
    assert not (container.paths.root / "clamav-db").exists()


def test_update_writes_fixed_config_and_signatures(container: AppContainer) -> None:
    updated: list[Path] = []
    s = service(container, updated)
    s.set_consent(True)
    res = s.update()
    assert res.ok and res.exit_code == 0 and any("daily.cvd" in ln for ln in res.output_tail)
    db = container.paths.root / "clamav-db"
    conf = (container.paths.root / "freshclam.conf").read_text(encoding="ascii")
    assert conf == f"DatabaseDirectory {db}\nDatabaseMirror {MIRROR}\n"
    st = s.status()
    assert st.present and set(st.files) == {"main.cvd", "daily.cvd", "bytecode.cvd"} and st.newest
    assert updated == [db]
    assert {"SIGNATURE_UPDATE_START", "SIGNATURE_UPDATE_FINISH"} <= set(actions(container))


def test_update_failure_is_reported(container: AppContainer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_FRESHCLAM_MODE", "fail")
    updated: list[Path] = []
    s = service(container, updated)
    s.set_consent(True)
    res = s.update()
    assert not res.ok and res.exit_code == 1 and "Can't download" in res.output_tail[-1]
    assert updated == [] and not s.status().present


def test_update_cancel_kills_freshclam(container: AppContainer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_FRESHCLAM_MODE", "slow")
    s = service(container)
    s.set_consent(True)
    tok = CancelToken()
    tok.cancel()
    t0 = time.monotonic()
    with pytest.raises(ScanCancelled):
        s.update(tok)
    assert time.monotonic() - t0 < 10


def test_settings_page_signature_controls(qtbot: QtBot, container: AppContainer) -> None:
    s = service(container)
    p = SettingsPage(container.settings, confirm=lambda *a: True, opener=lambda _p: True,
                     restarter=lambda: True, signatures=s)
    qtbot.addWidget(p)
    assert "尚未下載" in p.sig_status.text() and not p.sig_update_button.isEnabled()
    p.sig_consent.setChecked(True)
    assert s.consented and p.sig_update_button.isEnabled()
    p.sig_update_button.click()
    assert p.busy and not p.sig_busy.isHidden() and not p.sig_busy.cancel_button.isHidden()
    qtbot.waitUntil(lambda: not p.busy, timeout=30000)
    assert "更新完成" in p.status_label.text() and "daily.cvd" in p.sig_status.text()
    p.sig_consent.setChecked(False)
    assert not s.consented and not p.sig_update_button.isEnabled()


def test_first_run_question(qtbot: QtBot, container: AppContainer) -> None:
    from sentinelx.core.enums import PrivilegeLevel
    from sentinelx.gui.main_window import MainWindow, Services

    c = container
    s = service(c)
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor,
                            c.reports, c.lab, c.settings, s), PrivilegeLevel.STANDARD)
    qtbot.addWidget(w)
    asked: list[str] = []
    assert w.ask_signature_consent(confirm=lambda _p, _t, m: asked.append(m) or False) is False
    assert asked and "database.clamav.net" in asked[0] and not s.consented
    assert w.ask_signature_consent(confirm=lambda *a: pytest.fail("asked twice")) is False  # only once
    w.close()


def test_first_run_yes_starts_update(qtbot: QtBot, container: AppContainer) -> None:
    from sentinelx.core.enums import PrivilegeLevel
    from sentinelx.gui.main_window import MainWindow, Services

    c = container
    s = service(c)
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor,
                            c.reports, c.lab, c.settings, s), PrivilegeLevel.STANDARD)
    qtbot.addWidget(w)
    assert w.ask_signature_consent(confirm=lambda *a: True)
    assert w.current_page_key() == "settings" and w.settings_page.busy
    qtbot.waitUntil(lambda: not w.settings_page.busy, timeout=30000)
    assert s.status().present
    w.close()


def test_bundled_clamav_location(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, container: AppContainer) -> None:
    app = tmp_path / "SentinelX"
    (app / "clamav").mkdir(parents=True)
    exe = app / "clamav" / "clamscan.exe"
    exe.write_bytes(b"")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(app / "SentinelX.exe"))
    assert clamav.bundled_location() == exe and clamav.default_locations()[0] == exe
    assert clamav.locate_clamscan() == exe and clamav.is_bundled(exe)
    # The bundled ClamAV always uses the per-user signature folder (its own folder is read-only).
    assert clamav_database_dir(container.config, container.paths, exe) == container.paths.root / "clamav-db"
    assert clamav_database_dir(container.config, container.paths, None) is None

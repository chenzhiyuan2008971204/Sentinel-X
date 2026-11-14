"""Audit 6 regression tests (after Phase 9)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from sentinelx.app.bootstrap import AppContainer, bootstrap
from sentinelx.app.paths import AppPaths
from sentinelx.core.enums import PrivilegeLevel
from sentinelx.services.signature_service import SignatureService

pytestmark = pytest.mark.gui
FAKE = [sys.executable, "-I", str(Path(__file__).parent.parent / "data" / "fake_freshclam.py")]


# ---- F1: a data folder with Chinese characters (e.g. a Chinese Windows user name) broke updates ----
def test_F1_update_with_chinese_data_folder(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "王小明" / "SentinelX")
    c = bootstrap(paths, console_log=False, privilege=PrivilegeLevel.STANDARD, engines=[])
    try:
        s = SignatureService(c.paths, c.config, c.config_store, c.audit, launcher=FAKE)
        s.set_consent(True)
        res = s.update()
        assert res.ok, res.output_tail
        conf = (paths.root / "freshclam.conf").read_text(encoding="utf-8")
        assert conf == f"DatabaseDirectory {paths.root / 'clamav-db'}\nDatabaseMirror database.clamav.net\n"
        assert s.status().present
    finally:
        c.shutdown()


# ---- F2: with ClamAV already working from its own signatures, the app said none were downloaded ----
def test_F2_working_clamav_is_not_reported_missing(container: AppContainer) -> None:
    s = SignatureService(container.paths, container.config, container.config_store, container.audit,
                         launcher=FAKE, engine_ready=lambda: True)
    assert not s.needs_prompt()  # nothing to ask: ClamAV already has signatures
    st = s.status()
    assert not st.present and st.engine_ready
    s2 = SignatureService(container.paths, container.config, container.config_store, container.audit,
                          launcher=FAKE, engine_ready=lambda: False)
    assert s2.needs_prompt() and not s2.status().engine_ready


def test_F2_settings_text_when_clamav_uses_other_signatures(qtbot, container: AppContainer) -> None:  # type: ignore[no-untyped-def]
    from sentinelx.gui.settings_page import SettingsPage

    s = SignatureService(container.paths, container.config, container.config_store, container.audit,
                         launcher=FAKE, engine_ready=lambda: True)
    p = SettingsPage(container.settings, confirm=lambda *a: True, opener=lambda _p: True, restarter=lambda: True,
                     signatures=s)
    qtbot.addWidget(p)
    assert "無法使用" not in p.sig_status.text() and "其他位置" in p.sig_status.text()


# ---- F3: uninstalling while the app ran reported success but left 50 files behind ----
@pytest.mark.skipif(sys.platform != "win32", reason="named mutex")
def test_F3_running_mutex_held_with_the_lock(tmp_path: Path) -> None:
    from sentinelx.app.instance import APP_MUTEX, InstanceLock, mutex_exists

    assert not mutex_exists()
    lock = InstanceLock(tmp_path)
    assert lock.acquire() and mutex_exists()
    lock.release()
    assert not mutex_exists()
    iss = (Path(__file__).parents[2] / "packaging" / "installer.iss").read_text(encoding="utf-8-sig")
    assert f"AppMutex={APP_MUTEX}" in iss

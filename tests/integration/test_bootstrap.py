from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import text

from sentinelx.app.bootstrap import AppContainer
from sentinelx.app.paths import AppPaths
from sentinelx.core.enums import PrivilegeLevel

pytestmark = pytest.mark.integration


def test_home_override(app_paths: AppPaths) -> None:
    import os

    from sentinelx.app.paths import HOME_ENV

    assert app_paths.root == Path(os.environ[HOME_ENV]).resolve()


def test_bootstrap_creates_layout(container: AppContainer) -> None:
    p = container.paths
    for d in (p.root, p.log_dir, p.vault_dir, p.reports_dir):
        assert d.is_dir()
    assert p.config_file.exists()
    assert p.database_file.exists()
    assert (p.log_dir / "sentinelx.log.jsonl").exists()


def test_bootstrap_records_start_in_audit(container: AppContainer) -> None:
    with container.db.engine.connect() as c:
        actions = [r[0] for r in c.execute(text("SELECT action FROM audit_log"))]
    assert actions == ["APP_START"]
    assert container.audit.verify().ok


def test_status_snapshot_is_real(container: AppContainer) -> None:
    s = container.status.snapshot()
    assert s.database_integrity_ok
    assert s.database_path == container.paths.database_file
    assert s.audit_chain.ok and s.audit_chain.entries == 1
    assert s.privilege is PrivilegeLevel.STANDARD
    assert [e.name for e in s.engines] == ["FakeAV"]


def test_default_engines_and_toggles(app_paths: AppPaths, tmp_path: Path) -> None:
    from sentinelx.app.bootstrap import build_engines
    from sentinelx.app.config import AppConfig
    from sentinelx.engines.clamav import ClamAVEngine
    from sentinelx.engines.clamd import ClamdEngine
    from sentinelx.storage.db import Database
    from sentinelx.storage.intel_repository import IntelStore
    from sentinelx.storage.rules_repository import RuleSetStore

    db = Database(tmp_path / "x.db")
    db.initialize()
    intel, rules = IntelStore(db), RuleSetStore(db, tmp_path / "rules")
    engines = build_engines(AppConfig(), app_paths, intel, rules)
    assert [e.name for e in engines] == ["ClamAV", "YARA", "HashIntel", "PEStatic"]
    assert isinstance(engines[0], ClamAVEngine)

    cfg = AppConfig()
    cfg.clamav.backend = "clamd"
    cfg.engines.yara = False
    engines = build_engines(cfg, app_paths, intel, rules)
    assert [e.name for e in engines] == ["ClamAV", "HashIntel", "PEStatic"]
    assert isinstance(engines[0], ClamdEngine)
    db.dispose()


def test_clamav_database_dir_resolution(app_paths: AppPaths, tmp_path: Path) -> None:
    from sentinelx.app.bootstrap import clamav_database_dir
    from sentinelx.app.config import AppConfig

    app_paths.ensure()
    assert clamav_database_dir(AppConfig(), app_paths) is None
    (app_paths.root / "clamav-db").mkdir()
    assert clamav_database_dir(AppConfig(), app_paths) == app_paths.root / "clamav-db"
    cfg = AppConfig()
    cfg.clamav.database_dir = str(tmp_path)
    assert clamav_database_dir(cfg, app_paths) == tmp_path

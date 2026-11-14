from __future__ import annotations

from pathlib import Path

import pytest
from fakes import make_tree
from sqlalchemy import text

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import ExclusionKind

pytestmark = pytest.mark.integration


def actions(c: AppContainer) -> list[str]:
    with c.db.engine.connect() as conn:
        return [r[0] for r in conn.execute(text("SELECT action FROM audit_log ORDER BY id"))]


def test_scan_is_audited(container: AppContainer, tmp_path: Path) -> None:
    make_tree(tmp_path / "t")
    s = container.scans.run_scan([tmp_path / "t"], CancelToken())
    assert actions(container)[-2:] == ["SCAN_START", "SCAN_FINISH"]
    assert container.audit.verify().ok
    assert container.scans.history()[0].id == s.job_id


def test_exclusion_crud_audited(container: AppContainer) -> None:
    eid = container.scans.add_exclusion(ExclusionKind.EXTENSION, "LOG", "noise")
    assert container.scans.exclusions()[0].value == ".log"
    assert container.scans.add_exclusion(ExclusionKind.EXTENSION, ".log") == eid  # no duplicate
    assert container.scans.remove_exclusion(eid)
    assert not container.scans.remove_exclusion(eid)
    assert actions(container).count("EXCLUSION_ADD") == 2
    assert "EXCLUSION_REMOVE" in actions(container)


def test_invalid_exclusion_rejected_and_not_stored(container: AppContainer) -> None:
    with pytest.raises(ValueError):
        container.scans.add_exclusion(ExclusionKind.SHA256, "not-a-hash")
    assert container.scans.exclusions() == []


def test_status_lists_engines(container: AppContainer) -> None:
    s = container.status.snapshot()
    assert [e.name for e in s.available_engines] == ["FakeAV"]

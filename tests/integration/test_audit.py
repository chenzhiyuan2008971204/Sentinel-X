from __future__ import annotations

import pytest
from sqlalchemy import text

from sentinelx.core.enums import AuditActor
from sentinelx.storage.audit import GENESIS_HASH, AuditLog
from sentinelx.storage.db import Database

pytestmark = pytest.mark.integration


def test_empty_chain_ok(db: Database) -> None:
    check = AuditLog(db).verify()
    assert check.ok and check.entries == 0


def test_chain_links(db: Database) -> None:
    a = AuditLog(db)
    a.record("SCAN_START", actor=AuditActor.USER, subject="C:\\x", detail={"n": 1})
    a.record("SCAN_STOP")
    with db.engine.connect() as c:
        rows = c.execute(text("SELECT prev_hash, entry_hash FROM audit_log ORDER BY id")).all()
    assert rows[0][0] == GENESIS_HASH
    assert rows[1][0] == rows[0][1]
    assert a.verify().ok


@pytest.mark.security
def test_detects_modified_entry(db: Database) -> None:
    a = AuditLog(db)
    a.record("QUARANTINE", subject="evil.exe")
    a.record("RESTORE", subject="evil.exe")
    with db.engine.begin() as c:
        c.execute(text("UPDATE audit_log SET subject='innocent.exe' WHERE id=1"))
    check = a.verify()
    assert not check.ok and check.first_bad_id == 1


@pytest.mark.security
def test_detects_deleted_entry(db: Database) -> None:
    a = AuditLog(db)
    for i in range(3):
        a.record("EVENT", detail={"i": i})
    with db.engine.begin() as c:
        c.execute(text("DELETE FROM audit_log WHERE id=2"))
    check = a.verify()
    assert not check.ok and check.first_bad_id == 3

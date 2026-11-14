from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sentinelx.storage.db import Database
from sentinelx.storage.orm import SCHEMA_VERSION

pytestmark = pytest.mark.integration


def _downgrade_to(path: Path, version: int) -> None:
    """Build a database the way an older release left it (columns/tables added later removed)."""
    d = Database(path)
    d.initialize()
    d.dispose()
    con = sqlite3.connect(path)
    if version < 6:
        # v5 quarantine table: no DELETED status, no deleted_at column.
        con.execute("DROP TABLE quarantine_items")
        con.execute(
            "CREATE TABLE quarantine_items (id INTEGER PRIMARY KEY, vault_id VARCHAR NOT NULL UNIQUE,"
            " original_path TEXT NOT NULL, sha256 VARCHAR(64) NOT NULL, size INTEGER NOT NULL,"
            " verdict_id INTEGER REFERENCES verdicts(id), confirmed_by_user_at VARCHAR NOT NULL,"
            " status VARCHAR NOT NULL, restored_at VARCHAR, zone_identifier TEXT, xor_key TEXT,"
            " duplicate_of INTEGER REFERENCES quarantine_items(id), original_mtime TEXT, original_attributes INTEGER,"
            " reason TEXT, restore_target TEXT, audit_entry_id INTEGER REFERENCES audit_log(id), error_detail TEXT,"
            " CONSTRAINT ck_status_enum CHECK (status IN ('QUARANTINED', 'RESTORED', 'RETAINED_ERROR')))"
        )
        con.execute("INSERT INTO quarantine_items (vault_id, original_path, sha256, size, confirmed_by_user_at, status,"
                     " reason) VALUES (?, 'C:/old.exe', ?, 5, 't', 'QUARANTINED', 'kept')", ("b" * 32, "c" * 64))
    if version < 5:
        con.execute("DROP INDEX IF EXISTS ix_alerts_dedup")
        con.execute("DROP INDEX IF EXISTS ix_events_kind")
        con.execute("ALTER TABLE security_events DROP COLUMN details_json")
        for col in ("rule_id", "dedup_key", "updated_at"):
            con.execute(f"ALTER TABLE alerts DROP COLUMN {col}")
    if version < 4:
        # SQLite cannot drop FK columns; recreate the table as releases 1-3 defined it.
        con.execute("DROP TABLE quarantine_items")
        con.execute(
            "CREATE TABLE quarantine_items (id INTEGER PRIMARY KEY, vault_id VARCHAR UNIQUE, original_path TEXT,"
            " sha256 VARCHAR(64), size INTEGER, verdict_id INTEGER REFERENCES verdicts(id),"
            " confirmed_by_user_at VARCHAR, status VARCHAR, restored_at VARCHAR, zone_identifier TEXT,"
            " CONSTRAINT ck_status_enum CHECK (status IN ('QUARANTINED', 'RESTORED', 'RETAINED_ERROR')))"
        )
    if version < 3:
        for col in ("confidence", "needs_review", "assessor_version"):
            con.execute(f"ALTER TABLE verdicts DROP COLUMN {col}")
        con.execute("DROP TABLE fp_suppressions")
    if version < 2:
        con.execute("ALTER TABLE engine_runs DROP COLUMN info_json")
    con.execute("UPDATE schema_meta SET value=? WHERE key='schema_version'", (str(version),))
    con.execute("INSERT INTO scan_jobs (started_at, status, targets_json, options_json, files_seen, files_assessed, "
                "files_not_assessed) VALUES ('2026-11-01T00:00:00Z', 'COMPLETED', '[]', '{}', 3, 3, 0)")
    con.execute("INSERT INTO files (sha256, size, path, path_norm, first_seen_at, last_seen_at) "
                "VALUES (?, 1, 'C:\\x', 'c:\\x', 't', 't')", ("a" * 64,))
    con.execute("INSERT INTO verdicts (file_id, classification, ordinal_score, explanation, "
                "contributing_detection_ids, created_at) VALUES (1, 'SUSPICIOUS', 200, 'old', '[]', 't')")
    con.commit()
    con.close()


@pytest.mark.parametrize("old", [1, 2, 3, 4, 5])
def test_old_database_migrates_with_backup(tmp_path: Path, old: int) -> None:
    path = tmp_path / "sentinelx.db"
    _downgrade_to(path, old)
    d = Database(path)
    assert d.initialize() == SCHEMA_VERSION
    assert d.schema_version() == SCHEMA_VERSION
    d.dispose()

    con = sqlite3.connect(path)
    assert "info_json" in [r[1] for r in con.execute("PRAGMA table_info(engine_runs)")]
    vcols = [r[1] for r in con.execute("PRAGMA table_info(verdicts)")]
    assert {"confidence", "needs_review", "assessor_version"} <= set(vcols)
    assert con.execute("SELECT name FROM sqlite_master WHERE name='fp_suppressions'").fetchone()
    qcols = {r[1] for r in con.execute("PRAGMA table_info(quarantine_items)")}
    assert {"xor_key", "audit_entry_id", "restore_target", "deleted_at"} <= qcols
    if old == 5:  # v6 rebuilt the table: rows kept, DELETED now allowed
        assert con.execute("SELECT original_path, reason, status FROM quarantine_items").fetchone() == (
            "C:/old.exe", "kept", "QUARANTINED")
        con.execute("UPDATE quarantine_items SET status='DELETED'")
        assert con.execute("PRAGMA foreign_key_check").fetchall() == []
    assert "details_json" in {r[1] for r in con.execute("PRAGMA table_info(security_events)")}
    assert {"rule_id", "dedup_key", "updated_at"} <= {r[1] for r in con.execute("PRAGMA table_info(alerts)")}
    assert con.execute("SELECT files_seen FROM scan_jobs").fetchone() == (3,)  # data kept
    assert con.execute("SELECT classification, confidence, needs_review FROM verdicts").fetchone() == (
        "SUSPICIOUS", "—", 0)
    con.close()

    backup = tmp_path / f"sentinelx.db.bak-v{old}"
    assert backup.exists()
    bcon = sqlite3.connect(backup)
    assert bcon.execute("SELECT value FROM schema_meta").fetchone() == (str(old),)
    bcon.close()


def test_migration_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "sentinelx.db"
    _downgrade_to(path, 1)
    for _ in range(2):
        d = Database(path)
        d.initialize()
        d.dispose()

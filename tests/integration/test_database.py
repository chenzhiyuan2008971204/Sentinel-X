from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from sentinelx.core.enums import Classification
from sentinelx.core.errors import DatabaseError
from sentinelx.storage.db import Database
from sentinelx.storage.orm import SCHEMA_VERSION, FileRecord, FileScan, ScanJob, SchemaMeta, Verdict

pytestmark = pytest.mark.integration

EXPECTED_TABLES = {
    "schema_meta", "scan_jobs", "files", "file_scans", "engine_runs", "detections", "verdicts",
    "manual_reviews", "exclusions", "quarantine_items", "security_events", "alerts",
    "intel_sources", "intel_hashes", "rule_sets", "reports", "audit_log", "fp_suppressions", "vt_reports",
}


def test_all_tables_created(db: Database) -> None:
    assert set(inspect(db.engine).get_table_names()) == EXPECTED_TABLES


def test_pragmas(db: Database) -> None:
    with db.engine.connect() as c:
        assert c.execute(text("PRAGMA foreign_keys")).scalar() == 1
        assert c.execute(text("PRAGMA journal_mode")).scalar() == "wal"


def test_schema_version_and_integrity(db: Database) -> None:
    assert db.schema_version() == SCHEMA_VERSION
    assert db.integrity_ok()


def test_initialize_is_idempotent(db: Database) -> None:
    assert db.initialize() == SCHEMA_VERSION


def test_newer_schema_refused(tmp_path: Path) -> None:
    d = Database(tmp_path / "x.db")
    d.initialize()
    with d.session() as s:
        s.get(SchemaMeta, "schema_version").value = str(SCHEMA_VERSION + 1)
    with pytest.raises(DatabaseError):
        d.initialize()
    d.dispose()


def test_classification_check_constraint(db: Database) -> None:
    with db.session() as s:
        f = FileRecord(sha256="a" * 64, size=1, path="C:\\x", path_norm="c:\\x")
        s.add(f)
        s.flush()
        s.add(Verdict(file_id=f.id, classification=Classification.CLEAN.value, explanation="ok"))
    with pytest.raises(IntegrityError):
        with db.session() as s:
            s.add(Verdict(file_id=1, classification="PROBABLY_FINE", explanation="x"))


def test_foreign_keys_enforced(db: Database) -> None:
    with pytest.raises(IntegrityError):
        with db.session() as s:
            s.add(FileScan(job_id=999, file_id=999))


def test_job_delete_cascades_but_files_remain(db: Database) -> None:
    with db.session() as s:
        job = ScanJob()
        f = FileRecord(sha256="b" * 64, size=2, path="C:\\y", path_norm="c:\\y")
        s.add_all([job, f])
        s.flush()
        s.add(FileScan(job_id=job.id, file_id=f.id))
        job_id = job.id
    with db.engine.begin() as c:
        c.execute(text("DELETE FROM scan_jobs WHERE id=:i"), {"i": job_id})
        assert c.execute(text("SELECT COUNT(*) FROM file_scans")).scalar() == 0
        assert c.execute(text("SELECT COUNT(*) FROM files")).scalar() == 1


def test_session_rolls_back_on_error(db: Database) -> None:
    with pytest.raises(RuntimeError):
        with db.session() as s:
            s.add(ScanJob())
            s.flush()
            raise RuntimeError("abort")
    with db.engine.connect() as c:
        assert c.execute(text("SELECT COUNT(*) FROM scan_jobs")).scalar() == 0


def test_unicode_path_database(tmp_path: Path) -> None:
    d = Database(tmp_path / "資料庫 測試" / "sentinelx.db")
    d.initialize()
    with d.session() as s:
        s.add(FileRecord(sha256="c" * 64, size=3, path="C:\\使用者\\文件.txt", path_norm="c:\\使用者\\文件.txt"))
    assert d.integrity_ok()
    d.dispose()
    assert sqlite3.connect(tmp_path / "資料庫 測試" / "sentinelx.db").execute(
        "SELECT path FROM files"
    ).fetchone()[0] == "C:\\使用者\\文件.txt"

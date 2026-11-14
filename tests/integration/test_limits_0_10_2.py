"""0.10.2 hardening of known limitations: R4 (audit chain), R12 (YARA compile), R18 (real-time records)."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER, FakeEngine
from sqlalchemy import func, select, text

from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken
from sentinelx.research.isolation import WorkerResult, check_yara_compile
from sentinelx.scanner.exclusions import ExclusionSet
from sentinelx.scanner.orchestrator import ScanOrchestrator
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.db import Database
from sentinelx.storage.orm import FileScan, ScanJob, Verdict
from sentinelx.storage.scan_repository import ScanRepository

pytestmark = pytest.mark.integration


# ---------- R18: real-time scan records retention ----------

def _scan(db: Database, folder: Path, name: str, data: bytes, origin: str) -> int:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_bytes(data)
    orch = ScanOrchestrator([FakeEngine()], ScanRepository(db), ScanLimits())
    orch.run([folder / name], ExclusionSet(), CancelToken(), origin=origin)
    with db.session() as s:
        return s.scalar(select(func.max(ScanJob.id)))


def _age(db: Database, job_id: int, days: int) -> None:
    old = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db.session() as s:
        s.execute(text("UPDATE scan_jobs SET started_at = :t, finished_at = :t WHERE id = :i"), {"t": old, "i": job_id})


def test_prune_removes_only_old_clean_realtime_batches(db: Database, tmp_path: Path) -> None:
    old_clean = _scan(db, tmp_path / "a", "clean.txt", b"harmless", "realtime")
    old_threat = _scan(db, tmp_path / "b", "bad.txt", b"x" + MALWARE_MARKER, "realtime")
    old_manual = _scan(db, tmp_path / "c", "manual.txt", b"harmless manual", "manual")
    new_clean = _scan(db, tmp_path / "d", "new.txt", b"harmless new", "realtime")
    for j in (old_clean, old_threat, old_manual):
        _age(db, j, 40)
    with db.session() as s:
        verdicts_before = s.scalar(select(func.count()).select_from(Verdict))

    assert ScanRepository(db).prune_realtime() == 1

    with db.session() as s:
        jobs = set(s.scalars(select(ScanJob.id)))
        assert jobs == {old_threat, old_manual, new_clean}
        assert s.scalar(select(func.count()).select_from(FileScan).where(FileScan.job_id == old_clean)) == 0
        assert s.scalar(select(func.count()).select_from(Verdict)) == verdicts_before  # verdicts are kept
    assert ScanRepository(db).prune_realtime() == 0
    assert db.integrity_ok()


def test_prune_keeps_batches_with_unassessed_files(db: Database, tmp_path: Path) -> None:
    job = _scan(db, tmp_path / "a", "f.txt", b"harmless", "realtime")
    with db.session() as s:
        s.execute(text("UPDATE file_scans SET assessed = 0 WHERE job_id = :j"), {"j": job})
    _age(db, job, 40)
    assert ScanRepository(db).prune_realtime() == 0


# ---------- R4: incremental audit chain verification ----------

class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def _log(db: Database, n: int) -> tuple[AuditLog, Clock]:
    clock = Clock()
    log = AuditLog(db, full_interval_s=600, clock=clock)
    for i in range(n):
        log.record("TEST", subject=str(i))
    return log, clock


def test_incremental_verify_counts_new_entries(db: Database) -> None:
    log, clock = _log(db, 5)
    assert log.verify().entries == 5
    clock.t = 10
    log.record("TEST", subject="more")
    r = log.verify()
    assert r.ok and r.entries == 6


def test_edit_of_last_verified_entry_found_immediately(db: Database) -> None:
    log, clock = _log(db, 5)
    assert log.verify().ok
    with db.session() as s:
        s.execute(text("UPDATE audit_log SET subject = 'forged' WHERE id = (SELECT MAX(id) FROM audit_log)"))
    clock.t = 10
    r = log.verify()
    assert not r.ok and r.reason == "entry content does not match its hash"


def test_deleted_older_entry_found_immediately(db: Database) -> None:
    log, clock = _log(db, 5)
    assert log.verify().ok
    with db.session() as s:
        s.execute(text("DELETE FROM audit_log WHERE id = (SELECT MIN(id) + 1 FROM audit_log)"))
    clock.t = 10
    assert not log.verify().ok


def test_edit_of_older_entry_found_by_next_full_pass(db: Database) -> None:
    log, clock = _log(db, 5)
    assert log.verify().ok
    with db.session() as s:
        s.execute(text("UPDATE audit_log SET subject = 'forged' WHERE id = (SELECT MIN(id) FROM audit_log)"))
    clock.t = 10
    assert log.verify().ok  # documented trade-off: incremental pass does not re-hash old entries
    assert not log.verify(full=True).ok
    clock.t = 700
    assert not log.verify().ok  # the periodic full pass finds it
    assert not AuditLog(db).verify().ok  # and so does every new start


def test_appended_forged_entry_found(db: Database) -> None:
    log, clock = _log(db, 3)
    assert log.verify().ok
    with db.session() as s:
        s.execute(text("INSERT INTO audit_log (at, actor, action, subject, detail_json, prev_hash, entry_hash) "
                       "VALUES ('2026-01-01T00:00:00Z', 'SYSTEM', 'X', '', '{}', 'bad', 'bad')"))
    clock.t = 10
    assert not log.verify().ok


# ---------- R12: YARA test rules compile in the confined worker ----------

GOOD_RULE = 'rule t { strings: $a = "hello" condition: $a }'


@pytest.mark.windows
def test_compile_check_in_worker_ok() -> None:
    r = check_yara_compile(GOOD_RULE, timeout_s=60)
    assert r.ok, r.error
    assert r.data["rule_count"] == 1 and r.confined


@pytest.mark.windows
def test_compile_check_reports_bad_rule() -> None:
    r = check_yara_compile("rule broken { condition: }", timeout_s=60)
    assert not r.ok and r.error


@pytest.mark.windows
def test_compile_check_rejects_include() -> None:
    r = check_yara_compile('include "x.yar"\n' + GOOD_RULE, timeout_s=60)
    assert not r.ok


def test_compile_check_times_out_and_kills_worker() -> None:
    slow = [sys.executable, "-c", "import time; time.sleep(30)"]
    r = check_yara_compile(GOOD_RULE, timeout_s=1, command=slow)
    assert not r.ok and "逾時" in (r.error or "")
    assert r.duration_ms < 10_000


def test_compile_check_can_be_cancelled() -> None:
    from sentinelx.core.cancel import ScanCancelled

    cancel = CancelToken()
    cancel.cancel()
    with pytest.raises(ScanCancelled):
        check_yara_compile(GOOD_RULE, timeout_s=30, cancel=cancel,
                           command=[sys.executable, "-c", "import time; time.sleep(30)"])


def test_lab_yara_test_stops_when_compile_check_fails(container, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "t.txt"
    target.write_bytes(b"hello")
    lab = container.lab
    lab._yara_compile_check = lambda *_a, **_k: WorkerResult(False, error="逾時（1 秒），已終止分析程序。")
    with pytest.raises(ValueError, match="規則編譯失敗"):
        lab.yara_test(GOOD_RULE, [target])

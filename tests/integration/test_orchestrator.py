from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
from fakes import ENGINE_ERROR_MARKER, FakeEngine, fake_clamscan_launcher, make_tree
from sqlalchemy import select

from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import ExclusionKind, ScanStatus
from sentinelx.core.models import ScanProgress
from sentinelx.engines.clamav import ClamAVEngine
from sentinelx.scanner.exclusions import ExclusionSet
from sentinelx.scanner.hashing import sha256_file
from sentinelx.scanner.orchestrator import NO_ENGINE_MESSAGE, ScanOrchestrator
from sentinelx.storage.db import Database
from sentinelx.storage.orm import Detection, EngineRun, FileRecord
from sentinelx.storage.scan_repository import ScanRepository

pytestmark = pytest.mark.integration


def run(db: Database, roots: list[Path], engines: list, *, excl: ExclusionSet | None = None,
        cancel: CancelToken | None = None, progress: list[ScanProgress] | None = None, batch: int = 64):
    orch = ScanOrchestrator(engines, ScanRepository(db), ScanLimits(), batch_size=batch)
    return orch.run(roots, excl or ExclusionSet(), cancel or CancelToken(),
                    progress.append if progress is not None else None)


def test_no_engine_means_failed_not_clean(db: Database, tmp_path: Path) -> None:
    make_tree(tmp_path)
    s = run(db, [tmp_path], [FakeEngine(available=False)])
    assert s.status == ScanStatus.FAILED.value and s.error_summary == NO_ENGINE_MESSAGE
    assert ScanRepository(db).list_jobs()[0].status == "FAILED"


def test_full_scan_persists_evidence(db: Database, tmp_path: Path) -> None:
    f = make_tree(tmp_path)
    progress: list[ScanProgress] = []
    s = run(db, [tmp_path], [FakeEngine()], progress=progress)
    assert s.status == ScanStatus.COMPLETED.value
    assert (s.files_seen, s.files_assessed, s.files_not_assessed, s.files_with_detections) == (4, 4, 0, 1)
    assert progress and progress[-1].files_done == 4 and progress[-1].detections == 1

    with db.session() as sess:
        det = sess.scalars(select(Detection)).one()
        run_row = sess.get(EngineRun, det.engine_run_id)
        assert det.rule_id == "Test.Marker"
        assert det.file_sha256 == sha256_file(f["bad"])
        assert json.loads(det.evidence_json)["marker"]
        assert det.confidence_explanation and det.detected_at
        assert (run_row.engine_name, run_row.engine_version, run_row.rules_version) == ("FakeAV", "9.9", "42")
        cjk = sess.scalars(select(FileRecord).where(FileRecord.path == str(f["cjk"]))).one()
        assert cjk.sha256 == sha256_file(f["cjk"]) and cjk.size == f["cjk"].stat().st_size and cjk.mtime

    files = ScanRepository(db).job_files(s.job_id)
    bad = next(x for x in files if x.path == str(f["bad"]))
    assert bad.detections == ["FakeAV: Test.Marker"] and bad.assessed


def test_engine_error_makes_job_partial(db: Database, tmp_path: Path) -> None:
    (tmp_path / "ok.txt").write_text("ok")
    (tmp_path / "err.txt").write_bytes(ENGINE_ERROR_MARKER)
    s = run(db, [tmp_path], [FakeEngine()])
    assert s.status == ScanStatus.PARTIAL.value
    assert (s.files_assessed, s.files_not_assessed) == (1, 1)
    row = next(x for x in ScanRepository(db).job_files(s.job_id) if x.path.endswith("err.txt"))
    assert not row.assessed and row.engine_errors and "測試用引擎錯誤" in (row.not_assessed_reason or "")


@pytest.mark.parametrize("engine", [FakeEngine(raise_on_scan=RuntimeError("boom")), FakeEngine(omit_results=True)])
def test_engine_crash_or_missing_result_never_clean(db: Database, tmp_path: Path, engine: FakeEngine) -> None:
    (tmp_path / "a.txt").write_text("a")
    s = run(db, [tmp_path], [engine])
    assert s.status == ScanStatus.PARTIAL.value
    assert s.files_assessed == 0 and s.files_not_assessed == 1


def test_one_engine_failing_marks_file_not_assessed(db: Database, tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a")
    s = run(db, [tmp_path], [FakeEngine("Good"), FakeEngine("Bad", raise_on_scan=OSError("x"))])
    assert s.status == ScanStatus.PARTIAL.value and s.files_assessed == 0


def test_exclusions_are_not_failures(db: Database, tmp_path: Path) -> None:
    f = make_tree(tmp_path)
    ex = ExclusionSet.from_pairs([
        (ExclusionKind.EXTENSION, ".md"),
        (ExclusionKind.SHA256, sha256_file(f["bad"])),
    ])
    eng = FakeEngine()
    s = run(db, [tmp_path], [eng], excl=ex)
    assert s.status == ScanStatus.COMPLETED.value
    assert s.files_with_detections == 0 and s.files_not_assessed == 2
    assert f["bad"] not in eng.scanned and f["deep"] not in eng.scanned


def test_batching(db: Database, tmp_path: Path) -> None:
    for i in range(10):
        (tmp_path / f"{i}.txt").write_text(str(i))
    eng = FakeEngine()
    s = run(db, [tmp_path], [eng], batch=3)
    assert eng.calls == 4 and s.files_assessed == 10


def test_cancel_mid_scan(db: Database, tmp_path: Path) -> None:
    for i in range(20):
        (tmp_path / f"{i}.txt").write_text(str(i))
    eng = FakeEngine(delay_per_file_s=0.2)
    tok = CancelToken()
    threading.Timer(0.3, tok.cancel).start()
    s = run(db, [tmp_path], [eng], cancel=tok, batch=5)
    assert s.status == ScanStatus.CANCELLED.value
    assert s.files_assessed < 20
    rows = ScanRepository(db).job_files(s.job_id)
    assert any(r.not_assessed_reason == "掃描已取消" for r in rows)


def test_history_counts_detections(db: Database, tmp_path: Path) -> None:
    make_tree(tmp_path)
    run(db, [tmp_path], [FakeEngine()])
    run(db, [tmp_path / "clean.txt"], [FakeEngine()])
    jobs = ScanRepository(db).list_jobs()
    assert [j.detections for j in jobs] == [0, 1]  # newest first


def test_rescan_reuses_file_record(db: Database, tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a")
    run(db, [tmp_path], [FakeEngine()])
    run(db, [tmp_path], [FakeEngine()])
    with db.session() as s:
        assert len(s.scalars(select(FileRecord)).all()) == 1


def test_end_to_end_with_fake_clamscan(db: Database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SX_FAKE_CLAM_MODE", "normal")
    f = make_tree(tmp_path)
    s = run(db, [tmp_path], [ClamAVEngine(None, launcher=fake_clamscan_launcher())])
    assert s.status == ScanStatus.COMPLETED.value
    assert s.files_with_detections == 1 and s.files_assessed == 4
    bad = next(x for x in ScanRepository(db).job_files(s.job_id) if x.path == str(f["bad"]))
    assert bad.detections == ["ClamAV: Sentinel.Test.Marker-1"]

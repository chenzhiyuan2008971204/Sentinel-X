"""Real ClamAV tests. Skipped unless ClamAV with signatures is installed.

Three independent checks:
1. EICAR through stdin (`clamscan -`): proves the installed engine and signatures detect EICAR
   without putting the file on disk, so Defender cannot interfere.
2. A custom hash signature (.hdb) for a harmless file we create: proves the whole Sentinel X
   pipeline (adapter, file list, output parsing, persistence) against real clamscan.exe,
   including CJK and space-containing paths, with nothing malicious on disk.
3. EICAR on disk through the full pipeline. Defender usually deletes it first; then the test
   is skipped, not passed (TEST_STRATEGY.md §4).
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import time
from pathlib import Path

import pytest
from fakes import eicar_bytes

from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import ScanStatus
from sentinelx.engines.clamav import ClamAVEngine, locate_clamscan
from sentinelx.scanner.exclusions import ExclusionSet
from sentinelx.scanner.orchestrator import ScanOrchestrator
from sentinelx.storage.db import Database
from sentinelx.storage.scan_repository import ScanRepository

pytestmark = [pytest.mark.integration, pytest.mark.needs_clamav]

USER_DB = Path(os.environ.get("LOCALAPPDATA", "")) / "SentinelX" / "clamav-db"
HARMLESS_SAMPLE = "Sentinel X harmless synthetic sample — 這不是惡意程式\n".encode()
CUSTOM_SIG = "Sentinel.Test.HarmlessSample"


def _db_dir() -> Path | None:
    return USER_DB if USER_DB.is_dir() else None


@pytest.fixture(scope="module")
def clam() -> ClamAVEngine:
    exe = locate_clamscan()
    if exe is None:
        pytest.skip("ClamAV is not installed")
    eng = ClamAVEngine(exe, timeout_s=600, database_dir=_db_dir())
    st = eng.availability()
    if not st.available:
        pytest.skip(f"ClamAV unavailable: {st.detail}")
    return eng


def scan(engines: list, roots: list[Path], db: Database):
    return ScanOrchestrator(engines, ScanRepository(db), ScanLimits()).run(roots, ExclusionSet(), CancelToken())


def test_engine_reports_versions(clam: ClamAVEngine) -> None:
    st = clam.availability()
    assert st.version and st.rules_version and st.rules_date


def test_eicar_via_stdin(clam: ClamAVEngine) -> None:
    exe = locate_clamscan()
    assert exe is not None
    db = _db_dir()
    cmd = [str(exe), "--no-summary", *([f"--database={db}"] if db else []), "-"]
    cp = subprocess.run(cmd, input=eicar_bytes(), capture_output=True, timeout=600)
    out = cp.stdout.decode("utf-8", "replace")
    assert cp.returncode == 1, out + cp.stderr.decode("utf-8", "replace")
    assert "Eicar" in out and "FOUND" in out


def test_full_pipeline_with_custom_signature_and_cjk_paths(clam: ClamAVEngine, db: Database, tmp_path: Path) -> None:
    sigdir = tmp_path / "sigs"
    sigdir.mkdir()
    md5 = hashlib.md5(HARMLESS_SAMPLE).hexdigest()  # noqa: S324 - ClamAV .hdb format uses MD5
    (sigdir / "sentinel-test.hdb").write_text(f"{md5}:{len(HARMLESS_SAMPLE)}:{CUSTOM_SIG}\n", encoding="ascii")

    exe = locate_clamscan()
    assert exe is not None
    # Real DB first: `clamscan --version` reports only the first --database it is given.
    real_db = _db_dir()
    launcher = [str(exe), *([f"--database={real_db}"] if real_db else []), f"--database={sigdir}"]
    eng = ClamAVEngine(None, timeout_s=600, launcher=launcher)

    root = tmp_path / "掃描 測試"
    (root / "子資料夾").mkdir(parents=True)
    flagged_ascii = root / "flagged.txt"
    flagged_cjk = root / "子資料夾" / "可疑 樣本.txt"
    clean_cjk = root / "子資料夾" / "一般文件.txt"
    flagged_ascii.write_bytes(HARMLESS_SAMPLE)
    flagged_cjk.write_bytes(HARMLESS_SAMPLE)
    clean_cjk.write_text("普通的內容", encoding="utf-8")

    s = scan([eng], [root], db)
    assert s.status == ScanStatus.COMPLETED.value, s.error_summary
    rows = {r.path: r for r in ScanRepository(db).job_files(s.job_id)}
    for p in (flagged_ascii, flagged_cjk):
        assert rows[str(p)].detections == [f"ClamAV: {CUSTOM_SIG}.UNOFFICIAL"], rows[str(p)]
    assert rows[str(clean_cjk)].assessed and rows[str(clean_cjk)].detections == []


def test_eicar_on_disk_full_pipeline(clam: ClamAVEngine, db: Database, tmp_path: Path) -> None:
    (tmp_path / "harmless.txt").write_text("nothing to see")
    eicar = tmp_path / "eicar.com"
    try:
        eicar.write_bytes(eicar_bytes())
    except OSError as exc:
        pytest.skip(f"EICAR write blocked by real-time protection: {exc}")
    time.sleep(1)
    if not eicar.exists():
        pytest.skip("EICAR file removed by real-time protection (Defender)")

    s = scan([clam], [tmp_path], db)
    if not eicar.exists():
        pytest.skip("EICAR file removed by real-time protection during the scan")
    assert s.status == ScanStatus.COMPLETED.value, s.error_summary
    rows = {Path(r.path).name: r for r in ScanRepository(db).job_files(s.job_id)}
    assert any("Eicar" in d for d in rows["eicar.com"].detections)
    assert rows["harmless.txt"].assessed and not rows["harmless.txt"].detections

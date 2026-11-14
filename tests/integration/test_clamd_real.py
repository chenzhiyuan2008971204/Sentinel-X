"""Real clamd.exe end-to-end. Skipped unless ClamAV with signatures is installed.

The fixture starts its own clamd on a random loopback port with a temporary config. The
signature database is hard-linked into a temp folder (no copy, user DB untouched) next to a
custom .hdb signature for a harmless synthetic file. clamd is stopped afterwards.
"""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fakes import eicar_bytes

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind
from sentinelx.core.models import ScanTarget
from sentinelx.engines.clamd import ClamdEngine

pytestmark = [pytest.mark.integration, pytest.mark.needs_clamav, pytest.mark.slow]

CLAMD = Path(r"C:\Program Files\ClamAV\clamd.exe")
USER_DB = Path(os.environ.get("LOCALAPPDATA", "")) / "SentinelX" / "clamav-db"
HARMLESS = "Sentinel X clamd harmless sample — 無害樣本\n".encode()
SIG = "Sentinel.Test.ClamdHarmless"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def clamd_engine(tmp_path_factory: pytest.TempPathFactory) -> Iterator[ClamdEngine]:
    if not CLAMD.is_file() or not (USER_DB / "main.cvd").is_file():
        pytest.skip("clamd.exe or ClamAV signatures not installed")
    work = tmp_path_factory.mktemp("clamd")
    db = work / "db"
    db.mkdir()
    for f in USER_DB.iterdir():
        if f.suffix in (".cvd", ".cld", ".cud"):
            try:
                os.link(f, db / f.name)
            except OSError:
                pytest.skip("cannot hard-link signature DB (different volume?)")
    md5 = hashlib.md5(HARMLESS).hexdigest()  # noqa: S324 - ClamAV .hdb format
    (db / "sentinel-test.hdb").write_text(f"{md5}:{len(HARMLESS)}:{SIG}\n", encoding="ascii")
    port = _free_port()
    conf = work / "clamd.conf"
    conf.write_text(
        f"TCPSocket {port}\nTCPAddr 127.0.0.1\nDatabaseDirectory {db}\nForeground yes\n"
        f"LogFile {work / 'clamd.log'}\nStreamMaxLength 25M\n",
        encoding="ascii",
    )
    proc = subprocess.Popen([str(CLAMD), f"--config-file={conf}"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, creationflags=0x08000000)
    eng = ClamdEngine("127.0.0.1", port, timeout_s=60)
    try:
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                log = (work / "clamd.log").read_text(errors="replace") if (work / "clamd.log").exists() else ""
                pytest.fail(f"clamd exited early ({proc.returncode}): {log[-800:]}")
            if eng.availability(refresh=True).available:
                break
            time.sleep(2)
        else:
            pytest.fail("clamd did not become ready within 240 s")
        yield eng
    finally:
        proc.kill()
        proc.wait(30)


def target(p: Path) -> ScanTarget:
    d = p.read_bytes()
    return ScanTarget(p, hashlib.sha256(d).hexdigest(), len(d))


def test_real_clamd_versions(clamd_engine: ClamdEngine) -> None:
    st = clamd_engine.availability()
    assert st.available and st.version and st.rules_version


def test_real_clamd_harmless_custom_signature_and_cjk(clamd_engine: ClamdEngine, tmp_path: Path) -> None:
    flagged = tmp_path / "中文 樣本.txt"
    flagged.write_bytes(HARMLESS)
    clean = tmp_path / "一般.txt"
    clean.write_text("普通內容", encoding="utf-8")
    tf, tc = target(flagged), target(clean)
    res = clamd_engine.scan_batch([tf, tc], CancelToken())
    assert res[tc].kind is EngineOutcomeKind.NO_FINDINGS
    assert res[tf].kind is EngineOutcomeKind.FINDINGS
    assert res[tf].detections[0].rule_id == f"{SIG}.UNOFFICIAL"
    assert res[tf].detections[0].evidence["backend"] == "clamd"


def test_real_clamd_eicar_on_disk(clamd_engine: ClamdEngine, tmp_path: Path) -> None:
    p = tmp_path / "eicar.com"
    try:
        p.write_bytes(eicar_bytes())
    except OSError as exc:
        pytest.skip(f"EICAR write blocked: {exc}")
    time.sleep(1)
    if not p.exists():
        pytest.skip("EICAR removed by real-time protection")
    try:
        t = target(p)
    except OSError:
        pytest.skip("EICAR removed by real-time protection")
    r = clamd_engine.scan_batch([t], CancelToken())[t]
    if r.kind is EngineOutcomeKind.ERROR and not p.exists():
        pytest.skip("EICAR removed by real-time protection during the scan")
    assert r.kind is EngineOutcomeKind.FINDINGS and "Eicar" in r.detections[0].rule_id

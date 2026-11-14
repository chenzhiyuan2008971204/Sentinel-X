"""Signature inspector (embedded + catalog) and the isolated research worker, on real
harmless Windows files (the signed python.exe, notepad.exe) and synthetic files."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pefile
import pytest

from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.enums import SignatureStatus
from sentinelx.engines import authenticode as ac
from sentinelx.engines.pe_static import PEStaticEngine
from sentinelx.research import isolation
from sentinelx.research.isolation import run_worker, worker_command

pytestmark = [pytest.mark.integration, pytest.mark.windows,
              pytest.mark.skipif(sys.platform != "win32", reason="Windows APIs")]

PY_EXE = Path(sys.executable)
NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
MAX = 100 * 1024 * 1024


def _catalog_only() -> Path:
    if not NOTEPAD.is_file():
        pytest.skip("notepad.exe not present")
    if ac.verify_authenticode(NOTEPAD).status is not SignatureStatus.UNSIGNED:
        pytest.skip("notepad.exe is embedded-signed on this build; no catalog-only sample")
    return NOTEPAD


def test_embedded_signature_chain() -> None:
    d = ac.inspect_signature(PY_EXE)
    if d.status is not SignatureStatus.VALID:
        pytest.skip(f"python.exe not signed here: {d.message}")
    assert d.source == "EMBEDDED" and d.catalog_file is None
    assert len(d.chain) >= 2 and d.chain[0].subject and d.chain[0].issuer == d.chain[1].subject
    assert all(len(c.sha1) == 40 and len(c.sha256) == 64 and c.not_before and c.not_after for c in d.chain)
    assert d.chain[-1].subject == d.chain[-1].issuer  # self-signed root last


def test_catalog_signature() -> None:
    p = _catalog_only()
    assert ac.verify_signature(p).status is SignatureStatus.VALID
    d = ac.inspect_signature(p)
    assert d.status is SignatureStatus.VALID and d.source == "CATALOG"
    assert d.catalog_file and d.catalog_file.lower().endswith(".cat") and d.chain


def test_pe_engine_uses_catalog_by_default() -> None:
    p = _catalog_only()
    from sentinelx.core.models import ScanTarget

    r = PEStaticEngine().analyze(ScanTarget(p, "0" * 64, p.stat().st_size))
    assert r.info["signature"]["status"] == "VALID" and r.info["signature"]["source"] == "CATALOG"


def test_unsigned_text_has_no_source(tmp_path: Path) -> None:
    p = tmp_path / "中文.txt"
    p.write_text("hello", encoding="utf-8")
    d = ac.inspect_signature(p)
    assert d.status is SignatureStatus.UNSIGNED and d.source is None and d.chain == ()


def test_tampered_copy_invalid(tmp_path: Path) -> None:
    if ac.verify_authenticode(PY_EXE).status is not SignatureStatus.VALID:
        pytest.skip("python.exe not signed")
    dst = tmp_path / "t.exe"
    shutil.copyfile(PY_EXE, dst)
    pe = pefile.PE(str(dst))
    pe.FILE_HEADER.TimeDateStamp = 4242
    data = pe.write()
    pe.close()
    dst.write_bytes(data)
    assert ac.inspect_signature(dst).status is SignatureStatus.INVALID


def test_detail_round_trip() -> None:
    d = ac.inspect_signature(PY_EXE)
    assert ac.SignatureDetail.from_dict(json.loads(json.dumps(d.to_dict()))) == d


# ---------------- isolated worker ----------------

def test_worker_command_fixed_arguments() -> None:
    assert worker_command(Path("C:/a b/x.exe"), 5, executable="py.exe", frozen=False) == [
        "py.exe", "-I", "-m", "sentinelx.research.worker", str(Path("C:/a b/x.exe")), "5"]
    assert worker_command(Path("x.exe"), 5, executable="SentinelX.exe", frozen=True) == [
        "SentinelX.exe", "--research-worker", "x.exe", "5"]


def test_worker_on_pe() -> None:
    r = run_worker(PY_EXE, MAX)
    assert r.ok and r.confined, r.error
    assert r.data["pe"]["engine_name"] == "PEStatic" and r.data["pe"]["info"]["is_pe"]
    assert r.data["signature"]["status"] in {s.value for s in SignatureStatus}
    assert len(r.data["sha256"]) == 64


def test_worker_on_text_and_dir(tmp_path: Path) -> None:
    p = tmp_path / "notes.txt"
    p.write_text("x")
    r = run_worker(p, MAX)
    assert r.ok and r.data["pe"]["kind"] == "SKIPPED"
    bad = run_worker(tmp_path, MAX)
    assert not bad.ok and "一般檔案" in (bad.error or "")


def test_worker_size_limit(tmp_path: Path) -> None:
    p = tmp_path / "big.bin"
    p.write_bytes(b"MZ" + b"\x00" * 4096)
    r = run_worker(p, 1024)
    assert not r.ok and "大小上限" in (r.error or "")


@pytest.mark.security
def test_worker_timeout_kills_process() -> None:
    started = time.monotonic()
    r = run_worker(PY_EXE, MAX, timeout_s=0.5, command=[sys.executable, "-c", "import time; time.sleep(30)"])
    assert not r.ok and "逾時" in (r.error or "")
    assert time.monotonic() - started < 10


@pytest.mark.security
def test_worker_cancel_kills_process() -> None:
    tok = CancelToken()
    tok.cancel()
    with pytest.raises(ScanCancelled):
        run_worker(PY_EXE, MAX, cancel=tok, command=[sys.executable, "-c", "import time; time.sleep(30)"])


@pytest.mark.security
def test_worker_garbage_output_is_error() -> None:
    r = run_worker(PY_EXE, MAX, command=[sys.executable, "-c", "print('not json <script>')"])
    assert not r.ok and "異常結束" in (r.error or "")


@pytest.mark.security
def test_worker_output_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(isolation, "MAX_OUTPUT_BYTES", 100)
    r = run_worker(PY_EXE, MAX, command=[sys.executable, "-c", "print('x' * 1000)"])
    assert not r.ok and "過大" in (r.error or "")


@pytest.mark.security
def test_confined_process_cannot_start_children() -> None:
    code = ("import subprocess, sys\n"
            "from sentinelx.research.worker import confine_self\n"
            "assert confine_self() is None\n"
            "try:\n"
            "    subprocess.run([sys.executable, '-c', '0'], check=True)\n"
            "    print('SPAWNED')\n"
            "except OSError:\n"
            "    print('BLOCKED')\n")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "BLOCKED", out.stderr


def test_main_dispatches_worker_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                     capsysbinary: pytest.CaptureFixture[bytes]) -> None:
    from sentinelx.app import main as app_main
    from sentinelx.research import worker

    monkeypatch.setattr(worker, "confine_self", lambda: None)  # never confine the test process itself
    p = tmp_path / "n.txt"
    p.write_text("x")
    assert app_main.main(["--research-worker", str(p), "1000"]) == 0
    data = json.loads(capsysbinary.readouterr().out.decode("utf-8"))
    assert data["ok"] and data["pe"]["kind"] == "SKIPPED"

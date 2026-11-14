"""PE static analysis on harmless samples: copies of the signed python.exe, modified with pefile."""

from __future__ import annotations

import hashlib
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import pefile
import pytest

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind, Severity, SignatureStatus
from sentinelx.core.models import ScanTarget
from sentinelx.engines.authenticode import SignatureInfo, verify_authenticode
from sentinelx.engines.pe_static import IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, PEStaticEngine

pytestmark = pytest.mark.integration

PY_EXE = Path(sys.executable)


def target(p: Path) -> ScanTarget:
    d = p.read_bytes()
    return ScanTarget(p, hashlib.sha256(d).hexdigest(), len(d))


def unsigned(_p: Path) -> SignatureInfo:
    return SignatureInfo(SignatureStatus.UNSIGNED, 0x800B0100, "no signature")


def run(eng: PEStaticEngine, p: Path):  # type: ignore[no-untyped-def]
    return eng.scan_batch([target(p)], CancelToken())[target(p)]


def modified_copy(tmp_path: Path, name: str, edit) -> Path:  # type: ignore[no-untyped-def]
    dst = tmp_path / name
    shutil.copyfile(PY_EXE, dst)
    pe = pefile.PE(str(dst))
    edit(pe)
    data = pe.write()
    pe.close()
    dst.write_bytes(data)
    return dst


def test_non_pe_is_skipped_not_error(tmp_path: Path) -> None:
    p = tmp_path / "notes.txt"
    p.write_text("hello")
    r = run(PEStaticEngine(verifier=unsigned), p)
    assert r.kind is EngineOutcomeKind.SKIPPED and r.completed and r.info == {"is_pe": False}


def test_malformed_mz_is_low_finding(tmp_path: Path) -> None:
    p = tmp_path / "fake.exe"
    p.write_bytes(b"MZ" + b"\x00" * 100)
    r = run(PEStaticEngine(verifier=unsigned), p)
    assert r.kind is EngineOutcomeKind.FINDINGS
    [d] = r.detections
    assert d.rule_id == "PE.Malformed" and d.severity_hint is Severity.LOW


def test_metadata_extracted(tmp_path: Path) -> None:
    r = run(PEStaticEngine(verifier=unsigned), PY_EXE)
    i = r.info
    assert i["is_pe"] and i["machine"] in ("x64", "x86", "ARM64") and not i["is_dll"]
    assert i["sections"] and all({"name", "entropy", "writable", "executable"} <= s.keys() for s in i["sections"])
    assert i["imports"] and i["import_function_count"] > 0
    assert i["entry_point_section"] is not None
    assert i["signature"]["status"] == "UNSIGNED"


def test_unsigned_is_not_a_detection() -> None:
    r = run(PEStaticEngine(verifier=unsigned), PY_EXE)
    assert not any("Signature" in d.rule_id for d in r.detections)


def test_writable_executable_section(tmp_path: Path) -> None:
    def edit(pe: pefile.PE) -> None:
        pe.sections[0].Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE

    r = run(PEStaticEngine(verifier=unsigned), modified_copy(tmp_path, "wx.exe", edit))
    rules = {d.rule_id: d for d in r.detections}
    assert "PE.Anomaly.WritableExecutableSection" in rules
    assert "不代表檔案是惡意程式" in rules["PE.Anomaly.WritableExecutableSection"].confidence_explanation


def test_packer_name_and_entry_point_outside(tmp_path: Path) -> None:
    def edit(pe: pefile.PE) -> None:
        pe.sections[0].Name = b"UPX0\x00\x00\x00\x00"
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x7FFFFFF0

    r = run(PEStaticEngine(verifier=unsigned), modified_copy(tmp_path, "upx.exe", edit))
    rules = {d.rule_id: d.severity_hint for d in r.detections}
    assert rules["PE.Anomaly.PackerSectionName"] is Severity.LOW
    assert rules["PE.Anomaly.EntryPointOutsideSections"] is Severity.MEDIUM


def test_future_timestamp_is_info(tmp_path: Path) -> None:
    def edit(pe: pefile.PE) -> None:
        pe.FILE_HEADER.TimeDateStamp = 0xF0000000  # year 2097

    eng = PEStaticEngine(verifier=unsigned, now=lambda: datetime(2026, 11, 2, tzinfo=UTC))
    r = run(eng, modified_copy(tmp_path, "future.exe", edit))
    assert {d.rule_id: d.severity_hint for d in r.detections}["PE.Anomaly.FutureTimestamp"] is Severity.INFO


def test_anomalies_never_high_severity(tmp_path: Path) -> None:
    def edit(pe: pefile.PE) -> None:
        for s in pe.sections:
            s.Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE
        pe.sections[0].Name = b"UPX1\x00\x00\x00\x00"
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x7FFFFFF0
        pe.FILE_HEADER.TimeDateStamp = 0xF0000000

    r = run(PEStaticEngine(), modified_copy(tmp_path, "many.exe", edit))
    assert r.detections and all(d.severity_hint is not Severity.HIGH for d in r.detections)


@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="WinVerifyTrust is Windows-only")
def test_real_authenticode_valid_and_tampered(tmp_path: Path) -> None:
    original = verify_authenticode(PY_EXE)
    if original.status is not SignatureStatus.VALID:
        pytest.skip(f"python.exe is not Authenticode-signed here ({original.message})")
    tampered = modified_copy(tmp_path, "tampered.exe", lambda pe: setattr(pe.FILE_HEADER, "TimeDateStamp", 12345))
    assert verify_authenticode(tampered).status is SignatureStatus.INVALID
    r = run(PEStaticEngine(), tampered)
    assert "PE.Signature.Invalid" in {d.rule_id for d in r.detections}
    assert r.info["signature"]["status"] == "INVALID"


@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="WinVerifyTrust is Windows-only")
def test_real_authenticode_on_text_and_cjk_path(tmp_path: Path) -> None:
    p = tmp_path / "中文 檔案.txt"
    p.write_text("x")
    assert verify_authenticode(p).status in (SignatureStatus.UNSIGNED, SignatureStatus.UNKNOWN)


@pytest.mark.security
def test_parser_crash_becomes_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    eng = PEStaticEngine(verifier=unsigned)

    def boom(_t: ScanTarget):  # type: ignore[no-untyped-def]
        raise RecursionError("hostile structure")

    monkeypatch.setattr(eng, "analyze", boom)
    r = run(eng, PY_EXE)
    assert r.kind is EngineOutcomeKind.ERROR and "RecursionError" in (r.error or "")

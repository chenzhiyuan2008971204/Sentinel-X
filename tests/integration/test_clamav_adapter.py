"""ClamAV adapter tests against a fake clamscan process (real subprocess, harmless script)."""

from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path

import pytest
from fakes import LIMITS_MARKER, MALWARE_MARKER, fake_clamscan_launcher

from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.enums import EngineOutcomeKind, Severity
from sentinelx.core.models import ScanTarget
from sentinelx.engines import clamav
from sentinelx.engines.clamav import ClamAVEngine, locate_clamscan

pytestmark = pytest.mark.integration


def target(p: Path) -> ScanTarget:
    data = p.read_bytes()
    return ScanTarget(p, hashlib.sha256(data).hexdigest(), len(data))


def engine(monkeypatch: pytest.MonkeyPatch, mode: str = "normal", timeout_s: int = 60) -> ClamAVEngine:
    monkeypatch.setenv("SX_FAKE_CLAM_MODE", mode)
    return ClamAVEngine(None, timeout_s=timeout_s, launcher=fake_clamscan_launcher())


def test_missing_executable_unavailable(tmp_path: Path) -> None:
    st = ClamAVEngine(tmp_path / "clamscan.exe").availability()
    assert not st.available and "找不到" in st.detail


@pytest.mark.security
def test_locate_rejects_wrong_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clamav, "default_locations", lambda: ())
    impostor = tmp_path / "evil.exe"
    impostor.write_bytes(b"MZ")
    assert locate_clamscan(str(impostor)) is None
    real_name = tmp_path / "clamscan.exe"
    real_name.write_bytes(b"MZ")
    assert locate_clamscan(str(real_name)) == real_name


def test_available_with_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    st = engine(monkeypatch).availability()
    assert st.available
    assert (st.version, st.rules_version) == ("1.5.4", "27800")


def test_missing_database_dir_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SX_FAKE_CLAM_MODE", "normal")
    eng = ClamAVEngine(None, database_dir=tmp_path / "nope", launcher=fake_clamscan_launcher())
    st = eng.availability()
    assert not st.available and "尚未下載病毒碼" in st.detail and "資料夾不存在" in st.detail


def test_no_signature_db_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    st = engine(monkeypatch, "nodb").availability()
    assert not st.available and st.version == "1.5.4" and "freshclam" in st.detail


def test_unavailable_engine_returns_errors_not_clean(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    p = tmp_path / "a.txt"
    p.write_text("a")
    res = engine(monkeypatch, "nodb").scan_batch([target(p)], CancelToken())
    assert all(o.kind is EngineOutcomeKind.ERROR for o in res.values())


def test_mixed_batch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    clean = tmp_path / "clean.txt"
    clean.write_text("hello")
    bad = tmp_path / "惡意 樣本.bin"  # CJK + space in the name
    bad.write_bytes(MALWARE_MARKER)
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    big = tmp_path / "limits.bin"
    big.write_bytes(LIMITS_MARKER)
    ts = [target(p) for p in (clean, bad, empty, big)]

    res = engine(monkeypatch).scan_batch(ts, CancelToken())
    assert res[ts[0]].kind is EngineOutcomeKind.NO_FINDINGS
    assert res[ts[2]].kind is EngineOutcomeKind.NO_FINDINGS

    found = res[ts[1]]
    assert found.kind is EngineOutcomeKind.FINDINGS
    [d] = found.detections
    assert d.rule_id == "Sentinel.Test.Marker-1"
    assert d.engine_name == "ClamAV" and d.engine_version == "1.5.4"
    assert d.file_sha256 == ts[1].sha256
    assert d.severity_hint is Severity.HIGH
    assert d.confidence_explanation and d.timestamp
    assert d.evidence["rules_version"] == "27800"

    limits = res[ts[3]]
    assert limits.kind is EngineOutcomeKind.ERROR and "未完整掃描" in (limits.error or "")


def test_unreadable_file_is_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    p = tmp_path / "gone.txt"
    p.write_text("x")
    t = target(p)
    p.unlink()
    res = engine(monkeypatch).scan_batch([t], CancelToken())
    assert res[t].kind is EngineOutcomeKind.ERROR


@pytest.mark.parametrize("mode", ["crash", "garbage", "partial"])
def test_engine_failures_never_clean(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str) -> None:
    ps = []
    for i in range(3):
        p = tmp_path / f"{i}.txt"
        p.write_text(str(i))
        ps.append(target(p))
    res = engine(monkeypatch, mode).scan_batch(ps, CancelToken())
    kinds = [res[t].kind for t in ps]
    if mode == "partial":
        assert kinds[:2] == [EngineOutcomeKind.NO_FINDINGS] * 2
        assert kinds[2] is EngineOutcomeKind.ERROR
    else:
        assert kinds == [EngineOutcomeKind.ERROR] * 3


def test_timeout_is_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    p = tmp_path / "a.txt"
    p.write_text("a")
    eng = engine(monkeypatch, "normal", timeout_s=1)
    eng.availability()  # cache status before switching to the hanging mode
    monkeypatch.setenv("SX_FAKE_CLAM_MODE", "hang")
    t0 = time.monotonic()
    res = eng.scan_batch([target(p)], CancelToken())
    assert time.monotonic() - t0 < 15
    assert "逾時" in (res[target(p)].error or "")


def test_cancel_kills_process_quickly(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    p = tmp_path / "a.txt"
    p.write_text("a")
    eng = engine(monkeypatch)
    eng.availability()
    monkeypatch.setenv("SX_FAKE_CLAM_MODE", "hang")
    tok = CancelToken()
    threading.Timer(0.5, tok.cancel).start()
    t0 = time.monotonic()
    with pytest.raises(ScanCancelled):
        eng.scan_batch([target(p)], tok)
    assert time.monotonic() - t0 < 5

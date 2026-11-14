"""clamd backend, plus the shared ClamAV contract both backends must satisfy."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from fakes import LIMITS_MARKER, MALWARE_MARKER, FakeClamd, fake_clamscan_launcher

from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.enums import EngineOutcomeKind
from sentinelx.core.models import ScanTarget
from sentinelx.engines.clamav import ClamAVEngine
from sentinelx.engines.clamd import ClamdEngine, parse_instream_reply

pytestmark = pytest.mark.integration


def target(p: Path) -> ScanTarget:
    data = p.read_bytes()
    return ScanTarget(p, hashlib.sha256(data).hexdigest(), len(data))


@pytest.fixture
def clamd() -> Iterator[Callable[[str], ClamdEngine]]:
    servers: list[FakeClamd] = []

    def make(mode: str = "normal") -> ClamdEngine:
        srv = FakeClamd(mode)
        servers.append(srv)
        return ClamdEngine("127.0.0.1", srv.port, timeout_s=5)

    yield make
    for s in servers:
        s.close()


# ---------- shared contract ----------
@pytest.fixture(params=["clamscan", "clamd"])
def backend(request: pytest.FixtureRequest, clamd: Callable[[str], ClamdEngine],
            monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    if request.param == "clamscan":
        monkeypatch.setenv("SX_FAKE_CLAM_MODE", "normal")
        return ClamAVEngine(None, launcher=fake_clamscan_launcher())
    return clamd("normal")


@pytest.mark.parametrize("name", ["plain.txt", "中文 檔名.bin"])
def test_contract_same_normalized_results(backend, tmp_path: Path, name: str) -> None:  # type: ignore[no-untyped-def]
    clean = tmp_path / f"clean-{name}"
    clean.write_text("hello")
    bad = tmp_path / f"bad-{name}"
    bad.write_bytes(MALWARE_MARKER)
    lim = tmp_path / f"lim-{name}"
    lim.write_bytes(LIMITS_MARKER)
    ts = [target(p) for p in (clean, bad, lim)]

    st = backend.availability()
    assert st.available and (st.version, st.rules_version) == ("1.5.4", "27800")
    res = backend.scan_batch(ts, CancelToken())
    assert res[ts[0]].kind is EngineOutcomeKind.NO_FINDINGS
    assert res[ts[1]].kind is EngineOutcomeKind.FINDINGS
    [d] = res[ts[1]].detections
    assert (d.engine_name, d.rule_id, d.file_sha256) == ("ClamAV", "Sentinel.Test.Marker-1", ts[1].sha256)
    assert res[ts[2]].kind is EngineOutcomeKind.ERROR  # limits exceeded = not fully scanned


# ---------- clamd specifics ----------
@pytest.mark.security
@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.0.5", "example.com"])
def test_clamd_refuses_non_loopback(host: str) -> None:
    with pytest.raises(ValueError):
        ClamdEngine(host, 3310)


def test_clamd_not_running_is_unavailable_and_errors(tmp_path: Path) -> None:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    eng = ClamdEngine("127.0.0.1", port, timeout_s=2)
    st = eng.availability()
    assert not st.available and "clamd" in st.detail
    p = tmp_path / "a.txt"
    p.write_text("a")
    assert eng.scan_batch([target(p)], CancelToken())[target(p)].kind is EngineOutcomeKind.ERROR


def test_clamd_without_db_unavailable(clamd: Callable[[str], ClamdEngine]) -> None:
    st = clamd("nodb").availability()
    assert not st.available and st.version == "1.5.4"


@pytest.mark.parametrize("mode", ["garbage", "sizelimit", "drop"])
def test_clamd_bad_replies_are_errors(clamd: Callable[[str], ClamdEngine], tmp_path: Path, mode: str) -> None:
    eng = clamd(mode)  # VERSION answers normally; only scan replies misbehave
    assert eng.availability().available
    p = tmp_path / "a.txt"
    p.write_text("a")
    assert eng.scan_batch([target(p)], CancelToken())[target(p)].kind is EngineOutcomeKind.ERROR


def test_clamd_cancel(clamd: Callable[[str], ClamdEngine], tmp_path: Path) -> None:
    p = tmp_path / "a.txt"
    p.write_text("a")
    tok = CancelToken()
    tok.cancel()
    with pytest.raises(ScanCancelled):
        clamd("normal").scan_batch([target(p)], tok)


@pytest.mark.parametrize(
    ("reply", "kind", "value"),
    [
        ("stream: OK", "OK", None),
        ("stream: Win.Test.EICAR_HDB-1 FOUND", "FOUND", "Win.Test.EICAR_HDB-1"),
        ("INSTREAM size limit exceeded. ERROR", "ERROR", "INSTREAM size limit exceeded"),
        ("stream: lstat() failed ERROR", "ERROR", "lstat() failed"),
    ],
)
def test_parse_instream_reply(reply: str, kind: str, value: str | None) -> None:
    line = parse_instream_reply(reply + "\0")
    assert line is not None and line.kind == kind
    assert (line.signature or line.message) == value


def test_parse_instream_reply_garbage() -> None:
    assert parse_instream_reply("hello") is None

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind, IntelVerdict, Severity, TrustLevel
from sentinelx.core.models import ScanTarget
from sentinelx.engines.hash_intel import HashIntelEngine
from sentinelx.storage.db import Database
from sentinelx.storage.intel_repository import IntelStore, parse_intel_lines

pytestmark = pytest.mark.integration

A, B, C = "a" * 64, "b" * 64, "c" * 64


def t(sha: str) -> ScanTarget:
    return ScanTarget(Path(f"C:/x/{sha[:4]}"), sha, 1)


def write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_parse_formats() -> None:
    text = "\n".join([
        "sha256,label,verdict",
        "# comment",
        A.upper(),
        f"{B},Trojan.Test",
        f"{C},Notepad,known_good",
        "not-a-hash",
        f"{A},x,weird-verdict",
        "",
    ])
    entries, invalid = parse_intel_lines(text, IntelVerdict.MALICIOUS)
    assert entries == [(A, None, IntelVerdict.MALICIOUS), (B, "Trojan.Test", IntelVerdict.MALICIOUS),
                       (C, "Notepad", IntelVerdict.KNOWN_GOOD)]
    assert invalid == [6, 7]


def test_import_and_sources(db: Database, tmp_path: Path) -> None:
    store = IntelStore(db)
    res = store.import_file(write(tmp_path, "l.txt", f"{A}\n{A}\n{B},bad\nzzz\n"), source_name="L1", trust=TrustLevel.HIGH)
    assert (res.imported, res.duplicates, res.invalid_count) == (2, 1, 1)
    [src] = store.sources()
    assert (src.name, src.trust, src.malicious, src.known_good) == ("L1", TrustLevel.HIGH, 2, 0)
    with pytest.raises(ValueError):
        store.import_file(write(tmp_path, "l2.txt", A), source_name="L1", trust=TrustLevel.LOW)


def test_import_rejects_empty_and_missing(db: Database, tmp_path: Path) -> None:
    store = IntelStore(db)
    with pytest.raises(ValueError):
        store.import_file(write(tmp_path, "e.txt", "nothing valid\n"), source_name="x", trust=TrustLevel.LOW)
    with pytest.raises(ValueError):
        store.import_file(tmp_path / "missing.txt", source_name="x", trust=TrustLevel.LOW)
    assert store.sources() == []


def test_engine_distinguishes_unknown_malicious_known_good(db: Database, tmp_path: Path) -> None:
    store = IntelStore(db)
    store.import_file(write(tmp_path, "bad.txt", f"{A},Evil\n"), source_name="Bad", trust=TrustLevel.MEDIUM)
    store.import_file(write(tmp_path, "good.txt", f"{B},Notepad\n"), source_name="Good", trust=TrustLevel.HIGH,
                      default_verdict=IntelVerdict.KNOWN_GOOD)
    eng = HashIntelEngine(store)
    res = eng.scan_batch([t(A), t(B), t(C)], CancelToken())

    mal = res[t(A)]
    assert mal.kind is EngineOutcomeKind.FINDINGS and mal.info["reputation"] == "MALICIOUS"
    [d] = mal.detections
    assert d.rule_id == "HashIntel.Bad" and d.severity_hint is Severity.MEDIUM and d.evidence["label"] == "Evil"
    assert d.file_sha256 == A and "可信度：中" in d.confidence_explanation

    good = res[t(B)]
    assert good.kind is EngineOutcomeKind.NO_FINDINGS and good.info["reputation"] == "KNOWN_GOOD"
    unknown = res[t(C)]
    assert unknown.kind is EngineOutcomeKind.NO_FINDINGS and unknown.info["reputation"] == "UNKNOWN"
    assert unknown.info != good.info  # unknown is never reported like known-good


def test_conflicting_sources_flagged(db: Database, tmp_path: Path) -> None:
    store = IntelStore(db)
    store.import_file(write(tmp_path, "bad.txt", A), source_name="Bad", trust=TrustLevel.LOW)
    store.import_file(write(tmp_path, "good.txt", A), source_name="Good", trust=TrustLevel.HIGH,
                      default_verdict=IntelVerdict.KNOWN_GOOD)
    r = HashIntelEngine(store).scan_batch([t(A)], CancelToken())[t(A)]
    [d] = r.detections
    assert d.severity_hint is Severity.LOW and d.evidence["conflict_with_known_good"] is True
    assert "矛盾" in d.confidence_explanation


def test_remove_source_and_stamp_changes(db: Database, tmp_path: Path) -> None:
    store = IntelStore(db)
    s0 = store.stamp()
    res = store.import_file(write(tmp_path, "bad.txt", A), source_name="Bad", trust=TrustLevel.HIGH)
    s1 = store.stamp()
    assert s0 != s1
    assert store.remove_source(res.source_id) is not None
    assert store.lookup_many([A])[A] == [] and store.stamp() != s1


def test_real_file_hash(db: Database, tmp_path: Path) -> None:
    f = tmp_path / "sample.txt"
    f.write_text("harmless")
    sha = hashlib.sha256(f.read_bytes()).hexdigest()
    store = IntelStore(db)
    store.import_file(write(tmp_path, "l.txt", f"{sha},sample"), source_name="S", trust=TrustLevel.HIGH)
    tgt = ScanTarget(f, sha, f.stat().st_size)
    assert HashIntelEngine(store).scan_batch([tgt], CancelToken())[tgt].kind is EngineOutcomeKind.FINDINGS

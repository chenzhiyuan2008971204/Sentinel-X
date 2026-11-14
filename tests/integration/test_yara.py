from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fakes import MALWARE_MARKER

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind, Severity
from sentinelx.core.models import ScanTarget
from sentinelx.engines.yara_engine import YaraEngine
from sentinelx.storage.db import Database
from sentinelx.storage.rules_repository import RuleSetStore, validate_rule_source

pytestmark = pytest.mark.integration

GOOD_RULES = """
rule TestMarker : test
{
    meta:
        description = "harmless test marker"
        severity = "high"
        confirming = "true"
    strings:
        $m = "SX-TEST-MALWARE-MARKER"
    condition:
        $m
}

rule WeakHeuristic
{
    meta:
        severity = "low"
    strings:
        $a = "weak-indicator"
    condition:
        $a
}
"""
PE_RULE = 'import "pe"\nrule IsPE { condition: pe.number_of_sections > 0 }\n'


def target(p: Path) -> ScanTarget:
    d = p.read_bytes()
    return ScanTarget(p, hashlib.sha256(d).hexdigest(), len(d))


@pytest.fixture
def store(db: Database, tmp_path_factory: pytest.TempPathFactory) -> RuleSetStore:
    return RuleSetStore(db, tmp_path_factory.mktemp("rules") / "yara")


def write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ---------- validation ----------
def test_validate_ok() -> None:
    v = validate_rule_source(GOOD_RULES)
    assert v.ok and v.rule_count == 2


@pytest.mark.parametrize(
    ("src", "fragment"),
    [
        ("rule broken { condition: }", "語法錯誤"),
        ('import "cuckoo"\nrule c { condition: true }', "cuckoo"),
        ('import "console"\nrule c { condition: true }', "console"),
        ('include "C:/Windows/win.ini"\nrule x { condition: true }', "include"),
        ("// only a comment", "沒有任何"),
    ],
)
def test_validate_rejects(src: str, fragment: str) -> None:
    v = validate_rule_source(src)
    assert not v.ok and fragment in (v.error or "")


# ---------- store ----------
def test_add_valid_copies_and_pins(store: RuleSetStore, tmp_path: Path) -> None:
    src = write(tmp_path, "my.yar", GOOD_RULES)
    r = store.add_from_file(src, "測試規則", "1.0")
    assert r.valid and r.enabled and r.version == "1.0" and r.rule_count == 2
    assert r.path != src and r.path.read_text(encoding="utf-8") == GOOD_RULES
    assert r.sha256 == hashlib.sha256(src.read_bytes()).hexdigest()


def test_add_invalid_registered_disabled_and_cannot_enable(store: RuleSetStore, tmp_path: Path) -> None:
    r = store.add_from_file(write(tmp_path, "bad.yar", 'import "cuckoo"\nrule c { condition: true }'))
    assert not r.valid and not r.enabled
    with pytest.raises(ValueError):
        store.set_enabled(r.id, True)


def test_duplicate_name_refused(store: RuleSetStore, tmp_path: Path) -> None:
    store.add_from_file(write(tmp_path, "a.yar", GOOD_RULES), "set-a")
    with pytest.raises(ValueError):
        store.add_from_file(write(tmp_path, "b.yar", PE_RULE), "set_a")  # same namespace


def test_auto_version_contains_hash(store: RuleSetStore, tmp_path: Path) -> None:
    r = store.add_from_file(write(tmp_path, "a.yar", GOOD_RULES))
    assert r.version.endswith(r.sha256[:8])


def test_non_utf8_and_oversize_rejected(store: RuleSetStore, tmp_path: Path) -> None:
    p = tmp_path / "x.yar"
    p.write_bytes(b"\xff\xfe\x00rule")
    with pytest.raises(ValueError):
        store.add_from_file(p)


def test_remove_deletes_only_own_copy(store: RuleSetStore, tmp_path: Path) -> None:
    src = write(tmp_path, "a.yar", GOOD_RULES)
    r = store.add_from_file(src)
    assert store.remove(r.id) is not None
    assert not r.path.exists() and src.exists()


# ---------- engine ----------
def test_no_rules_means_unavailable(store: RuleSetStore) -> None:
    st = YaraEngine(store).availability()
    assert not st.available and "沒有啟用" in st.detail


def test_match_records_structured_evidence(store: RuleSetStore, tmp_path: Path) -> None:
    store.add_from_file(write(tmp_path, "a.yar", GOOD_RULES), "sx-test", "2.1")
    eng = YaraEngine(store)
    st = eng.availability()
    assert st.available and st.rules_version == "sx-test@2.1"

    hit = tmp_path / "中文 樣本.bin"
    hit.write_bytes(b"xx" + MALWARE_MARKER + b" weak-indicator")
    miss = tmp_path / "clean.txt"
    miss.write_text("nothing")
    th, tm = target(hit), target(miss)
    res = eng.scan_batch([th, tm], CancelToken())

    assert res[tm].kind is EngineOutcomeKind.NO_FINDINGS
    r = res[th]
    assert r.kind is EngineOutcomeKind.FINDINGS
    by_rule = {d.rule_id: d for d in r.detections}
    assert set(by_rule) == {"sx_test.TestMarker", "sx_test.WeakHeuristic"}
    strong = by_rule["sx_test.TestMarker"]
    assert strong.severity_hint is Severity.HIGH and strong.evidence["confirming"] is True
    assert strong.evidence["strings"][0]["id"] == "$m" and strong.evidence["strings"][0]["offsets"] == [2]
    assert strong.evidence["rule_set_version"] == "2.1" and strong.evidence["tags"] == ["test"]
    assert strong.file_sha256 == th.sha256 and strong.engine_version
    assert "harmless test marker" in strong.confidence_explanation
    weak = by_rule["sx_test.WeakHeuristic"]
    assert weak.severity_hint is Severity.LOW and weak.evidence["confirming"] is False


def test_pe_module_rule(store: RuleSetStore, tmp_path: Path) -> None:
    import sys

    store.add_from_file(write(tmp_path, "pe.yar", PE_RULE), "pe-rules")
    eng = YaraEngine(store)
    exe = Path(sys.executable)
    r = eng.scan_batch([target(exe)], CancelToken())[target(exe)]
    assert [d.rule_id for d in r.detections] == ["pe_rules.IsPE"]


@pytest.mark.security
def test_tampered_rule_copy_is_not_used(store: RuleSetStore, tmp_path: Path) -> None:
    r = store.add_from_file(write(tmp_path, "a.yar", GOOD_RULES), "sx")
    r.path.write_text("rule Evil { condition: true }", encoding="utf-8")
    st = YaraEngine(store).availability()
    assert not st.available and "已被變更" in st.detail


def test_disable_reload(store: RuleSetStore, tmp_path: Path) -> None:
    r = store.add_from_file(write(tmp_path, "a.yar", GOOD_RULES), "sx")
    eng = YaraEngine(store)
    assert eng.availability().available
    store.set_enabled(r.id, False)
    assert not eng.availability(refresh=True).available


def test_oversize_file_is_error(store: RuleSetStore, tmp_path: Path) -> None:
    store.add_from_file(write(tmp_path, "a.yar", GOOD_RULES), "sx")
    eng = YaraEngine(store, max_file_size_mb=1)
    p = tmp_path / "big.bin"
    with open(p, "wb") as f:
        f.truncate(2 * 1024 * 1024)
    assert eng.scan_batch([target(p)], CancelToken())[target(p)].kind is EngineOutcomeKind.ERROR

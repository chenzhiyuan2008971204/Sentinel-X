"""Risk assessment rules, with emphasis on conflicting and partial engine results."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sentinelx.core.enums import Classification as C
from sentinelx.core.enums import EngineOutcomeKind as K
from sentinelx.core.enums import Severity as S
from sentinelx.core.models import DetectionRecord, DetectionResult, FileResult
from sentinelx.core.risk import SCORE_DISCLAIMER, Reliability, Suppression, assess, grade, unassessed

pytestmark = pytest.mark.unit
SHA = "f" * 64


def det(engine: str, rule: str, sev: S, **ev: Any) -> DetectionRecord:
    return DetectionRecord(engine, "1", rule, sev, ev, SHA, "x")


def res(engine: str, *dets: DetectionRecord, kind: K | None = None, info: dict | None = None,
        error: str | None = None) -> DetectionResult:
    k = kind or (K.FINDINGS if dets else K.NO_FINDINGS)
    return DetectionResult(engine, k, "1", "r", tuple(dets), error=error, info=info or {})


def fr(*outcomes: DetectionResult, reason: str | None = None) -> FileResult:
    return FileResult(Path("C:/x/f.exe"), 1, None, None, SHA, tuple(outcomes), reason)


CLAM_OK = res("ClamAV")
YARA_OK = res("YARA")
PE_OK = res("PEStatic")
HASH_UNKNOWN = res("HashIntel", info={"reputation": "UNKNOWN", "sources": []})
CLAM_SIG = det("ClamAV", "Win.Trojan.X", S.HIGH)
CLAM_PUA = det("ClamAV", "PUA.Win.Tool", S.MEDIUM)
CLAM_HEUR = det("ClamAV", "Heuristics.Encrypted", S.MEDIUM)
YARA_CONFIRM = det("YARA", "ns.Strong", S.HIGH, confirming=True)
YARA_MED = det("YARA", "ns.Med", S.MEDIUM, confirming=False)
YARA_LOW = det("YARA", "ns.Low", S.LOW, confirming=False)
PE_WX = det("PEStatic", "PE.Anomaly.WritableExecutableSection", S.LOW)
PE_ENTROPY = det("PEStatic", "PE.Anomaly.HighEntropySection", S.LOW)
PE_SIG_INVALID = det("PEStatic", "PE.Signature.Invalid", S.MEDIUM)
PE_TS = det("PEStatic", "PE.Anomaly.FutureTimestamp", S.INFO)


def hash_bad(trust: str, conflict: bool = False) -> DetectionRecord:
    return det("HashIntel", "HashIntel.Src", {"HIGH": S.HIGH, "MEDIUM": S.MEDIUM}.get(trust, S.LOW),
               trust=trust, conflict_with_known_good=conflict)


def known_good(trust: str = "HIGH") -> dict:
    return {"reputation": "KNOWN_GOOD", "sources": [{"source": "Vendor", "verdict": "KNOWN_GOOD", "trust": trust}]}


# ---------------- grading ----------------
@pytest.mark.parametrize(("d", "rel"), [
    (CLAM_SIG, Reliability.STRONG), (CLAM_PUA, Reliability.MODERATE), (CLAM_HEUR, Reliability.MODERATE),
    (YARA_CONFIRM, Reliability.STRONG), (YARA_MED, Reliability.MODERATE), (YARA_LOW, Reliability.WEAK),
    (PE_WX, Reliability.WEAK), (PE_SIG_INVALID, Reliability.WEAK), (PE_TS, Reliability.INFO),
    (hash_bad("HIGH"), Reliability.STRONG), (hash_bad("MEDIUM"), Reliability.MODERATE), (hash_bad("LOW"), Reliability.WEAK),
    (hash_bad("HIGH", conflict=True), Reliability.MODERATE),
    (det("SomeNewAV", "X", S.HIGH), Reliability.MODERATE), (det("SomeNewAV", "X", S.MEDIUM), Reliability.WEAK),
])
def test_grading(d: DetectionRecord, rel: Reliability) -> None:
    assert grade(d)[0] is rel


def test_pe_evidence_never_above_weak() -> None:
    for sev in S:
        assert grade(det("PEStatic", "PE.Anything", sev))[0] in (Reliability.WEAK, Reliability.INFO)


# ---------------- basic classes ----------------
def test_all_engines_silent_is_clean_with_disclaimer() -> None:
    a = assess(fr(CLAM_OK, YARA_OK, PE_OK, HASH_UNKNOWN))
    assert a.classification is C.CLEAN and a.confidence == "中"
    assert "不代表檔案一定安全" in a.explanation and SCORE_DISCLAIMER in a.explanation


def test_clean_with_single_signature_engine_is_low_confidence() -> None:
    assert assess(fr(CLAM_OK, PE_OK)).confidence == "低"


def test_engine_error_without_evidence_is_unknown() -> None:
    a = assess(fr(res("ClamAV", kind=K.ERROR, error="timeout"), YARA_OK))
    assert a.classification is C.UNKNOWN and "timeout" in a.explanation


def test_unreadable_file_is_unknown() -> None:
    a = unassessed("權限不足")
    assert a.classification is C.UNKNOWN and "權限不足" in a.explanation and a.evidence == ()


def test_clamav_signature_confirms() -> None:
    a = assess(fr(res("ClamAV", CLAM_SIG), YARA_OK, PE_OK))
    assert a.classification is C.CONFIRMED_THREAT and not a.needs_review
    assert [e.detection.rule_id for e in a.contributing] == ["Win.Trojan.X"]


def test_confirming_yara_confirms() -> None:
    assert assess(fr(CLAM_OK, res("YARA", YARA_CONFIRM))).classification is C.CONFIRMED_THREAT


def test_high_trust_hash_confirms_low_trust_does_not() -> None:
    assert assess(fr(CLAM_OK, res("HashIntel", hash_bad("HIGH")))).classification is C.CONFIRMED_THREAT
    assert assess(fr(CLAM_OK, res("HashIntel", hash_bad("LOW")))).classification is C.CLEAN


# ---------------- "a single weak heuristic must not confirm malware" ----------------
@pytest.mark.parametrize("weak", [PE_WX, PE_ENTROPY, YARA_LOW, hash_bad("LOW"), PE_SIG_INVALID])
def test_single_weak_never_confirms_or_suspects(weak: DetectionRecord) -> None:
    a = assess(fr(CLAM_OK, res(weak.engine_name, weak)))
    assert a.classification is C.CLEAN
    assert "弱特徵" in a.explanation


def test_many_weak_from_one_engine_stays_clean() -> None:
    a = assess(fr(CLAM_OK, res("PEStatic", PE_WX, PE_ENTROPY, PE_SIG_INVALID)))
    assert a.classification is C.CLEAN


def test_weak_from_two_engines_is_suspicious_not_confirmed() -> None:
    a = assess(fr(CLAM_OK, res("PEStatic", PE_WX), res("YARA", YARA_LOW)))
    assert a.classification is C.SUSPICIOUS and a.confidence == "低" and a.needs_review


def test_single_moderate_is_suspicious() -> None:
    for d in (CLAM_PUA, CLAM_HEUR, YARA_MED, hash_bad("MEDIUM")):
        assert assess(fr(res(d.engine_name, d))).classification is C.SUSPICIOUS


def test_two_moderate_same_engine_not_corroboration() -> None:
    assert assess(fr(res("ClamAV", CLAM_PUA, CLAM_HEUR))).classification is C.SUSPICIOUS


def test_two_moderate_independent_engines_confirm() -> None:
    a = assess(fr(res("ClamAV", CLAM_HEUR), res("YARA", YARA_MED)))
    assert a.classification is C.CONFIRMED_THREAT and "互相印證" in a.explanation


# ---------------- "missing signatures must not imply malicious behavior" ----------------
def test_unsigned_pe_is_not_evidence() -> None:
    pe = res("PEStatic", info={"is_pe": True, "signature": {"status": "UNSIGNED"}})
    a = assess(fr(CLAM_OK, pe))
    assert a.classification is C.CLEAN and a.evidence == ()


def test_info_records_never_count() -> None:
    a = assess(fr(CLAM_OK, res("PEStatic", PE_TS, PE_TS)))
    assert a.classification is C.CLEAN and len(a.evidence) == 2 and a.contributing == ()


# ---------------- conflicts between engines and intel ----------------
def test_signature_vs_trusted_known_good_downgrades_for_review() -> None:
    a = assess(fr(res("ClamAV", CLAM_SIG), res("HashIntel", info=known_good("HIGH"))))
    assert a.classification is C.SUSPICIOUS and a.needs_review
    assert any("衝突" in n for n in a.notes)


def test_two_strong_engines_vs_known_good_stays_confirmed_but_reviewed() -> None:
    a = assess(fr(res("ClamAV", CLAM_SIG), res("YARA", YARA_CONFIRM), res("HashIntel", info=known_good("HIGH"))))
    assert a.classification is C.CONFIRMED_THREAT and a.needs_review and a.confidence == "高"


def test_low_trust_known_good_does_not_override() -> None:
    a = assess(fr(res("ClamAV", CLAM_SIG), res("HashIntel", info=known_good("LOW"))))
    assert a.classification is C.CONFIRMED_THREAT and not a.needs_review


def test_conflicting_hash_sources_downgrade_evidence() -> None:
    a = assess(fr(CLAM_OK, res("HashIntel", hash_bad("HIGH", conflict=True))))
    assert a.classification is C.SUSPICIOUS


def test_disagreement_between_detection_engines_is_reported() -> None:
    a = assess(fr(CLAM_OK, res("YARA", YARA_CONFIRM)))
    assert a.classification is C.CONFIRMED_THREAT
    assert any("不一致" in n and "ClamAV" in n for n in a.notes)


def test_strong_evidence_survives_other_engine_failure_but_notes_it() -> None:
    a = assess(fr(res("ClamAV", CLAM_SIG), res("YARA", kind=K.ERROR, error="timeout")))
    assert a.classification is C.CONFIRMED_THREAT
    assert any("未完成評估" in n for n in a.notes)


def test_weak_evidence_with_engine_failure_is_unknown_not_clean() -> None:
    a = assess(fr(res("ClamAV", kind=K.ERROR, error="crash"), res("PEStatic", PE_WX)))
    assert a.classification is C.UNKNOWN


def test_confidence_high_when_strong_and_independent_moderate() -> None:
    a = assess(fr(res("ClamAV", CLAM_SIG), res("YARA", YARA_MED)))
    assert a.confidence == "高"


def test_single_strong_is_medium_confidence() -> None:
    assert assess(fr(res("ClamAV", CLAM_SIG), YARA_OK)).confidence == "中"


# ---------------- false-positive suppression ----------------
def test_rule_suppression_removes_evidence_but_keeps_it_visible() -> None:
    s = Suppression(SHA, "Win.Trojan.X", "內部工具")
    a = assess(fr(res("ClamAV", CLAM_SIG), YARA_OK), [s])
    assert a.classification is C.CLEAN
    assert a.evidence[0].suppressed_by == s and "內部工具" in a.explanation


def test_hash_suppression_covers_all_rules_for_that_file_only() -> None:
    s = Suppression(SHA, None, "已確認誤判")
    a = assess(fr(res("ClamAV", CLAM_SIG), res("YARA", YARA_CONFIRM)), [s])
    assert a.classification is C.CLEAN
    other = Suppression("0" * 64, None, "別的檔案")
    assert assess(fr(res("ClamAV", CLAM_SIG)), [other]).classification is C.CONFIRMED_THREAT


def test_partial_suppression_leaves_remaining_evidence() -> None:
    s = Suppression(SHA, "Win.Trojan.X", "fp")
    a = assess(fr(res("ClamAV", CLAM_SIG), res("YARA", YARA_MED)), [s])
    assert a.classification is C.SUSPICIOUS


# ---------------- score is ordinal only ----------------
def test_score_orders_classes_and_is_not_probability() -> None:
    scores = [
        assess(fr(res("ClamAV", CLAM_SIG))).ordinal_score,
        assess(fr(res("ClamAV", CLAM_PUA))).ordinal_score,
        assess(fr(res("ClamAV", kind=K.ERROR, error="x"))).ordinal_score,
        assess(fr(CLAM_OK)).ordinal_score,
    ]
    assert scores == sorted(scores, reverse=True)
    assert all(0 <= s < 400 for s in scores)
    a = assess(fr(res("ClamAV", CLAM_SIG)))
    assert "機率" in a.explanation and "%" not in a.explanation


def test_every_classification_has_explanation() -> None:
    cases = [fr(CLAM_OK), fr(res("ClamAV", CLAM_PUA)), fr(res("ClamAV", CLAM_SIG)),
             fr(res("ClamAV", kind=K.ERROR, error="e"))]
    for f in cases:
        a = assess(f)
        assert a.explanation.startswith("分類：") and "判斷依據" in a.explanation

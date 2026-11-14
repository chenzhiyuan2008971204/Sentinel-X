"""Evidence-based risk assessment (pure logic, no I/O).

Every detection is first graded for reliability, then the grades are combined:

  Reliability of one piece of evidence
    STRONG    ClamAV signature match (not PUA / heuristic); hash listed MALICIOUS by a
              HIGH-trust source; YARA rule whose author marked it `confirming`;
              10 or more VirusTotal engines say malicious.
    MODERATE  ClamAV PUA / heuristic; MEDIUM-trust hash source; YARA rule of high or
              medium severity; 3-9 VirusTotal engines; HIGH-severity hit from an engine
              Sentinel X does not know.
    WEAK      PE structural anomalies (never more than weak); LOW-trust hash source;
              low-severity YARA rule; 1-2 VirusTotal engines (often false positives);
              anything else.
    INFO      INFO-severity records. Shown, never counted.
  A hash source that conflicts with another source listing the same hash as known-good is
  graded one level lower.

  Classification
    CONFIRMED_THREAT  at least one STRONG item, or MODERATE items from two or more
                      independent engines.
    SUSPICIOUS        at least one MODERATE item, or WEAK items from two or more
                      independent engines.
    UNKNOWN           none of the above, and the file was not fully assessed (an engine
                      failed, limits were hit, or it could not be read).
    CLEAN             none of the above, and every engine finished. This means "nothing
                      known was found by these engines", never "safe".
  So a single weak heuristic can never produce more than an observation, and a missing
  digital signature is not evidence at all (the PE engine records it as a fact).

  Conflicts
    A HIGH-trust known-good hash listing contradicting a CONFIRMED result lowers it to
    SUSPICIOUS for manual review, unless STRONG evidence comes from two or more engines.

  The ordinal score is only for sorting lists. It is not a probability.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from sentinelx.core.enums import Classification, EngineOutcomeKind, Severity
from sentinelx.core.models import DetectionRecord, FileResult

ASSESSOR_VERSION = "risk-rules-4"  # 2: VirusTotal (0.15.0); 3: sandbox (0.16.0); 4: VirusTotal not independent of ClamAV, higher bar alone (audit 8)
VT_STRONG_MIN = 25  # VirusTotal alone: at least this many engines and more than half of them

CLASS_TEXT = {
    Classification.CONFIRMED_THREAT: "確認威脅",
    Classification.SUSPICIOUS: "可疑",
    Classification.UNKNOWN: "未知",
    Classification.CLEAN: "未發現威脅",
}
SCORE_DISCLAIMER = "排序分數只用來排列清單，不是惡意程式的機率。"


class Reliability(StrEnum):
    STRONG = "STRONG"
    MODERATE = "MODERATE"
    WEAK = "WEAK"
    INFO = "INFO"


_REL_TEXT = {Reliability.STRONG: "強", Reliability.MODERATE: "中", Reliability.WEAK: "弱", Reliability.INFO: "資訊"}
_DOWNGRADE = {Reliability.STRONG: Reliability.MODERATE, Reliability.MODERATE: Reliability.WEAK,
              Reliability.WEAK: Reliability.WEAK, Reliability.INFO: Reliability.INFO}


@dataclass(frozen=True)
class Suppression:
    """A user false-positive decision: ignore `rule_id` (or every rule when None) for this hash."""

    sha256: str
    rule_id: str | None
    reason: str

    def matches(self, d: DetectionRecord) -> bool:
        return d.file_sha256 == self.sha256 and (self.rule_id is None or self.rule_id == d.rule_id)


@dataclass(frozen=True)
class EvidenceItem:
    index: int  # position in FileResult.detections (stable order: engines, then records)
    detection: DetectionRecord
    reliability: Reliability
    reason: str
    suppressed_by: Suppression | None = None

    @property
    def counts(self) -> bool:
        return self.suppressed_by is None and self.reliability is not Reliability.INFO


@dataclass(frozen=True)
class Assessment:
    classification: Classification
    ordinal_score: int
    confidence: str  # 高 / 中 / 低 / —  (qualitative, not a probability)
    explanation: str
    evidence: tuple[EvidenceItem, ...]
    needs_review: bool
    notes: tuple[str, ...]
    assessor_version: str = ASSESSOR_VERSION

    @property
    def contributing(self) -> tuple[EvidenceItem, ...]:
        return tuple(e for e in self.evidence if e.counts)


def grade(d: DetectionRecord) -> tuple[Reliability, str]:
    """Reliability of one detection, with the reason in zh-TW."""
    if d.severity_hint is Severity.INFO:
        return Reliability.INFO, "資訊等級，不列入判斷"
    eng = d.engine_name
    ev = d.evidence
    if eng == "ClamAV":
        if d.severity_hint is Severity.HIGH:
            return Reliability.STRONG, "ClamAV 病毒碼比對"
        if d.severity_hint is Severity.MEDIUM:
            return Reliability.MODERATE, "ClamAV 啟發式或 PUA 偵測"
        return Reliability.WEAK, "ClamAV 低等級偵測"
    if eng == "HashIntel":
        trust = str(ev.get("trust", "LOW"))
        rel = {"HIGH": Reliability.STRONG, "MEDIUM": Reliability.MODERATE}.get(trust, Reliability.WEAK)
        reason = f"雜湊完全相符，情報來源可信度 {trust}"
        if ev.get("conflict_with_known_good"):
            rel = _DOWNGRADE[rel]
            reason += "；另有來源列為已知良好，降低一級"
        return rel, reason
    if eng == "YARA":
        if ev.get("confirming"):
            return Reliability.STRONG, "YARA 規則作者標示為高可信度"
        if d.severity_hint in (Severity.HIGH, Severity.MEDIUM):
            return Reliability.MODERATE, f"YARA 規則（{d.severity_hint.value}）"
        return Reliability.WEAK, "低等級 YARA 規則"
    if eng == "PEStatic":
        return Reliability.WEAK, "PE 結構特徵，只能作為輔助證據"
    if eng == "Sandbox":
        strength = str(ev.get("strength", "weak"))
        rel = {"strong": Reliability.STRONG, "moderate": Reliability.MODERATE}.get(strength, Reliability.WEAK)
        return rel, "試跑室觀察到的行為"
    if eng == "VirusTotal":
        n, total = int(ev.get("malicious", 0) or 0), int(ev.get("engines_total", 0) or 0)
        # Engineering audit 8 (H2): grey software (cracks, game cheats, system tools, packed
        # programs) often reaches 10-20 detections. Alone, VirusTotal is strong only when a clear
        # majority of a large panel agrees.
        if n >= VT_STRONG_MIN and n * 2 > total:
            return Reliability.STRONG, f"VirusTotal：{total} 家防毒中 {n} 家判定惡意（過半數）"
        if n >= 10:
            return Reliability.MODERATE, f"VirusTotal：{total} 家防毒中 {n} 家判定惡意（未過半，可能是灰色軟體）"
        return Reliability.WEAK, f"VirusTotal：{total} 家防毒中只有 {n} 家判定惡意（常是誤判或灰色軟體）"
    if d.severity_hint is Severity.HIGH:
        return Reliability.MODERATE, f"未知引擎 {eng} 的高等級偵測（未經評等，視為中）"
    return Reliability.WEAK, f"未知引擎 {eng} 的偵測"


def _engines(items: Iterable[EvidenceItem]) -> set[str]:
    return {e.detection.engine_name for e in items}


# ClamAV is one of the engines VirusTotal reports, so the two do not confirm each other
# independently (engineering audit 8, H2).
_SAME_SOURCE = {"ClamAV": "ClamAV/VirusTotal", "VirusTotal": "ClamAV/VirusTotal"}


def _sources(items: Iterable[EvidenceItem]) -> set[str]:
    """Independent sources of evidence (engines that share verdicts count once)."""
    return {_SAME_SOURCE.get(e.detection.engine_name, e.detection.engine_name) for e in items}


def _trusted_known_good(fr: FileResult) -> list[str]:
    out = []
    for o in fr.outcomes:
        if o.engine_name != "HashIntel":
            continue
        for s in o.info.get("sources", []):
            if s.get("verdict") == "KNOWN_GOOD" and s.get("trust") == "HIGH":
                out.append(str(s.get("source")))
    return out


def assess(fr: FileResult, suppressions: Sequence[Suppression] = ()) -> Assessment:
    evidence: list[EvidenceItem] = []
    for i, d in enumerate(fr.detections):
        rel, reason = grade(d)
        sup = next((s for s in suppressions if s.matches(d)), None)
        evidence.append(EvidenceItem(i, d, rel, reason, sup))

    active = [e for e in evidence if e.counts]
    strong = [e for e in active if e.reliability is Reliability.STRONG]
    moderate = [e for e in active if e.reliability is Reliability.MODERATE]
    weak = [e for e in active if e.reliability is Reliability.WEAK]
    notes: list[str] = []
    needs_review = False

    if strong:
        cls = Classification.CONFIRMED_THREAT
        basis = f"有 {len(strong)} 項強證據"
    elif len(_sources(moderate)) >= 2:
        cls = Classification.CONFIRMED_THREAT
        basis = f"{len(_sources(moderate))} 個獨立來源的中等證據互相印證"
    elif moderate:
        cls = Classification.SUSPICIOUS
        basis = "有中等證據，但沒有其他引擎印證"
    elif len(_sources(weak)) >= 2:
        cls = Classification.SUSPICIOUS
        basis = f"{len(_sources(weak))} 個獨立來源各自發現弱特徵"
    elif not fr.assessed:
        cls = Classification.UNKNOWN
        basis = "檔案沒有完成評估：" + (fr.not_assessed_reason or _errors_text(fr))
    elif not _capable_clean(fr):
        cls = Classification.UNKNOWN
        basis = "沒有任何能偵測惡意程式的偵測引擎完成評估（只有結構分析或沒有惡意雜湊的情報），無法判斷"
    else:
        cls = Classification.CLEAN
        basis = "所有引擎都完成評估，沒有達到可疑門檻的證據"

    # Conflict with trusted known-good intelligence.
    good_sources = _trusted_known_good(fr)
    if good_sources and cls is Classification.CONFIRMED_THREAT:
        needs_review = True
        if len(_sources(strong)) >= 2:
            notes.append(f"衝突：高可信度來源 {', '.join(good_sources)} 將此雜湊列為已知良好，但兩個以上引擎有強證據，維持確認威脅並需人工審查。")
        else:
            cls = Classification.SUSPICIOUS
            notes.append(f"衝突：高可信度來源 {', '.join(good_sources)} 將此雜湊列為已知良好，與偵測結果矛盾，降為可疑並需人工審查。")

    # Independent engine comparison: which detection-capable engines saw nothing.
    hit_engines = _engines(active)
    silent = [o.engine_name for o in fr.outcomes
              if o.kind is EngineOutcomeKind.NO_FINDINGS and o.engine_name not in hit_engines
              and o.engine_name not in ("PEStatic", "HashIntel", "Sandbox")
              and not (o.engine_name == "VirusTotal" and not o.info.get("found"))]
    if hit_engines and silent:
        notes.append(f"引擎結果不一致：{'、'.join(sorted(hit_engines))} 有發現，但 {'、'.join(silent)} 沒有發現。")
    failed = [o.engine_name for o in fr.outcomes if o.kind is EngineOutcomeKind.ERROR]
    if failed and cls is not Classification.UNKNOWN:
        notes.append(f"部分引擎未完成評估（{'、'.join(failed)}），結果可能不完整。")

    suppressed = [e for e in evidence if e.suppressed_by is not None]
    if suppressed:
        notes.append(f"{len(suppressed)} 項證據因使用者標記為誤判而不列入判斷（證據仍保留）。")
    if cls is Classification.CLEAN and weak:
        notes.append(f"觀察到 {len(weak)} 項弱特徵，但只來自單一引擎，未達可疑門檻。")
    if cls is Classification.SUSPICIOUS:
        needs_review = True

    confidence = _confidence(cls, strong, moderate, fr)
    score = _score(cls, strong, moderate, weak)
    explanation = _explain(cls, basis, confidence, score, evidence, notes)
    return Assessment(cls, score, confidence, explanation, tuple(evidence), needs_review, tuple(notes))


def unassessed(reason: str) -> Assessment:
    """Assessment for a file no engine could look at (unreadable, over limits, cancelled)."""
    expl = _explain(Classification.UNKNOWN, f"檔案沒有完成評估：{reason}", "—", _score(Classification.UNKNOWN, [], [], []), [], [])
    return Assessment(Classification.UNKNOWN, _score(Classification.UNKNOWN, [], [], []), "—", expl, (), False, ())


CONTEXT_ENGINES = frozenset({"PEStatic", "HashIntel", "VirusTotal", "Sandbox"})


def _capable_clean(fr: FileResult) -> bool:
    """CLEAN needs a completed assessment by an engine that could have found something (B6).
    PE analysis never qualifies; hash intel only when it held malicious hashes. An engine whose
    findings were all marked false positive still examined the file, so FINDINGS counts too."""
    for o in fr.outcomes:
        if o.kind not in (EngineOutcomeKind.NO_FINDINGS, EngineOutcomeKind.FINDINGS):
            continue
        if o.engine_name not in CONTEXT_ENGINES:
            return True
        if o.engine_name in ("HashIntel", "VirusTotal") and o.info.get("detection_capable"):
            return True
    return False


def _errors_text(fr: FileResult) -> str:
    errs = [f"{o.engine_name}：{o.error}" for o in fr.outcomes if o.kind is EngineOutcomeKind.ERROR]
    return "；".join(errs) or "沒有引擎完成評估"


def _confidence(cls: Classification, strong: list[EvidenceItem], moderate: list[EvidenceItem], fr: FileResult) -> str:
    if cls is Classification.CONFIRMED_THREAT:
        corroborated = len(_sources(strong)) >= 2 or (strong and (_sources(moderate) - _sources(strong)))
        return "高" if corroborated else "中"
    if cls is Classification.SUSPICIOUS:
        return "中" if moderate else "低"
    if cls is Classification.CLEAN:
        capable_done = [o for o in fr.outcomes if o.kind is EngineOutcomeKind.NO_FINDINGS
                        and o.engine_name not in CONTEXT_ENGINES]
        return "中" if len(capable_done) >= 2 else "低"
    return "—"


def _score(cls: Classification, strong: list, moderate: list, weak: list) -> int:  # type: ignore[type-arg]
    base = {Classification.CONFIRMED_THREAT: 300, Classification.SUSPICIOUS: 200,
            Classification.UNKNOWN: 100, Classification.CLEAN: 0}[cls]
    return base + min(99, 20 * len(strong) + 8 * len(moderate) + 2 * len(weak))


def _explain(cls: Classification, basis: str, confidence: str, score: int,
             evidence: Sequence[EvidenceItem], notes: Sequence[str]) -> str:
    lines = [f"分類：{CLASS_TEXT[cls]}（{cls.value}）", f"判斷依據：{basis}。", f"信心：{confidence}"]
    if evidence:
        lines.append("證據：")
        for e in evidence:
            d = e.detection
            state = f"（已標記誤判：{e.suppressed_by.reason}）" if e.suppressed_by else ""
            lines.append(f"  - [{_REL_TEXT[e.reliability]}] {d.engine_name} {d.rule_id}：{e.reason}{state}")
    lines.extend(notes)
    if cls is Classification.CLEAN:
        lines.append("「未發現威脅」只代表這些引擎沒有找到已知的惡意特徵，不代表檔案一定安全。")
    lines.append(f"排序分數：{score}。{SCORE_DISCLAIMER}")
    return "\n".join(lines)

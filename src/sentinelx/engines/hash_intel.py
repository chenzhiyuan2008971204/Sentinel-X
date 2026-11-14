"""SHA-256 reputation against locally maintained intelligence.

Three distinct outcomes per file:
- listed as MALICIOUS in at least one source  -> FINDINGS (severity follows source trust)
- listed only as KNOWN_GOOD                   -> NO_FINDINGS, info.reputation = KNOWN_GOOD
- not listed anywhere                         -> NO_FINDINGS, info.reputation = UNKNOWN
Conflicting sources (malicious and known-good) are reported as findings with the conflict
recorded in evidence; resolving it is the risk engine's job (Phase 4).
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind, IntelVerdict, Severity, TrustLevel
from sentinelx.core.models import DetectionRecord, DetectionResult, EngineStatus, ScanTarget
from sentinelx.storage.intel_repository import IntelMatch, IntelStore

ENGINE_NAME = "HashIntel"
ENGINE_VERSION = "1.0"
_TRUST_SEVERITY = {TrustLevel.HIGH: Severity.HIGH, TrustLevel.MEDIUM: Severity.MEDIUM, TrustLevel.LOW: Severity.LOW}
_TRUST_TEXT = {TrustLevel.HIGH: "高", TrustLevel.MEDIUM: "中", TrustLevel.LOW: "低"}


class HashIntelEngine:
    name = ENGINE_NAME

    def __init__(self, store: IntelStore) -> None:
        self._store = store

    def availability(self, refresh: bool = False) -> EngineStatus:
        # Always available (an empty intel set yields UNKNOWN), but it can only *detect*
        # something once at least one MALICIOUS hash has been imported.
        stamp = self._store.stamp()
        n_bad = self._store.malicious_count()
        detail = f"本機雜湊情報：{stamp}" + ("" if n_bad else "（沒有惡意雜湊，只能提供信譽資訊）")
        return EngineStatus(ENGINE_NAME, True, version=ENGINE_VERSION, rules_version=stamp,
                            detail=detail, detection_capable=n_bad > 0)

    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken) -> dict[ScanTarget, DetectionResult]:
        cancel.raise_if_cancelled()
        started = time.monotonic()
        stamp = self._store.stamp()
        capable = self._store.malicious_count() > 0
        matches = self._store.lookup_many(t.sha256 for t in targets)
        ms = int((time.monotonic() - started) * 1000)
        out: dict[ScanTarget, DetectionResult] = {}
        for t in targets:
            hits = matches.get(t.sha256, [])
            bad = [m for m in hits if m.verdict is IntelVerdict.MALICIOUS]
            good = [m for m in hits if m.verdict is IntelVerdict.KNOWN_GOOD]
            reputation = "MALICIOUS" if bad else ("KNOWN_GOOD" if good else "UNKNOWN")
            info = {
                "reputation": reputation,
                "detection_capable": capable,  # "no match" only means something if bad hashes exist
                "sources": [{"source": m.source, "verdict": m.verdict.value, "trust": m.trust.value} for m in hits],
            }
            base = dict(engine_name=ENGINE_NAME, engine_version=ENGINE_VERSION, rules_version=stamp,
                        duration_ms=ms, info=info)
            if not bad:
                out[t] = DetectionResult(kind=EngineOutcomeKind.NO_FINDINGS, **base)
                continue
            dets = tuple(self._detection(m, t, conflict=bool(good)) for m in bad)
            out[t] = DetectionResult(kind=EngineOutcomeKind.FINDINGS, detections=dets, **base)
        return out

    @staticmethod
    def _detection(m: IntelMatch, t: ScanTarget, *, conflict: bool) -> DetectionRecord:
        text = (
            f"此 SHA-256 列在本機威脅情報「{m.source}」中，標記為惡意"
            + (f"（{m.label}）" if m.label else "")
            + f"。來源可信度：{_TRUST_TEXT[m.trust]}。雜湊完全相符代表是同一個檔案，但判斷正確與否取決於情報來源。"
            + ("注意：另有來源將此雜湊標記為已知良好，結果互相矛盾。" if conflict else "")
        )
        return DetectionRecord(
            engine_name=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            rule_id=f"HashIntel.{m.source}",
            severity_hint=_TRUST_SEVERITY[m.trust],
            evidence={"source": m.source, "source_version": m.source_version, "trust": m.trust.value,
                      "label": m.label, "sha256": m.sha256, "conflict_with_known_good": conflict},
            file_sha256=t.sha256,
            confidence_explanation=text,
        )

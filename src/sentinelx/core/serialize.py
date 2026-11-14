"""JSON-safe conversion of engine results (worker process boundary, reports).

Plain dicts only: the isolated worker sends JSON, never pickles, so a compromised parser
process cannot hand the GUI process an object to execute.
"""

from __future__ import annotations

from typing import Any

from sentinelx.core.enums import EngineOutcomeKind, Severity
from sentinelx.core.models import DetectionRecord, DetectionResult


def detection_to_dict(d: DetectionRecord) -> dict[str, Any]:
    return {
        "engine_name": d.engine_name, "engine_version": d.engine_version, "rule_id": d.rule_id,
        "severity_hint": d.severity_hint.value, "evidence": d.evidence, "file_sha256": d.file_sha256,
        "confidence_explanation": d.confidence_explanation, "timestamp": d.timestamp,
    }


def detection_from_dict(d: dict[str, Any]) -> DetectionRecord:
    return DetectionRecord(
        str(d["engine_name"]), d.get("engine_version"), str(d["rule_id"]), Severity(d["severity_hint"]),
        dict(d.get("evidence") or {}), str(d["file_sha256"]), str(d.get("confidence_explanation", "")),
        str(d.get("timestamp", "")),
    )


def result_to_dict(r: DetectionResult) -> dict[str, Any]:
    return {
        "engine_name": r.engine_name, "kind": r.kind.value, "engine_version": r.engine_version,
        "rules_version": r.rules_version, "detections": [detection_to_dict(d) for d in r.detections],
        "error": r.error, "duration_ms": r.duration_ms, "info": r.info,
    }


def result_from_dict(d: dict[str, Any]) -> DetectionResult:
    return DetectionResult(
        str(d["engine_name"]), EngineOutcomeKind(d["kind"]), d.get("engine_version"), d.get("rules_version"),
        tuple(detection_from_dict(x) for x in d.get("detections", [])), d.get("error"), d.get("duration_ms"),
        dict(d.get("info") or {}),
    )

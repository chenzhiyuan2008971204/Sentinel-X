"""Standalone YARA engine (yara-python / libyara, in-process).

- Rules come from the RuleSetStore (validated, hash-pinned copies). Each set is compiled
  into its own namespace, so rule ids are `<namespace>.<rule>`.
- Files are matched from memory (bounded by the scan size limit) instead of by path, which
  avoids libyara's non-ASCII path handling on Windows.
- Rule meta `severity` (info/low/medium/high/critical) or a YARA Forge `score` sets the severity hint (default medium);
  meta `confirming = true` marks a rule the author considers high-reliability (used by the
  risk engine in Phase 4). Matched string identifiers and offsets are recorded, not the bytes.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Sequence
from typing import Any

import yara

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind, Severity
from sentinelx.core.models import DetectionRecord, DetectionResult, EngineStatus, ScanTarget
from sentinelx.storage.rules_repository import RuleSetRow, RuleSetStore, namespace_for

ENGINE_NAME = "YARA"
_SEVERITY = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH}
MAX_STRINGS = 10


def rule_severity(meta: dict[str, str]) -> Severity:
    """Severity from rule meta: `severity` (info/low/medium/high/critical) first, then a numeric
    `score` 0-100 as used by YARA Forge (80+ high, 60+ medium, 40+ low, below that info),
    otherwise medium."""
    sev = meta.get("severity", "").strip().lower()
    if sev == "critical":
        return Severity.HIGH
    if sev in _SEVERITY:
        return _SEVERITY[sev]
    try:
        score = int(float(meta.get("score", "")))
    except ValueError:
        return Severity.MEDIUM
    if score >= 80:
        return Severity.HIGH
    if score >= 60:
        return Severity.MEDIUM
    if score >= 40:
        return Severity.LOW
    return Severity.INFO
MAX_OFFSETS = 5


def _meta_str(v: Any) -> str:
    return v if isinstance(v, str) else str(v)


class YaraEngine:
    name = ENGINE_NAME

    def __init__(self, store: RuleSetStore, *, timeout_s: int = 60, max_file_size_mb: int = 100) -> None:
        self._store = store
        self._timeout = timeout_s
        self._max_bytes = max_file_size_mb * 1024 * 1024
        self._lock = threading.Lock()
        self._compiled: yara.Rules | None = None
        self._sets: list[RuleSetRow] = []
        self._status: EngineStatus | None = None

    def _rules_version(self) -> str:
        return ";".join(f"{r.name}@{r.version}" for r in self._sets)

    def availability(self, refresh: bool = False) -> EngineStatus:
        with self._lock:
            if self._status is not None and not refresh:
                return self._status
            self._status = self._load()
            return self._status

    def _load(self) -> EngineStatus:
        loaded, problems = self._store.load_enabled()
        self._sets, self._compiled = [], None
        note = ("；".join(problems)) if problems else ""
        if not loaded:
            msg = "沒有啟用的 YARA 規則集。請在「威脅情報」頁面加入規則。"
            return EngineStatus(ENGINE_NAME, False, version=yara.YARA_VERSION, detail=f"{msg}{' ' + note if note else ''}")
        try:
            self._compiled = yara.compile(
                sources={namespace_for(r.name): src for r, src in loaded}, includes=False
            )
        except yara.Error as exc:
            return EngineStatus(ENGINE_NAME, False, version=yara.YARA_VERSION, detail=f"YARA 規則編譯失敗：{exc}")
        sets = [r for r, _ in loaded]
        self._sets = sets
        return EngineStatus(
            ENGINE_NAME, True, version=yara.YARA_VERSION, rules_version=self._rules_version(),
            detail=f"{len(sets)} 個規則集，{sum(r.rule_count for r in sets)} 條規則" + (f"；{note}" if note else ""),
        )

    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken) -> dict[ScanTarget, DetectionResult]:
        with self._lock:  # consistent snapshot: rules may be reloaded from the GUI thread meanwhile
            st = self._status if self._status is not None else self._load()
            self._status = st
            rules, sets = self._compiled, list(self._sets)
        out: dict[ScanTarget, DetectionResult] = {}
        for t in targets:
            cancel.raise_if_cancelled()
            base: dict[str, Any] = dict(engine_name=ENGINE_NAME, engine_version=st.version, rules_version=st.rules_version)
            if not st.available or rules is None:
                out[t] = DetectionResult(kind=EngineOutcomeKind.ERROR, error=st.detail, **base)
                continue
            if t.size > self._max_bytes:
                out[t] = DetectionResult(kind=EngineOutcomeKind.ERROR, error="檔案超過 YARA 掃描大小上限", **base)
                continue
            started = time.monotonic()
            try:
                data = t.path.read_bytes()
                matches = rules.match(data=data, timeout=self._timeout)
            except OSError as exc:
                out[t] = DetectionResult(kind=EngineOutcomeKind.ERROR, error=f"無法讀取檔案：{exc.strerror or exc}", **base)
                continue
            except yara.TimeoutError:
                out[t] = DetectionResult(kind=EngineOutcomeKind.ERROR, error=f"YARA 比對逾時（{self._timeout} 秒）", **base)
                continue
            except yara.Error as exc:
                out[t] = DetectionResult(kind=EngineOutcomeKind.ERROR, error=f"YARA 比對失敗：{exc}", **base)
                continue
            ms = int((time.monotonic() - started) * 1000)
            dets = tuple(self._detection(m, t, sets) for m in matches)
            kind = EngineOutcomeKind.FINDINGS if dets else EngineOutcomeKind.NO_FINDINGS
            out[t] = DetectionResult(kind=kind, detections=dets, duration_ms=ms,
                                     info={"rule_sets": [f"{r.name}@{r.version}" for r in sets]}, **base)
        return out

    @staticmethod
    def _detection(m: Any, t: ScanTarget, sets: list[RuleSetRow]) -> DetectionRecord:
        meta = {k: _meta_str(v) for k, v in (m.meta or {}).items()}
        severity = rule_severity(meta)
        confirming = meta.get("confirming", "").lower() in ("true", "1", "yes")
        rule_set = next((r for r in sets if namespace_for(r.name) == m.namespace), None)
        strings = [
            {"id": s.identifier, "offsets": [i.offset for i in s.instances[:MAX_OFFSETS]], "count": len(s.instances)}
            for s in list(m.strings)[:MAX_STRINGS]
        ]
        desc = meta.get("description", "")
        explanation = (
            f"YARA 規則 {m.namespace}.{m.rule} 命中"
            f"（規則集 {rule_set.name if rule_set else m.namespace} {rule_set.version if rule_set else ''}）。"
            + (f"{desc}。" if desc else "")
            + ("規則作者標示為高可信度。" if confirming else "YARA 規則的可靠度取決於規則品質，需搭配其他證據判斷。")
        )
        return DetectionRecord(
            engine_name=ENGINE_NAME,
            engine_version=yara.YARA_VERSION,
            rule_id=f"{m.namespace}.{m.rule}",
            severity_hint=severity,
            evidence={
                "rule": m.rule, "namespace": m.namespace, "tags": list(m.tags), "meta": meta,
                "strings": strings, "confirming": confirming,
                "rule_set": rule_set.name if rule_set else None,
                "rule_set_version": rule_set.version if rule_set else None,
            },
            file_sha256=t.sha256,
            confidence_explanation=explanation,
        )

"""Research Lab use cases. Read-only analysis of user-selected files; nothing is executed.

The lab never creates or changes a verdict: it shows facts, stored evidence and history,
and test YARA rules that are not registered for scanning.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import AuditActor, ReportKind
from sentinelx.core.models import DetectionResult
from sentinelx.core.serialize import result_from_dict
from sentinelx.core.timeutil import utc_now_iso
from sentinelx.engines.authenticode import SignatureDetail
from sentinelx.reporting.builders import comparison_report, sample_report
from sentinelx.research import compare as cmp_mod
from sentinelx.research import yara_lab
from sentinelx.research.isolation import WorkerResult, check_yara_compile, run_worker
from sentinelx.research.sample import FileFacts, file_facts
from sentinelx.services.report_service import GenerateResult, ReportService
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.intel_repository import IntelMatch, IntelStore
from sentinelx.storage.research_repository import (
    EvidenceRun,
    ResearchRepository,
    StoredVerdict,
    TimelineEvent,
    normalize_sha,
)

WorkerRunner = Callable[..., WorkerResult]


@dataclass(frozen=True)
class SampleInspection:
    facts: FileFacts
    pe: DetectionResult | None
    signature: SignatureDetail | None
    worker_error: str | None
    worker_confined: bool
    worker_ms: int
    sha_changed: bool  # the worker read different content than was hashed (file changed meanwhile)
    inspected_at: str


@dataclass(frozen=True)
class HashLookup:
    sha256: str
    intel: tuple[IntelMatch, ...]
    latest: tuple[str, StoredVerdict] | None  # (path, verdict)
    stored_runs: int


class LabService:
    def __init__(self, limits: ScanLimits, intel: IntelStore, research: ResearchRepository, audit: AuditLog,
                 reports: ReportService, *, worker: WorkerRunner = run_worker,
                 yara_compile_check: Callable[..., WorkerResult] = check_yara_compile) -> None:
        self._limits = limits
        self._intel = intel
        self._research = research
        self._audit = audit
        self._reports = reports
        self._worker = worker
        self._yara_compile_check = yara_compile_check

    @property
    def max_bytes(self) -> int:
        return self._limits.max_file_size_mb * 1024 * 1024

    # ---- sample ----
    def inspect(self, path: Path, cancel: CancelToken | None = None) -> SampleInspection:
        cancel = cancel or CancelToken()
        facts = file_facts(path, self.max_bytes, cancel)
        res = self._worker(path, self.max_bytes, timeout_s=float(self._limits.engine_timeout_s), cancel=cancel)
        pe = sig = None
        changed = False
        if res.ok:
            pe = result_from_dict(res.data["pe"])
            sig = SignatureDetail.from_dict(res.data["signature"])
            changed = res.data.get("sha256") != facts.sha256
        insp = SampleInspection(facts, pe, sig, res.error, res.confined, res.duration_ms, changed, utc_now_iso())
        self._audit.record("LAB_INSPECT", actor=AuditActor.USER, subject=str(path),
                           detail={"sha256": facts.sha256, "worker_ok": res.ok, "confined": res.confined})
        return insp

    def lookup(self, sha256: str) -> HashLookup:
        sha = normalize_sha(sha256)
        return HashLookup(sha, tuple(self._intel.lookup_many([sha])[sha]), self._research.latest_verdict(sha),
                          len(self._research.evidence_for_sha(sha)))

    def evidence(self, sha256: str) -> list[EvidenceRun]:
        return self._research.evidence_for_sha(sha256)

    def timeline(self, sha256: str) -> list[TimelineEvent]:
        return self._research.timeline_for_sha(sha256)

    # ---- YARA ----
    def yara_test(self, source: str, targets: Sequence[Path], cancel: CancelToken | None = None) -> yara_lab.YaraTestRun:
        if len(source.encode("utf-8")) > yara_lab.MAX_RULE_BYTES:
            raise ValueError("規則內容超過 1 MB。")
        # Compile once in the confined worker first: a rule that takes too long to compile is
        # stopped there (time limit, cancel) instead of blocking this process (audit R12).
        check = self._yara_compile_check(source, timeout_s=self._limits.yara_timeout_s, cancel=cancel)
        if not check.ok:
            raise ValueError(f"規則編譯失敗：{check.error}")
        run = yara_lab.run_test(source, targets, max_bytes=self.max_bytes, timeout_s=self._limits.yara_timeout_s,
                                cancel=cancel)
        self._audit.record("YARA_TEST", actor=AuditActor.USER, subject=f"{len(run.results)} 個檔案",
                           detail={"rule_sha256": run.rule_sha256, "rules": run.rule_count, "matched": run.matched,
                                   "targets": [r.sha256 for r in run.results if r.sha256][:50]})
        return run

    # ---- comparison ----
    def compare(self, a: Path, b: Path, cancel: CancelToken | None = None
                ) -> tuple[cmp_mod.Comparison, SampleInspection, SampleInspection]:
        cancel = cancel or CancelToken()
        ia = self.inspect(a, cancel)
        ib = self.inspect(b, cancel)
        bd = cmp_mod.byte_diff(a, b, cancel)
        notes: list[str] = []
        pe = None
        if ia.pe is not None and ib.pe is not None and ia.pe.info.get("is_pe") and ib.pe.info.get("is_pe"):
            pe = cmp_mod.pe_diff(ia.pe.info, ib.pe.info)
        for label, insp in (("A", ia), ("B", ib)):
            if insp.worker_error:
                notes.append(f"檔案 {label} 的結構分析失敗：{insp.worker_error}")
        result = cmp_mod.Comparison(a, b, ia.facts.sha256, ib.facts.sha256, bd, pe, tuple(notes))
        self._audit.record("LAB_COMPARE", actor=AuditActor.USER, subject=f"{a} ↔ {b}",
                           detail={"sha256_a": ia.facts.sha256, "sha256_b": ib.facts.sha256,
                                   "identical": result.identical})
        return result, ia, ib

    # ---- reports ----
    def sample_document(self, sha256: str, inspection: SampleInspection | None,
                        yara_runs: Sequence[yara_lab.YaraTestRun] = ()) -> dict[str, Any]:
        sha = normalize_sha(sha256)
        if inspection is not None and inspection.facts.sha256 != sha:
            raise ValueError("檢視結果與 SHA-256 不一致。")
        runs = [r for r in yara_runs if any(t.sha256 == sha for t in r.results)]
        return sample_report(self.lookup(sha), inspection, self.evidence(sha), self.timeline(sha), runs,
                             self._reports.tool_versions())

    def export_sample(self, sha256: str, inspection: SampleInspection | None,
                      yara_runs: Sequence[yara_lab.YaraTestRun], kinds: Sequence[ReportKind]) -> GenerateResult:
        return self._reports.generate(self.sample_document(sha256, inspection, yara_runs), kinds)

    def export_comparison(self, comparison: cmp_mod.Comparison, a: SampleInspection | None,
                          b: SampleInspection | None, kinds: Sequence[ReportKind]) -> GenerateResult:
        return self._reports.generate(comparison_report(comparison, a, b, self._reports.tool_versions()), kinds)

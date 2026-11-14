"""Threat Center use cases: list verdicts, manual review, false-positive management.

Review decisions:
  CONFIRM                 human confirms the threat -> new verdict CONFIRMED_THREAT
                          (explanation records that it was a human decision).
  DISMISS_FALSE_POSITIVE  adds suppressions (for the contributing rules, or the whole file)
                          and re-assesses from the stored engine results -> new verdict.
  ESCALATE                recorded only; the verdict stays open for review.
Every decision needs a reason and is audit-logged. Evidence is never deleted.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Literal

from sentinelx.core.enums import AuditActor, Classification, ReviewDecision
from sentinelx.core.risk import Assessment, assess, unassessed
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.verdict_repository import SuppressionRow, ThreatRow, VerdictDetail, VerdictRepository

Scope = Literal["rules", "file"]


class ReviewService:
    def __init__(self, repo: VerdictRepository, audit: AuditLog) -> None:
        self._repo = repo
        self._audit = audit

    def threats(self, include_resolved: bool = False) -> list[ThreatRow]:
        return self._repo.threats(include_resolved)

    def detail(self, verdict_id: int) -> VerdictDetail | None:
        return self._repo.detail(verdict_id)

    def attention_counts(self) -> tuple[int, int]:
        return self._repo.attention_counts()

    def class_counts(self) -> dict[Classification, int]:
        return self._repo.class_counts()

    def suppressions(self) -> list[SuppressionRow]:
        return self._repo.list_suppressions()

    def review(self, verdict_id: int, decision: ReviewDecision, reason: str, scope: Scope = "rules") -> int:
        """Record a decision. Returns the id of the verdict that is now current for the file."""
        reason = reason.strip()
        if not reason:
            raise ValueError("請填寫審查原因。")
        row = self._repo.get(verdict_id)
        if row is None:
            raise ValueError("找不到這個判定。")
        if not self._repo.is_latest(verdict_id):
            raise ValueError("這個判定已被較新的判定取代，請重新整理後再審查。")

        review_id = self._repo.add_review(verdict_id, decision, reason)
        self._audit.record(f"REVIEW_{decision.value}", actor=AuditActor.USER, subject=row.path,
                           detail={"verdict_id": verdict_id, "sha256": row.sha256, "reason": reason, "scope": scope})

        if decision is ReviewDecision.ESCALATE:
            return verdict_id

        if decision is ReviewDecision.DISMISS_FALSE_POSITIVE:
            if not row.sha256:
                raise ValueError("檔案沒有 SHA-256，無法建立誤判排除。")
            detail = self._repo.detail(verdict_id)
            rules = sorted({d.rule_id for r in (detail.results if detail else ()) for d in r.detections})
            if scope == "file" or not rules:
                self._repo.add_suppression(row.sha256, None, reason, review_id)
            else:
                for rule in rules:
                    self._repo.add_suppression(row.sha256, rule, reason, review_id)
            current = self._reassess(row.file_id)
            # Every other copy of the same content too (an earlier download, the quarantined
            # original): otherwise their old "confirmed threat" verdict keeps the hash on the
            # process guard's list and the program is closed whenever it starts.
            for file_id in self._repo.files_with_sha(row.sha256):
                if file_id != row.file_id:
                    try:
                        self._reassess(file_id)
                    except ValueError:
                        pass  # a copy without stored engine results keeps its verdict
            return current

        # CONFIRM
        return self._reassess(row.file_id, confirmed_by_user=reason)

    def dismiss_whole_file(self, verdict_id: int, reason: str) -> int:
        """Mark the file of this (possibly older) verdict as a false positive, whole file. Used when
        the user restores a file from the quarantine and says it is safe: the same content is then
        no longer quarantined, locked or stopped, wherever it appears again."""
        row = self._repo.get(verdict_id)
        latest = self._repo.latest_for_file(row.file_id) if row is not None else None
        if latest is None:
            raise ValueError("找不到這個檔案的判定，無法標記為誤判。")
        return self.review(latest, ReviewDecision.DISMISS_FALSE_POSITIVE, reason, scope="file")

    def remove_suppression(self, suppression_id: int) -> bool:
        row = self._repo.deactivate_suppression(suppression_id)
        if row is None:
            return False
        self._audit.record("FP_SUPPRESSION_REMOVE", actor=AuditActor.USER, subject=row.sha256,
                           detail={"rule_id": row.rule_id, "reason": row.reason})
        for file_id in self._repo.files_with_sha(row.sha256):
            self._reassess(file_id)
        return True

    def _reassess(self, file_id: int, confirmed_by_user: str | None = None) -> int:
        fr, ids = self._repo.load_latest_result(file_id)
        if fr is None:
            raise ValueError("找不到這個檔案的掃描結果。")
        a: Assessment = (assess(fr, self._repo.active_suppressions()) if fr.outcomes
                         else unassessed(fr.not_assessed_reason or "未掃描"))
        if confirmed_by_user is not None:
            a = replace(
                a,
                classification=Classification.CONFIRMED_THREAT,
                confidence="人工確認",
                needs_review=False,
                ordinal_score=max(a.ordinal_score, 300),
                explanation=f"由使用者人工確認為威脅（原因：{confirmed_by_user}）。\n"
                            f"以下為引擎證據的自動評估（人工確認前）：\n{a.explanation}",
            )
        return self._repo.add_verdict(file_id, a, ids)

"""Quarantine use cases. Every state-changing call requires `confirmed=True`, which the GUI
only passes after an explicit confirmation dialog that shows the file and destination."""

from __future__ import annotations

from pathlib import Path

from sentinelx.core.enums import Classification
from sentinelx.quarantine.vault import QItem, QuarantineVault
from sentinelx.quarantine.win32fs import QuarantineError
from sentinelx.storage.verdict_repository import VerdictRepository


class QuarantineService:
    def __init__(self, vault: QuarantineVault, verdicts: VerdictRepository) -> None:
        self._vault = vault
        self._verdicts = verdicts

    @property
    def ready(self) -> bool:
        return self._vault.ready

    @property
    def problem(self) -> str:
        return self._vault.problem

    def items(self) -> list[QItem]:
        return self._vault.items()

    def is_quarantined(self, sha256: str | None, path: str) -> bool:
        return bool(sha256) and self._vault.active_for(sha256 or "", path) is not None

    def quarantine_verdict(self, verdict_id: int, reason: str, *, confirmed: bool) -> QItem:
        """Quarantine the file of a CONFIRMED_THREAT verdict (latest verdict only)."""
        if not confirmed:
            raise QuarantineError("not confirmed", user_message="隔離需要使用者明確確認。")
        reason = reason.strip()
        if not reason:
            raise QuarantineError("no reason", user_message="請填寫隔離原因。")
        row = self._verdicts.get(verdict_id)
        if row is None:
            raise QuarantineError("no verdict", user_message="找不到這個判定。")
        if not self._verdicts.is_latest(verdict_id):
            raise QuarantineError("stale verdict", user_message="這個判定已被較新的判定取代，請重新整理。")
        if row.classification is not Classification.CONFIRMED_THREAT:
            raise QuarantineError("not confirmed threat",
                                  user_message="只有判定為「確認威脅」的檔案可以隔離；可疑檔案請先人工審查。")
        if not row.sha256:
            raise QuarantineError("no hash", user_message="檔案沒有 SHA-256，無法隔離。")
        return self._vault.quarantine(Path(row.path), row.sha256, verdict_id=verdict_id, reason=reason)

    def verify(self, item_id: int) -> tuple[bool, str]:
        return self._vault.verify(item_id)

    def delete(self, item_id: int, reason: str = "使用者從隔離區永久刪除", *, confirmed: bool) -> QItem:
        """Permanently delete a quarantined file. Requires the user's explicit confirmation."""
        if not confirmed:
            raise QuarantineError("not confirmed", user_message="永久刪除需要使用者明確確認。")
        return self._vault.delete(item_id, reason.strip() or "使用者從隔離區永久刪除")

    def restore(self, item_id: int, target: Path | None = None, *, confirmed: bool) -> QItem:
        if not confirmed:
            raise QuarantineError("not confirmed", user_message="還原需要使用者明確確認。")
        return self._vault.restore(item_id, target)

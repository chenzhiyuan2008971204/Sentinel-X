"""Quarantine page: list vault items, verify integrity, restore with explicit confirmation.

There is deliberately no "delete permanently" action.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from sentinelx.core.enums import QuarantineStatus
from sentinelx.gui import theme
from sentinelx.gui.confirm import Confirm, ask
from sentinelx.gui.widgets import BusyBar, item, muted, table, title
from sentinelx.gui.workers import TaskRunner
from sentinelx.quarantine.win32fs import QuarantineError
from sentinelx.services.quarantine_service import QuarantineService

STATUS_TEXT = {
    QuarantineStatus.QUARANTINED: ("隔離中", theme.WARN),
    QuarantineStatus.RESTORED: ("已還原", theme.TEXT_MUTED),
    QuarantineStatus.RETAINED_ERROR: ("原檔未移除", theme.BAD),
    QuarantineStatus.DELETED: ("已永久刪除", theme.TEXT_MUTED),
}


class QuarantinePage(QWidget):
    def __init__(self, service: QuarantineService, confirm: Confirm = ask,
                 mark_safe: Callable[[int, str], object] | None = None) -> None:
        super().__init__()
        self.setObjectName("page_quarantine")
        self._svc = service
        self._mark_safe = mark_safe  # (verdict id, reason): whole-file false positive
        self.confirm = confirm
        self.runner = TaskRunner(self)
        self.runner.busy_changed.connect(lambda _b: self._update_buttons())
        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(12)
        lay.addWidget(title(self.tr("隔離區")))
        lay.addWidget(muted(self.tr(
            "被關在這裡的檔案不能執行，也不會造成危害。確定是誤判可以「還原」；確定不要了可以「永久刪除」。"
            "Sentinel X 不會自己刪除任何檔案，只有你按下並確認才會刪除。")))
        self.vault_status = QLabel()
        self.vault_status.setTextFormat(Qt.TextFormat.PlainText)
        self.vault_status.setWordWrap(True)
        lay.addWidget(self.vault_status)
        self.table = table(["#", "狀態", "隔離時間 (UTC)", "原始路徑", "SHA-256", "大小", "原因", "說明"])
        lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.verify_button = QPushButton(self.tr("驗證完整性"))
        self.restore_button = QPushButton(self.tr("還原到原位置…"))
        self.restore_to_button = QPushButton(self.tr("還原到其他位置…"))
        self.delete_button = QPushButton(self.tr("永久刪除…"))
        self.delete_button.setObjectName("danger")
        self.delete_button.clicked.connect(self.delete_selected)
        self.refresh_button = QPushButton(self.tr("重新整理"))
        self.verify_button.clicked.connect(self.verify_selected)
        self.restore_button.clicked.connect(lambda: self.restore_selected(None))
        self.restore_to_button.clicked.connect(self._restore_elsewhere)
        self.refresh_button.clicked.connect(self.refresh)
        for b in (self.verify_button, self.restore_button, self.restore_to_button, self.delete_button):
            row.addWidget(b)
        row.addStretch(1)
        row.addWidget(self.refresh_button)
        lay.addLayout(row)
        self.busy_bar = BusyBar(self.runner)
        lay.addWidget(self.busy_bar)
        self.msg = QLabel()
        self.msg.setWordWrap(True)
        self.msg.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.msg)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.refresh()

    def refresh(self) -> None:
        if self._svc.ready:
            self.vault_status.setText(self.tr("隔離區正常：權限已限制為只有目前使用者。"))
            self.vault_status.setStyleSheet(f"color: {theme.OK};")
        else:
            self.vault_status.setText(self.tr("隔離區無法使用：{0}").format(self._svc.problem))
            self.vault_status.setStyleSheet(f"color: {theme.BAD};")
        rows = self._svc.items()
        self.table.clearSelection()
        self.table.setRowCount(len(rows))
        for i, q in enumerate(rows):
            st, color = STATUS_TEXT[q.status]
            note = q.error_detail or (f"已還原到 {q.restore_target}" if q.restore_target else "")
            if q.deleted_at:
                note = (note + "；" if note else "") + f"於 {q.deleted_at} 永久刪除"
            if q.duplicate_of:
                note = (note + "；" if note else "") + f"與 #{q.duplicate_of} 內容相同"
            vals = [str(q.id), st, q.quarantined_at, q.original_path, q.sha256, f"{q.size:,}", q.reason or "", note]
            for c, v in enumerate(vals):
                self.table.setItem(i, c, item(v, color if c == 1 else None))
        self._update_buttons()

    def _selected(self):  # type: ignore[no-untyped-def]
        row = self.table.currentRow()
        if row < 0 or not self.table.selectedItems():
            return None
        item_id = int(self.table.item(row, 0).text())
        return next((q for q in self._svc.items() if q.id == item_id), None)

    def _update_buttons(self) -> None:
        q = self._selected()
        idle = not self.runner.busy
        active = idle and q is not None and q.status is QuarantineStatus.QUARANTINED
        self.restore_button.setEnabled(active)
        self.delete_button.setEnabled(active)
        self.restore_to_button.setEnabled(active)
        self.verify_button.setEnabled(idle and q is not None
                                      and q.status not in (QuarantineStatus.RESTORED, QuarantineStatus.DELETED))
        self.refresh_button.setEnabled(idle)

    @property
    def busy(self) -> bool:
        return self.runner.busy

    def shutdown(self) -> None:
        self.runner.shutdown()

    def verify_selected(self) -> None:
        q = self._selected()
        if q is None:
            return
        qid, svc = q.id, self._svc

        def done(res: object) -> None:
            ok, text = res  # type: ignore[misc]
            self._msg(text, theme.OK if ok else theme.BAD)

        self.runner.run(lambda _c: svc.verify(qid), done, lambda m: self._msg(m, theme.BAD),
                        self.tr("驗證中…（重新計算 SHA-256）"), cancellable=False)

    def _restore_elsewhere(self) -> None:
        q = self._selected()
        if q is None:
            return
        f, _ = QFileDialog.getSaveFileName(self, self.tr("還原到…"), str(Path(q.original_path).name))
        if f:
            self.restore_selected(Path(f))

    def restore_selected(self, target: Path | None) -> None:
        q = self._selected()
        if q is None:
            return
        dest = str(target) if target else q.original_path
        message = self.tr(
            "確定要還原這個被判定為威脅的檔案嗎？\n\n檔案：{0}\nSHA-256：{1}\n還原到：{2}\n\n"
            "還原後檔案可以被執行。只有在確定它是誤判時才還原。").format(q.original_path, q.sha256, dest)
        if not self.confirm(self, self.tr("確認還原"), message):
            self._msg(self.tr("已取消還原。"), theme.TEXT_MUTED)
            return
        mark_safe, vid = self._mark_safe, q.verdict_id
        safe = mark_safe is not None and vid is not None and self.confirm(self, self.tr("也標記為誤判？"), self.tr(
            "要不要同時把這個檔案標記為誤判（你確定它是安全的）？\n\n"
            "標記：之後重新下載、複製或執行「完全相同」的檔案，都不會再被隔離、鎖住或關掉。"
            "檔案內容只要有一點不同（例如新版本），仍會重新檢查。標記可以在「需要處理的檔案 → 誤判排除」取消。\n\n"
            "不標記：只還原這一次；重新下載同一個檔案時，仍會被當成威脅處理。"))
        qid, svc = q.id, self._svc

        def job(_c: object) -> object:
            try:
                r = svc.restore(qid, target, confirmed=True)
            except QuarantineError as exc:
                raise ValueError(exc.user_message) from exc  # shown as-is
            if safe:
                assert mark_safe is not None and vid is not None
                try:
                    mark_safe(vid, "從隔離區還原時，使用者確認為誤判")
                except ValueError as exc:
                    return r, str(exc)
            return r, None

        def done(result: object) -> None:
            r, problem = result  # type: ignore[misc]
            self.refresh()
            text = self.tr("已還原到 {0}，SHA-256 驗證相符。").format(r.restore_target)
            if safe and problem is None:
                text += self.tr("已標記為誤判：同一個檔案之後不會再被擋。")
            elif problem:
                text += self.tr("但無法標記為誤判（{0}），可以到「需要處理的檔案」手動標記。").format(problem)
            self._msg(text, theme.OK if not problem else theme.WARN)

        def failed(m: str) -> None:
            self.refresh()
            self._msg(m, theme.BAD)

        self.runner.run(job, done, failed, self.tr("還原中…（驗證並寫回檔案，無法中途取消）"), cancellable=False)

    def delete_selected(self) -> None:
        q = self._selected()
        if q is None:
            return
        message = self.tr(
            "確定要永久刪除這個檔案嗎？刪除後無法復原，也不能再還原。\n\n檔案：{0}\nSHA-256：{1}\n\n"
            "如果你不確定它是不是誤判，請先保留在隔離區：放在這裡它不能執行，也不會造成危害。"
            "紀錄（路徑、SHA-256、原因）會保留，之後同樣內容的檔案仍會被認出來。").format(q.original_path, q.sha256)
        if not self.confirm(self, self.tr("確認永久刪除"), message):
            self._msg(self.tr("已取消刪除。"), theme.TEXT_MUTED)
            return
        qid, svc = q.id, self._svc

        def job(_c: object) -> object:
            try:
                return svc.delete(qid, confirmed=True)
            except QuarantineError as exc:
                raise ValueError(exc.user_message) from exc

        def done(_r: object) -> None:
            self.refresh()
            self._msg(self.tr("已永久刪除。紀錄已保留在稽核紀錄中。"), theme.OK)

        def failed(m: str) -> None:
            self.refresh()
            self._msg(m, theme.BAD)

        self.runner.run(job, done, failed, self.tr("刪除中…"), cancellable=False)

    def _msg(self, text: str, color: str) -> None:
        self.msg.setText(text)
        self.msg.setStyleSheet(f"color: {color};")

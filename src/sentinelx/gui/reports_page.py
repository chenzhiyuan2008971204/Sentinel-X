"""Reports page: list generated reports with an integrity check, open or copy them, and
generate a report for a past scan job.

A report whose file no longer matches the SHA-256 recorded when it was generated is shown
as modified; opening it needs an explicit confirmation and copying it is refused.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from sentinelx.core.enums import ReportKind
from sentinelx.gui import theme
from sentinelx.gui.confirm import Confirm, ask
from sentinelx.gui.widgets import item, muted, table, title
from sentinelx.gui.workers import CallWorker, start_worker
from sentinelx.services.report_service import SUBJECT_TEXT, GenerateResult, Integrity, ReportService
from sentinelx.storage.report_repository import ReportRow

INTEGRITY_TEXT = {Integrity.OK: ("未變更", theme.OK), Integrity.MODIFIED: ("已被修改", theme.BAD),
                  Integrity.MISSING: ("檔案不存在", theme.WARN)}
Opener = Callable[[Path], bool]


def default_opener(path: Path) -> bool:
    return QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))


class ReportsPage(QWidget):
    def __init__(self, service: ReportService, confirm: Confirm = ask, opener: Opener = default_opener) -> None:
        super().__init__()
        self.setObjectName("page_reports")
        self._svc = service
        self.confirm = confirm
        self.opener = opener
        self._rows: list[ReportRow] = []
        self.integrity: dict[int, Integrity] = {}
        self._thread: QThread | None = None
        self._worker: CallWorker | None = None
        self._verify_thread: QThread | None = None
        self._verify_worker: CallWorker | None = None
        self._verify_again = False
        self._note = ""

        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(10)
        lay.addWidget(title(self.tr("報告")))
        lay.addWidget(muted(self.tr("所有產生的報告都存在資料夾 {0}，並在資料庫與稽核紀錄保存每個檔案的 SHA-256。"
                                    "「完整性」比對檔案目前的雜湊與產生時記錄的雜湊。").format(service.reports_dir)))

        gen = QHBoxLayout()
        gen.addWidget(QLabel(self.tr("產生掃描報告：")))
        self.job_combo = QComboBox()
        self.job_combo.setMinimumWidth(320)
        gen.addWidget(self.job_combo, 1)
        self.fmt_json = QCheckBox("JSON")
        self.fmt_html = QCheckBox("HTML")
        self.fmt_pdf = QCheckBox("PDF")
        for cb in (self.fmt_json, self.fmt_html, self.fmt_pdf):
            cb.setChecked(True)
            gen.addWidget(cb)
        self.generate_button = QPushButton(self.tr("產生"))
        self.generate_button.clicked.connect(self.generate_scan_report)
        gen.addWidget(self.generate_button)
        lay.addLayout(gen)

        self.table = table([self.tr("產生時間（UTC）"), self.tr("類型"), self.tr("格式"), self.tr("主題"),
                            self.tr("檔名"), self.tr("完整性")])
        self.table.itemSelectionChanged.connect(self._update_buttons)
        lay.addWidget(self.table, 1)

        row = QHBoxLayout()
        self.refresh_button = QPushButton(self.tr("重新整理並驗證"))
        self.refresh_button.clicked.connect(lambda: self.refresh())
        self.open_button = QPushButton(self.tr("開啟"))
        self.open_button.clicked.connect(self.open_selected)
        self.folder_button = QPushButton(self.tr("開啟報告資料夾"))
        self.folder_button.clicked.connect(self.open_folder)
        self.copy_button = QPushButton(self.tr("另存複本…"))
        self.copy_button.clicked.connect(self._save_copy_dialog)
        for b in (self.refresh_button, self.open_button, self.folder_button, self.copy_button):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.status_label)
        self.refresh()

    # ---------- list ----------
    @property
    def verifying(self) -> bool:
        return self._verify_thread is not None

    def refresh(self, note: str = "") -> None:
        """List the reports now; hash them in the background (they can be large and many).
        `note` (e.g. the result of a generation) stays in front of the status text."""
        self._note = note
        self._rows = self._svc.reports()
        self.integrity = {}
        self.table.setRowCount(0)
        for r in self._rows:
            i = self.table.rowCount()
            self.table.insertRow(i)
            vals = [r.created_at, SUBJECT_TEXT.get(r.subject_type, r.subject_type), r.kind.value,
                    r.subject_ref if len(r.subject_ref) <= 40 else r.subject_ref[:40] + "…", Path(r.path).name,
                    self.tr("檢查中…")]
            for c, v in enumerate(vals):
                self.table.setItem(i, c, item(v, theme.TEXT_MUTED if c == 5 else None))
        self._status(self._prefix() + self.tr("共 {0} 份報告，正在驗證完整性…").format(len(self._rows)), theme.TEXT_MUTED)
        self.refresh_jobs()
        self._update_buttons()
        self._start_verify()

    def _start_verify(self) -> None:
        if self._verify_thread is not None:
            self._verify_again = True  # the list changed while hashing: check again afterwards
            return
        rows, svc = list(self._rows), self._svc
        self._verify_worker = CallWorker(lambda: {r.id: svc.integrity(r) for r in rows})
        self._verify_worker.finished.connect(self._on_verified)
        self._verify_worker.failed.connect(self._on_verify_failed)
        self._verify_thread = start_worker(self._verify_worker)

    def _end_verify(self) -> bool:
        if self._verify_thread is not None:
            self._verify_thread.wait()
        self._verify_thread = None
        self._verify_worker = None
        again, self._verify_again = self._verify_again, False
        if again:
            self._start_verify()
        return again

    def _on_verify_failed(self, msg: str) -> None:
        if not self._end_verify():
            self._status(self.tr("無法驗證完整性：{0}").format(msg), theme.BAD)

    def _on_verified(self, result: dict[int, Integrity]) -> None:
        if self._end_verify():
            return
        self.integrity = result
        for i, r in enumerate(self._rows):
            state = result.get(r.id)
            if state is not None:
                text, color = INTEGRITY_TEXT[state]
                self.table.setItem(i, 5, item(text, color))
        bad = sum(1 for v in result.values() if v is not Integrity.OK)
        self._status(self._prefix() + self.tr("共 {0} 份報告").format(len(self._rows))
                     + (self.tr("，{0} 份已被修改或不存在").format(bad) if bad else self.tr("，全部未變更")),
                     theme.WARN if bad else theme.TEXT_MUTED)
        self._update_buttons()

    def _prefix(self) -> str:
        return f"{self._note}。" if self._note else ""

    def refresh_jobs(self) -> None:
        current = self.job_combo.currentData()
        self.job_combo.clear()
        for j in self._svc.scan_jobs():
            self.job_combo.addItem(self.tr("#{0}　{1}　{2}　{3} 個檔案").format(j.id, j.started_at, j.status, j.files_seen), j.id)
        if current is not None:
            idx = self.job_combo.findData(current)
            if idx >= 0:
                self.job_combo.setCurrentIndex(idx)
        self._update_buttons()

    def selected(self) -> ReportRow | None:
        rows = self.table.selectionModel().selectedRows()
        return self._rows[rows[0].row()] if rows else None

    def _update_buttons(self) -> None:
        sel = self.selected()
        idle = self._thread is None
        self.open_button.setEnabled(sel is not None)
        self.copy_button.setEnabled(sel is not None and self.integrity.get(sel.id) is Integrity.OK)
        self.generate_button.setEnabled(idle and self.job_combo.count() > 0)

    def _status(self, text: str, color: str) -> None:
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color};")

    # ---------- actions ----------
    def open_selected(self) -> None:
        r = self.selected()
        if r is None:
            return
        state = self._svc.integrity(r)
        self.integrity[r.id] = state
        if state is Integrity.MISSING:
            self._status(self.tr("報告檔不存在：{0}").format(r.path), theme.WARN)
            return
        if state is Integrity.MODIFIED and not self.confirm(
                self, self.tr("報告已被修改"),
                self.tr("這份報告的內容與產生時記錄的 SHA-256 不符，可能已被修改：\n{0}\n\n仍要開啟嗎？").format(r.path)):
            return
        if not self.opener(Path(r.path)):
            self._status(self.tr("系統無法開啟此檔案。"), theme.BAD)

    def open_folder(self) -> None:
        self._svc.reports_dir.mkdir(parents=True, exist_ok=True)
        if not self.opener(self._svc.reports_dir):
            self._status(self.tr("系統無法開啟資料夾。"), theme.BAD)

    def _save_copy_dialog(self) -> None:
        r = self.selected()
        if r is None:
            return
        f, _ = QFileDialog.getSaveFileName(self, self.tr("另存報告複本"), Path(r.path).name)
        if f:
            self.save_copy_to(Path(f))

    def save_copy_to(self, dest: Path) -> None:
        r = self.selected()
        if r is None:
            return
        try:
            self._svc.export_copy(r, dest)
        except (ValueError, OSError) as exc:
            self._status(self.tr("無法另存：{0}").format(exc), theme.BAD)
            return
        self._status(self.tr("已另存到 {0}").format(dest), theme.OK)

    def _kinds(self) -> list[ReportKind]:
        return [k for k, cb in ((ReportKind.JSON, self.fmt_json), (ReportKind.HTML, self.fmt_html),
                                (ReportKind.PDF, self.fmt_pdf)) if cb.isChecked()]

    def generate_scan_report(self) -> None:
        if self._thread is not None or self.job_combo.count() == 0:
            return
        job_id, kinds, svc = int(self.job_combo.currentData()), self._kinds(), self._svc
        self._worker = CallWorker(lambda: svc.scan_report(job_id, kinds))
        self._worker.finished.connect(self._on_generated)
        self._worker.failed.connect(self._on_failed)
        self._status(self.tr("產生掃描 #{0} 的報告中…").format(job_id), theme.TEXT_MUTED)
        self._thread = start_worker(self._worker)
        self._update_buttons()

    def _finish(self) -> None:
        if self._thread is not None:
            self._thread.wait()
        self._thread = None
        self._worker = None

    def _on_failed(self, msg: str) -> None:
        self._finish()
        self._update_buttons()
        self._status(self.tr("無法產生報告：{0}").format(msg), theme.BAD)

    def _on_generated(self, res: GenerateResult) -> None:
        self._finish()
        msg = self.tr("已產生 {0} 份報告").format(len(res.rows))
        if res.errors:
            msg += self.tr("；失敗：") + "；".join(res.errors)
        self.refresh(note=msg)

    def shutdown(self) -> None:
        self._verify_again = False
        if self._verify_thread is not None:
            self._verify_thread.wait()
            self._verify_thread = None
            self._verify_worker = None
        if self._thread is not None:
            self._thread.wait()
            self._thread = None
            self._worker = None

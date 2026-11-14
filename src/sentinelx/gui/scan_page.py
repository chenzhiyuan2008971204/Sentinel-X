"""Scan Center: engine status, targets, async scan with progress/cancel, history, exclusions."""

from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import QThread, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import ExclusionKind, ScanStatus
from sentinelx.core.models import ScanProgress, ScanSummary
from sentinelx.core.risk import CLASS_TEXT
from sentinelx.gui import theme
from sentinelx.gui.threat_page import CLASS_COLOR
from sentinelx.gui.workers import ScanWorker, start_worker
from sentinelx.services.scan_service import ScanService

STATUS_TEXT = {
    ScanStatus.RUNNING.value: "執行中",
    ScanStatus.COMPLETED.value: "完成",
    ScanStatus.PARTIAL.value: "部分完成",
    ScanStatus.CANCELLED.value: "已取消",
    ScanStatus.FAILED.value: "失敗",
}
STATUS_COLOR = {
    ScanStatus.COMPLETED.value: theme.OK,
    ScanStatus.PARTIAL.value: theme.WARN,
    ScanStatus.CANCELLED.value: theme.WARN,
    ScanStatus.FAILED.value: theme.BAD,
}
KIND_TEXT = {
    ExclusionKind.PATH_PREFIX: "資料夾",
    ExclusionKind.PATH: "單一檔案",
    ExclusionKind.EXTENSION: "副檔名",
    ExclusionKind.SHA256: "SHA-256",
}


def _item(text: str, color: str | None = None) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if color:
        it.setForeground(QColor(color))
    return it


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    t.horizontalHeader().setStretchLastSection(True)
    return t


MAX_FILE_ROWS = 10_000  # rows shown for one scan; the scan report has all of them

class ScanCenterPage(QWidget):
    def __init__(self, scans: ScanService) -> None:
        super().__init__()
        self.setObjectName("page_scan")
        self._scans = scans
        self._cancel: CancelToken | None = None
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self.last_summary: ScanSummary | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(12)
        title = QLabel(self.tr("掃描中心"))
        title.setObjectName("pageTitle")
        lay.addWidget(title)

        # Engines
        eng_box = QFrame()
        eng_box.setObjectName("card")
        eng_lay = QHBoxLayout(eng_box)
        self.engine_label = QLabel()
        self.engine_label.setWordWrap(True)
        self.engine_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.refresh_engines_button = QPushButton(self.tr("重新偵測引擎"))
        self.refresh_engines_button.clicked.connect(lambda: self.refresh_engines(refresh=True))
        eng_lay.addWidget(self.engine_label, 1)
        eng_lay.addWidget(self.refresh_engines_button)
        lay.addWidget(eng_box)

        # Targets
        tgt_row = QHBoxLayout()
        self.targets = QListWidget()
        self.targets.setMaximumHeight(90)
        btns = QVBoxLayout()
        self.add_file_button = QPushButton(self.tr("加入檔案"))
        self.add_folder_button = QPushButton(self.tr("加入資料夾"))
        self.remove_target_button = QPushButton(self.tr("移除選取"))
        self.add_file_button.clicked.connect(self._pick_files)
        self.add_folder_button.clicked.connect(self._pick_folder)
        self.remove_target_button.clicked.connect(self._remove_selected_target)
        for b in (self.add_file_button, self.add_folder_button, self.remove_target_button):
            btns.addWidget(b)
        tgt_row.addWidget(self.targets, 1)
        tgt_row.addLayout(btns)
        lay.addLayout(tgt_row)

        # Run controls
        run_row = QHBoxLayout()
        self.start_button = QPushButton(self.tr("開始掃描"))
        self.cancel_button = QPushButton(self.tr("取消"))
        self.start_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setEnabled(False)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        run_row.addWidget(self.start_button)
        run_row.addWidget(self.cancel_button)
        run_row.addWidget(self.progress_bar, 1)
        lay.addLayout(run_row)
        self.progress_label = QLabel()
        self.progress_label.setObjectName("muted")
        self.progress_label.setWordWrap(True)
        self.progress_label.setTextFormat(Qt.TextFormat.PlainText)  # shows file paths
        self.result_label = QLabel()
        self.result_label.setWordWrap(True)
        self.result_label.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.progress_label)
        lay.addWidget(self.result_label)

        # History + exclusions
        self.tabs = QTabWidget()
        hist = QSplitter(Qt.Orientation.Vertical)
        self.jobs_table = _table(["#", "開始時間 (UTC)", "狀態", "檢查", "完成評估", "未完成評估",
                                  "確認 / 可疑", "目標"])
        self.jobs_table.itemSelectionChanged.connect(self._show_selected_job)
        self.files_table = _table(["判定（掃描當時）", "檔案", "證據 / 原因", "SHA-256"])
        hist.addWidget(self.jobs_table)
        hist.addWidget(self.files_table)
        self.files_note = QLabel()
        self.files_note.setObjectName("muted")
        self.files_note.setTextFormat(Qt.TextFormat.PlainText)
        hist.addWidget(self.files_note)
        self.tabs.addTab(hist, self.tr("掃描紀錄"))
        self.tabs.addTab(self._build_exclusions_tab(), self.tr("排除項目"))
        lay.addWidget(self.tabs, 1)

        self.refresh_engines()
        self.refresh_history()
        self.refresh_exclusions()
        self._update_buttons()

    # ---------- exclusions ----------
    def _build_exclusions_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        row = QHBoxLayout()
        self.excl_kind = QComboBox()
        for kind, text in KIND_TEXT.items():
            self.excl_kind.addItem(text, kind)
        self.excl_value = QLineEdit()
        self.excl_value.setPlaceholderText(self.tr("例如 C:\\Data\\logs、.log 或 SHA-256"))
        self.excl_reason = QLineEdit()
        self.excl_reason.setPlaceholderText(self.tr("原因（選填）"))
        self.add_excl_button = QPushButton(self.tr("新增排除"))
        self.add_excl_button.clicked.connect(self._add_exclusion)
        row.addWidget(self.excl_kind)
        row.addWidget(self.excl_value, 2)
        row.addWidget(self.excl_reason, 1)
        row.addWidget(self.add_excl_button)
        v.addLayout(row)
        self.excl_error = QLabel()
        self.excl_error.setTextFormat(Qt.TextFormat.PlainText)
        self.excl_error.setStyleSheet(f"color: {theme.BAD};")
        v.addWidget(self.excl_error)
        self.excl_table = _table(["#", "類型", "值", "原因", "建立時間 (UTC)"])
        v.addWidget(self.excl_table, 1)
        self.remove_excl_button = QPushButton(self.tr("刪除選取的排除"))
        self.remove_excl_button.clicked.connect(self._remove_exclusion)
        v.addWidget(self.remove_excl_button, alignment=Qt.AlignmentFlag.AlignLeft)
        return w

    def refresh_exclusions(self) -> None:
        rows = self._scans.exclusions()
        self.excl_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.excl_table.setItem(i, 0, _item(str(r.id)))
            self.excl_table.setItem(i, 1, _item(KIND_TEXT[r.kind]))
            self.excl_table.setItem(i, 2, _item(r.value))
            self.excl_table.setItem(i, 3, _item(r.reason or ""))
            self.excl_table.setItem(i, 4, _item(r.created_at))

    def _add_exclusion(self) -> None:
        kind = ExclusionKind(self.excl_kind.currentData())  # Qt returns the enum as a plain str
        try:
            self._scans.add_exclusion(kind, self.excl_value.text(), self.excl_reason.text().strip() or None)
        except ValueError as exc:
            self.excl_error.setText(str(exc))
            return
        self.excl_error.clear()
        self.excl_value.clear()
        self.excl_reason.clear()
        self.refresh_exclusions()

    def _remove_exclusion(self) -> None:
        row = self.excl_table.currentRow()
        if row < 0:
            self.excl_error.setText(self.tr("請先選取要刪除的排除項目。"))
            return
        self._scans.remove_exclusion(int(self.excl_table.item(row, 0).text()))
        self.excl_error.clear()
        self.refresh_exclusions()

    # ---------- engines ----------
    def refresh_engines(self, refresh: bool = False) -> None:
        parts = []
        for s in self._scans.engine_statuses(refresh=refresh):
            if s.available:
                date = f"，{s.rules_date}" if s.rules_date else ""
                kind = "病毒碼" if s.name == "ClamAV" else "規則／資料"
                parts.append(f"<span style='color:{theme.OK}'>● {html.escape(s.name)} {html.escape(s.version or '')}</span>"
                             f"（{kind} {html.escape(s.rules_version or '')}{html.escape(date)}）")
            else:
                ver = f" {s.version}" if s.version else ""
                parts.append(f"<span style='color:{theme.BAD}'>● {html.escape(s.name + ver)} 無法使用</span>："
                             f"{html.escape(s.detail)}")
        if not parts:
            parts.append(f"<span style='color:{theme.BAD}'>沒有已設定的偵測引擎。</span>")
        self.engine_label.setText("<br>".join(parts))
        self._update_buttons()

    # ---------- targets ----------
    def add_target(self, path: Path) -> None:
        s = str(path)
        existing = {self.targets.item(i).text() for i in range(self.targets.count())}
        if s not in existing:
            self.targets.addItem(s)
        self._update_buttons()

    def clear_targets(self) -> None:
        self.targets.clear()
        self._update_buttons()

    def target_paths(self) -> list[Path]:
        return [Path(self.targets.item(i).text()) for i in range(self.targets.count())]

    def _pick_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, self.tr("選擇要掃描的檔案"))
        for f in files:
            self.add_target(Path(f))

    def _pick_folder(self) -> None:
        d = QFileDialog.getExistingDirectory(self, self.tr("選擇要掃描的資料夾"))
        if d:
            self.add_target(Path(d))

    def _remove_selected_target(self) -> None:
        for it in self.targets.selectedItems():
            self.targets.takeItem(self.targets.row(it))
        self._update_buttons()

    # ---------- scanning ----------
    @property
    def scanning(self) -> bool:
        return self._thread is not None

    def _update_buttons(self) -> None:
        busy = self.scanning
        engines_ok = self._scans.any_engine_available()
        has_targets = self.targets.count() > 0
        self.start_button.setEnabled(not busy and engines_ok and has_targets)
        self.cancel_button.setEnabled(busy)
        for b in (self.add_file_button, self.add_folder_button, self.remove_target_button,
                  self.refresh_engines_button):
            b.setEnabled(not busy)
        if not busy:
            if not engines_ok:
                self.progress_label.setText(self.tr(
                    "沒有可用的偵測引擎，無法掃描。需要 ClamAV（含病毒碼）、已啟用的 YARA 規則，或含惡意雜湊的情報；"
                    "PE 結構分析不能單獨判定惡意。設定完成後按「重新偵測引擎」。"))
            elif not has_targets:
                self.progress_label.setText(self.tr("請加入要掃描的檔案或資料夾。"))

    def start_scan(self) -> None:
        if self.scanning or not self.start_button.isEnabled():
            return
        self._cancel = CancelToken()
        self._worker = ScanWorker(self._scans, self.target_paths(), self._cancel)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self.result_label.clear()
        self.progress_bar.setRange(0, 0)  # busy indicator; total is unknown while walking
        self.progress_label.setText(self.tr("掃描中…"))
        self._thread = start_worker(self._worker)
        self._update_buttons()

    def cancel_scan(self) -> None:
        if self._cancel is not None:
            self._cancel.cancel()
            self.cancel_button.setEnabled(False)
            self.progress_label.setText(self.tr("正在取消…"))

    def _on_progress(self, p: ScanProgress) -> None:
        self.progress_label.setText(
            self.tr("已檢查 {0} 個項目，完成 {1}，未完成評估 {2}，偵測 {3}｜{4}").format(
                p.files_seen, p.files_done, p.files_skipped, p.detections, p.current_path
            )
        )

    def _scan_done(self) -> None:
        if self._thread is not None and not self._thread.wait(30000):
            # Never drop a running QThread (Qt aborts the process); keep it and report.
            self.result_label.setText(self.tr("背景工作未能正常結束，請重新啟動程式。"))
            return
        self._thread = None
        self._worker = None
        self._cancel = None
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        self._update_buttons()
        self.refresh_history()

    def _on_finished(self, s: ScanSummary) -> None:
        self.last_summary = s
        color = STATUS_COLOR.get(s.status, theme.TEXT)
        if s.confirmed:
            color = theme.BAD
        elif s.suspicious and color == theme.OK:
            color = theme.WARN
        text = self.tr("掃描{0}：檢查 {1} 個項目，完成評估 {2}，未完成評估 {3}。").format(
            STATUS_TEXT.get(s.status, s.status), s.files_seen, s.files_assessed, s.files_not_assessed,
        )
        if s.status != ScanStatus.FAILED.value:
            text += self.tr(" 判定：確認威脅 {0}、可疑 {1}、未知 {2}、未發現威脅 {3}。").format(
                s.confirmed, s.suspicious, s.unknown, s.clean)
        if s.error_summary:
            text += " " + s.error_summary
        if s.confirmed or s.suspicious:
            text += self.tr(" 請到「威脅中心」查看依據並進行審查。")
        elif s.status == ScanStatus.COMPLETED.value:
            text += self.tr(" 「未發現威脅」只代表引擎沒有找到已知特徵，不代表檔案一定安全。")
        self.result_label.setText(text)
        self.result_label.setStyleSheet(f"color: {color};")
        self.progress_label.clear()
        self._scan_done()
        self._select_job(s.job_id)

    def _on_failed(self, msg: str) -> None:
        self.result_label.setText(self.tr("掃描失敗：{0}").format(msg))
        self.result_label.setStyleSheet(f"color: {theme.BAD};")
        self._scan_done()

    def shutdown(self) -> None:
        """Called when the window closes: cancel, then wait until the worker has stopped.

        A QThread must never be destroyed while running (Qt aborts the process), so there is
        no timeout here. Cancellation is checked per file, per hash chunk and inside ClamAV;
        the worst case is one in-flight YARA match up to its configured timeout.
        """
        if self._cancel is not None:
            self._cancel.cancel()
        if self._thread is not None:
            self._thread.wait()
            self._thread = None
            self._worker = None

    # ---------- history ----------
    def refresh_history(self) -> None:
        jobs = self._scans.history()
        self.jobs_table.setRowCount(len(jobs))
        for i, j in enumerate(jobs):
            threats = f"{j.confirmed} / {j.suspicious}"
            vals = [str(j.id), j.started_at, STATUS_TEXT.get(j.status, j.status), str(j.files_seen),
                    str(j.files_assessed), str(j.files_not_assessed), threats, "; ".join(j.targets)]
            for c, v in enumerate(vals):
                color = STATUS_COLOR.get(j.status) if c == 2 else None
                if c == 6 and (j.confirmed or j.suspicious):
                    color = theme.BAD if j.confirmed else theme.WARN
                self.jobs_table.setItem(i, c, _item(v, color))

    def _select_job(self, job_id: int) -> None:
        for r in range(self.jobs_table.rowCount()):
            if self.jobs_table.item(r, 0).text() == str(job_id):
                self.jobs_table.selectRow(r)
                return

    def _show_selected_job(self) -> None:
        row = self.jobs_table.currentRow()
        if row < 0:
            self.files_table.setRowCount(0)
            self.files_note.clear()
            return
        files = self._scans.job_files(int(self.jobs_table.item(row, 0).text()))
        # Not-clean files first, so nothing that needs attention falls past the display limit.
        files.sort(key=lambda f: 0 if (f.detections or f.engine_errors or not f.assessed) else 1)
        total = len(files)
        files = files[:MAX_FILE_ROWS]
        self.files_note.setText(self.tr("共 {0} 個檔案，畫面只列出前 {1} 個（有發現或未完成評估的排在前面）；"
                                        "完整清單請在「報告」頁產生掃描報告。").format(total, MAX_FILE_ROWS)
                                if total > MAX_FILE_ROWS else "")
        self.files_table.setRowCount(len(files))
        for i, f in enumerate(files):
            if f.classification is None:
                status, color = "已排除", theme.TEXT_MUTED
            else:
                status, color = CLASS_TEXT[f.classification], CLASS_COLOR[f.classification]
                if f.confidence and f.confidence != "—":
                    status += f"（信心 {f.confidence}）"
            if f.detections:
                note = "、".join(f.detections)
            elif not f.assessed:
                note = f.not_assessed_reason or ""
            else:
                note = ""
            self.files_table.setItem(i, 0, _item(status, color))
            self.files_table.setItem(i, 1, _item(f.path))
            self.files_table.setItem(i, 2, _item(note))
            self.files_table.setItem(i, 3, _item(f.sha256 or ""))

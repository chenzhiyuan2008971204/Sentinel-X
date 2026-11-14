"""Threat Center: verdicts that need attention, their evidence, and the manual review workflow."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from sentinelx.core.enums import Classification, EngineOutcomeKind, ReviewDecision
from sentinelx.core.risk import CLASS_TEXT
from sentinelx.gui import theme
from sentinelx.gui.confirm import Confirm, ask
from sentinelx.gui.widgets import BusyBar, item, muted, table, title
from sentinelx.gui.workers import TaskRunner
from sentinelx.quarantine.win32fs import QuarantineError
from sentinelx.services.quarantine_service import QuarantineService
from sentinelx.services.review_service import ReviewService
from sentinelx.storage.verdict_repository import VerdictDetail

CLASS_COLOR = {
    Classification.CONFIRMED_THREAT: theme.BAD,
    Classification.SUSPICIOUS: theme.WARN,
    Classification.UNKNOWN: theme.TEXT_MUTED,
    Classification.CLEAN: theme.OK,
}
DECISION_TEXT = {
    ReviewDecision.CONFIRM: "已確認",
    ReviewDecision.DISMISS_FALSE_POSITIVE: "標記誤判",
    ReviewDecision.ESCALATE: "待進一步分析",
}
KIND_TEXT = {
    EngineOutcomeKind.FINDINGS: "有發現",
    EngineOutcomeKind.NO_FINDINGS: "未發現",
    EngineOutcomeKind.SKIPPED: "不適用",
    EngineOutcomeKind.ERROR: "無法評估",
}


def e(v: Any) -> str:
    return html.escape(str(v))


class ThreatCenterPage(QWidget):
    def __init__(self, reviews: ReviewService, quarantine: QuarantineService | None = None,
                 confirm: Confirm = ask) -> None:
        super().__init__()
        self.setObjectName("page_threats")
        self._svc = reviews
        self._q = quarantine
        self.confirm = confirm
        self._current: int | None = None
        self.runner = TaskRunner(self)
        self.runner.busy_changed.connect(lambda _b: self._set_review_enabled(self._current is not None))

        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(12)
        lay.addWidget(title(self.tr("威脅中心")))
        lay.addWidget(muted(self.tr(
            "列出最新判定為「確認威脅」、「可疑」或需要人工審查的檔案。每個判定都附有依據；"
            "排序分數只用來排序，不是機率。審查不會刪除任何檔案或證據。")))
        self.tabs = QTabWidget()
        self.tabs.addTab(self._threats_tab(), self.tr("待處理"))
        self.tabs.addTab(self._fp_tab(), self.tr("誤判排除"))
        lay.addWidget(self.tabs, 1)
        self.refresh()

    # ---------- threats ----------
    def _threats_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        top = QHBoxLayout()
        self.include_resolved = QCheckBox(self.tr("顯示所有檔案的最新判定（含未發現威脅）"))
        self.include_resolved.toggled.connect(self.refresh)
        self.refresh_button = QPushButton(self.tr("重新整理"))
        self.refresh_button.clicked.connect(self.refresh)
        top.addWidget(self.include_resolved)
        top.addStretch(1)
        top.addWidget(self.refresh_button)
        v.addLayout(top)

        split = QSplitter(Qt.Orientation.Vertical)
        self.table = table(["#", "分類", "信心", "排序分數", "審查", "檔案", "主要證據"])
        self.table.itemSelectionChanged.connect(self._show_selected)
        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        split.addWidget(self.table)
        split.addWidget(self.detail)
        v.addWidget(split, 1)

        row = QHBoxLayout()
        self.reason_edit = QLineEdit()
        self.reason_edit.setPlaceholderText(self.tr("審查原因（必填）"))
        self.whole_file = QCheckBox(self.tr("誤判時排除整個檔案（否則只排除命中的規則）"))
        row.addWidget(self.reason_edit, 2)
        row.addWidget(self.whole_file)
        v.addLayout(row)
        btns = QHBoxLayout()
        self.confirm_button = QPushButton(self.tr("確認為威脅"))
        self.fp_button = QPushButton(self.tr("標記為誤判"))
        self.escalate_button = QPushButton(self.tr("需要進一步分析"))
        self.confirm_button.clicked.connect(lambda: self.review(ReviewDecision.CONFIRM))
        self.fp_button.clicked.connect(lambda: self.review(ReviewDecision.DISMISS_FALSE_POSITIVE))
        self.escalate_button.clicked.connect(lambda: self.review(ReviewDecision.ESCALATE))
        for b in (self.confirm_button, self.fp_button, self.escalate_button):
            btns.addWidget(b)
        btns.addStretch(1)
        self.quarantine_button = QPushButton(self.tr("隔離檔案…"))
        self.quarantine_button.clicked.connect(self.quarantine_selected)
        self.quarantine_button.setVisible(self._q is not None)
        btns.addWidget(self.quarantine_button)
        v.addLayout(btns)
        self.busy_bar = BusyBar(self.runner)
        v.addWidget(self.busy_bar)
        self.msg = QLabel()
        self.msg.setWordWrap(True)
        self.msg.setTextFormat(Qt.TextFormat.PlainText)
        v.addWidget(self.msg)
        return w

    def refresh(self) -> None:
        rows = self._svc.threats(self.include_resolved.isChecked())
        self.table.clearSelection()
        self.table.setCurrentCell(-1, -1)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            c = CLASS_COLOR[r.classification]
            review = DECISION_TEXT[r.last_review] if r.last_review else ("需審查" if r.needs_review else "")
            if self._q is not None and self._q.is_quarantined(r.sha256, r.path):
                review = (review + "，" if review else "") + "已隔離"
            elif r.file_missing:
                review = (review + "，" if review else "") + "檔案已不在原位置"
            vals = [str(r.verdict_id), CLASS_TEXT[r.classification], r.confidence, str(r.ordinal_score),
                    review, r.path, r.summary]
            for col, val in enumerate(vals):
                self.table.setItem(i, col, item(val, c if col == 1 else None))
        self._current = None
        self.detail.clear()
        self._set_review_enabled(False)
        self.refresh_suppressions()

    def _set_review_enabled(self, on: bool) -> None:
        on = on and not self.runner.busy
        for b in (self.confirm_button, self.fp_button, self.escalate_button):
            b.setEnabled(on)
        self.quarantine_button.setEnabled(on and self._can_quarantine())
        if self._q is not None and not self._q.ready:
            self.quarantine_button.setToolTip(self.tr("隔離區無法使用：{0}").format(self._q.problem))

    def _can_quarantine(self) -> bool:
        if self._q is None or not self._q.ready or self._current is None:
            return False
        d = self._svc.detail(self._current)
        return (d is not None and d.row.classification is Classification.CONFIRMED_THREAT
                and not self._q.is_quarantined(d.row.sha256, d.row.path) and Path(d.row.path).exists())

    def quarantine_selected(self) -> None:
        if self._q is None or self._current is None:
            return
        d = self._svc.detail(self._current)
        if d is None:
            return
        reason = self.reason_edit.text().strip()
        if not reason:
            self._msg(self.tr("請先填寫原因（會記錄在隔離紀錄中）。"), theme.WARN)
            return
        message = self.tr(
            "確定要隔離這個檔案嗎？\n\n檔案：{0}\nSHA-256：{1}\n\n檔案會被移到隔離區並從原位置移除，"
            "之後可以在「隔離區」頁面還原。").format(d.row.path, d.row.sha256)
        if not self.confirm(self, self.tr("確認隔離"), message):
            self._msg(self.tr("已取消隔離。"), theme.TEXT_MUTED)
            return
        vid, q = self._current, self._q

        def job(_c: object) -> object:
            try:
                return q.quarantine_verdict(vid, reason, confirmed=True)
            except QuarantineError as exc:
                raise ValueError(exc.user_message) from exc

        def done(_r: object) -> None:
            self.reason_edit.clear()
            self.refresh()
            self.select_verdict(vid)
            self._msg(self.tr("已隔離。"), theme.OK)

        self.runner.run(job, done, lambda m: self._msg(m, theme.BAD),
                        self.tr("隔離中…（複製、驗證後移除原檔，無法中途取消）"), cancellable=False)

    @property
    def busy(self) -> bool:
        return self.runner.busy

    def shutdown(self) -> None:
        self.runner.shutdown()

    def select_verdict(self, verdict_id: int) -> bool:
        for r in range(self.table.rowCount()):
            if self.table.item(r, 0).text() == str(verdict_id):
                self.table.selectRow(r)
                self._show_selected()  # explicit: selecting an already-current row emits no signal
                return True
        return False

    def _show_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        self._current = int(self.table.item(row, 0).text())
        d = self._svc.detail(self._current)
        self.detail.setHtml(render_detail(d) if d else "")
        self._set_review_enabled(d is not None)

    def review(self, decision: ReviewDecision) -> None:
        if self._current is None:
            self._msg(self.tr("請先選取一個判定。"), theme.WARN)
            return
        try:
            new_id = self._svc.review(self._current, decision, self.reason_edit.text(),
                                      "file" if self.whole_file.isChecked() else "rules")
        except ValueError as exc:
            self._msg(str(exc), theme.BAD)
            return
        self.reason_edit.clear()
        self.refresh()
        self._msg(self.tr("已記錄：{0}。").format(DECISION_TEXT[decision]), theme.OK)
        self.select_verdict(new_id)

    def _msg(self, text: str, color: str) -> None:
        self.msg.setText(text)
        self.msg.setStyleSheet(f"color: {color};")

    # ---------- false-positive suppressions ----------
    def _fp_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(muted(self.tr("被標記為誤判的證據仍保留在紀錄中，只是不列入判斷。移除排除後，相關檔案會立即重新評估。")))
        self.fp_table = table(["#", "SHA-256", "規則", "原因", "建立時間 (UTC)"])
        v.addWidget(self.fp_table, 1)
        self.remove_fp_button = QPushButton(self.tr("移除選取的排除並重新評估"))
        self.remove_fp_button.clicked.connect(self._remove_fp)
        v.addWidget(self.remove_fp_button, alignment=Qt.AlignmentFlag.AlignLeft)
        return w

    def refresh_suppressions(self) -> None:
        rows = self._svc.suppressions()
        self.fp_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for col, val in enumerate([str(r.id), r.sha256, r.rule_id or "（整個檔案）", r.reason, r.created_at]):
                self.fp_table.setItem(i, col, item(val))

    def _remove_fp(self) -> None:
        row = self.fp_table.currentRow()
        if row < 0:
            self._msg(self.tr("請先選取要移除的排除。"), theme.WARN)
            return
        self._svc.remove_suppression(int(self.fp_table.item(row, 0).text()))
        self.refresh()


def render_detail(d: VerdictDetail) -> str:
    r = d.row
    c = CLASS_COLOR[r.classification]
    out = [
        f"<h3 style='color:{c}'>{e(CLASS_TEXT[r.classification])}（{e(r.classification.value)}）</h3>",
        f"<p>檔案：{e(r.path)}<br>SHA-256：<code>{e(r.sha256 or '')}</code><br>"
        f"信心：{e(r.confidence)}　排序分數：{r.ordinal_score}（不是機率）</p>",
        "<h4>判定說明</h4>",
        "<pre style='white-space:pre-wrap'>" + e(d.explanation) + "</pre>",
        "<h4>各引擎原始結果</h4><ul>",
    ]
    for res in d.results:
        line = f"<li><b>{e(res.engine_name)} {e(res.engine_version or '')}</b>：{KIND_TEXT[res.kind]}"
        if res.error:
            line += f"<br><span style='color:{theme.BAD}'>{e(res.error)}</span>"
        for det in res.detections:
            line += f"<br>　[{e(det.severity_hint.value)}] {e(det.rule_id)}：{e(det.confidence_explanation)}"
        out.append(line + "</li>")
    out.append("</ul>")
    if d.reviews:
        out.append("<h4>審查紀錄</h4><ul>")
        out.extend(f"<li>{e(t)}　{e(DECISION_TEXT[dec])}：{e(reason)}</li>" for t, dec, reason in d.reviews)
        out.append("</ul>")
    if len(d.history) > 1:
        out.append("<h4>判定歷史</h4><ul>")
        out.extend(f"<li>#{vid}　{e(t)}　{e(CLASS_TEXT[cls])}</li>" for vid, t, cls in d.history)
        out.append("</ul>")
    return "\n".join(out)

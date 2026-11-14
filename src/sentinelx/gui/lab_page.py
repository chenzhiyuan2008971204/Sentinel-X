"""Research Lab page: a static analysis workspace for one sample at a time.

Nothing here executes the sample. Every string that comes from a file, a signature or the
database is untrusted: rich-text views escape it, tables show it as plain text.
"""

from __future__ import annotations

import html
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import ReportKind
from sentinelx.core.risk import CLASS_TEXT
from sentinelx.gui import theme
from sentinelx.gui.static_page import KIND_TEXT
from sentinelx.gui.widgets import item, muted, table, title
from sentinelx.gui.workers import CallWorker, start_worker
from sentinelx.research.compare import Comparison
from sentinelx.research.yara_lab import YaraTestRun
from sentinelx.services.lab_service import HashLookup, LabService, SampleInspection
from sentinelx.services.report_service import GenerateResult
from sentinelx.storage.research_repository import EvidenceRun, TimelineEvent

YARA_TEMPLATE = """rule Example_Test
{
    meta:
        description = "測試用規則：只對你選擇的無害檔案比對"
    strings:
        $text = "This program cannot be run in DOS mode"
    condition:
        $text
}
"""
SIG_SOURCE = {"EMBEDDED": "內嵌簽章", "CATALOG": "系統目錄檔"}


def e(v: Any) -> str:
    return html.escape("—" if v is None or v == "" else str(v))


def _rows(pairs: list[tuple[str, Any]]) -> str:
    return "<table cellspacing='0' cellpadding='3'>" + "".join(
        f"<tr><td style='color:{theme.TEXT_MUTED}'>{e(k)}</td><td>{e(v)}</td></tr>" for k, v in pairs) + "</table>"


class ResearchLabPage(QWidget):
    def __init__(self, lab: LabService) -> None:
        super().__init__()
        self.setObjectName("page_lab")
        self._lab = lab
        self._thread: QThread | None = None
        self._worker: CallWorker | None = None
        self._cancel: CancelToken | None = None
        self._on_done_cb: Callable[[Any], None] | None = None
        self.sha256: str | None = None
        self.inspection: SampleInspection | None = None
        self.lookup_result: HashLookup | None = None
        self.evidence: list[EvidenceRun] = []
        self.timeline: list[TimelineEvent] = []
        self.yara_runs: list[YaraTestRun] = []
        self.comparison: tuple[Comparison, SampleInspection, SampleInspection] | None = None
        self.last_export: GenerateResult | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 20)
        lay.setSpacing(10)
        lay.addWidget(title(self.tr("研究實驗室")))
        lay.addWidget(muted(self.tr("靜態研究工作區：只讀取檔案，絕不執行。PE 結構與簽章在獨立的分析程序中解析"
                                    "（限制時間與記憶體）。實驗室不會產生或修改判定。")))

        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(self.tr("樣本檔案路徑"))
        self.browse_button = QPushButton(self.tr("選擇檔案…"))
        self.browse_button.clicked.connect(self._browse)
        self.inspect_button = QPushButton(self.tr("檢視樣本"))
        self.inspect_button.clicked.connect(self.start_inspect)
        row.addWidget(self.path_edit, 1)
        row.addWidget(self.browse_button)
        row.addWidget(self.inspect_button)
        lay.addLayout(row)
        row2 = QHBoxLayout()
        self.hash_edit = QLineEdit()
        self.hash_edit.setPlaceholderText(self.tr("或輸入 SHA-256，只查詢情報、已儲存的證據與歷史"))
        self.lookup_button = QPushButton(self.tr("查詢雜湊"))
        self.lookup_button.clicked.connect(self.start_lookup)
        row2.addWidget(self.hash_edit, 1)
        row2.addWidget(self.lookup_button)
        lay.addLayout(row2)

        srow = QHBoxLayout()
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # indeterminate: work is done in steps that cannot report a fraction
        self.progress.setTextVisible(False)
        self.progress.setFixedWidth(160)
        self.progress.setVisible(False)
        self.cancel_button = QPushButton(self.tr("取消"))
        self.cancel_button.clicked.connect(self.cancel)
        self.cancel_button.setVisible(False)
        srow.addWidget(self.status_label, 1)
        srow.addWidget(self.progress)
        srow.addWidget(self.cancel_button)
        lay.addLayout(srow)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_overview(), self.tr("概要"))
        self.tabs.addTab(self._build_pe(), self.tr("PE 結構"))
        self.tabs.addTab(self._build_signature(), self.tr("數位簽章"))
        self.tabs.addTab(self._build_yara(), self.tr("YARA 測試"))
        self.tabs.addTab(self._build_evidence(), self.tr("偵測證據"))
        self.tabs.addTab(self._build_compare(), self.tr("檔案比較"))
        self.tabs.addTab(self._build_timeline(), self.tr("分析時間軸"))
        lay.addWidget(self.tabs, 1)

        exp = QHBoxLayout()
        exp.addWidget(QLabel(self.tr("研究報告格式：")))
        self.fmt_json = QCheckBox("JSON")
        self.fmt_html = QCheckBox("HTML")
        self.fmt_pdf = QCheckBox("PDF")
        for cb in (self.fmt_json, self.fmt_html, self.fmt_pdf):
            cb.setChecked(True)
            exp.addWidget(cb)
        self.export_button = QPushButton(self.tr("匯出研究報告"))
        self.export_button.clicked.connect(self.start_export)
        exp.addWidget(self.export_button)
        self.export_label = QLabel()
        self.export_label.setTextFormat(Qt.TextFormat.PlainText)
        self.export_label.setWordWrap(True)
        exp.addWidget(self.export_label, 1)
        lay.addLayout(exp)
        self._update_buttons()

    # ---------- tab construction ----------
    def _build_overview(self) -> QWidget:
        self.overview = QTextBrowser()
        self.overview.setOpenLinks(False)
        self.overview.setHtml(f"<p style='color:{theme.TEXT_MUTED}'>{e(self.tr('選擇一個檔案或輸入 SHA-256 開始。'))}</p>")
        return self.overview

    def _build_pe(self) -> QWidget:
        w = QSplitter(Qt.Orientation.Vertical)
        self.pe_header = QTextBrowser()
        self.pe_header.setOpenLinks(False)
        self.sections_table = table([self.tr("名稱"), self.tr("虛擬位址"), self.tr("虛擬大小"), self.tr("原始大小"),
                                     self.tr("亂度"), self.tr("權限")])
        self.imports_tree = QTreeWidget()
        self.imports_tree.setHeaderLabels([self.tr("匯入（DLL／函式）"), self.tr("數量")])
        w.addWidget(self.pe_header)
        w.addWidget(self.sections_table)
        w.addWidget(self.imports_tree)
        return w

    def _build_signature(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        self.sig_view = QTextBrowser()
        self.sig_view.setOpenLinks(False)
        self.chain_table = table([self.tr("主體"), self.tr("簽發者"), self.tr("序號"), self.tr("生效"), self.tr("到期"),
                                  self.tr("SHA-1 指紋")])
        lay.addWidget(self.sig_view, 1)
        lay.addWidget(QLabel(self.tr("憑證鏈（簽署者在前）")))
        lay.addWidget(self.chain_table, 1)
        return w

    def _build_yara(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(muted(self.tr("在這裡撰寫或載入 YARA 規則，對你選擇的無害檔案測試。測試規則不會加入掃描，"
                                    "也不影響任何判定；要正式使用請到「威脅情報」頁面加入規則檔。")))
        self.rule_edit = QPlainTextEdit()
        self.rule_edit.setPlainText(YARA_TEMPLATE)
        lay.addWidget(self.rule_edit, 2)
        row = QHBoxLayout()
        self.load_rule_button = QPushButton(self.tr("從檔案載入規則…"))
        self.load_rule_button.clicked.connect(self._load_rule)
        self.yara_sample_button = QPushButton(self.tr("測試目前樣本"))
        self.yara_sample_button.clicked.connect(lambda: self.run_yara([Path(self.inspection.facts.path)])
                                                if self.inspection else None)
        self.yara_files_button = QPushButton(self.tr("測試其他檔案…"))
        self.yara_files_button.clicked.connect(self._yara_pick_files)
        self.yara_folder_button = QPushButton(self.tr("測試資料夾…"))
        self.yara_folder_button.clicked.connect(self._yara_pick_folder)
        for b in (self.load_rule_button, self.yara_sample_button, self.yara_files_button, self.yara_folder_button):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        self.yara_label = QLabel()
        self.yara_label.setWordWrap(True)
        self.yara_label.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.yara_label)
        self.yara_table = table([self.tr("檔案"), self.tr("規則"), self.tr("字串"), self.tr("位移"), self.tr("長度"),
                                 self.tr("十六進位"), self.tr("文字"), self.tr("備註")])
        lay.addWidget(self.yara_table, 3)
        return w

    def _build_evidence(self) -> QWidget:
        w = QSplitter(Qt.Orientation.Vertical)
        self.evidence_table = table([self.tr("掃描時間"), self.tr("掃描 #"), self.tr("引擎"), self.tr("引擎版本"),
                                     self.tr("規則／病毒碼版本"), self.tr("結果"), self.tr("規則 ID"), self.tr("嚴重度")])
        self.evidence_table.itemSelectionChanged.connect(self._show_evidence)
        self.evidence_detail = QTextBrowser()
        self.evidence_detail.setOpenLinks(False)
        w.addWidget(self.evidence_table)
        w.addWidget(self.evidence_detail)
        self._evidence_rows: list[tuple[EvidenceRun, int | None]] = []
        return w

    def _build_compare(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(muted(self.tr("把目前樣本（A）與另一個檔案（B）比較：雜湊、相同位移的位元組，以及兩者都是 PE 時的結構差異。")))
        row = QHBoxLayout()
        self.compare_edit = QLineEdit()
        self.compare_edit.setPlaceholderText(self.tr("檔案 B 的路徑"))
        self.compare_browse = QPushButton(self.tr("選擇檔案…"))
        self.compare_browse.clicked.connect(self._browse_compare)
        self.compare_button = QPushButton(self.tr("比較"))
        self.compare_button.clicked.connect(self.start_compare)
        self.compare_export_button = QPushButton(self.tr("匯出比較報告"))
        self.compare_export_button.clicked.connect(self.start_export_comparison)
        row.addWidget(self.compare_edit, 1)
        for b in (self.compare_browse, self.compare_button, self.compare_export_button):
            row.addWidget(b)
        lay.addLayout(row)
        self.compare_view = QTextBrowser()
        self.compare_view.setOpenLinks(False)
        lay.addWidget(self.compare_view, 1)
        return w

    def _build_timeline(self) -> QWidget:
        self.timeline_table = table([self.tr("時間（UTC）"), self.tr("類別"), self.tr("事件"), self.tr("細節")])
        return self.timeline_table

    # ---------- background work ----------
    @property
    def busy(self) -> bool:
        return self._thread is not None

    def _run(self, fn: Callable[[CancelToken], object], on_done: Callable[[Any], None], text: str) -> None:
        if self.busy:
            return
        self._cancel = CancelToken()
        cancel = self._cancel
        self._on_done_cb = on_done
        self._worker = CallWorker(lambda: fn(cancel))
        # Bound methods of this widget, so Qt queues the call onto the GUI thread.
        self._worker.finished.connect(self._done)
        self._worker.failed.connect(self._failed)
        self._status(text, theme.TEXT_MUTED)
        self._thread = start_worker(self._worker)
        self._update_buttons()

    def _finish(self) -> None:
        if self._thread is not None:
            self._thread.wait()
        self._thread = None
        self._worker = None
        self._cancel = None
        self._on_done_cb = None
        self._update_buttons()

    def _done(self, result: Any) -> None:
        cb = self._on_done_cb
        self._finish()
        if cb is not None:
            cb(result)

    def _failed(self, msg: str) -> None:
        self._finish()
        if msg.startswith("ScanCancelled"):
            self._status(self.tr("已取消。"), theme.TEXT_MUTED)
            return
        self._status(self.tr("失敗：{0}").format(msg), theme.BAD)

    def cancel(self) -> None:
        """Stops between steps; a running isolated worker process is killed."""
        if self._cancel is not None:
            self._cancel.cancel()
            self.cancel_button.setEnabled(False)
            self._status(self.tr("正在取消…"), theme.TEXT_MUTED)

    def shutdown(self) -> None:
        if self._cancel is not None:
            self._cancel.cancel()  # also kills the isolated worker process
        if self._thread is not None:
            self._thread.wait()
            self._thread = None
            self._worker = None

    def _update_buttons(self) -> None:
        idle = not self.busy
        self.progress.setVisible(not idle)
        self.cancel_button.setVisible(not idle)
        self.cancel_button.setEnabled(not idle)
        for b in (self.inspect_button, self.browse_button, self.lookup_button, self.load_rule_button,
                  self.yara_files_button, self.yara_folder_button, self.compare_browse):
            b.setEnabled(idle)
        self.yara_sample_button.setEnabled(idle and self.inspection is not None)
        self.compare_button.setEnabled(idle and self.inspection is not None)
        self.compare_export_button.setEnabled(idle and self.comparison is not None)
        self.export_button.setEnabled(idle and self.sha256 is not None)

    def _status(self, text: str, color: str) -> None:
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color};")

    # ---------- sample / hash ----------
    def _browse(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, self.tr("選擇要研究的檔案"))
        if f:
            self.path_edit.setText(f)

    def start_inspect(self) -> None:
        text = self.path_edit.text().strip()
        if not text:
            self._status(self.tr("請先選擇檔案。"), theme.WARN)
            return
        path, lab = Path(text), self._lab

        def job(cancel: CancelToken) -> object:
            insp = lab.inspect(path, cancel)
            sha = insp.facts.sha256
            return insp, lab.lookup(sha), lab.evidence(sha), lab.timeline(sha)

        self._run(job, self._on_loaded, self.tr("檢視中…（在獨立程序中解析 PE 與簽章）"))

    def start_lookup(self) -> None:
        text, lab = self.hash_edit.text(), self._lab

        def job(_cancel: CancelToken) -> object:
            lk = lab.lookup(text)
            return None, lk, lab.evidence(lk.sha256), lab.timeline(lk.sha256)

        self._run(job, self._on_loaded, self.tr("查詢中…"))

    def _on_loaded(self, result: tuple[SampleInspection | None, HashLookup, list[EvidenceRun], list[TimelineEvent]]) -> None:
        insp, lk, evidence, tl = result
        if self.sha256 != lk.sha256:
            self.comparison = None
            self.compare_view.clear()
        self.inspection, self.lookup_result, self.evidence, self.timeline = insp, lk, evidence, tl
        self.sha256 = lk.sha256
        if insp is not None:
            self.hash_edit.setText(lk.sha256)
        self._render_overview()
        self._render_pe()
        self._render_signature()
        self._render_evidence()
        self._render_timeline()
        self._update_buttons()
        msg = self.tr("已載入 {0}").format(insp.facts.path.name if insp else lk.sha256[:16] + "…")
        color = theme.OK
        if insp is not None and insp.worker_error:
            msg += self.tr("；結構分析失敗：{0}").format(insp.worker_error)
            color = theme.WARN
        self._status(msg, color)

    def refresh_history(self) -> None:
        """Reload stored evidence and timeline for the current hash (data may change on other pages)."""
        if self.sha256 is None or self.busy:
            return
        self.lookup_result = self._lab.lookup(self.sha256)
        self.evidence = self._lab.evidence(self.sha256)
        self.timeline = self._lab.timeline(self.sha256)
        self._render_overview()
        self._render_evidence()
        self._render_timeline()

    # ---------- rendering ----------
    def _render_overview(self) -> None:
        lk, insp = self.lookup_result, self.inspection
        if lk is None:
            return
        out = []
        if insp is not None:
            f = insp.facts
            out.append(f"<h3>{e(f.path.name)}</h3>")
            out.append(_rows([("路徑", f.path), ("大小", f"{f.size:,} bytes"), ("類型（依檔頭判斷）", f.file_type),
                              ("MD5", f.md5), ("SHA-1", f.sha1), ("SHA-256", f.sha256),
                              ("修改時間（UTC）", f.modified), ("建立時間（UTC）", f.created)]))
            if f.motw:
                out.append("<p><b>下載來源標記（Zone.Identifier）</b>：此標記可被修改，僅供參考</p>")
                out.append(_rows(list(f.motw.items())))
            else:
                out.append(f"<p style='color:{theme.TEXT_MUTED}'>沒有下載來源標記（Zone.Identifier）。</p>")
            iso = "是：獨立程序，記憶體上限 1 GB，禁止再啟動程序" if insp.worker_confined else "否（無法建立限制）"
            out.append(f"<p style='color:{theme.TEXT_MUTED}'>隔離分析程序：{e(iso)}；耗時 {insp.worker_ms} 毫秒</p>")
            if insp.sha_changed:
                out.append(f"<p style='color:{theme.WARN}'>分析期間檔案內容改變，結構分析可能對應到不同的內容。</p>")
        else:
            out.append(f"<h3>SHA-256 {e(lk.sha256)}</h3><p style='color:{theme.TEXT_MUTED}'>只依雜湊查詢，沒有檢視檔案本身。</p>")
        out.append("<h4>本機威脅情報</h4>")
        if lk.intel:
            out.append("<ul>" + "".join(f"<li>{e(m.source)} {e(m.source_version)}（可信度 {e(m.trust.value)}）："
                                        f"<b>{e(m.verdict.value)}</b> {e(m.label)}</li>" for m in lk.intel) + "</ul>")
        else:
            out.append(f"<p style='color:{theme.TEXT_MUTED}'>不在任何本機情報中（未知，不代表安全）。</p>")
        out.append("<h4>目前判定（資料庫中最新）</h4>")
        if lk.latest is not None:
            path, v = lk.latest
            out.append(_rows([("分類", f"{CLASS_TEXT[v.classification]}（{v.classification.value}）"), ("信心", v.confidence),
                              ("檔案", path), ("時間（UTC）", v.created_at)]))
        else:
            out.append(f"<p style='color:{theme.TEXT_MUTED}'>尚未掃描過，沒有判定。研究實驗室本身不產生判定；"
                       "要判定請在掃描中心掃描此檔案。</p>")
        out.append(f"<p>已儲存的引擎結果：{lk.stored_runs} 筆（見「偵測證據」）</p>")
        self.overview.setHtml("\n".join(out))

    def _render_pe(self) -> None:
        self.sections_table.setRowCount(0)
        self.imports_tree.clear()
        insp = self.inspection
        pe = insp.pe if insp else None
        if pe is None or not pe.info.get("is_pe"):
            msg = "沒有檔案可分析。" if insp is None else (
                insp.worker_error or ("不是 PE 檔案。" if pe is not None and pe.kind.value == "SKIPPED"
                                      else (pe.error if pe and pe.error else "PE 結構無法解析。")))
            extra = "".join(f"<li>{e(d.rule_id)}：{e(d.confidence_explanation)}</li>" for d in (pe.detections if pe else ()))
            self.pe_header.setHtml(f"<p>{e(msg)}</p>" + (f"<ul>{extra}</ul>" if extra else ""))
            return
        i = pe.info
        label, color = KIND_TEXT[pe.kind]
        parts = [f"<p>{e(pe.engine_name)} {e(pe.engine_version)}：<span style='color:{color}'>{label}</span></p>",
                 _rows([("架構", i.get("machine")), ("類型", "DLL" if i.get("is_dll") else "執行檔"),
                        (".NET", "是" if i.get("is_dotnet") else "否"), ("子系統", i.get("subsystem")),
                        ("編譯時間戳記", i.get("compile_timestamp")), ("進入點", f"{i.get('entry_point')}（{i.get('entry_point_section')}）"),
                        ("映像基底", i.get("image_base")), ("imphash", i.get("imphash")), ("匯出數", i.get("export_count")),
                        ("附加資料（overlay）", f"{i.get('overlay_bytes', 0):,} bytes")])]
        if pe.detections:
            parts.append("<p><b>結構特徵</b>（不是惡意判定）</p><ul>" + "".join(
                f"<li>[{e(d.severity_hint.value)}] {e(d.rule_id)}：{e(d.confidence_explanation)}</li>" for d in pe.detections) + "</ul>")
        vi = i.get("version_info") or {}
        if vi:
            parts.append("<p><b>版本資訊</b>（檔案自述，可被偽造）</p>" + _rows(list(vi.items())))
        if i.get("parser_warnings"):
            parts.append("<p><b>解析器警告</b></p><ul>" + "".join(f"<li>{e(w)}</li>" for w in i["parser_warnings"]) + "</ul>")
        self.pe_header.setHtml("\n".join(parts))
        for s in i.get("sections", []):
            r = self.sections_table.rowCount()
            self.sections_table.insertRow(r)
            perms = ("W" if s["writable"] else "-") + ("X" if s["executable"] else "-")
            for c, v in enumerate([s["name"], s["virtual_address"], s["virtual_size"], s["raw_size"], s["entropy"], perms]):
                self.sections_table.setItem(r, c, item(str(v), theme.WARN if (c == 5 and perms == "WX") else None))
        for dll, funcs in i.get("imports", {}).items():
            top = QTreeWidgetItem([dll, str(len(funcs))])
            for fn in funcs:
                top.addChild(QTreeWidgetItem([fn, ""]))
            self.imports_tree.addTopLevelItem(top)
        self.imports_tree.resizeColumnToContents(0)

    def _render_signature(self) -> None:
        self.chain_table.setRowCount(0)
        insp = self.inspection
        sig = insp.signature if insp else None
        if sig is None:
            self.sig_view.setHtml(f"<p>{e('沒有檔案可檢查。' if insp is None else insp.worker_error or '無法檢查簽章。')}</p>")
            return
        color = {"VALID": theme.OK, "INVALID": theme.BAD, "UNTRUSTED_ROOT": theme.WARN}.get(sig.status.value, theme.TEXT)
        self.sig_view.setHtml(
            f"<h3 style='color:{color}'>{e(sig.status.value)}：{e(sig.message)}</h3>"
            + _rows([("簽章來源", SIG_SOURCE.get(sig.source or "", "—")), ("目錄檔", sig.catalog_file),
                     ("驗證代碼", f"0x{sig.code:08X}" if sig.code is not None else None),
                     ("有時間戳記", "是" if sig.timestamped else "否"), ("簽署時間（時間戳記，UTC）", sig.signing_time),
                     ("備註", "；".join(sig.notes) if sig.notes else None)])
            + f"<p style='color:{theme.TEXT_MUTED}'>離線驗證：不檢查憑證撤銷，不連網。未簽署不代表惡意；"
              "有效簽章只證明來源與未被竄改，不證明安全。</p>")
        for c in sig.chain:
            r = self.chain_table.rowCount()
            self.chain_table.insertRow(r)
            for col, v in enumerate([c.subject, c.issuer, c.serial, c.not_before, c.not_after, c.sha1]):
                self.chain_table.setItem(r, col, item(v or "—"))

    def _render_evidence(self) -> None:
        self.evidence_table.setRowCount(0)
        self._evidence_rows = []
        self.evidence_detail.clear()
        for ev in self.evidence:
            r = ev.result
            for idx in (range(len(r.detections)) if r.detections else [None]):
                d = r.detections[idx] if idx is not None else None
                label, color = KIND_TEXT[r.kind]
                row = self.evidence_table.rowCount()
                self.evidence_table.insertRow(row)
                vals = [ev.scanned_at, str(ev.job_id), r.engine_name, r.engine_version or "—", r.rules_version or "—",
                        label, d.rule_id if d else (r.error or "—"), d.severity_hint.value if d else "—"]
                for c, v in enumerate(vals):
                    self.evidence_table.setItem(row, c, item(v, color if c == 5 else None))
                self._evidence_rows.append((ev, idx))
        if not self.evidence:
            self.evidence_detail.setHtml(f"<p style='color:{theme.TEXT_MUTED}'>資料庫中沒有此雜湊的掃描證據。</p>")

    def _show_evidence(self) -> None:
        rows = self.evidence_table.selectionModel().selectedRows()
        if not rows:
            return
        ev, idx = self._evidence_rows[rows[0].row()]
        r = ev.result
        parts = [_rows([("檔案路徑（掃描時）", ev.path), ("掃描", f"#{ev.job_id}，{ev.scanned_at}"),
                        ("引擎", f"{r.engine_name} {r.engine_version or ''}"), ("規則／病毒碼版本", r.rules_version),
                        ("耗時（毫秒）", r.duration_ms), ("錯誤", r.error)])]
        if idx is not None:
            d = r.detections[idx]
            parts.append(f"<h4>{e(d.rule_id)}（{e(d.severity_hint.value)}）</h4><p>{e(d.confidence_explanation)}</p>"
                         + _rows([("偵測時間", d.timestamp), ("檔案 SHA-256", d.file_sha256)])
                         + f"<pre>{e(json.dumps(d.evidence, ensure_ascii=False, indent=2))}</pre>")
        if r.info:
            parts.append("<p><b>引擎記錄的其他事實</b></p><pre>"
                         + e(json.dumps(r.info, ensure_ascii=False, indent=2)[:20000]) + "</pre>")
        self.evidence_detail.setHtml("\n".join(parts))

    def _render_timeline(self) -> None:
        self.timeline_table.setRowCount(0)
        for ev in self.timeline:
            r = self.timeline_table.rowCount()
            self.timeline_table.insertRow(r)
            for c, v in enumerate([ev.at, ev.category, ev.title, ev.detail]):
                self.timeline_table.setItem(r, c, item(v or "—"))

    # ---------- YARA ----------
    def _load_rule(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, self.tr("載入 YARA 規則"), "", "YARA (*.yar *.yara);;*.*")
        if f:
            self.load_rule_file(Path(f))

    def load_rule_file(self, path: Path) -> None:
        try:
            if path.stat().st_size > 1024 * 1024:
                raise ValueError("規則檔超過 1 MB。")
            self.rule_edit.setPlainText(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError) as exc:
            self.yara_label.setText(self.tr("無法載入：{0}").format(exc))

    def _yara_pick_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, self.tr("選擇要測試的無害檔案"))
        if files:
            self.run_yara([Path(f) for f in files])

    def _yara_pick_folder(self) -> None:
        d = QFileDialog.getExistingDirectory(self, self.tr("選擇資料夾（只測試第一層檔案）"))
        if d:
            self.run_yara([Path(d)])

    def run_yara(self, targets: list[Path]) -> None:
        source, lab = self.rule_edit.toPlainText(), self._lab
        self._run(lambda cancel: lab.yara_test(source, targets, cancel), self._on_yara, self.tr("YARA 測試中…"))

    def _on_yara(self, run: YaraTestRun) -> None:
        self.yara_runs.append(run)
        self.yara_table.setRowCount(0)

        def add(vals: list[str], color: str | None = None) -> None:
            r = self.yara_table.rowCount()
            self.yara_table.insertRow(r)
            for c, v in enumerate(vals):
                self.yara_table.setItem(r, c, item(v, color))

        for t in run.results:
            name = str(t.path)
            if t.error:
                add([name, "—", "—", "—", "—", "—", "—", t.error], theme.BAD)
            elif not t.hits:
                add([name, self.tr("（未命中）"), "", "", "", "", "", ""], theme.TEXT_MUTED)
            for h in t.hits:
                if not h.strings:
                    add([name, h.rule, "—", "—", "—", "—", "—", self.tr("條件命中，無字串")], theme.WARN)
                for s in h.strings:
                    add([name, h.rule, s.identifier, str(s.offset), str(s.length), s.hex, s.text,
                         self.tr("共 {0} 處").format(h.string_instances)], theme.WARN)
        msg = self.tr("{0} 條規則（SHA-256 {1}…），測試 {2} 個檔案，{3} 個命中。").format(
            run.rule_count, run.rule_sha256[:12], len(run.results), run.matched)
        if run.skipped:
            msg += self.tr(" 略過：") + "；".join(run.skipped)
        self.yara_label.setText(msg)
        self._status(self.tr("YARA 測試完成。測試規則不影響判定。"), theme.OK)
        self.tabs.setCurrentIndex(3)

    # ---------- comparison ----------
    def _browse_compare(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, self.tr("選擇要比較的檔案"))
        if f:
            self.compare_edit.setText(f)

    def start_compare(self) -> None:
        if self.inspection is None:
            return
        text = self.compare_edit.text().strip()
        if not text:
            self._status(self.tr("請先選擇檔案 B。"), theme.WARN)
            return
        a, b, lab = self.inspection.facts.path, Path(text), self._lab
        self._run(lambda cancel: lab.compare(a, b, cancel), self._on_compare, self.tr("比較中…"))

    def _on_compare(self, result: tuple[Comparison, SampleInspection, SampleInspection]) -> None:
        self.comparison = result
        self.compare_view.setHtml(render_comparison(result[0]))
        self._update_buttons()
        self._status(self.tr("比較完成：{0}").format(self.tr("內容完全相同") if result[0].identical else self.tr("內容不同")),
                     theme.OK)

    # ---------- export ----------
    def _kinds(self) -> list[ReportKind]:
        return [k for k, cb in ((ReportKind.JSON, self.fmt_json), (ReportKind.HTML, self.fmt_html),
                                (ReportKind.PDF, self.fmt_pdf)) if cb.isChecked()]

    def start_export(self) -> None:
        if self.sha256 is None:
            return
        sha, insp, runs, kinds, lab = self.sha256, self.inspection, list(self.yara_runs), self._kinds(), self._lab
        self._run(lambda _c: lab.export_sample(sha, insp, runs, kinds), self._on_exported, self.tr("產生報告中…"))

    def start_export_comparison(self) -> None:
        if self.comparison is None:
            return
        (cmp, a, b), kinds, lab = self.comparison, self._kinds(), self._lab
        self._run(lambda _c: lab.export_comparison(cmp, a, b, kinds), self._on_exported, self.tr("產生比較報告中…"))

    def _on_exported(self, res: GenerateResult) -> None:
        self.last_export = res
        files = "、".join(Path(r.path).name for r in res.rows)
        msg = self.tr("已產生：{0}（在「報告」頁面查看）").format(files) if res.rows else self.tr("沒有產生任何報告")
        if res.errors:
            msg += self.tr("；失敗：") + "；".join(res.errors)
        self.export_label.setText(msg)
        self.export_label.setStyleSheet(f"color: {theme.WARN if res.errors else theme.OK};")
        self._status(self.tr("報告已記錄在稽核紀錄中，並保存每個檔案的 SHA-256。"), theme.OK)
        self.refresh_history()


def render_comparison(c: Comparison) -> str:
    b = c.bytes
    same = "<b style='color:%s'>內容完全相同</b>" % theme.OK if c.identical else "<b>內容不同</b>"
    out = [f"<p>{same}</p>",
           _rows([("A", c.path_a), ("A 的 SHA-256", c.sha256_a), ("A 大小", f"{b.size_a:,}"),
                  ("B", c.path_b), ("B 的 SHA-256", c.sha256_b), ("B 大小", f"{b.size_b:,}"),
                  ("第一個不同的位移", b.first_difference), ("共同長度內不同的位元組", f"{b.differing_bytes:,}"),
                  ("相同位移位元組相同比例", f"{b.same_offset_ratio:.2%}")]),
           f"<p style='color:{theme.TEXT_MUTED}'>只比較相同位移的位元組，不是相似度演算法。</p>"]
    if c.pe is not None:
        p = c.pe
        if p.fields:
            out.append("<h4>PE 標頭差異</h4><table cellpadding='3'><tr><th>欄位</th><th>A</th><th>B</th></tr>"
                       + "".join(f"<tr><td>{e(k)}</td><td>{e(x)}</td><td>{e(y)}</td></tr>" for k, x, y in p.fields) + "</table>")
        else:
            out.append("<p>PE 標頭欄位相同。</p>")
        status = {"only_a": "只在 A", "only_b": "只在 B", "changed": "不同", "same": "相同"}
        out.append("<h4>區段</h4><ul>" + "".join(
            f"<li>{e(s.name)}：{status[s.status]}"
            + (f"（A {e(s.a['raw_size'])} bytes／亂度 {e(s.a['entropy'])}" if s.a else "（A —")
            + (f"；B {e(s.b['raw_size'])} bytes／亂度 {e(s.b['entropy'])}）" if s.b else "；B —）") + "</li>"
            for s in p.sections) + "</ul>")
        if p.imports:
            out.append("<h4>匯入差異</h4><ul>" + "".join(
                f"<li><b>{e(i.dll)}</b>：{status[i.status]}"
                + (f"；B 新增 {e(', '.join(i.added[:30]))}" if i.added else "")
                + (f"；B 缺少 {e(', '.join(i.removed[:30]))}" if i.removed else "") + "</li>" for i in p.imports) + "</ul>")
        else:
            out.append("<p>匯入相同。</p>")
        if p.version_info:
            out.append("<h4>版本資訊差異</h4><ul>" + "".join(
                f"<li>{e(k)}：A {e(x)}；B {e(y)}</li>" for k, x, y in p.version_info) + "</ul>")
        out.append(f"<p>簽章狀態：A {e(p.signature[0])}；B {e(p.signature[1])}</p>")
    else:
        out.append(f"<p style='color:{theme.TEXT_MUTED}'>兩個檔案不都是可解析的 PE 檔，沒有結構比較。</p>")
    for n in c.notes:
        out.append(f"<p style='color:{theme.WARN}'>{e(n)}</p>")
    return "\n".join(out)

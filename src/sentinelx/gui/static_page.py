"""Static Analysis page: analyze one file with all engines and show the evidence.

Every string that comes from the analyzed file (section names, imports, version info) is
HTML-escaped before display.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from PySide6.QtCore import QThread, Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextBrowser, QVBoxLayout, QWidget

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind
from sentinelx.core.risk import CLASS_TEXT
from sentinelx.gui import theme
from sentinelx.gui.threat_page import CLASS_COLOR
from sentinelx.gui.widgets import muted, title
from sentinelx.gui.workers import CallWorker, start_worker
from sentinelx.services.static_analysis_service import StaticAnalysisService, StaticReport

KIND_TEXT = {
    EngineOutcomeKind.FINDINGS: ("有發現", theme.WARN),
    EngineOutcomeKind.NO_FINDINGS: ("未發現", theme.OK),
    EngineOutcomeKind.SKIPPED: ("不適用", theme.TEXT_MUTED),
    EngineOutcomeKind.ERROR: ("無法評估", theme.BAD),
}
SEV_COLOR = {"HIGH": theme.BAD, "MEDIUM": theme.WARN, "LOW": theme.TEXT, "INFO": theme.TEXT_MUTED}


def e(v: Any) -> str:
    return html.escape(str(v))


class StaticAnalysisPage(QWidget):
    def __init__(self, service: StaticAnalysisService) -> None:
        super().__init__()
        self.setObjectName("page_static")
        self._svc = service
        self._thread: QThread | None = None
        self._worker: CallWorker | None = None
        self._cancel: CancelToken | None = None
        self.last_report: StaticReport | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(12)
        lay.addWidget(title(self.tr("靜態分析")))
        lay.addWidget(muted(self.tr("以所有啟用的引擎分析單一檔案。只讀取檔案內容，絕不執行檔案。")))
        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(self.tr("檔案路徑"))
        self.browse_button = QPushButton(self.tr("選擇檔案…"))
        self.browse_button.clicked.connect(self._browse)
        self.analyze_button = QPushButton(self.tr("開始分析"))
        self.analyze_button.clicked.connect(self.start_analysis)
        row.addWidget(self.path_edit, 1)
        row.addWidget(self.browse_button)
        row.addWidget(self.analyze_button)
        self.cancel_button = QPushButton(self.tr("取消"))
        self.cancel_button.clicked.connect(self.cancel)
        self.cancel_button.setEnabled(False)
        row.addWidget(self.cancel_button)
        lay.addLayout(row)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.status_label)
        self.report = QTextBrowser()
        self.report.setOpenLinks(False)
        lay.addWidget(self.report, 1)

    @property
    def busy(self) -> bool:
        return self._thread is not None

    def _browse(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, self.tr("選擇要分析的檔案"))
        if f:
            self.path_edit.setText(f)

    def start_analysis(self) -> None:
        if self.busy:
            return
        text = self.path_edit.text().strip()
        if not text:
            self._status(self.tr("請先選擇檔案。"), theme.WARN)
            return
        path = Path(text)
        self._cancel = CancelToken()
        cancel = self._cancel
        self._worker = CallWorker(lambda: self._svc.analyze(path, cancel))
        self._worker.finished.connect(self._on_done)
        self._worker.failed.connect(self._on_failed)
        self.analyze_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self._status(self.tr("分析中…（若啟用 ClamAV，載入病毒碼需要數秒）"), theme.TEXT_MUTED)
        self._thread = start_worker(self._worker)

    def _finish(self) -> None:
        if self._thread is not None:
            self._thread.wait()  # the worker already returned; the event loop is stopping
        self._thread = None
        self._worker = None
        self._cancel = None
        self.analyze_button.setEnabled(True)
        self.browse_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

    def cancel(self) -> None:
        if self._cancel is not None:
            self._cancel.cancel()
            self.cancel_button.setEnabled(False)
            self._status(self.tr("正在取消…（目前的引擎完成這個檔案後停止）"), theme.TEXT_MUTED)

    def _on_failed(self, msg: str) -> None:
        self._finish()
        if msg.startswith("ScanCancelled"):
            self._status(self.tr("已取消分析。"), theme.TEXT_MUTED)
            return
        self._status(self.tr("無法分析：{0}").format(msg), theme.BAD)

    def _on_done(self, rep: StaticReport) -> None:
        self._finish()
        self.last_report = rep
        n_err = sum(1 for r in rep.results if r.kind is EngineOutcomeKind.ERROR)
        n_det = sum(len(r.detections) for r in rep.results)
        msg = self.tr("分析完成：{0} 項發現").format(n_det)
        if n_err:
            msg += self.tr("，{0} 個引擎無法評估").format(n_err)
        color = theme.WARN if (n_err or n_det) else theme.OK
        if rep.assessment is not None:
            msg += self.tr("。綜合判定：{0}").format(CLASS_TEXT[rep.assessment.classification])
            color = CLASS_COLOR[rep.assessment.classification]
        self._status(msg, color)
        self.report.setHtml(render_report(rep))

    def shutdown(self) -> None:
        """Cancel and wait until the worker has stopped. A QThread must never be destroyed
        while running (Qt aborts the process). Cancellation is checked between engines and
        inside ClamAV; the worst case is one in-flight YARA match up to its timeout."""
        if self._cancel is not None:
            self._cancel.cancel()
        if self._thread is not None:
            self._thread.wait()
            self._thread = None
            self._worker = None

    def _status(self, text: str, color: str) -> None:
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color};")


def render_report(rep: StaticReport) -> str:
    out = [f"<h3>{e(rep.path.name)}</h3>",
           f"<p>路徑：{e(rep.path)}<br>大小：{rep.size:,} bytes<br>SHA-256：<code>{e(rep.sha256)}</code></p>"]
    a = rep.assessment
    if a is not None:
        c = CLASS_COLOR[a.classification]
        out.append(f"<h3 style='color:{c}'>綜合判定：{e(CLASS_TEXT[a.classification])}</h3>")
        out.append("<pre style='white-space:pre-wrap'>" + e(a.explanation) + "</pre>")
        out.append("<p style='color:%s'>此判定不會儲存；要留下紀錄並審查，請在掃描中心掃描此檔案。</p>" % theme.TEXT_MUTED)
    for r in rep.results:
        label, color = KIND_TEXT[r.kind]
        ver = f" {e(r.engine_version)}" if r.engine_version else ""
        out.append(f"<h4>{e(r.engine_name)}{ver}：<span style='color:{color}'>{label}</span></h4>")
        if r.rules_version:
            out.append(f"<p style='color:{theme.TEXT_MUTED}'>規則／資料版本：{e(r.rules_version)}</p>")
        if r.error:
            out.append(f"<p style='color:{theme.BAD}'>{e(r.error)}</p>")
        if r.detections:
            out.append("<ul>")
            for d in r.detections:
                c = SEV_COLOR.get(d.severity_hint.value, theme.TEXT)
                out.append(f"<li><b style='color:{c}'>[{e(d.severity_hint.value)}] {e(d.rule_id)}</b><br>"
                           f"{e(d.confidence_explanation)}</li>")
            out.append("</ul>")
        out.append(_render_info(r.engine_name, r.info))
    return "\n".join(out)


def _render_info(engine: str, info: dict[str, Any]) -> str:
    if not info:
        return ""
    if engine == "PEStatic" and info.get("is_pe"):
        sig = info.get("signature", {})
        parts = [
            "<table cellspacing='0' cellpadding='3'>",
            *(f"<tr><td style='color:{theme.TEXT_MUTED}'>{e(k)}</td><td>{e(v)}</td></tr>" for k, v in [
                ("架構", info.get("machine")), ("類型", "DLL" if info.get("is_dll") else "執行檔"),
                (".NET", "是" if info.get("is_dotnet") else "否"), ("子系統", info.get("subsystem")),
                ("編譯時間", info.get("compile_timestamp")), ("進入點", f"{info.get('entry_point')}（{info.get('entry_point_section')}）"),
                ("數位簽章", f"{sig.get('status')}：{sig.get('message')}"), ("imphash", info.get("imphash")),
                ("附加資料 (overlay)", f"{info.get('overlay_bytes', 0):,} bytes"),
            ]),
            "</table>",
        ]
        if info.get("version_info"):
            parts.append("<p><b>版本資訊</b><br>" + "<br>".join(
                f"{e(k)}：{e(v)}" for k, v in info["version_info"].items()) + "</p>")
        parts.append("<p><b>區段</b></p><table cellspacing='0' cellpadding='3'><tr>"
                     "<th>名稱</th><th>虛擬大小</th><th>原始大小</th><th>亂度</th><th>權限</th></tr>")
        for s in info.get("sections", []):
            perms = ("W" if s["writable"] else "-") + ("X" if s["executable"] else "-")
            parts.append(f"<tr><td>{e(s['name'])}</td><td>{s['virtual_size']}</td><td>{s['raw_size']}</td>"
                         f"<td>{s['entropy']}</td><td>{perms}</td></tr>")
        parts.append("</table>")
        imports = info.get("imports", {})
        parts.append(f"<p><b>匯入</b>（{len(imports)} 個 DLL，{info.get('import_function_count', 0)} 個函式）</p><ul>")
        for dll, funcs in imports.items():
            shown = ", ".join(funcs[:25]) + (" …" if len(funcs) > 25 else "")
            parts.append(f"<li><b>{e(dll)}</b>：{e(shown)}</li>")
        parts.append("</ul>")
        return "\n".join(parts)
    if engine == "HashIntel":
        rep = {"MALICIOUS": "列為惡意", "KNOWN_GOOD": "已知良好", "UNKNOWN": "未知（不在任何本機情報中，不代表安全）"}
        return f"<p>信譽：{e(rep.get(info.get('reputation', ''), info.get('reputation')))}</p>"
    return ""

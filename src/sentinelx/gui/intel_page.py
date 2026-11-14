"""Threat Intelligence page: local hash intelligence sources and YARA rule sets."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThread
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from sentinelx.core.enums import IntelVerdict, TrustLevel
from sentinelx.gui import theme
from sentinelx.gui.widgets import item, muted, table, title
from sentinelx.gui.workers import CallWorker, start_worker
from sentinelx.services.intel_service import IntelService
from sentinelx.storage.intel_repository import ImportResult

TRUST_TEXT = {TrustLevel.HIGH: "高", TrustLevel.MEDIUM: "中", TrustLevel.LOW: "低"}
VERDICT_TEXT = {IntelVerdict.MALICIOUS: "惡意", IntelVerdict.KNOWN_GOOD: "已知良好"}


class ThreatIntelPage(QWidget):
    def __init__(self, intel: IntelService) -> None:
        super().__init__()
        self.setObjectName("page_intel")
        self._intel = intel
        self._import_thread: QThread | None = None
        self._import_worker: CallWorker | None = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(12)
        lay.addWidget(title(self.tr("威脅情報")))
        lay.addWidget(muted(self.tr("所有情報都存放在本機，不會連網查詢。雜湊不在任何清單中代表「未知」，不代表安全。")))
        self.tabs = QTabWidget()
        self.tabs.addTab(self._hash_tab(), self.tr("雜湊情報"))
        self.tabs.addTab(self._yara_tab(), self.tr("YARA 規則"))
        lay.addWidget(self.tabs, 1)
        self.refresh_sources()
        self.refresh_rules()

    # ---------- hash intel ----------
    def _hash_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        row = QHBoxLayout()
        self.src_name = QLineEdit()
        self.src_name.setPlaceholderText(self.tr("來源名稱，例如 MyBlocklist"))
        self.src_trust = QComboBox()
        for t in (TrustLevel.MEDIUM, TrustLevel.HIGH, TrustLevel.LOW):
            self.src_trust.addItem(self.tr("可信度：") + TRUST_TEXT[t], t.value)
        self.src_verdict = QComboBox()
        for vd in (IntelVerdict.MALICIOUS, IntelVerdict.KNOWN_GOOD):
            self.src_verdict.addItem(self.tr("預設分類：") + VERDICT_TEXT[vd], vd.value)
        self.import_button = QPushButton(self.tr("匯入雜湊清單…"))
        self.import_button.clicked.connect(self._pick_hash_file)
        row.addWidget(self.src_name, 2)
        row.addWidget(self.src_trust)
        row.addWidget(self.src_verdict)
        row.addWidget(self.import_button)
        v.addLayout(row)
        v.addWidget(muted(self.tr("格式：每行一個 SHA-256，可加「,名稱,分類」（分類為 malicious 或 known_good）。")))
        self.hash_msg = QLabel()
        self.hash_msg.setWordWrap(True)
        self.hash_msg.setTextFormat(Qt.TextFormat.PlainText)
        v.addWidget(self.hash_msg)
        self.src_table = table(["#", "來源", "可信度", "惡意", "已知良好", "匯入時間 (UTC)", "說明"])
        v.addWidget(self.src_table, 1)
        self.remove_src_button = QPushButton(self.tr("刪除選取的來源"))
        self.remove_src_button.clicked.connect(self._remove_source)
        v.addWidget(self.remove_src_button, alignment=Qt.AlignmentFlag.AlignLeft)

        look = QHBoxLayout()
        self.lookup_edit = QLineEdit()
        self.lookup_edit.setPlaceholderText(self.tr("輸入 SHA-256 查詢"))
        self.lookup_button = QPushButton(self.tr("查詢"))
        self.lookup_button.clicked.connect(self.lookup)
        look.addWidget(self.lookup_edit, 1)
        look.addWidget(self.lookup_button)
        v.addLayout(look)
        self.lookup_result = QLabel()
        self.lookup_result.setWordWrap(True)
        self.lookup_result.setTextFormat(Qt.TextFormat.PlainText)  # labels come from imported files
        self.lookup_result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(self.lookup_result)
        return w

    def _pick_hash_file(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, self.tr("選擇雜湊清單"), "", self.tr("文字檔 (*.txt *.csv);;所有檔案 (*)"))
        if f:
            self.import_hashes(Path(f))

    @property
    def importing(self) -> bool:
        return self._import_thread is not None

    def import_hashes(self, path: Path) -> None:
        """Runs in the background: a large list (up to 200 MB) takes minutes to store."""
        if self.importing:
            return
        svc, name = self._intel, self.src_name.text()
        trust, verdict = TrustLevel(self.src_trust.currentData()), IntelVerdict(self.src_verdict.currentData())
        self._import_worker = CallWorker(lambda: svc.import_hashes(path, name, trust, verdict))
        self._import_worker.finished.connect(self._on_imported)
        self._import_worker.failed.connect(self._on_import_failed)
        self.import_button.setEnabled(False)
        self._msg(self.hash_msg, self.tr("匯入中…（大型清單可能需要數分鐘）"), theme.TEXT_MUTED)
        self._import_thread = start_worker(self._import_worker)

    def _end_import(self) -> None:
        if self._import_thread is not None:
            self._import_thread.wait()
        self._import_thread = None
        self._import_worker = None
        self.import_button.setEnabled(True)

    def _on_import_failed(self, msg: str) -> None:
        self._end_import()
        self._msg(self.hash_msg, msg, theme.BAD)

    def shutdown(self) -> None:
        if self._import_thread is not None:
            self._import_thread.wait()  # the import is one transaction; let it finish
            self._import_thread = None
            self._import_worker = None

    def _on_imported(self, res: ImportResult) -> None:
        self._end_import()
        text = self.tr("已匯入 {0} 筆").format(res.imported)
        if res.duplicates:
            text += self.tr("，重複 {0} 筆已略過").format(res.duplicates)
        if res.invalid_count:
            text += self.tr("，無效 {0} 行（第 {1} 行…）").format(res.invalid_count, ", ".join(map(str, res.invalid_lines[:5])))
        self._msg(self.hash_msg, text, theme.WARN if res.invalid_count else theme.OK)
        self.src_name.clear()
        self.refresh_sources()

    def refresh_sources(self) -> None:
        rows = self._intel.sources()
        self.src_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for c, val in enumerate([str(r.id), r.name, TRUST_TEXT[r.trust], str(r.malicious), str(r.known_good),
                                     r.imported_at, r.origin_note or ""]):
                self.src_table.setItem(i, c, item(val))

    def _remove_source(self) -> None:
        row = self.src_table.currentRow()
        if row < 0:
            self._msg(self.hash_msg, self.tr("請先選取要刪除的來源。"), theme.WARN)
            return
        self._intel.remove_source(int(self.src_table.item(row, 0).text()))
        self.hash_msg.clear()
        self.refresh_sources()

    def lookup(self) -> None:
        try:
            matches = self._intel.lookup(self.lookup_edit.text())
        except ValueError as exc:
            self._msg(self.lookup_result, str(exc), theme.BAD)
            return
        if not matches:
            self._msg(self.lookup_result, self.tr("未知：此雜湊不在任何本機情報來源中（不代表安全）。"), theme.TEXT_MUTED)
            return
        parts = [f"{m.source}（可信度 {TRUST_TEXT[m.trust]}）：{VERDICT_TEXT[m.verdict]}" + (f"，{m.label}" if m.label else "")
                 for m in matches]
        bad = any(m.verdict is IntelVerdict.MALICIOUS for m in matches)
        self._msg(self.lookup_result, "；".join(parts), theme.BAD if bad else theme.OK)

    # ---------- YARA ----------
    def _yara_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        row = QHBoxLayout()
        self.rule_name = QLineEdit()
        self.rule_name.setPlaceholderText(self.tr("規則集名稱（預設為檔名）"))
        self.rule_version = QLineEdit()
        self.rule_version.setPlaceholderText(self.tr("版本（選填，預設自動產生）"))
        self.add_rule_button = QPushButton(self.tr("加入規則檔…"))
        self.add_rule_button.clicked.connect(self._pick_rule_file)
        row.addWidget(self.rule_name, 2)
        row.addWidget(self.rule_version, 1)
        row.addWidget(self.add_rule_button)
        v.addLayout(row)
        v.addWidget(muted(self.tr("規則檔會被複製到 Sentinel X 的資料夾並以 SHA-256 鎖定；之後若被修改會自動停用。不允許 include 與 console 等模組。")))
        self.rule_msg = QLabel()
        self.rule_msg.setWordWrap(True)
        self.rule_msg.setTextFormat(Qt.TextFormat.PlainText)  # includes YARA compiler messages
        v.addWidget(self.rule_msg)
        self.rule_table = table(["#", "名稱", "版本", "規則數", "狀態", "已啟用", "驗證訊息"])
        v.addWidget(self.rule_table, 1)
        btns = QHBoxLayout()
        self.toggle_rule_button = QPushButton(self.tr("啟用 / 停用"))
        self.toggle_rule_button.clicked.connect(self._toggle_rule)
        self.remove_rule_button = QPushButton(self.tr("刪除規則集"))
        self.remove_rule_button.clicked.connect(self._remove_rule)
        btns.addWidget(self.toggle_rule_button)
        btns.addWidget(self.remove_rule_button)
        btns.addStretch(1)
        v.addLayout(btns)
        return w

    def _pick_rule_file(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, self.tr("選擇 YARA 規則檔"), "", self.tr("YARA (*.yar *.yara);;所有檔案 (*)"))
        if f:
            self.add_rule_file(Path(f))

    def add_rule_file(self, path: Path) -> None:
        try:
            r = self._intel.add_rule_file(path, self.rule_name.text() or None, self.rule_version.text() or None)
        except ValueError as exc:
            self._msg(self.rule_msg, str(exc), theme.BAD)
            return
        if r.valid:
            self._msg(self.rule_msg, self.tr("已加入並啟用「{0}」，共 {1} 條規則。").format(r.name, r.rule_count), theme.OK)
        else:
            self._msg(self.rule_msg, self.tr("已加入「{0}」但驗證失敗，未啟用：{1}").format(r.name, r.validation_error), theme.BAD)
        self.rule_name.clear()
        self.rule_version.clear()
        self.refresh_rules()

    def refresh_rules(self) -> None:
        rows = self._intel.rule_sets()
        self.rule_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            status, color = (("有效", theme.OK) if r.valid else ("驗證失敗", theme.BAD))
            vals = [str(r.id), r.name, r.version, str(r.rule_count), status, "是" if r.enabled else "否",
                    r.validation_error or ""]
            for c, val in enumerate(vals):
                self.rule_table.setItem(i, c, item(val, color if c == 4 else None))

    def _selected_rule_id(self) -> int | None:
        row = self.rule_table.currentRow()
        if row < 0:
            self._msg(self.rule_msg, self.tr("請先選取規則集。"), theme.WARN)
            return None
        return int(self.rule_table.item(row, 0).text())

    def _toggle_rule(self) -> None:
        rid = self._selected_rule_id()
        if rid is None:
            return
        current = next(r for r in self._intel.rule_sets() if r.id == rid)
        try:
            self._intel.set_rule_enabled(rid, not current.enabled)
        except ValueError as exc:
            self._msg(self.rule_msg, str(exc), theme.BAD)
            return
        self.rule_msg.clear()
        self.refresh_rules()

    def _remove_rule(self) -> None:
        rid = self._selected_rule_id()
        if rid is None:
            return
        self._intel.remove_rule_set(rid)
        self.rule_msg.clear()
        self.refresh_rules()

    @staticmethod
    def _msg(lbl: QLabel, text: str, color: str) -> None:
        lbl.setText(text)
        lbl.setStyleSheet(f"color: {color};")

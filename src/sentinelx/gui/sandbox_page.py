"""Trial-run room page: run a file you want to install inside a disposable virtual machine first."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from sentinelx.core.enums import Classification
from sentinelx.gui import theme
from sentinelx.gui.confirm import Confirm, ask
from sentinelx.gui.widgets import BusyBar, muted, title
from sentinelx.gui.workers import TaskRunner
from sentinelx.sandbox import FINISHED
from sentinelx.services.sandbox_service import SandboxService, TrialResult

Picker = Callable[[QWidget], Path | None]


def _pick(parent: QWidget) -> Path | None:
    f, _ = QFileDialog.getOpenFileName(parent, "選擇要試跑的檔案")
    return Path(f) if f else None


class SandboxPage(QWidget):
    def __init__(self, service: SandboxService, confirm: Confirm = ask, picker: Picker = _pick,
                 quarantine: Callable[[int], str] | None = None, finished: bool = FINISHED) -> None:
        super().__init__()
        self.setObjectName("page_sandbox")
        self._svc = service
        self.confirm = confirm
        self._pick = picker
        self._quarantine = quarantine
        self.runner = TaskRunner(self)
        self.runner.busy_changed.connect(lambda _b: self.refresh())
        self.result: TrialResult | None = None
        self.finished = finished

        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 20)
        lay.setSpacing(12)
        lay.addWidget(title(self.tr("試跑室")))
        lay.addWidget(muted(self.tr(
            "想安裝一個軟體但不確定安不安全？先放進「試跑室」：Sentinel X 會在一台隔離、沒有網路的假電腦（虛擬機）裡執行它，"
            "觀察一段時間，看它有沒有做壞事。結束後假電腦會整台還原，你的電腦完全不會執行這個檔案。"
            "每次試跑都會先讓假電腦重新開機（約 3～6 分鐘），再加上你選的觀察時間。"
            "試跑前會先向 VirtualBox 官方網站確認最新版本（一天一次，不會送出你電腦的資料）；版本太舊就不試跑，請你先更新。"
            "注意：有些病毒會發現自己在虛擬機裡而裝乖，或等更久才發作，所以「沒看到壞事」不代表一定安全。")))

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.status_label)

        row = QHBoxLayout()
        self.run_button = QPushButton(self.tr("選擇檔案，開始試跑…"))
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self.start_trial)
        self.duration = QComboBox()
        for label, sec in (("觀察 2 分鐘（建議）", 120), ("觀察 5 分鐘", 300), ("觀察 10 分鐘（抓會先等一下的病毒）", 600),
                           ("觀察 30 分鐘（最仔細）", 1800), ("觀察 1 分鐘", 60)):
            self.duration.addItem(self.tr(label), sec)
        self.build_button = QPushButton(self.tr("建立試跑室"))
        self.build_button.clicked.connect(self.start_build)
        row.addWidget(self.run_button)
        row.addWidget(self.duration)
        row.addStretch(1)
        row.addWidget(self.build_button)
        lay.addLayout(row)
        self.busy_bar = BusyBar(self.runner)
        lay.addWidget(self.busy_bar)

        self.result_box = QFrame()
        self.result_box.setObjectName("card")
        rb = QVBoxLayout(self.result_box)
        rb.setContentsMargins(20, 14, 20, 14)
        self.result_title = QLabel()
        self.result_title.setObjectName("rowTitle")
        self.result_title.setWordWrap(True)
        self.result_title.setTextFormat(Qt.TextFormat.PlainText)
        self.behaviours = QListWidget()
        self.behaviours.setMaximumHeight(170)
        self.result_detail = QLabel()
        self.result_detail.setObjectName("muted")
        self.result_detail.setWordWrap(True)
        self.result_detail.setTextFormat(Qt.TextFormat.PlainText)
        self.quarantine_button = QPushButton(self.tr("把這個檔案關進隔離區"))
        self.quarantine_button.clicked.connect(self.quarantine_result)
        for w in (self.result_title, self.behaviours, self.result_detail, self.quarantine_button):
            rb.addWidget(w)
        self.result_box.setVisible(False)
        lay.addWidget(self.result_box)
        self.msg = QLabel()
        self.msg.setWordWrap(True)
        self.msg.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.msg)
        lay.addStretch(1)
        self.refresh()

    @property
    def busy(self) -> bool:
        return self.runner.busy or self._svc.busy

    def shutdown(self) -> None:
        self.runner.shutdown()

    def refresh(self) -> None:
        st = self._svc.status()
        if not self.finished:
            self.status_label.setText(self.tr(
                "試跑室還在開發中，暫時不能使用：在真的電腦上建立假電腦時還有問題沒解決。"
                "完成並通過測試前，下面的按鈕會保持停用。"))
            self.status_label.setStyleSheet(f"color: {theme.WARN};")
            for b in (self.build_button, self.run_button):
                b.setEnabled(False)
            self.duration.setEnabled(False)
            return
        current = st.version_check is None or st.version_check.ok  # audit 8, M6
        text = self.tr("狀態：") + st.detail
        if st.version_check is not None and st.version_check.ok:
            text += "\n" + st.version_check.message
        self.status_label.setText(text)
        good = st.ready and not st.rebuild_due and current
        self.status_label.setStyleSheet(f"color: {theme.OK if good else (theme.WARN if current else theme.BAD)};")
        can_build = bool(st.virtualbox and st.iso) and current
        self.build_button.setText(self.tr("重建試跑室") if st.vm_exists else self.tr("建立試跑室"))
        self.build_button.setEnabled(can_build and not self.busy)
        self.run_button.setEnabled(st.ready and current and not self.busy)
        self.duration.setEnabled(not self.busy)

    def _msg(self, text: str, color: str) -> None:
        self.msg.setText(text)
        self.msg.setStyleSheet(f"color: {color};")

    def start_build(self) -> None:
        if self.busy or not self.finished:
            return
        st = self._svc.status()
        text = self.tr("建立試跑室會自動在虛擬機裡安裝 Windows（約 1～2 小時，期間可以照常用電腦，但會比較慢）。"
                       "安裝期間假電腦會暫時連上網路，向微軟啟用免費試用版；那時裡面還沒有任何要測試的檔案，"
                       "啟用後網路卡會整個拔掉再存成乾淨狀態，之後試跑一律沒有網路。"
                       "會用到約 4 GB 記憶體和 20～40 GB 硬碟空間。要開始嗎？")
        if st.vm_exists:
            text = self.tr("重建會刪除目前的試跑室，再從頭安裝一次（約 1～2 小時）。要開始嗎？")
        if not self.confirm(self, self.tr("建立試跑室"), text):
            return
        svc = self._svc

        def done(_r: object) -> None:
            self._msg(self.tr("試跑室建立完成，可以開始試跑。"), theme.OK)
            self.refresh()

        def failed(m: str) -> None:
            self._msg(self.tr("建立失敗：{0}").format(m), theme.BAD)
            self.refresh()

        self.runner.run(lambda c: svc.build(self.runner.message.emit, c), done, failed, self.tr("準備建立試跑室…"))

    def start_trial(self, path: Path | None = None) -> None:
        if self.busy or not self.finished:
            return
        path = path or self._pick(self)
        if path is None:
            return
        seconds = int(self.duration.currentData())
        svc = self._svc
        self.result_box.setVisible(False)

        def done(r: object) -> None:
            self.show_result(r)  # type: ignore[arg-type]
            self.refresh()

        def failed(m: str) -> None:
            self._msg(self.tr("試跑失敗：{0}").format(m), theme.BAD)
            self.refresh()

        self.runner.run(lambda c: svc.trial(path, seconds=seconds, progress=self.runner.message.emit, cancel=c),
                        done, failed, self.tr("準備試跑…"))

    def show_result(self, r: TrialResult) -> None:
        self.result = r
        bad = r.classification is Classification.CONFIRMED_THREAT
        warn = bool(r.behaviours) or r.classification is Classification.SUSPICIOUS
        color = theme.BAD if bad else (theme.WARN if warn else theme.OK)
        self.result_title.setText(f"{Path(r.path).name}\n{r.summary}")
        self.result_title.setStyleSheet(f"color: {color};")
        self.behaviours.clear()
        for b in r.behaviours or [self.tr("沒有觀察到可疑行為。")]:
            self.behaviours.addItem(b)
        procs = [p.get("name") for p in r.report.get("processes") or [] if p.get("name")]
        self.result_detail.setText(self.tr("試跑時啟動的程式：{0}。完整證據在「需要處理的檔案」與掃描紀錄中。").format(
            "、".join(procs[:8]) or self.tr("（沒有）")))
        self.quarantine_button.setVisible(bad and self._quarantine is not None and r.file is not None
                                          and r.file.verdict_id is not None)
        self.result_box.setVisible(True)
        self._msg("", theme.TEXT)

    def quarantine_result(self) -> None:
        r = self.result
        if r is None or r.file is None or r.file.verdict_id is None or self._quarantine is None:
            return
        if not self.confirm(self, self.tr("隔離檔案"), self.tr("把 {0} 關進隔離區？（不會刪除，誤判時可以還原）").format(r.path)):
            return
        if self.busy:
            return
        quarantine, vid = self._quarantine, r.file.verdict_id
        self.quarantine_button.setVisible(False)

        def failed(m: str) -> None:
            self._msg(m, theme.BAD)
            self.quarantine_button.setVisible(True)

        # In the background: a large installer takes a while to copy into the vault (audit 8, L5).
        self.runner.run(lambda _c: quarantine(vid), lambda msg: self._msg(str(msg), theme.OK), failed,
                        self.tr("隔離中…"), cancellable=False)

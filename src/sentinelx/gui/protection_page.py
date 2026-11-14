"""Real-time protection page: on/off, what is watched, engine state, options, recent activity."""

from __future__ import annotations

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from sentinelx.gui import theme
from sentinelx.gui.confirm import Confirm, ask
from sentinelx.gui.widgets import item, muted, table, title
from sentinelx.services.protection_service import ProtectionService

LEVEL_COLOR = {"info": theme.TEXT, "warn": theme.WARN, "bad": theme.BAD}
ENGINE_TEXT = {"ready": ("就緒", theme.OK), "starting": ("載入中", theme.WARN), "error": ("無法使用", theme.BAD),
               "stopped": ("未啟動", theme.TEXT_MUTED), "clamscan": ("clamscan（較慢）", theme.WARN),
               "low_memory": ("省記憶體模式", theme.WARN)}
OPTIONS = (
    ("auto_quarantine", "自動隔離病毒",
     "確定是病毒的檔案會被關進隔離區，不能執行；不會刪除，誤判時可以還原。"),
    ("exec_lock", "新程式先鎖住",
     "下載、桌面、文件與 USB 裡新出現的 .exe 等程式，檢查完之前不能打開；沒問題會自動解鎖，通常幾秒。"),
    ("watch_autostart", "盯住開機自動執行",
     "病毒最常把自己設成「每次開機都自動執行」。有程式新加入開機自動執行（登錄機碼、啟動資料夾、排程工作、服務）時，"
     "會立刻檢查它；有問題或沒有數位簽章就通知你。只觀察，不會自己刪除任何設定。"),
    ("ransomware_watch", "勒索病毒警報",
     "如果你的文件、照片在短時間內被大量改成奇怪的副檔名或被換掉（勒索病毒加密檔案的樣子），立刻警告你，"
     "並列出寫入最多的程式讓你停止。不會自動停止任何程式。"),
    ("ransomware_decoys", "放置防勒索誘餌檔",
     "在文件、桌面、圖片等資料夾放一個隱藏的「誘餌」資料夾（幾個假文件，約 70 KB）。一般程式不會碰它們，"
     "被改動就幾乎確定是勒索病毒，能更早發現。關掉時會自動移除。"),
    ("kill_known_threats", "關掉正在執行的病毒",
     "如果已知的病毒（包括從隔離區拿出來的）被打開，會立刻把它關掉。"),
    ("download_gate", "下載完成時告訴我結果",
     "下載安裝檔後跳通知，說明有沒有發現問題、是誰發行的。"),
    ("start_at_login", "開機時自動啟動",
     "登入 Windows 後在右下角常駐，不用每次自己打開。"),
    ("watch_all_drives", "全域防護：檢查所有硬碟",
     "所有硬碟上新增或修改的檔案都會檢查（Windows 系統資料夾與不停變動的快取除外）。開啟時下面四個資料夾選項不需要。"),
    ("low_memory", "省記憶體模式（8 GB 以下的電腦）",
     "不讓 ClamAV 一直待在記憶體裡，約省 950 MB。代價：下載、桌面、文件、USB 的檔案仍用 ClamAV 檢查但比較慢（每次要先載入病毒碼）；"
     "其他位置的檔案只用 YARA、雜湊比對和 VirusTotal 檢查，抓得比較少。記憶體夠用就不要開。"),
    ("watch_downloads", "檢查下載資料夾", "大部分病毒是從網路下載來的，建議一定要開。"),
    ("watch_desktop_documents", "檢查桌面和文件", "放到桌面或文件資料夾的新檔案也會被檢查。"),
    ("watch_temp", "檢查暫存資料夾", "程式安裝或解壓縮時常用的資料夾；可能會增加一點負擔。"),
    ("watch_removable", "檢查 USB 隨身碟", "插入隨身碟或記憶卡時，自動檢查裡面的檔案。"),
)


class ProtectionBridge(QObject):
    """Carries notifications from protection threads to the GUI thread."""

    notified = Signal(str, str, str)  # level, title, message
    signatures_changed = Signal()  # automatic signature update finished


class ProtectionPage(QWidget):
    def __init__(self, service: ProtectionService, confirm: Confirm = ask) -> None:
        super().__init__()
        self.setObjectName("page_protection")
        self._svc = service
        self.confirm = confirm
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        scroll.setWidget(body)
        outer.addWidget(scroll)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(32, 28, 32, 20)
        lay.setSpacing(12)
        lay.addWidget(title(self.tr("即時防護")))
        lay.addWidget(muted(self.tr(
            "開啟後，新檔案一出現就會自動檢查。它是 Windows Defender 之外的第二道防線，請兩個一起用。"
            "限制：只有下載資料夾裡的新程式能在打開前擋下；其他檔案是出現後幾秒內檢查。")))

        top = QHBoxLayout()
        self.state_label = QLabel()
        self.state_label.setObjectName("cardValue")
        self.state_label.setTextFormat(Qt.TextFormat.PlainText)
        self.toggle_button = QPushButton()
        self.toggle_button.clicked.connect(self.toggle)
        top.addWidget(self.state_label, 1)
        top.addWidget(self.toggle_button)
        lay.addLayout(top)

        info = QGridLayout()
        self.engine_label = QLabel()
        self.counts_label = QLabel()
        self.where_label = QLabel()
        for i, lbl in enumerate((self.engine_label, self.counts_label, self.where_label)):
            lbl.setWordWrap(True)
            lbl.setTextFormat(Qt.TextFormat.PlainText)
            info.addWidget(lbl, i, 0)
        lay.addLayout(info)

        # Ransomware warning: shown only while there is one; nothing is stopped without the user.
        self.alert_box = QFrame()
        self.alert_box.setObjectName("card")
        ab = QVBoxLayout(self.alert_box)
        ab.setContentsMargins(20, 14, 20, 14)
        self.alert_title = QLabel()
        self.alert_title.setObjectName("rowTitle")
        self.alert_title.setWordWrap(True)
        self.alert_title.setTextFormat(Qt.TextFormat.PlainText)
        self.alert_text = QLabel()
        self.alert_text.setWordWrap(True)
        self.alert_text.setTextFormat(Qt.TextFormat.PlainText)
        self.writers = QListWidget()
        self.writers.setMaximumHeight(110)
        arow = QHBoxLayout()
        self.stop_button = QPushButton(self.tr("停止選取的程式"))
        self.stop_button.setObjectName("danger")
        self.stop_button.clicked.connect(self.stop_selected_writer)
        self.dismiss_button = QPushButton(self.tr("我知道了，關閉警報"))
        self.dismiss_button.clicked.connect(self.dismiss_alert)
        arow.addWidget(self.stop_button)
        arow.addStretch(1)
        arow.addWidget(self.dismiss_button)
        self.alert_msg = QLabel()
        self.alert_msg.setWordWrap(True)
        self.alert_msg.setTextFormat(Qt.TextFormat.PlainText)
        for w in (self.alert_title, self.alert_text, self.writers):
            ab.addWidget(w)
        ab.addLayout(arow)
        ab.addWidget(self.alert_msg)
        self.alert_box.setVisible(False)
        self._shown_alert: object | None = None
        lay.addWidget(self.alert_box)

        box = QGroupBox(self.tr("選項"))
        grid = QGridLayout(box)
        self.options: dict[str, QCheckBox] = {}
        grid.setHorizontalSpacing(28)
        grid.setVerticalSpacing(10)
        self.option_help: dict[str, QLabel] = {}
        for i, (key, text, help_text) in enumerate(OPTIONS):
            cell = QVBoxLayout()
            cell.setSpacing(2)
            cell.setContentsMargins(0, 2, 0, 6)
            cb = QCheckBox(self.tr(text))
            cb.setChecked(bool(getattr(service.settings, key)))
            cb.toggled.connect(lambda on, k=key: self._option(k, on))
            help_label = QLabel(self.tr(help_text))
            help_label.setObjectName("optionHelp")
            help_label.setWordWrap(True)
            cell.addWidget(cb)
            cell.addWidget(help_label)
            self.options[key] = cb
            self.option_help[key] = help_label
            grid.addLayout(cell, i // 2, i % 2)
        lay.addWidget(box)

        lock_box = QGroupBox(self.tr("被鎖住的檔案（有問題或可疑，目前不能打開）"))
        lv = QVBoxLayout(lock_box)
        self.locks_table = table([self.tr("狀態"), self.tr("原因"), self.tr("鎖住時間（UTC）"), self.tr("檔案")])
        self.locks_table.setMaximumHeight(140)
        lv.addWidget(self.locks_table)
        lrow = QHBoxLayout()
        self.unlock_button = QPushButton(self.tr("解鎖選取的檔案"))
        self.unlock_button.clicked.connect(self.unlock_selected)
        lrow.addWidget(self.unlock_button)
        lrow.addWidget(muted(self.tr("只有在你確定檔案安全時才解鎖。解鎖後檔案就可以執行。")), 1)
        lv.addLayout(lrow)
        lay.addWidget(lock_box)

        lay.addWidget(QLabel(self.tr("最近檢查過的檔案")))
        self.activity = table([self.tr("時間（UTC）"), self.tr("結果"), self.tr("處理"), self.tr("檔案")])
        self.activity.setMinimumHeight(220)
        lay.addWidget(self.activity, 1)
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    def toggle(self) -> None:
        if self._svc.settings.enabled:
            if not self.confirm(self, self.tr("關閉即時防護"), self.tr(
                    "確定要關閉即時防護嗎？新下載的檔案將不會被自動檢查。")):
                return
            self._svc.set_enabled(False)
        else:
            self._svc.set_enabled(True)
        self.refresh()

    def unlock_selected(self) -> None:
        row = self.locks_table.currentRow()
        if row < 0:
            return
        cell = self.locks_table.item(row, 3)
        if cell is None:
            return
        path = cell.text()
        if not self.confirm(self, self.tr("解鎖檔案"), self.tr(
                "確定要解鎖嗎？解鎖後這個檔案就可以執行。\n\n{0}\n\n"
                "只有在你確定它安全（例如已在威脅中心標記為誤判）時才解鎖。").format(path)):
            return
        if not self._svc.unlock(path):
            self.confirm(self, self.tr("解鎖失敗"), self.tr("無法變更這個檔案的權限，可能正被其他程式使用。請稍後再試。"))
        self.refresh()

    def stop_selected_writer(self) -> None:
        it = self.writers.currentItem()
        if it is None:
            return
        pid, name = it.data(Qt.ItemDataRole.UserRole)
        if not self.confirm(self, self.tr("停止程式"), self.tr(
                "確定要停止 {0}（程式編號 {1}）嗎？\n\n如果它是你正在用的軟體（例如正在同步或備份），"
                "停止後要自己重新打開；沒存的資料可能會不見。").format(name, pid)):
            return
        try:
            msg = self._svc.stop_writer(pid, name)
            self.alert_msg.setStyleSheet(f"color: {theme.OK};")
        except PermissionError as exc:
            msg = str(exc)
            self.alert_msg.setStyleSheet(f"color: {theme.BAD};")
        self.alert_msg.setText(msg)

    def dismiss_alert(self) -> None:
        self._svc.dismiss_ransomware_alert()
        self.refresh()

    def _show_alert(self) -> None:
        a = self._svc.ransomware.alert
        self.alert_box.setVisible(a is not None)
        if a is None or a is self._shown_alert:
            return
        self._shown_alert = a
        color = theme.BAD if a.level == "bad" else theme.WARN
        self.alert_title.setText(self.tr("可能有勒索病毒正在加密你的檔案！") if a.level == "bad"
                                 else self.tr("大量文件在短時間內被修改"))
        self.alert_title.setStyleSheet(f"color: {color};")
        self.alert_text.setText(a.reason + self.tr(
            "\n例如：{0}\n建議：先停止下面不認識的程式；拔掉外接硬碟與網路線（或關 Wi-Fi），避免備份也被加密。"
            "下面是最近寫入最多的程式，不一定都是病毒。").format("；".join(a.examples[:3])))
        self.writers.clear()
        for w in a.writers:
            entry = QListWidgetItem(self.tr("{0}（編號 {1}，寫入 {2:g} MB）　{3}").format(w.name, w.pid, w.written_mb, w.exe))
            entry.setData(Qt.ItemDataRole.UserRole, (w.pid, w.name))
            self.writers.addItem(entry)
        if not a.writers:
            self.writers.addItem(self.tr("找不到寫入最多的程式（它可能以系統管理員身分執行）。請重新開機並執行完整掃描。"))
        self.stop_button.setEnabled(bool(a.writers))
        self.alert_msg.setText("")

    def _option(self, key: str, on: bool) -> None:
        if bool(getattr(self._svc.settings, key)) != on:
            self._svc.update(**{key: on})
        self.refresh()

    def refresh(self) -> None:
        st = self._svc.status()
        self._show_alert()
        if st.running:
            self.state_label.setText(self.tr("● 防護中"))
            self.state_label.setStyleSheet(f"color: {theme.OK};")
            self.toggle_button.setText(self.tr("關閉即時防護"))
        else:
            self.state_label.setText(self.tr("○ 即時防護已關閉"))
            self.state_label.setStyleSheet(f"color: {theme.WARN};")
            self.toggle_button.setText(self.tr("開啟即時防護"))
        text, color = ENGINE_TEXT.get(st.engine_state, (st.engine_state, theme.TEXT))
        self.engine_label.setText(self.tr("病毒檢查引擎：{0}　{1}").format(text, st.engine_detail))
        self.engine_label.setStyleSheet(f"color: {color};")
        guard = self.tr("執行中") if st.guard_running else self.tr("未啟用")
        self.counts_label.setText(self.tr("這次啟動後：檢查了 {0} 個檔案，擋下 {1} 個，關掉病毒程式 {2} 個；"
                                          "排隊等待檢查 {3} 個。關掉病毒程式的功能：{4}")
                                  .format(st.scanned, st.blocked, st.terminated, st.queue, guard))
        where = list(st.folders) + [self.tr("卸除式磁碟：{0}").format(d) for d in st.drives]
        self.where_label.setText(self.tr("監看中：") + ("；".join(where) if where else self.tr("（無）")))
        held = self._svc.locks.entries()
        self.locks_table.setRowCount(len(held))
        for i, e in enumerate(held):
            state = self.tr("等待檢查") if e.state == "pending" else self.tr("已鎖住")
            color = theme.WARN if e.state == "pending" else theme.BAD
            for c, v in enumerate((state, e.reason, e.at, e.path)):
                self.locks_table.setItem(i, c, item(v, color if c < 2 else None))
        self.unlock_button.setEnabled(any(e.state == "held" for e in held))
        rows = self._svc.activity()[:200]
        self.activity.setRowCount(len(rows))
        for i, a in enumerate(rows):
            for c, v in enumerate((a.at, a.result, a.action, a.path)):
                self.activity.setItem(i, c, item(v, LEVEL_COLOR.get(a.level) if c < 3 else None))

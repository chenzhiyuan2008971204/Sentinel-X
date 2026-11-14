"""Behaviour Monitor page: sources, start/stop, watched folders, timeline with filters,
alerts with facts and analysis shown separately, admin relaunch and Sysmon guide.

Passive only: there is no control here that ends a process or blocks anything.
"""

from __future__ import annotations

import html
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from sentinelx.core.enums import AlertStatus, EventSource, PrivilegeLevel, Severity
from sentinelx.gui import theme
from sentinelx.gui.confirm import Confirm, ask
from sentinelx.gui.pages import PRIVILEGE_TEXT
from sentinelx.gui.widgets import item, muted, table, title
from sentinelx.monitor.events import KIND_TEXT, EventKind
from sentinelx.services.monitor_service import SYSMON_URL, MonitorService

SEV_TEXT = {Severity.HIGH: "高", Severity.MEDIUM: "中", Severity.LOW: "低", Severity.INFO: "資訊"}
SEV_COLOR = {Severity.HIGH: theme.BAD, Severity.MEDIUM: theme.WARN, Severity.LOW: theme.TEXT, Severity.INFO: theme.TEXT_MUTED}
ALERT_STATUS_TEXT = {AlertStatus.OPEN: "未處理", AlertStatus.ACKNOWLEDGED: "已讀", AlertStatus.DISMISSED: "已忽略"}


def _open_url(url: str) -> None:
    QDesktopServices.openUrl(QUrl(url))


class BehaviorMonitorPage(QWidget):
    REFRESH_MS = 2000

    def __init__(self, service: MonitorService, *, confirm: Confirm = ask,
                 open_url: Callable[[str], None] = _open_url,
                 quit_app: Callable[[], None] = lambda: QApplication.quit()) -> None:
        super().__init__()
        self.setObjectName("page_behavior")
        self._svc = service
        self.confirm = confirm
        self._open_url = open_url
        self._quit = quit_app

        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(10)
        lay.addWidget(title(self.tr("行為監控")))
        lay.addWidget(muted(self.tr(
            "被動觀察模式：只記錄事件與產生警示，不會終止程序、不會阻擋任何活動，也不會變更 Windows 安全設定。")))

        top = QHBoxLayout()
        self.state_label = QLabel()
        self.state_label.setTextFormat(Qt.TextFormat.PlainText)
        self.start_button = QPushButton(self.tr("開始監控"))
        self.stop_button = QPushButton(self.tr("停止監控"))
        self.recheck_button = QPushButton(self.tr("重新偵測來源"))
        self.elevate_button = QPushButton(self.tr("以系統管理員身分重新啟動…"))
        self.sysmon_button = QPushButton(self.tr("Sysmon 設定指南"))
        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)
        self.recheck_button.clicked.connect(self.refresh_sources)
        self.elevate_button.clicked.connect(self.request_elevation)
        self.sysmon_button.clicked.connect(lambda: self.tabs.setCurrentIndex(3))
        top.addWidget(self.state_label, 1)
        for b in (self.start_button, self.stop_button, self.recheck_button, self.elevate_button, self.sysmon_button):
            top.addWidget(b)
        lay.addLayout(top)
        self.elevate_button.setVisible(service.privilege is not PrivilegeLevel.ADMINISTRATOR)

        self.sources = table(["來源", "狀態", "說明"])
        self.sources.setMaximumHeight(190)
        lay.addWidget(self.sources)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._timeline_tab(), self.tr("事件時間軸"))
        self.tabs.addTab(self._alerts_tab(), self.tr("警示"))
        self.tabs.addTab(self._folders_tab(), self.tr("監看資料夾"))
        self.tabs.addTab(self._sysmon_tab(), self.tr("Sysmon 設定指南"))
        lay.addWidget(self.tabs, 1)
        self.msg = QLabel()
        self.msg.setWordWrap(True)
        self.msg.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.msg)

        self.timer = QTimer(self)
        self.timer.setInterval(self.REFRESH_MS)
        self.timer.timeout.connect(self._tick)
        self.refresh_sources()
        self.refresh_all()

    # ---------- state ----------
    def _update_state(self) -> None:
        running = self._svc.running
        stats = self._svc.stats
        txt = self.tr("執行權限：{0}　狀態：{1}").format(
            PRIVILEGE_TEXT[self._svc.privilege], self.tr("監控中") if running else self.tr("未啟動"))
        if running and stats:
            txt += self.tr("　本次已記錄 {0} 個事件、{1} 則新警示").format(stats.events, stats.alerts)
            if stats.last_error:
                txt += self.tr("　最近錯誤：{0}").format(stats.last_error)
        self.state_label.setText(txt)
        self.state_label.setStyleSheet(f"color: {theme.OK if running else theme.TEXT_MUTED};")
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.recheck_button.setEnabled(not running)

    def refresh_sources(self) -> None:
        sts = self._svc.statuses()
        self.sources.setRowCount(len(sts))
        for i, s in enumerate(sts):
            if s.available:
                state, color = self.tr("可用"), theme.OK
            elif s.requires_admin:
                state, color = self.tr("需要系統管理員"), theme.WARN
            else:
                state, color = self.tr("無法使用"), theme.TEXT_MUTED
            for c, v in enumerate([s.name, state, s.detail]):
                self.sources.setItem(i, c, item(v, color if c == 1 else None))
        self._update_state()

    def start(self) -> None:
        sts = self._svc.start()
        self.refresh_sources()
        active = [s.name for s in sts if s.available]
        self._msg(self.tr("已開始被動監控：{0}").format("、".join(active)) if active
                  else self.tr("沒有可用的事件來源。"), theme.OK if active else theme.WARN)
        self.timer.start()

    def stop(self) -> None:
        self._svc.stop()
        self.timer.stop()
        self.refresh_sources()
        self.refresh_all()
        self._msg(self.tr("已停止監控。"), theme.TEXT_MUTED)

    def _tick(self) -> None:
        if not self.isVisible():
            return
        self._update_state()
        self.refresh_timeline()
        self.refresh_alerts(keep_selection=True)

    def refresh_all(self) -> None:
        self._update_state()
        self.refresh_timeline()
        self.refresh_alerts()
        self.refresh_folders()

    def shutdown(self) -> None:
        self.timer.stop()
        self._svc.stop()

    # ---------- timeline ----------
    def _timeline_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        row = QHBoxLayout()
        self.source_filter = QComboBox()
        self.source_filter.addItem(self.tr("全部來源"), None)
        for s in EventSource:
            self.source_filter.addItem(s.value, s.value)
        self.kind_filter = QComboBox()
        self.kind_filter.addItem(self.tr("全部類型"), None)
        for k in EventKind:
            self.kind_filter.addItem(KIND_TEXT[k], k.value)
        self.text_filter = QLineEdit()
        self.text_filter.setPlaceholderText(self.tr("搜尋程序、路徑、命令列或遠端位址"))
        self.apply_filter_button = QPushButton(self.tr("套用篩選"))
        self.apply_filter_button.clicked.connect(self.refresh_timeline)
        self.text_filter.returnPressed.connect(self.refresh_timeline)
        row.addWidget(self.source_filter)
        row.addWidget(self.kind_filter)
        row.addWidget(self.text_filter, 1)
        row.addWidget(self.apply_filter_button)
        v.addLayout(row)
        self.timeline = table(["#", "時間 (UTC)", "來源", "類型", "程序", "PID", "對象"])
        v.addWidget(self.timeline, 1)
        return w

    def refresh_timeline(self) -> None:
        src = self.source_filter.currentData()
        kind = self.kind_filter.currentData()
        evs = self._svc.events(source=EventSource(src) if src else None, kind=EventKind(kind) if kind else None,
                               text=self.text_filter.text(), limit=500)
        self.timeline.setRowCount(len(evs))
        for i, e in enumerate(evs):
            target = e.target_path or (f"{e.remote_addr}:{e.remote_port}" if e.remote_addr else "") or \
                str(e.details.get("note") or "")
            vals = [str(e.id), e.occurred_at, e.source.value, KIND_TEXT[e.kind], e.process_path or e.process_name or "",
                    str(e.pid or ""), target]
            for c, val in enumerate(vals):
                self.timeline.setItem(i, c, item(val))

    # ---------- alerts ----------
    def _alerts_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        row = QHBoxLayout()
        self.show_closed = QCheckBox(self.tr("顯示已讀與已忽略的警示"))
        self.show_closed.toggled.connect(lambda _=False: self.refresh_alerts())
        row.addWidget(self.show_closed)
        row.addStretch(1)
        self.ack_button = QPushButton(self.tr("標記為已讀"))
        self.dismiss_button = QPushButton(self.tr("忽略"))
        self.ack_button.clicked.connect(lambda: self._set_status(AlertStatus.ACKNOWLEDGED))
        self.dismiss_button.clicked.connect(lambda: self._set_status(AlertStatus.DISMISSED))
        row.addWidget(self.ack_button)
        row.addWidget(self.dismiss_button)
        v.addLayout(row)
        split = QSplitter(Qt.Orientation.Vertical)
        self.alert_table = table(["#", "時間 (UTC)", "嚴重性", "狀態", "警示"])
        self.alert_table.itemSelectionChanged.connect(self._show_alert)
        self.alert_detail = QTextBrowser()
        self.alert_detail.setOpenLinks(False)
        split.addWidget(self.alert_table)
        split.addWidget(self.alert_detail)
        v.addWidget(split, 1)
        return w

    def refresh_alerts(self, keep_selection: bool = False) -> None:
        current = self._selected_alert_id() if keep_selection else None
        rows = self._svc.alerts(self.show_closed.isChecked())
        self.alert_table.blockSignals(True)
        self.alert_table.clearSelection()
        self.alert_table.setRowCount(len(rows))
        for i, a in enumerate(rows):
            vals = [str(a.id), a.created_at, SEV_TEXT[a.severity], ALERT_STATUS_TEXT[a.status], a.title]
            for c, val in enumerate(vals):
                self.alert_table.setItem(i, c, item(val, SEV_COLOR[a.severity] if c == 2 else None))
        self.alert_table.blockSignals(False)
        if current is not None:
            for r in range(self.alert_table.rowCount()):
                if self.alert_table.item(r, 0).text() == str(current):
                    self.alert_table.selectRow(r)
                    break
        if self._selected_alert_id() is None:
            self.alert_detail.clear()
        self._update_alert_buttons()

    def _selected_alert_id(self) -> int | None:
        row = self.alert_table.currentRow()
        if row < 0 or not self.alert_table.selectedItems():
            return None
        return int(self.alert_table.item(row, 0).text())

    def _update_alert_buttons(self) -> None:
        a = self._current_alert()
        open_ = a is not None and a.status is AlertStatus.OPEN
        self.ack_button.setEnabled(open_)
        self.dismiss_button.setEnabled(open_)

    def _current_alert(self):  # type: ignore[no-untyped-def]
        aid = self._selected_alert_id()
        if aid is None:
            return None
        return next((a for a in self._svc.alerts(True) if a.id == aid), None)

    def _show_alert(self) -> None:
        a = self._current_alert()
        self._update_alert_buttons()
        if a is None:
            return
        e = html.escape
        c = SEV_COLOR[a.severity]
        out = [f"<h3 style='color:{c}'>{e(a.title)}</h3>",
               f"<p>嚴重性：{e(SEV_TEXT[a.severity])}　規則：{e(a.rule_id or '')}　建立：{e(a.created_at)}</p>",
               "<h4>觀察到的事實</h4><ul>"]
        out += [f"<li>{e(f)}</li>" for f in a.observed_facts]
        out.append("</ul><h4>分析推論（不是事實，請自行判斷）</h4>")
        out.append(f"<p>{e(a.analysis)}</p>")
        out.append(f"<p style='color:{theme.TEXT_MUTED}'>Sentinel X 只記錄與提示，不會對此警示採取任何自動動作。</p>")
        self.alert_detail.setHtml("".join(out))

    def _set_status(self, status: AlertStatus) -> None:
        aid = self._selected_alert_id()
        if aid is None:
            return
        self._svc.set_alert_status(aid, status)
        self.refresh_alerts()

    # ---------- folders ----------
    def _folders_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(muted(self.tr("只監看你指定的資料夾（含子資料夾）。變更會在下次開始監控時生效。")))
        self.folder_list = QListWidget()
        v.addWidget(self.folder_list, 1)
        row = QHBoxLayout()
        self.add_folder_button = QPushButton(self.tr("加入資料夾…"))
        self.remove_folder_button = QPushButton(self.tr("移除選取"))
        self.add_folder_button.clicked.connect(self._pick_folder)
        self.remove_folder_button.clicked.connect(self._remove_folder)
        row.addWidget(self.add_folder_button)
        row.addWidget(self.remove_folder_button)
        row.addStretch(1)
        v.addLayout(row)
        return w

    def refresh_folders(self) -> None:
        self.folder_list.clear()
        self.folder_list.addItems(self._svc.watch_dirs)

    def _pick_folder(self) -> None:
        d = QFileDialog.getExistingDirectory(self, self.tr("選擇要監看的資料夾"))
        if d:
            self.add_folder(Path(d))

    def add_folder(self, folder: Path) -> None:
        try:
            self._svc.add_watch_dir(folder)
        except ValueError as exc:
            self._msg(str(exc), theme.BAD)
            return
        self.refresh_folders()
        self.refresh_sources()
        self._msg(self.tr("已加入監看資料夾。") + (self.tr("請停止後重新開始監控以套用。") if self._svc.running else ""),
                  theme.OK)

    def _remove_folder(self) -> None:
        it = self.folder_list.currentItem()
        if it is None:
            return
        self._svc.remove_watch_dir(it.text())
        self.refresh_folders()
        self.refresh_sources()

    # ---------- Sysmon / elevation ----------
    def _sysmon_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.sysmon_state = QLabel()
        self.sysmon_state.setTextFormat(Qt.TextFormat.PlainText)
        v.addWidget(self.sysmon_state)
        steps = QLabel(self._svc.sysmon_steps())
        steps.setTextFormat(Qt.TextFormat.PlainText)
        steps.setWordWrap(True)
        steps.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(steps)
        row = QHBoxLayout()
        self.sysmon_page_button = QPushButton(self.tr("開啟微軟官方 Sysmon 頁面"))
        self.save_config_button = QPushButton(self.tr("儲存建議設定檔…"))
        self.sysmon_page_button.clicked.connect(lambda: self._open_url(SYSMON_URL))
        self.save_config_button.clicked.connect(self._pick_config_dest)
        row.addWidget(self.sysmon_page_button)
        row.addWidget(self.save_config_button)
        row.addStretch(1)
        v.addLayout(row)
        v.addStretch(1)
        self._update_sysmon_state()
        return w

    def _update_sysmon_state(self) -> None:
        if self._svc.sysmon_installed():
            self.sysmon_state.setText(self.tr("已偵測到 Sysmon。"))
            self.sysmon_state.setStyleSheet(f"color: {theme.OK};")
        else:
            self.sysmon_state.setText(self.tr("尚未偵測到 Sysmon（選用）。沒有 Sysmon 時，程序與網路事件改以輪詢方式收集。"))
            self.sysmon_state.setStyleSheet(f"color: {theme.TEXT_MUTED};")

    def _pick_config_dest(self) -> None:
        f, _ = QFileDialog.getSaveFileName(self, self.tr("儲存 Sysmon 設定檔"), "sysmon-sentinelx.xml", "XML (*.xml)")
        if f:
            self.save_sysmon_config(Path(f))

    def save_sysmon_config(self, dest: Path) -> None:
        try:
            self._svc.save_sysmon_config(dest)
        except (ValueError, OSError) as exc:
            self._msg(str(exc), theme.BAD)
            return
        self._msg(self.tr("已儲存到 {0}，請先閱讀內容再使用。").format(dest), theme.OK)

    def request_elevation(self) -> None:
        message = self.tr(
            "要以系統管理員身分重新啟動 Sentinel X 嗎？\n\nWindows 會顯示使用者帳戶控制（UAC）提示。"
            "管理員模式只用於讀取 Sysmon 與安全性記錄；同樣不會終止程序或變更安全設定。\n"
            "目前的視窗會關閉，進行中的監控會停止。")
        if not self.confirm(self, self.tr("確認重新啟動"), message):
            return
        if self._svc.request_elevation():
            self.shutdown()
            self._quit()
        else:
            self._msg(self.tr("沒有取得系統管理員權限（可能在 UAC 提示中選擇了「否」）。"), theme.WARN)

    def _msg(self, text: str, color: str) -> None:
        self.msg.setText(text)
        self.msg.setStyleSheet(f"color: {color};")

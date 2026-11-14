from __future__ import annotations

import logging
from dataclasses import dataclass

from PySide6.QtCore import QEasingCurve, QPointF, QPropertyAnimation, Qt, QTimer
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPixmap
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsOpacityEffect,
    QMenu,
    QSystemTrayIcon,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from sentinelx import __version__
from sentinelx.core.enums import PrivilegeLevel, QuarantineStatus
from sentinelx.gui import theme
from sentinelx.gui.intel_page import ThreatIntelPage
from sentinelx.gui.lab_page import ResearchLabPage
from sentinelx.gui.monitor_page import BehaviorMonitorPage
from sentinelx.gui.home_page import HomePage, HomeState
from sentinelx.gui.pages import PAGE_SPECS, PRIVILEGE_TEXT, DashboardPage, NotImplementedPage
from sentinelx.gui.quarantine_page import QuarantinePage
from sentinelx.gui.confirm import Confirm, ask_yes_no
from sentinelx.gui.protection_page import ProtectionBridge, ProtectionPage
from sentinelx.gui.reports_page import ReportsPage
from sentinelx.gui.settings_page import SettingsPage
from sentinelx.gui.scan_page import ScanCenterPage
from sentinelx.services.lab_service import LabService
from sentinelx.services.monitor_service import MonitorService
from sentinelx.services.quarantine_service import QuarantineService
from sentinelx.services.report_service import ReportService
from sentinelx.services.settings_service import SettingsService
from sentinelx.services.signature_service import SignatureService
from sentinelx.services.virustotal_service import VirusTotalService
from sentinelx.services.rule_update_service import RuleUpdateService
from sentinelx.services.sandbox_service import SandboxService
from sentinelx.gui.sandbox_page import SandboxPage
from sentinelx.services.protection_service import ProtectionService
from sentinelx.gui.static_page import StaticAnalysisPage
from sentinelx.gui.threat_page import ThreatCenterPage
from sentinelx.services.intel_service import IntelService
from sentinelx.services.review_service import ReviewService
from sentinelx.services.scan_service import ScanService
from sentinelx.services.static_analysis_service import StaticAnalysisService
from sentinelx.services.status_service import StatusService


log = logging.getLogger(__name__)
INDICATOR_INTERVAL_MS = 10_000
ADVANCED_HEADER = "__advanced__"
FADE_MS = 160


def shield_icon() -> QIcon:
    """Tray icon drawn at run time (no image asset is shipped)."""
    pm = QPixmap(64, 64)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    path = QPainterPath()
    path.moveTo(32, 4)
    path.lineTo(58, 14)
    path.cubicTo(58, 38, 48, 52, 32, 60)
    path.cubicTo(16, 52, 6, 38, 6, 14)
    path.closeSubpath()
    p.fillPath(path, QColor(theme.CYAN))
    p.setPen(QColor(theme.NAVY_900))
    pen = p.pen()
    pen.setWidth(6)
    p.setPen(pen)
    p.drawPolyline([QPointF(20, 32), QPointF(29, 41), QPointF(45, 23)])
    p.end()
    return QIcon(pm)


@dataclass(frozen=True)
class Services:
    """Everything the GUI may call. The GUI never touches storage or engines directly."""

    status: StatusService
    scans: ScanService
    intel: IntelService
    static: StaticAnalysisService
    reviews: ReviewService
    quarantine: QuarantineService
    monitor: MonitorService
    reports: ReportService
    lab: LabService
    settings: SettingsService
    signatures: SignatureService | None = None
    protection: ProtectionService | None = None
    virustotal: VirusTotalService | None = None
    sandbox: SandboxService | None = None
    rule_updates: RuleUpdateService | None = None


class MainWindow(QMainWindow):
    def __init__(self, services: Services, privilege: PrivilegeLevel) -> None:
        super().__init__()
        title = self.tr("Sentinel X 研究版 {0}").format(__version__)
        if privilege is PrivilegeLevel.ADMINISTRATOR:
            title += self.tr("（系統管理員模式）")
        self.setWindowTitle(title)
        self.resize(1200, 760)
        self.setMinimumSize(900, 600)

        central = QWidget()
        central.setObjectName("central")
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        side = QWidget()
        side_lay = QVBoxLayout(side)
        side_lay.setContentsMargins(0, 0, 0, 0)
        side_lay.setSpacing(0)
        brand = QLabel("SENTINEL X")
        brand.setObjectName("brand")
        edition = QLabel(self.tr("研究版"))
        edition.setObjectName("edition")
        side.setObjectName("side")
        side.setFixedWidth(220)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        side_lay.addWidget(brand)
        side_lay.addWidget(edition)
        side_lay.addWidget(self.nav, 1)

        self.scan_page = ScanCenterPage(services.scans)
        self.intel_page = ThreatIntelPage(services.intel)
        self.static_page = StaticAnalysisPage(services.static)
        self.threat_page = ThreatCenterPage(services.reviews, services.quarantine)
        self.quarantine_page = QuarantinePage(services.quarantine, mark_safe=services.reviews.dismiss_whole_file)
        self.monitor_page = BehaviorMonitorPage(services.monitor)
        self.dashboard = DashboardPage(services.status, services.reviews, services.scans)
        self.lab_page = ResearchLabPage(services.lab)
        self.reports_page = ReportsPage(services.reports)
        self.settings_page = SettingsPage(services.settings, signatures=services.signatures,
                                          virustotal=services.virustotal, rule_updates=services.rule_updates)
        self.protection_page = ProtectionPage(services.protection) if services.protection is not None else None
        self._services = services
        self.home_page = HomePage(self.home_state, self.home_action)
        self.sandbox_page = (SandboxPage(services.sandbox, quarantine=self._quarantine_verdict)
                             if services.sandbox is not None else None)
        self.notifications: list[tuple[str, str, str]] = []
        self.bridge = ProtectionBridge(self)
        self.bridge.notified.connect(self.notify)
        self.bridge.signatures_changed.connect(self.settings_page.refresh_signatures)
        if services.protection is not None:
            services.protection.notifier = self.bridge.notified.emit  # thread-safe: queued to the GUI thread
        if services.signatures is not None:
            services.signatures.on_auto_result = self._signature_auto_result  # runs on the update thread
        if services.sandbox is not None:
            services.sandbox.notifier = self.bridge.notified.emit  # automatic rebuild runs on its own thread
        if services.rule_updates is not None:
            services.rule_updates.on_result = lambda level, msg: self.bridge.notified.emit(level, self.tr("YARA 規則"), msg)
        real_pages: dict[str, QWidget] = {
            "home": self.home_page,
            "dashboard": self.dashboard,
            "scan": self.scan_page,
            "threats": self.threat_page,
            "lab": self.lab_page,
            "behavior": self.monitor_page,
            "quarantine": self.quarantine_page,
            "intel": self.intel_page,
            "static": self.static_page,
            "reports": self.reports_page,
            "settings": self.settings_page,
        }
        if self.protection_page is not None:
            real_pages["protection"] = self.protection_page
        if self.sandbox_page is not None:
            real_pages["sandbox"] = self.sandbox_page

        self.stack = QStackedWidget()
        self.pages: dict[str, QWidget] = {}
        self._titles: dict[str, str] = {}
        self._advanced_keys: list[str] = []
        self.advanced_open = False
        for spec in PAGE_SPECS:
            page = real_pages.get(spec.key) or NotImplementedPage(spec)
            self.pages[spec.key] = page
            self._titles[spec.key] = spec.title
            self.stack.addWidget(page)
        # Everyday pages first; research tools under a header that opens and closes them.
        for spec in [s for s in PAGE_SPECS if not s.advanced]:
            self._nav_item(spec.key, spec.title)
        self.advanced_header = QListWidgetItem()
        self.advanced_header.setData(Qt.ItemDataRole.UserRole, ADVANCED_HEADER)
        self.advanced_header.setFlags(Qt.ItemFlag.ItemIsEnabled)
        self.advanced_header.setToolTip(self.tr("研究用的工具：詳細狀態、樣本分析、行為監控、威脅情報、報告"))
        self.nav.addItem(self.advanced_header)
        for spec in [s for s in PAGE_SPECS if s.advanced]:
            self._nav_item(spec.key, spec.title).setHidden(True)
            self._advanced_keys.append(spec.key)
        self._set_advanced(False)
        self.nav.itemClicked.connect(self._nav_clicked)

        self._fade: QPropertyAnimation | None = None
        self.badges: dict[str, int] = {}
        self.nav.currentRowChanged.connect(self._on_nav)
        self.nav.setCurrentRow(0)

        root.addWidget(side)
        root.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        # Status indicators: always visible, refreshed from real state.
        sb = self.statusBar()
        self.privilege_label = QLabel(self.tr("執行權限：{0}").format(PRIVILEGE_TEXT[privilege]))
        self.protection_label = QLabel()
        self.protection_label.setTextFormat(Qt.TextFormat.PlainText)
        sb.addPermanentWidget(self.protection_label)
        self.monitor_label = QLabel()
        self.engines_label = QLabel()
        self.privilege_label.setVisible(privilege is PrivilegeLevel.ADMINISTRATOR)  # only the unusual case
        for lbl in (self.privilege_label, self.monitor_label, self.engines_label):
            lbl.setTextFormat(Qt.TextFormat.PlainText)
            sb.addPermanentWidget(lbl)
        self._build_tray()
        self.update_indicators()
        self._timer = QTimer(self)
        self._timer.setInterval(INDICATOR_INTERVAL_MS)
        self._timer.timeout.connect(self.update_indicators)
        self._timer.start()

    def update_indicators(self) -> None:
        """Counts next to page names and the status bar, from the database and services.
        Runs on a timer: count queries only, and errors are shown, never raised."""
        try:
            self._update_indicators()
        except Exception as exc:  # noqa: BLE001 - e.g. database busy; retried on the next tick
            log.warning("indicator refresh failed", exc_info=True)
            self.monitor_label.setText(self.tr("狀態暫時無法更新：{0}").format(type(exc).__name__))
            self.monitor_label.setStyleSheet(f"color: {theme.WARN};")

    def _update_indicators(self) -> None:
        s = self._services
        n_threats, pending = s.reviews.attention_counts()
        alerts = s.monitor.open_alert_count()
        held = sum(1 for q in s.quarantine.items() if q.status is QuarantineStatus.QUARANTINED)
        self.badges = {"threats": n_threats, "behavior": alerts, "quarantine": held}
        tips = {"threats": self.tr("需要注意的判定 {0} 個，其中待審查 {1} 個").format(n_threats, pending),
                "behavior": self.tr("未處理的警示 {0} 則").format(alerts),
                "quarantine": self.tr("隔離中的檔案 {0} 個").format(held)}
        for row in range(self.nav.count()):
            it = self.nav.item(row)
            key = str(it.data(Qt.ItemDataRole.UserRole))
            if key not in self._titles:
                continue
            n = self.badges.get(key, 0)
            it.setText(f"{self._titles[key]}  ({n})" if n else self._titles[key])
            it.setToolTip(tips.get(key, ""))
        self._advanced_text()
        if self.stack.currentWidget() is self.home_page:
            self.home_page.refresh()
        if s.protection is not None:
            on = s.protection.running
            self.protection_label.setText(self.tr("● 即時防護：開啟") if on else self.tr("○ 即時防護：關閉"))
            self.protection_label.setStyleSheet(f"color: {theme.OK if on else theme.WARN};")
            if getattr(self, "_tray", None) is not None:
                self._tray_toggle.setChecked(on)
                self._tray.setToolTip("Sentinel X：" + (self.tr("即時防護開啟") if on else self.tr("即時防護關閉")))
        if s.monitor.running:
            self.monitor_label.setText(self.tr("● 行為監控：執行中"))
            self.monitor_label.setStyleSheet(f"color: {theme.OK};")
        else:
            self.monitor_label.setText(self.tr("○ 行為監控：未啟動"))
            self.monitor_label.setStyleSheet(f"color: {theme.TEXT_MUTED};")
        self.monitor_label.setVisible(s.monitor.running)  # research tool: shown only while it runs
        engines = s.scans.engine_statuses()
        ok = [e for e in engines if e.available]
        self.engines_label.setText(self.tr("檢查引擎 {0}/{1} 可用").format(len(ok), len(engines)))
        self.engines_label.setStyleSheet(f"color: {theme.OK if s.scans.any_engine_available() else theme.BAD};")

    # ---------- navigation ----------
    def _nav_item(self, key: str, title: str) -> QListWidgetItem:
        item = QListWidgetItem(title)
        item.setData(Qt.ItemDataRole.UserRole, key)
        self.nav.addItem(item)
        return item

    def _set_advanced(self, open_: bool) -> None:
        self.advanced_open = open_
        for row in range(self.nav.count()):
            it = self.nav.item(row)
            if it.data(Qt.ItemDataRole.UserRole) in self._advanced_keys:
                it.setHidden(not open_)
        self._advanced_text()

    def _advanced_text(self) -> None:
        n = sum(getattr(self, "badges", {}).get(k, 0) for k in self._advanced_keys)
        arrow = "▾" if self.advanced_open else "▸"
        extra = f"  ({n})" if n and not self.advanced_open else ""
        self.advanced_header.setText(f"{arrow} " + self.tr("進階功能") + extra)

    def _nav_clicked(self, item: QListWidgetItem) -> None:
        if item is self.advanced_header:
            self._set_advanced(not self.advanced_open)

    def go_to(self, key: str) -> None:
        """Show a page by its key (opens 「進階功能」 when needed)."""
        if key in self._advanced_keys and not self.advanced_open:
            self._set_advanced(True)
        for row in range(self.nav.count()):
            if self.nav.item(row).data(Qt.ItemDataRole.UserRole) == key:
                self.nav.setCurrentRow(row)
                return

    def _on_nav(self, row: int) -> None:
        item = self.nav.item(row)
        key = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if key not in self.pages:
            return
        self.stack.setCurrentWidget(self.pages[key])
        current = self.stack.currentWidget()
        self._fade_in(current)
        if current is self.home_page:
            self.home_page.refresh()
        # Data may change on other pages (rules added, scans finished, reviews made).
        if current is self.scan_page and not self.scan_page.scanning:
            self.scan_page.refresh_engines()
        elif current is self.threat_page and not self.threat_page.busy:
            self.threat_page.refresh()
        elif current is self.quarantine_page and not self.quarantine_page.busy:
            self.quarantine_page.refresh()
        elif current is self.monitor_page:
            self.monitor_page.refresh_all()
        elif current is self.dashboard:
            self.dashboard.refresh()
        elif current is self.reports_page:
            self.reports_page.refresh()
        elif current is self.lab_page:
            self.lab_page.refresh_history()
        elif self.protection_page is not None and current is self.protection_page:
            self.protection_page.refresh()
        if hasattr(self, "_timer"):
            self.update_indicators()

    def _fade_in(self, page: QWidget) -> None:
        """Short opacity transition; the effect is removed afterwards (it slows text widgets)."""
        if self._fade is not None:
            self._fade.stop()
            self._fade = None
        effect = QGraphicsOpacityEffect(page)
        page.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(FADE_MS)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.finished.connect(lambda: page.setGraphicsEffect(None))
        anim.start()
        self._fade = anim

    def closeEvent(self, event: QCloseEvent) -> None:
        p = self._services.protection
        if self._tray is not None and not self._quitting and p is not None and p.settings.enabled:
            # Keep protecting in the background; quit from the tray menu.
            event.ignore()
            self.hide()
            if not self._told_tray:
                self._told_tray = True
                self._tray.showMessage("Sentinel X", self.tr("即時防護仍在背景執行。要結束請在系統匣圖示按右鍵。"),
                                       QSystemTrayIcon.MessageIcon.Information, 8000)
            return
        self._timer.stop()
        if self._tray is not None:
            self._tray.hide()
        for page in (self.scan_page, self.static_page, self.monitor_page, self.lab_page, self.reports_page,
                     self.intel_page, self.threat_page, self.quarantine_page, self.settings_page):
            page.shutdown()
        if self.sandbox_page is not None:
            self.sandbox_page.shutdown()
        super().closeEvent(event)
        # main.py turns off quit-on-last-window while protection runs in the tray; protection may
        # have been turned off since. A real close must still end the program (audit G1).
        QApplication.quit()

    # ---------- tray and background protection ----------
    def _build_tray(self) -> None:
        self._tray = None
        self._told_tray = False
        self._quitting = False
        if self._services.protection is None or not QSystemTrayIcon.isSystemTrayAvailable():
            return
        tray = QSystemTrayIcon(shield_icon(), self)
        tray.setToolTip("Sentinel X")
        menu = QMenu(self)
        menu.addAction(self.tr("開啟 Sentinel X"), self.show_window)
        self._tray_toggle = menu.addAction(self.tr("即時防護"), self._tray_toggle_protection)
        self._tray_toggle.setCheckable(True)
        menu.addSeparator()
        menu.addAction(self.tr("結束 Sentinel X（停止防護）"), self._quit_from_tray)
        tray.setContextMenu(menu)
        tray.activated.connect(lambda reason: self.show_window()
                               if reason in (QSystemTrayIcon.ActivationReason.DoubleClick,
                                             QSystemTrayIcon.ActivationReason.Trigger) else None)
        tray.messageClicked.connect(self.show_window)
        tray.show()
        self._tray = tray

    def show_window(self) -> None:
        self.show()
        self.setWindowState(self.windowState() & ~Qt.WindowState.WindowMinimized)
        self.raise_()
        self.activateWindow()

    @property
    def has_tray(self) -> bool:
        return self._tray is not None

    def prepare_quit(self) -> None:
        self._quitting = True

    def _quit_from_tray(self) -> None:
        self._quitting = True
        QApplication.quit()

    def _tray_toggle_protection(self) -> None:
        p = self._services.protection
        if p is not None:
            p.set_enabled(not p.settings.enabled)
            self.update_indicators()

    def _signature_auto_result(self, res: object) -> None:
        """Called on the automatic-update thread; only emits queued signals."""
        ok = bool(getattr(res, "ok", False))
        if not ok:
            self.bridge.notified.emit("warn", self.tr("病毒碼自動更新失敗"),
                                      self.tr("2 小時後會再試一次。詳細內容見「設定 → ClamAV 病毒碼」。"))
        self.bridge.signatures_changed.emit()

    def notify(self, level: str, title: str, message: str) -> None:
        """From protection threads via ProtectionBridge (queued to the GUI thread)."""
        if self._tray is not None:
            icon = {"bad": QSystemTrayIcon.MessageIcon.Critical, "warn": QSystemTrayIcon.MessageIcon.Warning}.get(
                level, QSystemTrayIcon.MessageIcon.Information)
            self._tray.showMessage(f"Sentinel X：{title}", message, icon, 10_000)
        self.notifications.append((level, title, message))
        if level == "bad":
            self.update_indicators()

    def ask_signature_consent(self, confirm: Confirm = ask_yes_no) -> bool:
        """First start: ask once whether ClamAV signatures may be downloaded. Nothing is
        downloaded without a yes; the answer is stored and can be changed in Settings."""
        sig = self._services.signatures
        if sig is None or not sig.needs_prompt():
            return False
        yes = confirm(self, self.tr("下載 ClamAV 病毒碼"), self.tr(
            "ClamAV 需要病毒碼才能偵測威脅，目前尚未下載。\n\n"
            "要從 ClamAV 官方伺服器（database.clamav.net，Cisco Talos 營運）下載嗎？\n"
            "第一次約數百 MB，可能需要數分鐘；只會下載病毒碼，不會傳送你的檔案。\n"
            "同意後每天會自動更新一次（可在「設定」關閉）。\n\n"
            "選「否」也可以之後在「設定」中下載。"))
        sig.set_consent(yes)
        if yes:
            self.go_to("settings")
            self.settings_page.sig_consent.setChecked(True)
            self.settings_page.start_signature_update()
        return yes

    def _quarantine_verdict(self, verdict_id: int) -> str:
        item = self._services.quarantine.quarantine_verdict(verdict_id, "試跑室確認有危險", confirmed=True)
        self.update_indicators()
        return self.tr("已隔離：{0}").format(item.original_path)

    def check_sandbox_rebuild(self) -> bool:
        """Start the automatic rebuild of the trial-run room when its evaluation is about to expire."""
        from sentinelx.sandbox import FINISHED

        sb = self._services.sandbox
        if not FINISHED:  # not usable yet (audit 8, H3): never build in the background
            return False
        try:
            return bool(sb is not None and sb.rebuild_if_due())
        except Exception:  # noqa: BLE001 - never breaks the window
            log.warning("sandbox rebuild check failed", exc_info=True)
            return False

    # ---------- home page ----------
    def home_state(self) -> HomeState:
        s = self._services
        n_threats, _pending = s.reviews.attention_counts()
        held_locks = len(s.protection.locks.entries("held")) if s.protection is not None else 0
        quarantined = sum(1 for q in s.quarantine.items() if q.status is QuarantineStatus.QUARANTINED)
        sig = s.signatures.status() if s.signatures is not None else None
        present = bool(sig and (sig.present or sig.engine_ready))
        return HomeState(
            protection_on=s.protection.running if s.protection is not None else None,
            signatures_present=present,
            signatures_newest=sig.newest if sig is not None else None,
            signatures_consented=bool(s.signatures and s.signatures.consented),
            attention=n_threats + held_locks,
            quarantined=quarantined,
            virustotal_on=s.virustotal.enabled() if s.virustotal is not None else None,
        )

    def home_action(self, key: str) -> None:
        s = self._services
        if key == "protect_on" and s.protection is not None:
            s.protection.set_enabled(True)
            self.update_indicators()
        elif key == "sandbox":
            self.go_to("sandbox")
        elif key == "quick_scan":
            self.quick_scan()
        elif key == "signatures":
            self.go_to("settings")
            sig = s.signatures
            if sig is not None and sig.consented and not self.settings_page.busy:
                self.settings_page.start_signature_update()
        elif key == "threats" and s.protection is not None and not s.reviews.attention_counts()[0] \
                and s.protection.locks.entries("held"):
            self.go_to("protection")  # only locked files: they are listed on the protection page
        elif key in self.pages:
            self.go_to(key)

    def quick_scan(self) -> list[str]:
        """Scan Downloads, Desktop and Documents. Returns the folders added."""
        from sentinelx.protection import locations

        self.go_to("scan")
        if self.scan_page.scanning:
            return []
        folders = [p for _l, p in locations.watched_folders(downloads_=True, desktop_documents=True, temp=False)]
        self.scan_page.clear_targets()
        for p in folders:
            self.scan_page.add_target(p)
        if self.scan_page.start_button.isEnabled():
            self.scan_page.start_scan()
        return [str(p) for p in folders]

    def current_page_key(self) -> str:
        return str(self.nav.currentItem().data(Qt.ItemDataRole.UserRole))

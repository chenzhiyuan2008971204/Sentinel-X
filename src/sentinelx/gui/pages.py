"""Page widgets.

Only the Dashboard has content in Phase 1, and it shows live status only. Other pages state
plainly that they are not implemented yet and in which phase they are planned; they have
no controls, so nothing on them can pretend to work.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from sentinelx.core.enums import Classification, PrivilegeLevel
from sentinelx.core.risk import CLASS_TEXT
from sentinelx.gui.charts import Bar, CategoryBars, DailyColumns
from sentinelx.gui import theme
from sentinelx.services.review_service import ReviewService
from sentinelx.services.scan_service import ScanService
from sentinelx.services.status_service import StatusService, SystemStatus


@dataclass(frozen=True)
class PageSpec:
    key: str
    title: str
    planned_phase: int | None  # None = implemented now
    advanced: bool = False  # research tools, under 「進階功能」 in the menu


PAGE_SPECS: tuple[PageSpec, ...] = (
    PageSpec("home", "首頁", None),
    PageSpec("scan", "掃描", None),
    PageSpec("sandbox", "試跑室", None),
    PageSpec("protection", "即時防護", None),
    PageSpec("threats", "需要處理的檔案", None),
    PageSpec("quarantine", "隔離區", None),
    PageSpec("settings", "設定", None),
    PageSpec("dashboard", "詳細狀態", None, advanced=True),
    PageSpec("lab", "研究實驗室", None, advanced=True),
    PageSpec("static", "靜態分析", None, advanced=True),
    PageSpec("behavior", "行為監控", None, advanced=True),
    PageSpec("intel", "威脅情報", None, advanced=True),
    PageSpec("reports", "報告", None, advanced=True),
)

PRIVILEGE_TEXT = {
    PrivilegeLevel.STANDARD: "一般使用者",
    PrivilegeLevel.ADMINISTRATOR: "系統管理員",
    PrivilegeLevel.UNKNOWN: "無法判斷",
}


def _title(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("pageTitle")
    return lbl


class NotImplementedPage(QWidget):
    def __init__(self, spec: PageSpec) -> None:
        super().__init__()
        self.setObjectName(f"page_{spec.key}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.addWidget(_title(spec.title))
        self.note = QLabel(self.tr("此頁面尚未實作，預計於 Phase {0} 完成。").format(spec.planned_phase))
        self.note.setObjectName("muted")
        lay.addWidget(self.note)
        lay.addStretch(1)


class _Card(QFrame):
    def __init__(self, title: str) -> None:
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        t = QLabel(title)
        t.setObjectName("cardTitle")
        self.value = QLabel("—")
        self.value.setObjectName("cardValue")
        self.value.setWordWrap(True)
        self.value.setTextFormat(Qt.TextFormat.PlainText)  # engine details and paths are untrusted text
        self.value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(t)
        lay.addWidget(self.value)

    def set(self, text: str, color: str | None = None) -> None:
        self.value.setText(text)
        self.value.setStyleSheet(f"color: {color};" if color else "")


class _ChartCard(QFrame):
    def __init__(self, title: str, chart: QWidget) -> None:
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        t = QLabel(title)
        t.setObjectName("cardTitle")
        lay.addWidget(t)
        lay.addWidget(chart)
        lay.addStretch(1)  # charts keep their height at the top when the row is taller


class DashboardPage(QWidget):
    def __init__(self, status: StatusService, reviews: ReviewService | None = None,
                 scans: ScanService | None = None) -> None:
        super().__init__()
        self.setObjectName("page_dashboard")
        self._status = status
        self._reviews = reviews
        self._scans = scans
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        scroll.setWidget(body)
        outer.addWidget(scroll)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(16)
        lay.addWidget(_title(self.tr("儀表板")))
        sub = QLabel(self.tr("以下為即時檢查結果。威脅統計以每個檔案最新的判定計算，只涵蓋已掃描過的檔案。"))
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        lay.addWidget(sub)

        self.grid = QGridLayout()
        self.grid.setSpacing(12)
        self.cards: dict[str, _Card] = {}
        items = [
            ("threats", self.tr("威脅判定（最新）")),
            ("review", self.tr("待人工審查")),
            ("unknown", self.tr("未完成評估的檔案")),
            ("version", self.tr("版本")),
            ("privilege", self.tr("執行權限")),
            ("engines", self.tr("偵測引擎")),
            ("database", self.tr("資料庫")),
            ("audit", self.tr("稽核紀錄")),
            ("root", self.tr("資料位置")),
        ]
        for key, title in items:
            self.cards[key] = _Card(title)
        self.columns = 0
        lay.addLayout(self.grid)

        self.chart_grid = QGridLayout()
        self.chart_grid.setSpacing(12)
        self.class_chart = CategoryBars(self.tr("尚未掃描過任何檔案"))
        self.activity_chart = DailyColumns(self.tr("最近 14 天沒有掃描"))
        self.chart_cards = [
            _ChartCard(self.tr("目前判定分布（每個檔案最新的判定）"), self.class_chart),
            _ChartCard(self.tr("最近 14 天完整評估的檔案數"), self.activity_chart),
        ]
        lay.addLayout(self.chart_grid)
        self._reflow(3)

        self.refresh_button = QPushButton(self.tr("重新檢查"))
        self.refresh_button.clicked.connect(self.refresh)
        lay.addWidget(self.refresh_button, alignment=Qt.AlignmentFlag.AlignLeft)
        lay.addStretch(1)
        self.refresh()

    def _reflow(self, columns: int) -> None:
        """Responsive layout: 3, 2 or 1 card columns depending on the page width."""
        if columns == self.columns:
            return
        self.columns = columns
        for i, card in enumerate(self.cards.values()):
            self.grid.addWidget(card, i // columns, i % columns)
        for col in range(3):
            self.grid.setColumnStretch(col, 1 if col < columns else 0)
        wide = columns >= 2
        for i, card in enumerate(self.chart_cards):
            self.chart_grid.addWidget(card, 0 if wide else i, i if wide else 0)
        self.chart_grid.setColumnStretch(0, 1)
        self.chart_grid.setColumnStretch(1, 1 if wide else 0)

    def resizeEvent(self, e) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
        w = e.size().width()
        self._reflow(3 if w >= 1000 else 2 if w >= 640 else 1)
        super().resizeEvent(e)

    def refresh(self) -> SystemStatus:
        s = self._status.snapshot()
        self.cards["version"].set(f"Sentinel X {s.app_version}（Python {s.python_version}）")
        priv_color = theme.WARN if s.privilege is PrivilegeLevel.ADMINISTRATOR else None
        self.cards["privilege"].set(PRIVILEGE_TEXT[s.privilege], priv_color)
        avail = s.available_engines
        if avail:
            self.cards["engines"].set("、".join(f"{e.name} {e.version}" for e in avail), theme.OK)
        elif s.engines:
            self.cards["engines"].set(
                self.tr("無可用引擎：") + "；".join(e.detail for e in s.engines), theme.BAD
            )
        else:
            self.cards["engines"].set(self.tr("未設定任何偵測引擎"), theme.BAD)
        if s.database_integrity_ok:
            self.cards["database"].set(self.tr("正常，結構版本 {0}").format(s.schema_version), theme.OK)
        else:
            self.cards["database"].set(self.tr("完整性檢查失敗"), theme.BAD)
        if s.audit_chain.ok:
            self.cards["audit"].set(self.tr("雜湊鏈完整，共 {0} 筆").format(s.audit_chain.entries), theme.OK)
        else:
            self.cards["audit"].set(
                self.tr("雜湊鏈在第 {0} 筆中斷").format(s.audit_chain.first_bad_id), theme.BAD
            )
        self.cards["root"].set(str(s.data_root))
        if self._reviews is not None:
            counts = self._reviews.class_counts()
            conf, susp = counts[Classification.CONFIRMED_THREAT], counts[Classification.SUSPICIOUS]
            self.cards["threats"].set(
                self.tr("確認威脅 {0}，可疑 {1}，未發現威脅 {2}").format(conf, susp, counts[Classification.CLEAN]),
                theme.BAD if conf else (theme.WARN if susp else theme.OK),
            )
            _, pending = self._reviews.attention_counts()
            self.cards["review"].set(self.tr("{0} 個").format(pending), theme.WARN if pending else None)
            unk = counts[Classification.UNKNOWN]
            self.cards["unknown"].set(self.tr("{0} 個").format(unk), theme.WARN if unk else None)
            self.class_chart.set_bars([
                Bar(CLASS_TEXT[c], counts[c], color, f"{CLASS_TEXT[c]}（{c.value}）：{counts[c]:,} 個檔案")
                for c, color in ((Classification.CONFIRMED_THREAT, theme.BAD), (Classification.SUSPICIOUS, theme.WARN),
                                 (Classification.UNKNOWN, theme.TEXT_MUTED), (Classification.CLEAN, theme.OK))])
        else:
            for k in ("threats", "review", "unknown"):
                self.cards[k].set(self.tr("無資料"), theme.TEXT_MUTED)
            self.class_chart.set_bars([])
        if self._scans is not None:
            self.activity_chart.set_bars([
                Bar(f"{d.day.month}/{d.day.day}", d.files_assessed, theme.CYAN,
                    f"{d.day.isoformat()}：{d.jobs} 次掃描，{d.files_assessed:,} 個檔案完整評估，"
                    f"{d.files_not_assessed:,} 個未完成評估或排除")
                for d in self._scans.daily_activity(14)])
        return s

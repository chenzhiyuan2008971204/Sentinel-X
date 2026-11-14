"""Home page: one look tells whether the computer is protected and what (if anything) to do.

Written for people who are not security experts: plain words, one main action, each item
says what it means. Every number and state comes from the real services.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from sentinelx.gui import theme

STALE_DAYS = 3  # signatures older than this are reported as out of date


@dataclass(frozen=True)
class HomeState:
    protection_on: bool | None  # None: real-time protection not available in this build
    signatures_present: bool
    signatures_newest: str | None  # UTC "YYYY-MM-DDTHH:MM:SSZ"
    signatures_consented: bool
    attention: int  # verdicts that need a look + files held by the execution lock
    quarantined: int
    scanned_today: int | None = None
    virustotal_on: bool | None = None  # None: not available in this build


def days_since(ts: str | None, now: datetime | None = None) -> int | None:
    if not ts:
        return None
    try:
        t = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None
    return max(0, ((now or datetime.now(UTC)) - t).days)


@dataclass(frozen=True)
class Hero:
    level: str  # ok / warn / bad
    headline: str
    detail: str
    action: str | None  # button text
    action_key: str | None  # what the button does


def hero_for(s: HomeState, now: datetime | None = None) -> Hero:
    """The single most important message, in priority order."""
    if s.protection_on is False:
        return Hero("bad", "即時防護已關閉", "新下載的檔案不會被自動檢查。建議現在開啟。", "開啟即時防護", "protect_on")
    if not s.signatures_present:
        if not s.signatures_consented:
            return Hero("warn", "還沒有病毒碼", "沒有病毒碼，就認不出大部分已知病毒。需要你同意下載一次。",
                        "前往下載病毒碼", "signatures")
        return Hero("warn", "還沒有病毒碼", "病毒碼還沒下載完成。沒有病毒碼，就認不出大部分已知病毒。",
                    "立即更新病毒碼", "signatures")
    if s.attention:
        return Hero("warn", f"有 {s.attention} 個檔案需要你看一下",
                    "Sentinel X 找到可能有問題的檔案，已經先擋下來。請看一下並決定怎麼處理。", "查看檔案", "threats")
    age = days_since(s.signatures_newest, now)
    if age is not None and age > STALE_DAYS:
        return Hero("warn", f"病毒碼已經 {age} 天沒更新", "舊的病毒碼認不出新的病毒。按下按鈕更新。",
                    "立即更新病毒碼", "signatures")
    if s.protection_on is None:
        return Hero("ok", "沒有發現需要處理的事", "這個版本沒有即時防護，請定期掃描。", "快速掃描", "quick_scan")
    when = "今天" if age == 0 else (f"{age} 天前" if age is not None else "已下載")
    return Hero("ok", "你的電腦受到保護", f"即時防護開啟中，病毒碼{when}更新。不需要做任何事。", None, None)


def checklist(s: HomeState, now: datetime | None = None) -> list[tuple[str, str, str, str, str | None, str | None]]:
    """(key, level, title, explanation, button, action) for each status row."""
    rows = []
    if s.protection_on is not None:
        rows.append(("protection", "ok" if s.protection_on else "bad",
                     "即時防護：" + ("開啟" if s.protection_on else "關閉"),
                     "自動檢查新下載、放到桌面或文件、插入 USB 的檔案；下載的新程式檢查完才能執行。",
                     None if s.protection_on else "開啟", None if s.protection_on else "protect_on"))
    age = days_since(s.signatures_newest, now)
    if not s.signatures_present:
        sig = ("bad", "病毒碼：還沒下載")
    elif age is not None and age > STALE_DAYS:
        sig = ("warn", f"病毒碼：{age} 天前更新")
    else:
        sig = ("ok", "病毒碼：" + ("今天更新" if age == 0 else (f"{age} 天前更新" if age is not None else "已下載")))
    rows.append(("signatures", sig[0], sig[1], "病毒碼是已知病毒的特徵清單，每天會自動更新。",
                 "更新" if sig[0] != "ok" else None, "signatures" if sig[0] != "ok" else None))
    rows.append(("threats", "warn" if s.attention else "ok",
                 f"需要你處理的檔案：{s.attention} 個" if s.attention else "需要你處理的檔案：沒有",
                 "可疑或確認有問題的檔案會列在這裡，由你決定隔離或標記為誤判。",
                 "查看" if s.attention else None, "threats" if s.attention else None))
    if s.virustotal_on is not None:
        rows.append(("virustotal", "ok" if s.virustotal_on else "warn",
                     "全球防毒查詢（VirusTotal）：" + ("開啟" if s.virustotal_on else "未設定"),
                     "用檔案指紋查 70 多家防毒的判斷，能認出更多新病毒；只送指紋，不上傳檔案。",
                     None if s.virustotal_on else "設定", None if s.virustotal_on else "settings"))
    rows.append(("quarantine", "ok", f"隔離區：{s.quarantined} 個檔案",
                 "被關起來的危險檔案，不能執行；誤判可以還原，不要的可以由你永久刪除。",
                 "打開" if s.quarantined else None, "quarantine" if s.quarantined else None))
    return rows


ICON = {"ok": "✓", "warn": "!", "bad": "✕"}
COLOR = {"ok": theme.OK, "warn": theme.WARN, "bad": theme.BAD}


class HomePage(QWidget):
    def __init__(self, state: Callable[[], HomeState], act: Callable[[str], None]) -> None:
        super().__init__()
        self.setObjectName("page_home")
        self._state = state
        self._act = act
        lay = QVBoxLayout(self)
        lay.setContentsMargins(40, 32, 40, 24)
        lay.setSpacing(18)

        hero = QFrame()
        hero.setObjectName("hero")
        h = QHBoxLayout(hero)
        h.setContentsMargins(28, 24, 28, 24)
        h.setSpacing(24)
        self.hero_icon = QLabel()
        self.hero_icon.setObjectName("heroIcon")
        self.hero_icon.setFixedSize(84, 84)
        self.hero_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        h.addWidget(self.hero_icon)
        text = QVBoxLayout()
        text.setSpacing(6)
        self.hero_title = QLabel()
        self.hero_title.setObjectName("heroTitle")
        self.hero_title.setTextFormat(Qt.TextFormat.PlainText)
        self.hero_detail = QLabel()
        self.hero_detail.setObjectName("heroDetail")
        self.hero_detail.setWordWrap(True)
        self.hero_detail.setTextFormat(Qt.TextFormat.PlainText)
        text.addStretch(1)
        text.addWidget(self.hero_title)
        text.addWidget(self.hero_detail)
        text.addStretch(1)
        h.addLayout(text, 1)
        self.hero_button = QPushButton()
        self.hero_button.setObjectName("primary")
        self.hero_button.clicked.connect(lambda: self._run(self._hero_key))
        h.addWidget(self.hero_button, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addWidget(hero)
        self._hero_key: str | None = None

        actions = QHBoxLayout()
        actions.setSpacing(14)
        self.quick_button = self._tile("快速掃描", "檢查下載、桌面和文件資料夾", "quick_scan")
        self.pick_button = self._tile("掃描指定位置", "自己選要檢查的檔案或資料夾", "scan")
        from sentinelx.sandbox import FINISHED

        self.sandbox_button = self._tile("試跑室" if FINISHED else "試跑室（開發中）",
                                         "要安裝的軟體，先在假電腦裡跑看看" if FINISHED else "還不能使用，完成後會開放",
                                         "sandbox")
        actions.addWidget(self.quick_button)
        actions.addWidget(self.pick_button)
        actions.addWidget(self.sandbox_button)
        lay.addLayout(actions)

        lay.addWidget(self._section("目前狀態"))
        self.rows_box = QFrame()
        self.rows_box.setObjectName("card")
        self.rows = QGridLayout(self.rows_box)
        self.rows.setContentsMargins(20, 10, 20, 10)
        self.rows.setVerticalSpacing(4)
        self.rows.setColumnStretch(1, 1)
        lay.addWidget(self.rows_box)
        lay.addStretch(1)
        self.row_widgets: dict[str, tuple[QLabel, QLabel, QLabel, QPushButton]] = {}
        self.row_actions: dict[str, str | None] = {}
        self.refresh()

    @staticmethod
    def _section(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("sectionTitle")
        return lbl

    def _tile(self, title: str, sub: str, key: str) -> QPushButton:
        b = QPushButton()
        b.setObjectName("tile")
        b.setMinimumHeight(80)
        b.setAccessibleName(f"{title}：{sub}")
        inner = QVBoxLayout(b)
        inner.setContentsMargins(20, 12, 20, 12)
        inner.setSpacing(2)
        t = QLabel(title)
        t.setObjectName("tileTitle")
        s = QLabel(sub)
        s.setObjectName("muted")
        for lbl in (t, s):
            lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            inner.addWidget(lbl)
        b.clicked.connect(lambda: self._run(key))
        return b

    def _run(self, key: str | None) -> None:
        if key:
            self._act(key)
            self.refresh()

    def _row(self, i: int, key: str) -> tuple[QLabel, QLabel, QLabel, QPushButton]:
        if key not in self.row_widgets:
            dot = QLabel()
            dot.setObjectName("rowDot")
            dot.setFixedWidth(28)
            dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
            title = QLabel()
            title.setObjectName("rowTitle")
            title.setTextFormat(Qt.TextFormat.PlainText)
            expl = QLabel()
            expl.setObjectName("muted")
            expl.setWordWrap(True)
            expl.setTextFormat(Qt.TextFormat.PlainText)
            btn = QPushButton()
            btn.setObjectName("secondary")
            btn.clicked.connect(lambda _=False, k=key: self._run(self.row_actions.get(k)))
            col = QVBoxLayout()
            col.setSpacing(2)
            col.setContentsMargins(0, 8, 0, 8)
            col.addWidget(title)
            col.addWidget(expl)
            holder = QWidget()
            holder.setLayout(col)
            self.rows.addWidget(dot, i, 0, Qt.AlignmentFlag.AlignTop)
            self.rows.addWidget(holder, i, 1)
            self.rows.addWidget(btn, i, 2, Qt.AlignmentFlag.AlignVCenter)
            self.row_widgets[key] = (dot, title, expl, btn)
        return self.row_widgets[key]

    def refresh(self) -> None:
        s = self._state()
        hero = hero_for(s)
        color = COLOR[hero.level]
        self.hero_icon.setText(ICON[hero.level])
        self.hero_icon.setStyleSheet(f"color: {color}; border: 3px solid {color}; border-radius: 42px;"
                                     "font-size: 40px; font-weight: 700;")
        self.hero_title.setText(hero.headline)
        self.hero_title.setStyleSheet(f"color: {color};")
        self.hero_detail.setText(hero.detail)
        self._hero_key = hero.action_key
        self.hero_button.setVisible(hero.action is not None)
        self.hero_button.setText(hero.action or "")
        for i, (key, level, title, expl, button, action) in enumerate(checklist(s)):
            dot, t, e, b = self._row(i, key)
            dot.setText(ICON[level])
            dot.setStyleSheet(f"color: {COLOR[level]}; font-size: 18px; font-weight: 700; padding-top: 8px;")
            t.setText(title)
            e.setText(expl)
            b.setVisible(button is not None)
            b.setText(button or "")
            self.row_actions[key] = action

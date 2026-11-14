"""Two small painted charts for the Dashboard. Real data only; an empty data set says so.

- `CategoryBars`: horizontal bars, one per category, each directly labelled with its name
  and value (identity never depends on colour alone).
- `DailyColumns`: one series of columns over days, with a hover tooltip per column.

Marks follow one style: thin bars, 4 px rounded data end, 2 px gaps, recessive baseline,
text in text colours (never in the bar colour).
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFont, QMouseEvent, QPainter, QPainterPath, QPaintEvent
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from sentinelx.gui import theme

RADIUS = 4.0
GAP = 2.0


@dataclass(frozen=True)
class Bar:
    label: str
    value: int
    color: str
    tip: str = ""


def _rounded_end(rect: QRectF, *, end: str) -> QPainterPath:
    """Rectangle with the data end rounded (right for horizontal bars, top for columns)."""
    r = min(RADIUS, rect.width() / 2, rect.height() / 2)
    p = QPainterPath()
    if end == "right":
        p.moveTo(rect.left(), rect.top())
        p.lineTo(rect.right() - r, rect.top())
        p.quadTo(rect.right(), rect.top(), rect.right(), rect.top() + r)
        p.lineTo(rect.right(), rect.bottom() - r)
        p.quadTo(rect.right(), rect.bottom(), rect.right() - r, rect.bottom())
        p.lineTo(rect.left(), rect.bottom())
    else:
        p.moveTo(rect.left(), rect.bottom())
        p.lineTo(rect.left(), rect.top() + r)
        p.quadTo(rect.left(), rect.top(), rect.left() + r, rect.top())
        p.lineTo(rect.right() - r, rect.top())
        p.quadTo(rect.right(), rect.top(), rect.right(), rect.top() + r)
        p.lineTo(rect.right(), rect.bottom())
    p.closeSubpath()
    return p


class _Chart(QWidget):
    def __init__(self, empty_text: str) -> None:
        super().__init__()
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.empty_text = empty_text
        self._hits: list[tuple[QRectF, str]] = []
        self.hover: int | None = None

    def _text(self, p: QPainter, color: str, size: int = 12) -> None:
        f = QFont(self.font())
        f.setPixelSize(size)
        p.setFont(f)
        p.setPen(QColor(color))

    def tip_at(self, pos: QPointF) -> tuple[int, str] | None:
        for i, (r, tip) in enumerate(self._hits):
            if r.contains(pos):
                return i, tip
        return None

    def mouseMoveEvent(self, e: QMouseEvent) -> None:  # noqa: N802
        hit = self.tip_at(e.position())
        new = hit[0] if hit else None
        if new != self.hover:
            self.hover = new
            self.update()
        if hit:
            QToolTip.showText(e.globalPosition().toPoint(), hit[1], self)
        else:
            QToolTip.hideText()

    def leaveEvent(self, _e: object) -> None:  # noqa: N802
        self.hover = None
        self.update()


class CategoryBars(_Chart):
    ROW = 30
    LABEL_W = 92

    def __init__(self, empty_text: str = "沒有資料") -> None:
        super().__init__(empty_text)
        self.bars: list[Bar] = []

    def set_bars(self, bars: list[Bar]) -> None:
        self.bars = bars
        self.setFixedHeight(max(1, len(bars)) * self.ROW + 8)
        self.setAccessibleDescription("；".join(f"{b.label} {b.value}" for b in bars))
        self.update()

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(320, self.height())

    def paintEvent(self, _e: QPaintEvent) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._hits = []
        total = sum(b.value for b in self.bars)
        if not self.bars or total == 0:
            self._text(p, theme.TEXT_MUTED, 13)
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.empty_text)
            return
        vmax = max(b.value for b in self.bars)
        value_w = 64
        x0 = float(self.LABEL_W)
        span = max(10.0, self.width() - x0 - value_w)
        for i, b in enumerate(self.bars):
            y = 4 + i * self.ROW
            row = QRectF(0, y, self.width(), self.ROW)
            self._text(p, theme.TEXT_MUTED, 12)
            p.drawText(QRectF(0, y, self.LABEL_W - 8, self.ROW), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                       b.label)
            w = span * b.value / vmax if vmax else 0
            bar = QRectF(x0, y + (self.ROW - 12) / 2, max(w, 2.0 if b.value else 0.0), 12)
            if b.value:
                c = QColor(b.color)
                if self.hover is not None and self.hover != i:
                    c.setAlpha(110)
                p.fillPath(_rounded_end(bar, end="right"), c)
            self._text(p, theme.TEXT, 12)
            p.drawText(QRectF(bar.right() + 8, y, value_w, self.ROW), Qt.AlignmentFlag.AlignVCenter, f"{b.value:,}")
            self._hits.append((row, b.tip or f"{b.label}：{b.value:,}"))


class DailyColumns(_Chart):
    def __init__(self, empty_text: str = "沒有資料") -> None:
        super().__init__(empty_text)
        self.bars: list[Bar] = []  # label = short date, value = count
        self.setFixedHeight(180)

    def set_bars(self, bars: list[Bar]) -> None:
        self.bars = bars
        self.setAccessibleDescription("；".join(f"{b.label} {b.value}" for b in bars))
        self.update()

    def paintEvent(self, _e: QPaintEvent) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._hits = []
        vmax = max((b.value for b in self.bars), default=0)
        top, bottom, left, right = 18.0, 22.0, 4.0, 4.0
        base_y = self.height() - bottom
        if not self.bars or vmax == 0:
            self._text(p, theme.TEXT_MUTED, 13)
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.empty_text)
            return
        p.setPen(QColor(theme.NAVY_600))
        p.drawLine(QPointF(left, base_y), QPointF(self.width() - right, base_y))
        self._text(p, theme.TEXT_MUTED, 11)
        p.drawText(QRectF(left, 0, 200, top), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   f"最高 {vmax:,}")
        n = len(self.bars)
        slot = (self.width() - left - right) / n
        bw = max(3.0, min(22.0, slot - 2 * GAP))
        plot_h = base_y - top
        for i, b in enumerate(self.bars):
            sx = left + i * slot
            h = plot_h * b.value / vmax
            if b.value:
                h = max(h, 2.0)
                rect = QRectF(sx + (slot - bw) / 2, base_y - h, bw, h)
                c = QColor(b.color)
                if self.hover is not None and self.hover != i:
                    c.setAlpha(110)
                p.fillPath(_rounded_end(rect, end="top"), c)
            if i in (0, n // 2, n - 1):
                self._text(p, theme.TEXT_MUTED, 11)
                p.drawText(QRectF(sx - 20, base_y + 2, slot + 40, bottom - 2), Qt.AlignmentFlag.AlignCenter, b.label)
            self._hits.append((QRectF(sx, 0, slot, self.height()), b.tip or f"{b.label}：{b.value:,}"))

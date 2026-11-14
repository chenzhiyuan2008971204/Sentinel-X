"""Dark navy / cyan theme."""

from __future__ import annotations

NAVY_900 = "#0b1220"
NAVY_800 = "#111a2e"
NAVY_700 = "#1a2540"
NAVY_600 = "#25324f"
CYAN = "#22d3ee"
CYAN_DIM = "#0e7490"
TEXT = "#e2e8f0"
TEXT_MUTED = "#94a3b8"
OK = "#34d399"
WARN = "#fbbf24"
BAD = "#f87171"

FONT_FAMILIES = ["Microsoft JhengHei UI", "Microsoft JhengHei", "Segoe UI", "sans-serif"]

STYLESHEET = f"""
QMainWindow, QWidget#central {{ background: {NAVY_900}; color: {TEXT}; }}
QWidget {{ color: {TEXT}; font-size: 14px; }}
QListWidget#nav {{
    background: {NAVY_800}; border: none; padding: 12px 8px; outline: 0;
}}
QListWidget#nav::item {{ padding: 10px 14px; border-radius: 6px; margin: 2px 0; color: {TEXT_MUTED}; }}
QListWidget#nav::item:hover {{ background: {NAVY_700}; color: {TEXT}; }}
QListWidget#nav::item:selected {{ background: {NAVY_600}; color: {CYAN}; border-left: 3px solid {CYAN}; }}
QLabel#brand {{ color: {CYAN}; font-size: 20px; font-weight: 700; padding: 18px 16px 6px 16px; background: {NAVY_800}; }}
QLabel#edition {{ color: {TEXT_MUTED}; font-size: 12px; padding: 0 16px 12px 16px; background: {NAVY_800}; }}
QLabel#pageTitle {{ font-size: 24px; font-weight: 600; color: {TEXT}; }}
QLabel#muted {{ color: {TEXT_MUTED}; }}
QFrame#card {{ background: {NAVY_800}; border: 1px solid {NAVY_600}; border-radius: 10px; }}
QLabel#cardTitle {{ color: {TEXT_MUTED}; font-size: 12px; }}
QLabel#cardValue {{ font-size: 16px; font-weight: 600; }}
QPushButton {{
    background: {CYAN_DIM}; color: white; border: none; border-radius: 6px; padding: 8px 16px;
}}
QPushButton:hover {{ background: {CYAN}; color: {NAVY_900}; }}
QPushButton:disabled {{ background: {NAVY_700}; color: #4b5a78; }}
QStatusBar {{ background: {NAVY_800}; color: {TEXT_MUTED}; }}
QListWidget, QTableWidget, QTreeWidget, QPlainTextEdit, QLineEdit, QComboBox, QTextBrowser {{
    background: {NAVY_800}; border: 1px solid {NAVY_600}; border-radius: 6px;
    selection-background-color: {NAVY_600}; selection-color: {CYAN};
}}
QLineEdit, QComboBox {{ padding: 6px 8px; }}
QComboBox QAbstractItemView {{ background: {NAVY_800}; selection-background-color: {NAVY_600}; }}
QTableWidget {{ gridline-color: {NAVY_700}; }}
QTreeWidget {{ color: {TEXT}; alternate-background-color: {NAVY_700}; }}
QPlainTextEdit {{ color: {TEXT}; font-family: Consolas, "Cascadia Mono", monospace; }}
QHeaderView::section {{
    background: {NAVY_700}; color: {TEXT_MUTED}; border: none; padding: 6px 8px;
}}
QTableCornerButton::section {{ background: {NAVY_700}; border: none; }}
QTabWidget::pane {{ border: 1px solid {NAVY_600}; border-radius: 6px; top: -1px; }}
QTabBar::tab {{
    background: {NAVY_800}; color: {TEXT_MUTED}; padding: 8px 16px;
    border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px;
}}
QTabBar::tab:selected {{ background: {NAVY_700}; color: {CYAN}; }}
QProgressBar {{ background: {NAVY_800}; border: 1px solid {NAVY_600}; border-radius: 4px; height: 8px; }}
QProgressBar::chunk {{ background: {CYAN}; border-radius: 4px; }}
QSplitter::handle {{ background: {NAVY_900}; }}
QSpinBox, QDoubleSpinBox {{
    background: {NAVY_800}; border: 1px solid {NAVY_600}; border-radius: 6px; padding: 5px 8px;
}}
QGroupBox {{
    border: 1px solid {NAVY_600}; border-radius: 10px; margin-top: 14px; padding: 16px 12px 10px 12px;
    background: {NAVY_800};
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 14px; padding: 0 6px; color: {CYAN}; }}
QCheckBox {{ spacing: 6px; }}
QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus, QPlainTextEdit:focus {{
    border: 1px solid {CYAN_DIM};
}}
QSpinBox::up-button, QSpinBox::down-button, QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {{
    width: 18px; background: {NAVY_700}; border: none;
}}
QSpinBox::up-button:hover, QSpinBox::down-button:hover, QDoubleSpinBox::up-button:hover,
QDoubleSpinBox::down-button:hover {{ background: {NAVY_600}; }}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
    width: 0; height: 0; border-left: 4px solid transparent; border-right: 4px solid transparent;
    border-bottom: 5px solid {TEXT_MUTED};
}}
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
    width: 0; height: 0; border-left: 4px solid transparent; border-right: 4px solid transparent;
    border-top: 5px solid {TEXT_MUTED};
}}
QScrollBar:vertical {{ background: {NAVY_900}; width: 10px; margin: 0; }}
QScrollBar:horizontal {{ background: {NAVY_900}; height: 10px; margin: 0; }}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
    background: {NAVY_600}; border-radius: 5px; min-height: 24px; min-width: 24px;
}}
QScrollBar::handle:hover {{ background: {CYAN_DIM}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QStatusBar QLabel {{ color: {TEXT_MUTED}; padding: 0 10px; }}
QLabel#statusOk {{ color: {OK}; }}
QLabel#statusWarn {{ color: {WARN}; }}
QWidget#side {{ background: {NAVY_800}; }}
QListWidget#nav::item {{ padding: 11px 16px; font-size: 15px; }}
QFrame#hero {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {NAVY_700}, stop:1 {NAVY_800});
    border: 1px solid {NAVY_600}; border-radius: 16px;
}}
QLabel#heroTitle {{ font-size: 28px; font-weight: 700; background: transparent; }}
QLabel#heroDetail {{ font-size: 15px; color: {TEXT_MUTED}; background: transparent; }}
QLabel#heroIcon {{ background: transparent; }}
QLabel#sectionTitle {{ font-size: 15px; font-weight: 600; color: {TEXT_MUTED}; padding-top: 4px; }}
QLabel#rowTitle {{ font-size: 15px; font-weight: 600; background: transparent; }}
QFrame#card QLabel {{ background: transparent; }}
QPushButton#primary {{
    background: {CYAN}; color: {NAVY_900}; font-size: 15px; font-weight: 700;
    padding: 12px 26px; border-radius: 10px;
}}
QPushButton#primary:hover {{ background: #67e8f9; }}
QPushButton#secondary {{
    background: transparent; color: {CYAN}; border: 1px solid {CYAN_DIM}; border-radius: 8px; padding: 6px 18px;
}}
QPushButton#secondary:hover {{ background: {NAVY_700}; color: {CYAN}; }}
QPushButton#tile {{
    background: {NAVY_800}; color: {TEXT}; border: 1px solid {NAVY_600}; border-radius: 14px;
    padding: 14px 20px; text-align: left; font-size: 15px;
}}
QPushButton#tile:hover {{ background: {NAVY_700}; border: 1px solid {CYAN_DIM}; color: {TEXT}; }}
QLabel#optionHelp {{ color: {TEXT_MUTED}; font-size: 12px; padding-left: 26px; }}
"""
STYLESHEET += f"""
QLabel#tileTitle {{ font-size: 16px; font-weight: 700; color: {TEXT}; background: transparent; }}
QPushButton#tile QLabel#muted {{ background: transparent; }}
"""
STYLESHEET += f"""
QPushButton#danger {{ background: transparent; color: {BAD}; border: 1px solid {BAD}; }}
QPushButton#danger:hover {{ background: {BAD}; color: {NAVY_900}; }}
QPushButton#danger:disabled {{ color: #4b5a78; border: 1px solid {NAVY_700}; }}
"""

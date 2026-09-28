"""Qt style sheet generated from a Palette."""

from __future__ import annotations

from genmap.ui.theme.palettes import Palette


def build_stylesheet(p: Palette, base_font_pt: int, mono_family: str) -> str:
    small = max(base_font_pt - 1, 7)
    return f"""
QWidget {{
    color: {p.text};
    font-size: {base_font_pt}pt;
}}
QMainWindow, QDialog, QStackedWidget > QWidget {{
    background: {p.window};
}}
QToolTip {{
    background: {p.surface};
    color: {p.text};
    border: 1px solid {p.border_strong};
    padding: 4px 6px;
}}
QLabel[role="title"] {{
    font-size: {base_font_pt + 7}pt;
    font-weight: 600;
}}
QLabel[role="subtitle"] {{
    color: {p.text_muted};
    font-size: {base_font_pt + 1}pt;
}}
QLabel[role="section"] {{
    font-size: {base_font_pt + 1}pt;
    font-weight: 600;
}}
QLabel[role="muted"] {{
    color: {p.text_muted};
}}
QLabel[role="small"] {{
    color: {p.text_muted};
    font-size: {small}pt;
}}
QLabel[role="metric"] {{
    font-size: {base_font_pt + 10}pt;
    font-weight: 600;
}}
QLabel[role="mono"] {{
    font-family: {mono_family};
}}
QLabel[status="ok"] {{ color: {p.success}; font-weight: 600; }}
QLabel[status="warning"] {{ color: {p.warning}; font-weight: 600; }}
QLabel[status="error"] {{ color: {p.danger}; font-weight: 600; }}
QLabel[status="info"] {{ color: {p.info}; font-weight: 600; }}
QCheckBox[status="warning"] {{ color: {p.warning}; }}
QPushButton[flat="true"][status="ok"] {{ color: {p.success}; }}
QPushButton[flat="true"][status="warning"] {{ color: {p.warning}; }}
QPushButton[flat="true"][status="error"] {{ color: {p.danger}; }}
QPushButton[flat="true"][status="info"] {{ color: {p.info}; }}

QFrame[card="true"] {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 6px;
}}
QFrame[card="true"] QLabel {{
    background: transparent;
}}
QFrame[role="separator"] {{
    background: {p.border};
    max-height: 1px;
    min-height: 1px;
}}
QFrame[role="banner-warning"] {{
    background: {p.surface_alt};
    border: 1px solid {p.warning};
    border-radius: 6px;
}}
QFrame[role="banner-error"] {{
    background: {p.surface_alt};
    border: 1px solid {p.danger};
    border-radius: 6px;
}}
QFrame[role="banner-info"] {{
    background: {p.surface_alt};
    border: 1px solid {p.border_strong};
    border-radius: 6px;
}}

QPushButton {{
    background: {p.surface};
    border: 1px solid {p.border_strong};
    border-radius: 4px;
    padding: 6px 14px;
    min-height: 18px;
}}
QPushButton:hover {{ background: {p.surface_alt}; }}
QPushButton:pressed {{ background: {p.selection}; }}
QPushButton:disabled {{ color: {p.text_muted}; border-color: {p.border}; }}
QPushButton[accent="true"] {{
    background: {p.accent};
    color: {p.accent_text};
    border: 1px solid {p.accent};
    font-weight: 600;
}}
QPushButton[accent="true"]:hover {{ background: {p.accent_hover}; border-color: {p.accent_hover}; }}
QPushButton[accent="true"]:pressed {{ background: {p.accent_pressed}; }}
QPushButton[accent="true"]:disabled {{ background: {p.border}; border-color: {p.border}; color: {p.text_muted}; }}
QPushButton[danger="true"] {{
    color: {p.danger};
    border-color: {p.danger};
}}
QPushButton[danger="true"]:disabled {{
    color: {p.text_muted};
    border-color: {p.border};
}}
QPushButton[flat="true"] {{
    border: none;
    background: transparent;
    padding: 4px 8px;
    color: {p.accent};
}}
QPushButton[flat="true"]:hover {{ text-decoration: underline; }}
QToolButton {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 4px;
}}
QToolButton:hover {{ background: {p.surface_alt}; border-color: {p.border}; }}

QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {{
    background: {p.input_bg};
    border: 1px solid {p.border_strong};
    border-radius: 4px;
    padding: 5px 7px;
    selection-background-color: {p.accent};
    selection-color: {p.accent_text};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border: 1px solid {p.accent};
}}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled, QPlainTextEdit:disabled {{
    color: {p.text_muted};
    background: {p.surface_alt};
}}
QLineEdit[invalid="true"] {{
    border: 1px solid {p.danger};
}}
QPlainTextEdit[role="console"] {{
    background: {p.console_bg};
    color: {p.console_text};
    border: 1px solid {p.border};
    font-family: {mono_family};
}}
QPlainTextEdit[role="mono"], QLineEdit[role="mono"], QTextEdit[role="mono"] {{
    font-family: {mono_family};
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox QAbstractItemView {{
    background: {p.surface};
    border: 1px solid {p.border_strong};
    selection-background-color: {p.selection};
    selection-color: {p.selection_text};
    outline: none;
}}
QSpinBox::up-button, QSpinBox::down-button {{
    width: 16px;
    border: none;
    background: transparent;
}}

QCheckBox, QRadioButton {{
    spacing: 8px;
    padding: 2px 0;
}}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 16px;
    height: 16px;
}}
QGroupBox {{
    border: 1px solid {p.border};
    border-radius: 6px;
    margin-top: 12px;
    padding: 10px 8px 6px 8px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: {p.text};
}}

QTabWidget::pane {{
    border: 1px solid {p.border};
    border-radius: 4px;
    background: {p.surface};
    top: -1px;
}}
QTabBar::tab {{
    background: {p.surface_alt};
    border: 1px solid {p.border};
    border-bottom: none;
    padding: 7px 14px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    color: {p.text_muted};
}}
QTabBar::tab:selected {{
    background: {p.surface};
    color: {p.text};
    font-weight: 600;
}}
QTabBar::tab:hover:!selected {{ color: {p.text}; }}

QTreeView, QTableView, QListView, QListWidget, QTreeWidget, QTableWidget {{
    background: {p.surface};
    alternate-background-color: {p.surface_alt};
    border: 1px solid {p.border};
    border-radius: 4px;
    selection-background-color: {p.selection};
    selection-color: {p.selection_text};
    outline: none;
}}
QTreeView::item, QTableView::item, QListView::item {{
    padding: 3px 4px;
    min-height: 22px;
}}
QTreeView::item:hover, QTableView::item:hover, QListView::item:hover {{
    background: {p.surface_alt};
}}
QTreeView::item:selected, QTableView::item:selected, QListView::item:selected {{
    background: {p.selection};
    color: {p.selection_text};
}}
QHeaderView::section {{
    background: {p.surface_alt};
    color: {p.text_muted};
    border: none;
    border-bottom: 1px solid {p.border};
    border-right: 1px solid {p.border};
    padding: 5px 6px;
    font-weight: 600;
}}
QTreeView::branch {{
    background: transparent;
}}

QScrollBar:vertical {{
    background: transparent;
    width: 12px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {p.border_strong};
    border-radius: 5px;
    min-height: 28px;
    margin: 2px 3px;
}}
QScrollBar::handle:vertical:hover {{ background: {p.text_muted}; }}
QScrollBar:horizontal {{
    background: transparent;
    height: 12px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {p.border_strong};
    border-radius: 5px;
    min-width: 28px;
    margin: 3px 2px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{
    width: 0; height: 0;
}}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

QProgressBar {{
    background: {p.surface_alt};
    border: 1px solid {p.border};
    border-radius: 4px;
    text-align: center;
    min-height: 16px;
}}
QProgressBar::chunk {{
    background: {p.accent};
    border-radius: 3px;
}}

QSplitter::handle {{
    background: {p.border};
}}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical {{ height: 1px; }}

QMenuBar {{
    background: {p.window};
    border-bottom: 1px solid {p.border};
}}
QMenuBar::item {{ padding: 5px 10px; background: transparent; }}
QMenuBar::item:selected {{ background: {p.surface_alt}; }}
QMenu {{
    background: {p.surface};
    border: 1px solid {p.border_strong};
    padding: 4px;
}}
QMenu::item {{ padding: 6px 24px 6px 12px; border-radius: 3px; }}
QMenu::item:selected {{ background: {p.selection}; color: {p.selection_text}; }}
QMenu::separator {{ height: 1px; background: {p.border}; margin: 4px 6px; }}

QStatusBar {{
    background: {p.surface};
    border-top: 1px solid {p.border};
    color: {p.text_muted};
}}
QStatusBar::item {{ border: none; }}

QListWidget#sidebar {{
    background: {p.sidebar_bg};
    color: {p.sidebar_text};
    border: none;
    border-radius: 0;
    outline: none;
    padding: 6px 0;
}}
QListWidget#sidebar::item {{
    padding: 7px 16px;
    margin: 1px 8px;
    border-radius: 4px;
    min-height: 20px;
}}
QListWidget#sidebar::item:hover {{ background: {p.sidebar_hover_bg}; }}
QListWidget#sidebar::item:selected {{
    background: {p.sidebar_selected_bg};
    color: {p.sidebar_selected_text};
    font-weight: 600;
}}
QListWidget#sidebar::item:disabled {{ color: {p.sidebar_muted}; }}
QWidget#sidebarContainer {{ background: {p.sidebar_bg}; }}
QWidget#sidebarHeader {{ background: transparent; }}
QLabel#brand {{
    color: {p.sidebar_text};
    font-size: {base_font_pt + 6}pt;
    font-weight: 700;
    letter-spacing: 2px;
    padding: 0;
    background: transparent;
}}
QLabel#brandSub {{
    color: {p.sidebar_muted};
    font-size: {small}pt;
    padding: 2px 20px 14px 62px;
    background: transparent;
}}
QLabel#sidebarFooter {{
    color: {p.sidebar_muted};
    font-size: {small}pt;
    padding: 8px 20px 12px 20px;
    background: transparent;
}}
QLabel[badge="true"] {{
    background: {p.badge_bg};
    border-radius: 9px;
    padding: 2px 8px;
    font-size: {small}pt;
    color: {p.text_muted};
}}
"""

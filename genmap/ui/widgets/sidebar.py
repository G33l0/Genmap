"""Navigation sidebar."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QVBoxLayout, QWidget

from genmap import __version__
from genmap.resources import logo_pixmap


@dataclass(frozen=True)
class NavEntry:
    key: str
    title: str
    tooltip: str = ""
    enabled: bool = True


class Sidebar(QWidget):
    page_selected = pyqtSignal(str)

    def __init__(self, entries: list[NavEntry], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("sidebarContainer")
        # Custom QWidget subclasses only paint style sheet backgrounds with this attribute.
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedWidth(210)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QWidget()
        header.setObjectName("sidebarHeader")
        header_row = QHBoxLayout(header)
        header_row.setContentsMargins(18, 18, 12, 2)
        header_row.setSpacing(10)
        self._logo = QLabel()
        self._logo.setFixedSize(34, 34)
        self._logo.setAccessibleName("Genmap logo")
        header_row.addWidget(self._logo)
        brand = QLabel("GENMAP")
        brand.setObjectName("brand")
        header_row.addWidget(brand, 1)
        layout.addWidget(header)
        sub = QLabel("Network mapping workbench")
        sub.setObjectName("brandSub")
        sub.setWordWrap(True)
        layout.addWidget(sub)

        self._list = QListWidget()
        self._list.setObjectName("sidebar")
        self._list.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self._list.setUniformItemSizes(True)
        self._list.setIconSize(QSize(16, 16))
        for entry in entries:
            item = QListWidgetItem(entry.title)
            item.setData(Qt.ItemDataRole.UserRole, entry.key)
            if entry.tooltip:
                item.setToolTip(entry.tooltip)
            if not entry.enabled:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self._list.addItem(item)
        self._list.currentItemChanged.connect(self._on_current_changed)
        layout.addWidget(self._list, 1)

        footer = QLabel(f"Version {__version__}")
        footer.setObjectName("sidebarFooter")
        layout.addWidget(footer)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._logo.setPixmap(logo_pixmap(34, self.devicePixelRatioF()))

    def clear_selection(self) -> None:
        self._list.blockSignals(True)
        self._list.setCurrentRow(-1)
        self._list.clearSelection()
        self._list.blockSignals(False)

    def _on_current_changed(self, current: Optional[QListWidgetItem], _previous) -> None:
        if current is not None:
            self.page_selected.emit(current.data(Qt.ItemDataRole.UserRole))

    def select(self, key: str) -> None:
        for index in range(self._list.count()):
            item = self._list.item(index)
            if item.data(Qt.ItemDataRole.UserRole) == key:
                if self._list.currentItem() is not item:
                    self._list.setCurrentItem(item)
                else:
                    self.page_selected.emit(key)
                return

    def set_badge(self, key: str, badge: str) -> None:
        for index in range(self._list.count()):
            item = self._list.item(index)
            if item.data(Qt.ItemDataRole.UserRole) == key:
                base = item.data(Qt.ItemDataRole.UserRole + 1) or item.text()
                item.setData(Qt.ItemDataRole.UserRole + 1, base)
                item.setText(f"{base}  {badge}" if badge else base)
                return

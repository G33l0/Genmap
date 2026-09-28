"""Navigation sidebar."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import QLabel, QListWidget, QListWidgetItem, QVBoxLayout, QWidget

from genmap import __version__


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
        self.setFixedWidth(210)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        brand = QLabel("GENMAP")
        brand.setObjectName("brand")
        sub = QLabel("Nmap frontend and recon platform")
        sub.setObjectName("brandSub")
        sub.setWordWrap(True)
        layout.addWidget(brand)
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

"""Base class for workspace pages."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from genmap.ui.app_context import AppContext


class BasePage(QWidget):
    page_key: str = ""
    page_title: str = ""

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.context = context

    def on_shown(self) -> None:
        """Called every time the page becomes visible."""

    def on_hidden(self) -> None:
        """Called when the page stops being visible."""


class ScrollPage(BasePage):
    """A page whose content scrolls vertically."""

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self.content = QWidget()
        self.layout_ = QVBoxLayout(self.content)
        self.layout_.setContentsMargins(28, 24, 28, 28)
        self.layout_.setSpacing(16)
        self._scroll.setWidget(self.content)
        outer.addWidget(self._scroll)

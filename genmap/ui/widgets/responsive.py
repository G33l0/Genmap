"""Layouts that adapt to the available width."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtWidgets import QGridLayout, QSizePolicy, QWidget


class ResponsiveGrid(QWidget):
    """Arranges child widgets in as many columns as the width allows.

    ``breakpoints`` maps a minimum width to a column count; the widest
    matching breakpoint wins. Items keep their insertion order and can span
    several columns when there is room for them.
    """

    def __init__(self, breakpoints: Optional[dict[int, int]] = None, parent: Optional[QWidget] = None, spacing: int = 14) -> None:
        super().__init__(parent)
        self._breakpoints = sorted((breakpoints or {0: 1, 900: 2}).items())
        self._items: list[tuple[QWidget, int]] = []
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(spacing)
        self._columns = 0
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    def add(self, widget: QWidget, span: int = 1) -> None:
        self._items.append((widget, span))
        self._relayout(force=True)

    def columns_for(self, width: int) -> int:
        columns = 1
        for minimum, count in self._breakpoints:
            if width >= minimum:
                columns = count
        return columns

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._relayout()

    def _relayout(self, force: bool = False) -> None:
        columns = self.columns_for(self.width() or 1)
        if columns == self._columns and not force:
            return
        self._columns = columns
        for widget, _ in self._items:
            self._grid.removeWidget(widget)
        for column in range(8):
            self._grid.setColumnStretch(column, 0)
        row = column = 0
        for widget, span in self._items:
            span = min(span, columns)
            if column + span > columns:
                row += 1
                column = 0
            self._grid.addWidget(widget, row, column, 1, span)
            column += span
            if column >= columns:
                row += 1
                column = 0
        for column in range(columns):
            self._grid.setColumnStretch(column, 1)

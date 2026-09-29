"""Layouts that adapt to the available width."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QPoint, QRect, QSize, Qt
from PyQt6.QtWidgets import QGridLayout, QLayout, QLayoutItem, QSizePolicy, QWidget


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


class FlowLayout(QLayout):
    """Places widgets left to right and wraps them onto new rows when space runs out,
    so button rows never squeeze their labels unreadable."""

    def __init__(self, parent: Optional[QWidget] = None, spacing: int = 8) -> None:
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self._spacing = spacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item: QLayoutItem) -> None:
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int) -> Optional[QLayoutItem]:
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index: int) -> Optional[QLayoutItem]:
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self) -> Qt.Orientation:
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._arrange(QRect(0, 0, width, 0), apply=False)

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        self._arrange(rect, apply=True)

    def sizeHint(self) -> QSize:
        return self.minimumSize()

    def minimumSize(self) -> QSize:
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        return size + QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def _arrange(self, rect: QRect, *, apply: bool) -> int:
        margins = self.contentsMargins()
        area = rect.adjusted(margins.left(), margins.top(), -margins.right(), -margins.bottom())
        x, y, line_height = area.x(), area.y(), 0
        for item in self._items:
            if item.widget() is not None and not item.widget().isVisible() and not item.widget().isVisibleTo(item.widget().parentWidget()):
                continue
            hint = item.sizeHint()
            if x + hint.width() > area.right() + 1 and line_height > 0:
                x = area.x()
                y += line_height + self._spacing
                line_height = 0
            if apply:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x += hint.width() + self._spacing
            line_height = max(line_height, hint.height())
        return y + line_height - rect.y() + margins.bottom()

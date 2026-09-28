"""Displays a list of Diagnostic records."""

from __future__ import annotations

from typing import Iterable, Optional

from PyQt6.QtWidgets import QGridLayout, QLabel, QVBoxLayout, QWidget

from genmap.core.diagnostics import Diagnostic, DiagnosticLevel
from genmap.ui.widgets.common import label

_MARKS = {
    DiagnosticLevel.OK: ("OK", "ok"),
    DiagnosticLevel.INFO: ("Info", "info"),
    DiagnosticLevel.WARNING: ("Warning", "warning"),
    DiagnosticLevel.ERROR: ("Error", "error"),
}


class DiagnosticsView(QWidget):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(10)
        self._empty = label("No diagnostics yet.", role="muted")
        self._layout.addWidget(self._empty)

    def clear(self) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            widget = item.widget()
            if widget is not None and widget is not self._empty:
                widget.deleteLater()
        self._layout.addWidget(self._empty)

    def set_diagnostics(self, diagnostics: Iterable[Diagnostic]) -> None:
        self.clear()
        items = list(diagnostics)
        self._empty.setVisible(not items)
        for diagnostic in items:
            self._layout.addWidget(self._row(diagnostic))

    def _row(self, diagnostic: Diagnostic) -> QWidget:
        text, status = _MARKS[diagnostic.level]
        row = QWidget()
        grid = QGridLayout(row)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(2)
        mark = label(text, status=status)
        mark.setFixedWidth(64)
        grid.addWidget(mark, 0, 0)
        title = label(diagnostic.title, role="section", selectable=True)
        grid.addWidget(title, 0, 1)
        if diagnostic.detail:
            grid.addWidget(label(diagnostic.detail, wrap=True, selectable=True), 1, 1)
        if diagnostic.remedy:
            remedy = label(diagnostic.remedy, role="muted", wrap=True, selectable=True)
            grid.addWidget(remedy, 2, 1)
        grid.setColumnStretch(1, 1)
        return row

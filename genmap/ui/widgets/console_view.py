"""Bounded, monospace console for live process output."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtGui import QColor, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import QPlainTextEdit, QWidget


class ConsoleView(QPlainTextEdit):
    def __init__(self, parent: Optional[QWidget] = None, *, max_lines: int = 20000) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setProperty("role", "console")
        self.setMaximumBlockCount(max_lines)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._stderr_format = QTextCharFormat()
        self._stderr_color = QColor("#F2B8B8")
        self._stderr_format.setForeground(self._stderr_color)
        self._auto_scroll = True
        self.verticalScrollBar().valueChanged.connect(self._on_scrolled)

    def set_stderr_color(self, color: str) -> None:
        self._stderr_color = QColor(color)
        self._stderr_format.setForeground(self._stderr_color)

    def set_max_lines(self, max_lines: int) -> None:
        self.setMaximumBlockCount(max_lines)

    def _on_scrolled(self, value: int) -> None:
        bar = self.verticalScrollBar()
        self._auto_scroll = value >= bar.maximum() - 2

    def append_line(self, text: str, is_stderr: bool = False) -> None:
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if is_stderr:
            cursor.insertText(text + "\n", self._stderr_format)
        else:
            cursor.insertText(text + "\n", QTextCharFormat())
        if self._auto_scroll:
            bar = self.verticalScrollBar()
            bar.setValue(bar.maximum())

    def set_text(self, text: str) -> None:
        self.setPlainText(text)
        bar = self.verticalScrollBar()
        bar.setValue(bar.maximum())

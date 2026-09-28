"""Error presentation with an expandable technical details section."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from genmap.errors import describe_exception


class ErrorDialog(QDialog):
    def __init__(
        self,
        parent: Optional[QWidget],
        title: str,
        message: str,
        remedy: Optional[str] = None,
        details: str = "",
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        message_label = QLabel(message)
        message_label.setWordWrap(True)
        message_label.setProperty("role", "section")
        message_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(message_label)

        if remedy:
            remedy_label = QLabel(remedy)
            remedy_label.setWordWrap(True)
            remedy_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(remedy_label)

        self._details = QPlainTextEdit(details)
        self._details.setReadOnly(True)
        self._details.setProperty("role", "mono")
        self._details.setMinimumHeight(180)
        self._details.hide()
        layout.addWidget(self._details)

        buttons = QHBoxLayout()
        self._toggle = QPushButton("Show technical details")
        self._toggle.setCheckable(True)
        self._toggle.setVisible(bool(details))
        self._toggle.toggled.connect(self._on_toggle)
        copy_button = QPushButton("Copy details")
        copy_button.setVisible(bool(details))
        copy_button.clicked.connect(lambda: QApplication.clipboard().setText(f"{message}\n{remedy or ''}\n\n{details}"))
        buttons.addWidget(self._toggle)
        buttons.addWidget(copy_button)
        buttons.addStretch(1)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        box.rejected.connect(self.reject)
        box.accepted.connect(self.accept)
        buttons.addWidget(box)
        layout.addLayout(buttons)

    def _on_toggle(self, checked: bool) -> None:
        self._details.setVisible(checked)
        self._toggle.setText("Hide technical details" if checked else "Show technical details")
        self.adjustSize()


def show_error(parent: Optional[QWidget], title: str, message: str, remedy: Optional[str] = None, details: str = "") -> None:
    dialog = ErrorDialog(parent, title, message, remedy, details)
    dialog.exec()


def show_exception(parent: Optional[QWidget], exc: BaseException, title: str = "Something went wrong") -> None:
    message, remedy, details = describe_exception(exc)
    show_error(parent, title, message, remedy, details)

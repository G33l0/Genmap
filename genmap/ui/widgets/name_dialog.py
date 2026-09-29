"""Small dialog for naming things (profiles, target groups)."""

from __future__ import annotations

from typing import Callable, Optional

from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit, QVBoxLayout, QWidget

from genmap.ui.widgets.common import form_layout, label
from genmap.ui.widgets.inputs import TextField


class NameDialog(QDialog):
    """Asks for a name and optional description.

    ``validator`` returns an error message for an unacceptable name, which is
    shown inline instead of closing the dialog.
    """

    def __init__(
        self,
        parent: Optional[QWidget],
        title: str,
        *,
        name: str = "",
        description: str = "",
        note: str = "",
        validator: Optional[Callable[[str], Optional[str]]] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(460)
        self._validator = validator
        layout = QVBoxLayout(self)
        if note:
            layout.addWidget(label(note, role="muted", wrap=True))
        form = form_layout()
        self.name = TextField("Name")
        self.name.setText(name)
        self.name.setMaxLength(120)
        self.description = QPlainTextEdit(description)
        self.description.setPlaceholderText("Optional description")
        self.description.setMaximumHeight(90)
        self.description.setTabChangesFocus(True)
        form.addRow("Name", self.name)
        form.addRow("Description", self.description)
        layout.addLayout(form)
        self.error = label("", status="error", wrap=True)
        self.error.hide()
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.name.setFocus()
        self.name.selectAll()

    def _accept(self) -> None:
        name = " ".join(self.name.text().split())
        problem = "A name is required." if not name else (self._validator(name) if self._validator else None)
        if problem:
            self.error.setText(problem)
            self.error.show()
            self.name.setFocus()
            return
        self.accept()

    def values(self) -> tuple[str, str]:
        return " ".join(self.name.text().split()), self.description.toPlainText().strip()

"""Confirmation shown before a scan starts."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from genmap.core.intrusiveness import IntrusivenessNotice, is_high_risk
from genmap.ui.widgets.common import label


class ConfirmScanDialog(QDialog):
    def __init__(
        self,
        parent: Optional[QWidget],
        command: str,
        targets: str,
        notices: list[IntrusivenessNotice],
        environment_warnings: list[str],
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Start scan")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(label("Review before starting", role="section"))
        layout.addWidget(label(f"Targets: {targets}", wrap=True, selectable=True))
        text = QPlainTextEdit(command)
        text.setReadOnly(True)
        text.setProperty("role", "mono")
        text.setMaximumHeight(90)
        layout.addWidget(text)

        for notice in notices:
            layout.addWidget(label(notice.message, status="error" if notice.level == "high" else "warning", wrap=True))
        for warning in environment_warnings:
            layout.addWidget(label(warning, status="warning", wrap=True))

        self.acknowledge: Optional[QCheckBox] = None
        if is_high_risk(notices):
            self.acknowledge = QCheckBox("I am authorized to run this scan against these targets.")
            layout.addWidget(self.acknowledge)

        self.buttons = QDialogButtonBox()
        self.start_button = self.buttons.addButton("Start scan", QDialogButtonBox.ButtonRole.AcceptRole)
        self.start_button.setProperty("accent", True)
        self.buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        if self.acknowledge is not None:
            self.start_button.setEnabled(False)
            self.acknowledge.toggled.connect(self.start_button.setEnabled)
        self.start_button.setFocus()

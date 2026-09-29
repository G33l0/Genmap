"""Small building blocks used throughout the interface."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLayout,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


def label(text: str = "", *, role: Optional[str] = None, status: Optional[str] = None, wrap: bool = False, selectable: bool = False) -> QLabel:
    widget = QLabel(text)
    if role:
        widget.setProperty("role", role)
    if status:
        widget.setProperty("status", status)
    if wrap:
        widget.setWordWrap(True)
    if selectable:
        widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return widget


def set_status(widget: QLabel, status: Optional[str]) -> None:
    widget.setProperty("status", status)
    repolish(widget)


def repolish(widget: QWidget) -> None:
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def separator() -> QFrame:
    frame = QFrame()
    frame.setProperty("role", "separator")
    frame.setFrameShape(QFrame.Shape.NoFrame)
    return frame


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self.title_label = label(title, role="title")
        self.subtitle_label = label(subtitle, role="subtitle", wrap=True)
        layout.addWidget(self.title_label)
        layout.addWidget(self.subtitle_label)
        self.subtitle_label.setVisible(bool(subtitle))

    def set_subtitle(self, text: str) -> None:
        self.subtitle_label.setText(text)
        self.subtitle_label.setVisible(bool(text))


class Card(QFrame):
    """A bordered surface with an optional title row."""

    def __init__(self, title: str = "", parent: Optional[QWidget] = None, *, actions: Optional[list[QWidget]] = None) -> None:
        super().__init__(parent)
        self.setProperty("card", True)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 16)
        outer.setSpacing(10)
        self.header_row = QHBoxLayout()
        self.header_row.setSpacing(8)
        self.title_label = label(title, role="section")
        self.header_row.addWidget(self.title_label)
        self.header_row.addStretch(1)
        for action in actions or []:
            self.header_row.addWidget(action)
        outer.addLayout(self.header_row)
        self.title_label.setVisible(bool(title))
        self.body = QVBoxLayout()
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(8)
        outer.addLayout(self.body)

    def add_widget(self, widget: QWidget, stretch: int = 0) -> None:
        self.body.addWidget(widget, stretch)

    def add_layout(self, layout: QLayout, stretch: int = 0) -> None:
        self.body.addLayout(layout, stretch)

    def add_stretch(self) -> None:
        self.body.addStretch(1)


class KeyValueGrid(QWidget):
    """Two column read only display of labelled values."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setHorizontalSpacing(18)
        self._grid.setVerticalSpacing(6)
        self._grid.setColumnStretch(1, 1)
        self._rows: dict[str, QLabel] = {}

    def add_row(self, key: str, value: str = "", *, mono: bool = False, status: Optional[str] = None) -> QLabel:
        row = self._grid.rowCount()
        key_label = label(key, role="muted")
        key_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        value_label = label(value, role="mono" if mono else None, status=status, wrap=True, selectable=True)
        value_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._grid.addWidget(key_label, row, 0)
        self._grid.addWidget(value_label, row, 1)
        self._rows[key] = value_label
        return value_label

    def set_value(self, key: str, value: str, *, status: Optional[str] = None) -> None:
        widget = self._rows.get(key)
        if widget is None:
            self.add_row(key, value, status=status)
            return
        widget.setText(value)
        set_status(widget, status)

    def clear(self) -> None:
        while self._grid.count():
            item = self._grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                # Detach at once; deleteLater alone leaves the old labels painted until the event loop runs.
                widget.hide()
                widget.setParent(None)
                widget.deleteLater()
        self._rows.clear()


class Metric(QFrame):
    def __init__(self, caption: str, value: str = "0", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setProperty("card", True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(2)
        self.value_label = label(value, role="metric")
        self.caption_label = label(caption, role="muted")
        layout.addWidget(self.value_label)
        layout.addWidget(self.caption_label)
        layout.addStretch(1)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)


class Banner(QFrame):
    """Inline notice for warnings, errors, or information."""

    def __init__(self, kind: str = "info", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setProperty("role", f"banner-{kind}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)
        self.title_label = label("", role="section")
        self.text_label = label("", wrap=True, selectable=True)
        layout.addWidget(self.title_label)
        layout.addWidget(self.text_label)
        self.hide()

    def show_message(self, title: str, text: str = "", kind: Optional[str] = None) -> None:
        if kind:
            self.setProperty("role", f"banner-{kind}")
            repolish(self)
        self.title_label.setText(title)
        self.title_label.setVisible(bool(title))
        self.text_label.setText(text)
        self.text_label.setVisible(bool(text))
        self.show()


def form_layout() -> QFormLayout:
    form = QFormLayout()
    form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
    form.setHorizontalSpacing(14)
    form.setVerticalSpacing(8)
    return form


def hint(text: str) -> QLabel:
    widget = label(text, role="small", wrap=True)
    # Wrapped labels otherwise stay at their preferred width inside form layouts.
    widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    return widget

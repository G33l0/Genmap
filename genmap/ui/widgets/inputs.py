"""Input widgets that map cleanly onto optional configuration values."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtWidgets import QComboBox, QLineEdit, QSpinBox, QWidget


class OptionalSpinBox(QSpinBox):
    """A spin box whose lowest position means "not set" (None)."""

    def __init__(self, minimum: int, maximum: int, *, unset_text: str = "Nmap default", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._unset = minimum - 1
        self.setRange(self._unset, maximum)
        self.setSpecialValueText(unset_text)
        self.setValue(self._unset)
        self.setAccelerated(True)
        self.setMinimumWidth(130)

    def optional_value(self) -> Optional[int]:
        value = self.value()
        return None if value == self._unset else value

    def set_optional_value(self, value: Optional[int]) -> None:
        self.setValue(self._unset if value is None else value)


class TextField(QLineEdit):
    """Line edit that returns None for empty text."""

    def __init__(self, placeholder: str = "", *, mono: bool = False, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setClearButtonEnabled(True)
        if mono:
            self.setProperty("role", "mono")

    def optional_text(self) -> Optional[str]:
        text = self.text().strip()
        return text or None

    def set_optional_text(self, value: Optional[str]) -> None:
        self.setText(value or "")


class EnumCombo(QComboBox):
    """Combo box whose items carry arbitrary data values."""

    def __init__(self, items: list[tuple[str, object]], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        for text, value in items:
            self.addItem(text, value)
        self.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)

    def current_value(self) -> object:
        return self.currentData()

    def set_current_value(self, value: object) -> None:
        for index in range(self.count()):
            if self.itemData(index) == value:
                self.setCurrentIndex(index)
                return


def split_list(text: str) -> list[str]:
    return [piece.strip() for piece in text.replace("\n", ",").split(",") if piece.strip()]

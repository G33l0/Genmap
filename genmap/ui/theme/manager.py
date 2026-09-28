"""Applies palettes to the running application."""

from __future__ import annotations

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPalette
from PyQt6.QtWidgets import QApplication

from genmap.ui.theme.palettes import DARK, LIGHT, Palette
from genmap.ui.theme.stylesheet import build_stylesheet


class ThemeManager(QObject):
    theme_changed = pyqtSignal(object)  # Palette

    def __init__(self, app: QApplication, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._app = app
        self.palette: Palette = LIGHT
        self.theme_name = "system"
        self.base_font_pt = 10
        self.mono_family = "Consolas, Cascadia Mono, Menlo, DejaVu Sans Mono, monospace"
        hints = app.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(self._on_system_scheme_changed)

    def _system_prefers_dark(self) -> bool:
        hints = self._app.styleHints()
        scheme = getattr(hints, "colorScheme", None)
        if scheme is None:
            return False
        return scheme() == Qt.ColorScheme.Dark

    def resolve(self, theme_name: str) -> Palette:
        if theme_name == "dark":
            return DARK
        if theme_name == "light":
            return LIGHT
        return DARK if self._system_prefers_dark() else LIGHT

    def apply(self, theme_name: str, *, base_font_pt: int | None = None, mono_family: str | None = None) -> None:
        self.theme_name = theme_name
        if base_font_pt is not None:
            self.base_font_pt = base_font_pt
        if mono_family:
            self.mono_family = mono_family
        self.palette = self.resolve(theme_name)
        self._apply_palette(self.palette)
        font = QFont(self._app.font())
        font.setPointSize(self.base_font_pt)
        self._app.setFont(font)
        self._app.setStyleSheet(build_stylesheet(self.palette, self.base_font_pt, self.mono_family))
        self.theme_changed.emit(self.palette)

    def _on_system_scheme_changed(self, *_args) -> None:
        if self.theme_name == "system":
            self.apply("system")

    def _apply_palette(self, p: Palette) -> None:
        qp = QPalette()
        roles = {
            QPalette.ColorRole.Window: p.window,
            QPalette.ColorRole.WindowText: p.text,
            QPalette.ColorRole.Base: p.input_bg,
            QPalette.ColorRole.AlternateBase: p.surface_alt,
            QPalette.ColorRole.ToolTipBase: p.surface,
            QPalette.ColorRole.ToolTipText: p.text,
            QPalette.ColorRole.Text: p.text,
            QPalette.ColorRole.Button: p.surface,
            QPalette.ColorRole.ButtonText: p.text,
            QPalette.ColorRole.BrightText: p.accent_text,
            QPalette.ColorRole.Highlight: p.selection,
            QPalette.ColorRole.HighlightedText: p.selection_text,
            QPalette.ColorRole.Link: p.accent,
            QPalette.ColorRole.PlaceholderText: p.text_muted,
            QPalette.ColorRole.Mid: p.border,
            QPalette.ColorRole.Dark: p.border_strong,
            QPalette.ColorRole.Light: p.surface_alt,
        }
        for role, color in roles.items():
            qp.setColor(role, QColor(color))
        qp.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(p.text_muted))
        qp.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(p.text_muted))
        qp.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(p.text_muted))
        self._app.setPalette(qp)

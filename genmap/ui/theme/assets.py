"""Small SVG images the style sheet needs, drawn in the active palette's colours.

Qt style sheets cannot recolour images, and restyling a subcontrol such as a
combo box drop down removes the platform's own arrow. Writing tiny SVGs per
palette keeps checkboxes, radio buttons, and arrows visible in every theme.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PyQt6.QtGui import QColor

from genmap.ui.theme.palettes import Palette

_CHECK = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M3.5 8.5l3 3 6-7" fill="none" stroke="{color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
_CHEVRON_DOWN = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 12 12"><path d="M2.5 4.5l3.5 3.5 3.5-3.5" fill="none" stroke="{color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>'
_CHEVRON_UP = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 12 12"><path d="M2.5 7.5l3.5-3.5 3.5 3.5" fill="none" stroke="{color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>'


@dataclass(frozen=True)
class ThemeAssets:
    check: str
    check_disabled: str
    arrow_down: str
    arrow_up: str
    arrow_down_disabled: str
    arrow_up_disabled: str


def _url(path: Path) -> str:
    # Forward slashes and quotes keep Windows paths with spaces valid in QSS.
    return f'url("{path.as_posix()}")'


def write_theme_assets(palette: Palette, directory: Path) -> ThemeAssets:
    directory.mkdir(parents=True, exist_ok=True)
    files = {
        "check": (_CHECK, palette.accent_text),
        "check_disabled": (_CHECK, palette.text_muted),
        "arrow_down": (_CHEVRON_DOWN, palette.text),
        "arrow_up": (_CHEVRON_UP, palette.text),
        "arrow_down_disabled": (_CHEVRON_DOWN, palette.text_muted),
        "arrow_up_disabled": (_CHEVRON_UP, palette.text_muted),
    }
    urls: dict[str, str] = {}
    for name, (template, color) in files.items():
        hex_color = QColor(color).name()
        path = directory / f"{name}-{palette.name}-{hex_color.lstrip('#')}.svg"
        if not path.is_file():
            path.write_text(template.format(color=hex_color), encoding="utf-8")
        urls[name] = _url(path)
    return ThemeAssets(**urls)

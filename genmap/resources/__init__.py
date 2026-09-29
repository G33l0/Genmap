"""Access to bundled resources (logo, icons).

Paths resolve relative to this package, which works both from source and
inside a PyInstaller bundle as long as the branding folder is collected.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

RESOURCE_DIR = Path(__file__).resolve().parent
BRANDING_DIR = RESOURCE_DIR / "branding"
LOGO_SVG = BRANDING_DIR / "genmap-logo.svg"
ICON_ICO = BRANDING_DIR / "genmap.ico"
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)


def icon_png(size: int) -> Path:
    return BRANDING_DIR / f"genmap-{size}.png"


@lru_cache(maxsize=1)
def app_icon():
    from PyQt6.QtGui import QIcon

    icon = QIcon()
    for size in ICON_SIZES:
        path = icon_png(size)
        if path.is_file():
            icon.addFile(str(path))
    if icon.isNull() and LOGO_SVG.is_file():
        icon = QIcon(str(LOGO_SVG))
    return icon


def logo_pixmap(size: int, device_pixel_ratio: float = 1.0):
    """Render the logo crisply at the requested logical size."""
    from PyQt6.QtCore import QByteArray, QRectF, Qt
    from PyQt6.QtGui import QPainter, QPixmap

    physical = max(1, int(round(size * device_pixel_ratio)))
    pixmap = QPixmap(physical, physical)
    pixmap.fill(Qt.GlobalColor.transparent)
    try:
        from PyQt6.QtSvg import QSvgRenderer

        renderer = QSvgRenderer(QByteArray(LOGO_SVG.read_bytes()))
        if renderer.isValid():
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            renderer.render(painter, QRectF(0, 0, physical, physical))
            painter.end()
            pixmap.setDevicePixelRatio(device_pixel_ratio)
            return pixmap
    except (ImportError, OSError):
        pass
    fallback = QPixmap(str(icon_png(256)))
    if fallback.isNull():
        return pixmap
    scaled = fallback.scaled(
        physical,
        physical,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )
    scaled.setDevicePixelRatio(device_pixel_ratio)
    return scaled

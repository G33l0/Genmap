"""Render the SVG logo into the PNG and ICO files used for packaging.

Run after changing genmap/resources/branding/genmap-logo.svg:

    python scripts/generate_icons.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QByteArray, QRectF, Qt  # noqa: E402
from PyQt6.QtGui import QGuiApplication, QImage, QPainter  # noqa: E402
from PyQt6.QtSvg import QSvgRenderer  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BRANDING = ROOT / "genmap" / "resources" / "branding"
SIZES = (16, 24, 32, 48, 64, 128, 256, 512)
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)


def render(renderer: QSvgRenderer, size: int) -> QImage:
    image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    return image


def write_ico(images: list[QImage], target: Path) -> None:
    """Pack PNG encoded frames into a Windows ICO container."""
    import struct

    from PyQt6.QtCore import QBuffer, QIODevice

    blobs: list[bytes] = []
    for image in images:
        buffer = QBuffer()
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        image.save(buffer, "PNG")
        blobs.append(bytes(buffer.data()))
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    for image, blob in zip(images, blobs):
        width = image.width() if image.width() < 256 else 0
        height = image.height() if image.height() < 256 else 0
        entries += struct.pack("<BBBBHHII", width, height, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    target.write_bytes(header + entries + b"".join(blobs))


def main() -> int:
    app = QGuiApplication(sys.argv)  # noqa: F841 - required for QImage painting
    svg = (BRANDING / "genmap-logo.svg").read_bytes()
    renderer = QSvgRenderer(QByteArray(svg))
    if not renderer.isValid():
        print("Logo SVG could not be parsed", file=sys.stderr)
        return 1
    rendered = {size: render(renderer, size) for size in SIZES}
    for size, image in rendered.items():
        image.save(str(BRANDING / f"genmap-{size}.png"), "PNG")
    write_ico([rendered[size] for size in ICO_SIZES], BRANDING / "genmap.ico")
    print(f"Wrote {len(SIZES)} PNG files and genmap.ico to {BRANDING}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

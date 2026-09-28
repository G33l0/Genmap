"""Application logging configuration.

Two handlers are installed: a rotating file in the log directory and a
console handler for development. The in-memory ring buffer lets the UI show
recent log lines without touching the filesystem.
"""

from __future__ import annotations

import collections
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Deque

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}


class RingBufferHandler(logging.Handler):
    """Keeps the most recent formatted records in memory."""

    def __init__(self, capacity: int = 2000) -> None:
        super().__init__()
        self.records: Deque[str] = collections.deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.records.append(self.format(record))
        except Exception:
            self.handleError(record)


ring_buffer = RingBufferHandler()


def level_from_name(name: str) -> int:
    return _LEVELS.get(name.upper(), logging.INFO)


def configure_logging(log_dir: Path, level: str = "INFO", console: bool = True) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "genmap.log"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level_from_name(level))
    root.addHandler(file_handler)

    ring_buffer.setFormatter(formatter)
    ring_buffer.setLevel(logging.DEBUG)
    root.addHandler(ring_buffer)

    if console and sys.stderr is not None:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level_from_name(level))
        root.addHandler(console_handler)

    # Qt and SQLAlchemy are chatty at DEBUG; keep them at INFO unless asked.
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    return log_file


def set_level(level: str) -> None:
    numeric = level_from_name(level)
    for handler in logging.getLogger().handlers:
        if handler is not ring_buffer:
            handler.setLevel(numeric)

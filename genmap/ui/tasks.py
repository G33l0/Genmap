"""Running blocking work off the UI thread.

``run_in_background`` executes a callable on the global thread pool and
delivers the result (or exception) back on the UI thread through queued
signals. Callers keep a reference to nothing; the pool owns the runnable.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal

log = logging.getLogger(__name__)

_live_bridges: set["_Bridge"] = set()


class _Bridge(QObject):
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(object)


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], Any], bridge: _Bridge) -> None:
        super().__init__()
        self._fn = fn
        self._bridge = bridge
        self.setAutoDelete(True)

    def run(self) -> None:
        try:
            result = self._fn()
        except BaseException as exc:
            self._bridge.failed.emit(exc)
        else:
            self._bridge.succeeded.emit(result)


def run_in_background(
    fn: Callable[[], Any],
    on_success: Callable[[Any], None],
    on_error: Optional[Callable[[BaseException], None]] = None,
) -> None:
    bridge = _Bridge()
    _live_bridges.add(bridge)

    def finish_success(result: Any) -> None:
        _live_bridges.discard(bridge)
        try:
            on_success(result)
        except Exception:
            log.exception("Background task success handler failed")

    def finish_error(exc: BaseException) -> None:
        _live_bridges.discard(bridge)
        if on_error is not None:
            on_error(exc)
        else:
            log.error("Background task failed: %s", exc, exc_info=exc)

    bridge.succeeded.connect(finish_success)
    bridge.failed.connect(finish_error)
    QThreadPool.globalInstance().start(_Task(fn, bridge))

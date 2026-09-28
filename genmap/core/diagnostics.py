"""Shared diagnostic records used by environment probes and modules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional


class DiagnosticLevel(str, Enum):
    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


_ORDER = [DiagnosticLevel.OK, DiagnosticLevel.INFO, DiagnosticLevel.WARNING, DiagnosticLevel.ERROR]


@dataclass(frozen=True)
class Diagnostic:
    level: DiagnosticLevel
    title: str
    detail: str = ""
    remedy: Optional[str] = None


def worst_level(diagnostics: Iterable[Diagnostic]) -> DiagnosticLevel:
    worst = DiagnosticLevel.OK
    for diagnostic in diagnostics:
        if _ORDER.index(diagnostic.level) > _ORDER.index(worst):
            worst = diagnostic.level
    return worst

"""Parsing of ``nmap --version`` output."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

_VERSION_LINE = re.compile(r"Nmap version (?P<version>\S+)", re.IGNORECASE)
_VERSION_NUMBER = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


@dataclass(frozen=True)
class NmapVersion:
    raw: str
    major: int
    minor: int
    patch: int = 0
    suffix: str = ""
    platform: Optional[str] = None
    compiled_with: tuple[str, ...] = field(default_factory=tuple)
    compiled_without: tuple[str, ...] = field(default_factory=tuple)
    nsock_engines: tuple[str, ...] = field(default_factory=tuple)

    @property
    def tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    @property
    def is_development(self) -> bool:
        return "SVN" in self.suffix.upper() or "DEV" in self.suffix.upper()

    def at_least(self, major: int, minor: int, patch: int = 0) -> bool:
        return self.tuple >= (major, minor, patch)

    def has_library(self, prefix: str) -> bool:
        prefix = prefix.lower()
        return any(item.lower().startswith(prefix) for item in self.compiled_with)

    def __str__(self) -> str:
        return f"Nmap {self.raw}"


def parse_version_output(text: str) -> Optional[NmapVersion]:
    """Parse the multi line output of ``nmap --version``.

    Returns None when the text does not look like Nmap at all, which is what
    happens when the configured path points at an unrelated executable.
    """
    match = _VERSION_LINE.search(text)
    if not match:
        return None
    raw = match.group("version")
    number = _VERSION_NUMBER.match(raw)
    if not number:
        return None
    major = int(number.group(1))
    minor = int(number.group(2))
    patch = int(number.group(3) or 0)
    suffix = raw[number.end():]

    platform = None
    compiled_with: list[str] = []
    compiled_without: list[str] = []
    engines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("platform:"):
            platform = stripped.split(":", 1)[1].strip() or None
        elif lower.startswith("compiled with:"):
            compiled_with = stripped.split(":", 1)[1].split()
        elif lower.startswith("compiled without:"):
            compiled_without = stripped.split(":", 1)[1].split()
        elif lower.startswith("available nsock engines:"):
            engines = stripped.split(":", 1)[1].split()

    return NmapVersion(
        raw=raw,
        major=major,
        minor=minor,
        patch=patch,
        suffix=suffix,
        platform=platform,
        compiled_with=tuple(compiled_with),
        compiled_without=tuple(compiled_without),
        nsock_engines=tuple(engines),
    )

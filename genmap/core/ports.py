"""Parsing and validation of Nmap port specifications.

The grammar mirrors what Nmap accepts for -p and --exclude-ports: comma
separated numbers, ranges, open ended ranges, service names with wildcards,
and protocol prefixes (T:, U:, S:, P:) that apply to everything that follows
until the next prefix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from genmap.errors import PortSpecificationError

MAX_PORT = 65535
MAX_PROTOCOL_NUMBER = 255

_PROTOCOL_PREFIXES = {"T": "tcp", "U": "udp", "S": "sctp", "P": "ip"}
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9_*?\[\]\-]+$")


@dataclass(frozen=True)
class PortRange:
    start: int
    end: int
    protocol: Optional[str] = None

    @property
    def count(self) -> int:
        return self.end - self.start + 1

    def as_nmap(self) -> str:
        if self.start == self.end:
            return str(self.start)
        return f"{self.start}-{self.end}"


@dataclass(frozen=True)
class ServicePattern:
    pattern: str
    protocol: Optional[str] = None

    def as_nmap(self) -> str:
        return self.pattern


@dataclass
class ParsedPorts:
    entries: list[PortRange | ServicePattern] = field(default_factory=list)
    raw: str = ""

    @property
    def ranges(self) -> list[PortRange]:
        return [e for e in self.entries if isinstance(e, PortRange)]

    @property
    def service_patterns(self) -> list[ServicePattern]:
        return [e for e in self.entries if isinstance(e, ServicePattern)]

    @property
    def explicit_port_count(self) -> int:
        return sum(r.count for r in self.ranges)

    @property
    def uses_service_names(self) -> bool:
        return bool(self.service_patterns)

    @property
    def protocols(self) -> set[str]:
        found = {r.protocol for r in self.ranges if r.protocol}
        found.update(p.protocol for p in self.service_patterns if p.protocol)
        return found

    def normalized(self) -> str:
        """Re-emit the specification in a canonical, Nmap compatible form."""
        pieces: list[str] = []
        current_protocol: Optional[str] = None
        for entry in self.entries:
            protocol, text = entry.protocol, entry.as_nmap()
            if protocol != current_protocol and protocol is not None:
                letter = next(k for k, v in _PROTOCOL_PREFIXES.items() if v == protocol)
                pieces.append(f"{letter}:{text}")
                current_protocol = protocol
            else:
                pieces.append(text)
        return ",".join(pieces)


def _parse_number(token: str, spec: str, upper: int) -> int:
    if not token.isdigit():
        raise PortSpecificationError(
            f"'{token}' in '{spec}' is not a valid port number.",
            remedy=f"Use numbers from 0 to {upper}, ranges like 8000-8100, or service names.",
        )
    value = int(token)
    if value > upper:
        raise PortSpecificationError(
            f"Port {value} in '{spec}' is above the maximum of {upper}.",
        )
    return value


def parse_port_specification(spec: str, *, protocol_scan: bool = False) -> ParsedPorts:
    """Parse an Nmap style port list or raise PortSpecificationError.

    When protocol_scan is true the numbers are IP protocol numbers and the
    upper bound drops to 255.
    """
    text = spec.strip()
    if not text:
        raise PortSpecificationError("Port specification is empty.")
    if any(ch.isspace() for ch in text):
        raise PortSpecificationError(
            f"Port specification '{text}' contains whitespace.",
            remedy="Separate ports with commas only, for example 22,80,443.",
        )

    upper = MAX_PROTOCOL_NUMBER if protocol_scan else MAX_PORT
    result = ParsedPorts(raw=text)
    protocol: Optional[str] = None

    for item in text.split(","):
        if item == "":
            raise PortSpecificationError(
                f"Port specification '{text}' has an empty entry.",
                remedy="Remove the extra comma.",
            )

        if len(item) >= 2 and item[1] == ":" and item[0].upper() in _PROTOCOL_PREFIXES:
            protocol = _PROTOCOL_PREFIXES[item[0].upper()]
            item = item[2:]
            if item == "":
                raise PortSpecificationError(
                    f"Protocol prefix in '{text}' must be followed by a port.",
                    remedy="Write it like T:22 or U:53,161.",
                )

        if item == "-":
            result.entries.append(PortRange(1, upper, protocol))
            continue

        if item[0].isdigit() or item[0] == "-":
            if "-" in item:
                start_text, _, end_text = item.partition("-")
                start = _parse_number(start_text, text, upper) if start_text else 1
                end = _parse_number(end_text, text, upper) if end_text else upper
                if start > end:
                    raise PortSpecificationError(
                        f"Range '{item}' in '{text}' runs backwards.",
                        remedy="Write ranges as low-high, for example 20-25.",
                    )
                result.entries.append(PortRange(start, end, protocol))
            else:
                value = _parse_number(item, text, upper)
                result.entries.append(PortRange(value, value, protocol))
            continue

        if _SERVICE_NAME.match(item):
            result.entries.append(ServicePattern(item, protocol))
            continue

        raise PortSpecificationError(
            f"'{item}' in '{text}' is not a valid port, range, or service name.",
        )

    return result


def validate_port_specification(spec: str, *, protocol_scan: bool = False) -> str:
    """Validate and return the trimmed specification for use on the command line."""
    return parse_port_specification(spec, protocol_scan=protocol_scan).raw


def merge_port_specifications(specs: Iterable[str]) -> str:
    seen: list[str] = []
    for spec in specs:
        for piece in spec.split(","):
            if piece and piece not in seen:
                seen.append(piece)
    return ",".join(seen)

"""Parsing of ``nmap --iflist`` output into interface and route records."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

_INTERFACE_HEADER = re.compile(r"^\*+INTERFACES\*+", re.IGNORECASE)
_ROUTE_HEADER = re.compile(r"^\*+ROUTES\*+", re.IGNORECASE)


@dataclass(frozen=True)
class NetworkInterface:
    device: str
    short_name: str
    address: Optional[str]
    interface_type: str
    is_up: bool
    mtu: Optional[int]
    mac: Optional[str]

    @property
    def label(self) -> str:
        pieces = [self.short_name or self.device]
        if self.address:
            pieces.append(self.address)
        if self.interface_type:
            pieces.append(self.interface_type)
        return "  ".join(pieces)


@dataclass(frozen=True)
class Route:
    destination: str
    device: str
    metric: Optional[int]
    gateway: Optional[str]


@dataclass
class InterfaceList:
    interfaces: list[NetworkInterface] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    raw: str = ""

    @property
    def usable_interfaces(self) -> list[NetworkInterface]:
        return [i for i in self.interfaces if i.is_up and i.interface_type.lower() != "loopback"]


_INTERFACE_ROW = re.compile(
    r"^(?P<dev>\S+)\s+\((?P<short>[^)]*)\)\s+(?P<ip>\S+)\s+(?P<type>\S+)\s+(?P<up>up|down)\s+(?P<mtu>\S+)(?:\s+(?P<mac>\S+))?",
    re.IGNORECASE,
)


def _parse_interface_row(line: str) -> Optional[NetworkInterface]:
    match = _INTERFACE_ROW.match(line.strip())
    if not match:
        return None
    address = match.group("ip")
    if address.startswith("(none)"):
        address = None
    mtu_text = match.group("mtu")
    mac = match.group("mac")
    return NetworkInterface(
        device=match.group("dev"),
        short_name=match.group("short"),
        address=address,
        interface_type=match.group("type"),
        is_up=match.group("up").lower() == "up",
        mtu=int(mtu_text) if mtu_text.isdigit() else None,
        mac=mac if mac and ":" in mac else None,
    )


def parse_iflist_output(text: str) -> InterfaceList:
    result = InterfaceList(raw=text)
    section: Optional[str] = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        if _INTERFACE_HEADER.match(line.strip()):
            section = "interfaces"
            continue
        if _ROUTE_HEADER.match(line.strip()):
            section = "routes"
            continue
        header = line.strip().upper()
        if header.startswith("DEV ") or header.startswith("DST/MASK"):
            continue
        if section == "interfaces":
            interface = _parse_interface_row(line)
            if interface:
                result.interfaces.append(interface)
        elif section == "routes":
            columns = line.split()
            if len(columns) < 2:
                continue
            metric = int(columns[2]) if len(columns) > 2 and columns[2].isdigit() else None
            gateway = columns[3] if len(columns) > 3 else None
            result.routes.append(Route(columns[0], columns[1], metric, gateway))
    return result

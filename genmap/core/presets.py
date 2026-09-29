"""Built in starting points for new scans.

Each preset is an ordinary ScanConfiguration produced by a function, so it
goes through the same validation and command building as anything the
user configures by hand. User defined profiles build on the same model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from genmap.core.scan_config import (
    PortSelectionMode,
    ScanConfiguration,
    ScanMode,
    TcpScanTechnique,
)


@dataclass(frozen=True)
class Preset:
    key: str
    name: str
    description: str
    factory: Callable[[], ScanConfiguration]

    def build(self) -> ScanConfiguration:
        config = self.factory()
        config.name = self.name
        config.description = self.description
        return config


def _default() -> ScanConfiguration:
    return ScanConfiguration()


def _quick_discovery() -> ScanConfiguration:
    config = ScanConfiguration()
    config.techniques.mode = ScanMode.PING_ONLY
    config.timing.template = 4
    return config


def _quick_scan() -> ScanConfiguration:
    config = ScanConfiguration()
    config.ports.mode = PortSelectionMode.TOP
    config.ports.top_ports = 100
    config.timing.template = 4
    return config


def _full_tcp() -> ScanConfiguration:
    config = ScanConfiguration()
    config.techniques.tcp = TcpScanTechnique.SYN
    config.ports.mode = PortSelectionMode.ALL
    config.timing.template = 4
    return config


def _service_enumeration() -> ScanConfiguration:
    config = ScanConfiguration()
    config.service_detection.enabled = True
    config.scripts.scripts = ["default"]
    config.timing.template = 4
    return config


def _udp_common() -> ScanConfiguration:
    config = ScanConfiguration()
    config.techniques.tcp = None
    config.techniques.udp = True
    config.ports.mode = PortSelectionMode.TOP
    config.ports.top_ports = 100
    config.service_detection.enabled = True
    config.service_detection.intensity = 0
    return config


def _network_inventory() -> ScanConfiguration:
    config = ScanConfiguration()
    config.ports.mode = PortSelectionMode.FAST
    config.service_detection.enabled = True
    config.os_detection.enabled = True
    config.os_detection.limit_to_promising = True
    config.timing.template = 4
    return config


PRESETS: tuple[Preset, ...] = (
    Preset("default", "Nmap defaults", "Top 1000 TCP ports with Nmap's default technique.", _default),
    Preset("quick_discovery", "Quick discovery", "Find live hosts without scanning ports (-sn).", _quick_discovery),
    Preset("quick_scan", "Quick scan", "Top 100 TCP ports with aggressive timing.", _quick_scan),
    Preset("full_tcp", "Full TCP", "All 65535 TCP ports with a SYN scan. Needs raw packet access.", _full_tcp),
    Preset(
        "service_enumeration",
        "Service enumeration",
        "Version detection plus the default NSE script set (-sV -sC).",
        _service_enumeration,
    ),
    Preset("udp_common", "UDP common ports", "Top 100 UDP ports with light version probing. Slow by nature.", _udp_common),
    Preset(
        "network_inventory",
        "Network inventory",
        "Fast port list with service and OS detection for asset inventory.",
        _network_inventory,
    ),
)


def preset_by_key(key: str) -> Preset:
    for preset in PRESETS:
        if preset.key == key:
            return preset
    return PRESETS[0]

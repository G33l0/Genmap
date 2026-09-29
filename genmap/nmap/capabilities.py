"""Capability detection for the installed Nmap.

Capabilities are derived from the version string, the libraries Nmap was
compiled with, the packet capture driver, and the privilege level. Each one
records whether it is believed to be available and why, so the UI can
explain limitations instead of letting a scan fail with a cryptic message.
An ``available`` value of None means Genmap could not tell.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Optional

from genmap.nmap.npcap import CaptureDriverInfo
from genmap.nmap.privileges import PrivilegeLevel
from genmap.nmap.version import NmapVersion


@dataclass(frozen=True)
class Capability:
    key: str
    label: str
    available: Optional[bool]
    detail: str = ""
    minimum_version: Optional[str] = None


@dataclass
class CapabilitySet:
    items: dict[str, Capability] = field(default_factory=dict)

    def add(self, capability: Capability) -> None:
        self.items[capability.key] = capability

    def get(self, key: str) -> Optional[Capability]:
        return self.items.get(key)

    def is_available(self, key: str) -> Optional[bool]:
        capability = self.items.get(key)
        return None if capability is None else capability.available

    def unavailable(self) -> list[Capability]:
        return [c for c in self.items.values() if c.available is False]

    def __iter__(self):
        return iter(self.items.values())


RAW_PACKET_KEY = "raw_packets"


def detect_capabilities(
    version: NmapVersion,
    capture_driver: CaptureDriverInfo,
    privileges: PrivilegeLevel,
) -> CapabilitySet:
    caps = CapabilitySet()
    windows = sys.platform.startswith("win")

    # Raw packet access underpins SYN scans, UDP scans, OS detection and more.
    if windows:
        if not capture_driver.usable:
            raw_available: Optional[bool] = False
            raw_detail = "Npcap was not detected. Nmap needs Npcap for raw packet scans on Windows."
        elif capture_driver.admin_only and privileges == PrivilegeLevel.STANDARD:
            raw_available = False
            raw_detail = "Npcap is installed in administrator only mode and Genmap is not elevated."
        elif privileges == PrivilegeLevel.UNKNOWN:
            raw_available = None
            raw_detail = "Npcap is present but the privilege level could not be determined."
        else:
            raw_available = True
            raw_detail = f"{capture_driver.name} is available."
    else:
        if privileges == PrivilegeLevel.ELEVATED:
            raw_available = True
            raw_detail = "Running with root privileges."
        elif privileges == PrivilegeLevel.STANDARD:
            raw_available = None
            raw_detail = (
                "Not running as root. Raw packet scans work only if the Nmap binary has "
                "CAP_NET_RAW or is set-uid; otherwise Nmap will refuse them."
            )
        else:
            raw_available = None
            raw_detail = "The privilege level could not be determined."

    caps.add(Capability(RAW_PACKET_KEY, "Raw packet scans", raw_available, raw_detail))

    for key, label in (
        ("syn_scan", "TCP SYN scan"),
        ("udp_scan", "UDP scan"),
        ("stealth_tcp_scans", "TCP ACK, Window, Maimon, FIN, NULL, and Xmas scans"),
        ("os_detection", "OS detection"),
        ("traceroute", "Traceroute"),
        ("idle_scan", "Idle scan"),
        ("ip_protocol_scan", "IP protocol scan"),
        ("packet_crafting", "Fragmentation, decoys, spoofing, and custom payloads"),
    ):
        caps.add(Capability(key, label, raw_available, raw_detail))

    caps.add(Capability("connect_scan", "TCP connect scan", True, "Works without special privileges."))

    caps.add(
        Capability(
            "sctp_scan",
            "SCTP INIT and COOKIE ECHO scans",
            raw_available if version.at_least(5, 0) else False,
            raw_detail if version.at_least(5, 0) else "Requires Nmap 5.00 or newer.",
            minimum_version="5.00",
        )
    )

    has_lua = version.has_library("liblua") or version.has_library("nmap-liblua")
    without_lua = any(item.lower().startswith(("liblua", "nmap-liblua")) for item in version.compiled_without)
    nse_available: Optional[bool] = True if has_lua else (False if without_lua else None)
    caps.add(
        Capability(
            "nse",
            "Nmap Scripting Engine",
            nse_available,
            "Lua support compiled in." if has_lua else "This Nmap build reports no Lua support; NSE scripts will not run." if without_lua else "Could not confirm Lua support from the version output.",
        )
    )

    has_ssl = version.has_library("openssl") or version.has_library("libssl")
    caps.add(
        Capability(
            "ssl",
            "SSL/TLS aware service detection and scripts",
            True if has_ssl else (False if any("ssl" in i.lower() for i in version.compiled_without) else None),
            "OpenSSL compiled in." if has_ssl else "Built without OpenSSL; TLS wrapped services and ssl-* scripts are limited.",
        )
    )

    has_ssh = version.has_library("libssh2") or version.has_library("nmap-libssh2")
    caps.add(
        Capability(
            "ssh_scripts",
            "SSH scripts (libssh2)",
            True if has_ssh else (False if any("ssh2" in i.lower() for i in version.compiled_without) else None),
            "libssh2 compiled in." if has_ssh else "Built without libssh2; ssh-auth-methods, ssh-brute and similar scripts are unavailable.",
        )
    )

    has_zlib = version.has_library("libz") or version.has_library("nmap-libz")
    caps.add(
        Capability(
            "zlib",
            "Compression support (zlib)",
            True if has_zlib else None,
            "zlib compiled in." if has_zlib else "zlib not reported; some HTTP scripts cannot decompress responses.",
        )
    )

    caps.add(
        Capability(
            "ipv6_os_detection",
            "IPv6 OS detection",
            raw_available if version.at_least(6, 0) else False,
            "" if version.at_least(6, 0) else "Requires Nmap 6.00 or newer.",
            minimum_version="6.00",
        )
    )
    caps.add(
        Capability(
            "defeat_icmp_ratelimit",
            "--defeat-icmp-ratelimit",
            version.at_least(7, 40),
            "" if version.at_least(7, 40) else "Requires Nmap 7.40 or newer.",
            minimum_version="7.40",
        )
    )
    caps.add(
        Capability(
            "noninteractive",
            "--noninteractive",
            version.at_least(7, 70),
            "Prevents Nmap from reading keyboard input while running under Genmap."
            if version.at_least(7, 70)
            else "Requires Nmap 7.70 or newer.",
            minimum_version="7.70",
        )
    )
    caps.add(
        Capability(
            "nsock_engines",
            "Selectable nsock engines",
            bool(version.nsock_engines),
            ", ".join(version.nsock_engines) if version.nsock_engines else "No engines reported.",
        )
    )
    return caps

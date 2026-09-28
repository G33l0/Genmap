"""Packet capture driver detection.

On Windows Nmap depends on Npcap (or the legacy WinPcap) for raw packet
scans. Elsewhere the equivalent is libpcap, which Nmap links at build time
and reports in ``nmap --version``.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class CaptureDriverStatus(str, Enum):
    DETECTED = "detected"
    MISSING = "missing"
    LEGACY = "legacy"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CaptureDriverInfo:
    status: CaptureDriverStatus
    name: str
    version: Optional[str] = None
    detail: str = ""
    admin_only: Optional[bool] = None
    service_running: Optional[bool] = None

    @property
    def usable(self) -> bool:
        return self.status in (CaptureDriverStatus.DETECTED, CaptureDriverStatus.LEGACY, CaptureDriverStatus.NOT_APPLICABLE)


def _read_registry_value(root, key_path: str, name: str):
    import winreg  # type: ignore[import-not-found]

    for flag in (0, getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0)):
        try:
            with winreg.OpenKey(root, key_path, 0, winreg.KEY_READ | flag) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return value
        except OSError:
            continue
    return None


def _service_running(name: str) -> Optional[bool]:
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return None
    start = _read_registry_value(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{name}", "Start")
    if start is None:
        return None
    # Start type 4 is disabled; anything else can be started on demand.
    return int(start) != 4


def detect_capture_driver(nmap_compiled_with: tuple[str, ...] = ()) -> CaptureDriverInfo:
    if not sys.platform.startswith("win"):
        libpcap = next((item for item in nmap_compiled_with if item.lower().startswith(("libpcap", "nmap-libpcap"))), None)
        if libpcap:
            return CaptureDriverInfo(
                CaptureDriverStatus.NOT_APPLICABLE,
                "libpcap",
                version=libpcap.split("-")[-1] if "-" in libpcap else None,
                detail=f"Nmap is linked against {libpcap}. Npcap is only used on Windows.",
            )
        return CaptureDriverInfo(
            CaptureDriverStatus.NOT_APPLICABLE,
            "libpcap",
            detail="Npcap is only used on Windows. Nmap uses libpcap on this platform.",
        )

    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    system32 = system_root / "System32"
    npcap_dir = system32 / "Npcap"
    npcap_dll = npcap_dir / "wpcap.dll"
    packet_dll = npcap_dir / "Packet.dll"
    legacy_dll = system32 / "wpcap.dll"

    version: Optional[str] = None
    admin_only: Optional[bool] = None
    try:
        import winreg  # type: ignore[import-not-found]

        for key_path in (r"SOFTWARE\Npcap", r"SOFTWARE\WOW6432Node\Npcap"):
            raw_admin = _read_registry_value(winreg.HKEY_LOCAL_MACHINE, key_path, "AdminOnly")
            if raw_admin is not None:
                admin_only = bool(int(raw_admin))
                break
        for key_path in (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst",
        ):
            raw_version = _read_registry_value(winreg.HKEY_LOCAL_MACHINE, key_path, "DisplayVersion")
            if isinstance(raw_version, str) and raw_version:
                version = raw_version
                break
    except ImportError:
        pass

    if npcap_dll.is_file() and packet_dll.is_file():
        running = _service_running("npcap")
        detail = f"Npcap driver files found in {npcap_dir}."
        if admin_only:
            detail += " Npcap was installed in administrator only mode, so scans must run elevated."
        if running is False:
            detail += " The npcap service is disabled."
        return CaptureDriverInfo(
            CaptureDriverStatus.DETECTED,
            "Npcap",
            version=version,
            detail=detail,
            admin_only=admin_only,
            service_running=running,
        )

    if legacy_dll.is_file():
        return CaptureDriverInfo(
            CaptureDriverStatus.LEGACY,
            "WinPcap",
            detail=f"Legacy WinPcap found at {legacy_dll}. Nmap recommends Npcap; WinPcap is unmaintained.",
        )

    return CaptureDriverInfo(
        CaptureDriverStatus.MISSING,
        "Npcap",
        detail="Npcap driver files were not found in System32\\Npcap. Raw packet scans will fail.",
    )

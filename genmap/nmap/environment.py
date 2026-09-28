"""Probing the local Nmap installation and summarising its readiness.

``probe_environment`` runs the executable a couple of times (version and
interface listing) with short timeouts. It never raises for an unusable
installation; instead the returned NmapEnvironment carries diagnostics the
UI can display. Callers should run it off the UI thread.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from genmap.core.diagnostics import Diagnostic, DiagnosticLevel, worst_level
from genmap.nmap.capabilities import CapabilitySet, detect_capabilities
from genmap.nmap.interfaces import InterfaceList, parse_iflist_output
from genmap.nmap.locator import LocatedNmap, find_data_directory, locate_nmap, validate_executable_path
from genmap.nmap.npcap import CaptureDriverInfo, CaptureDriverStatus, detect_capture_driver
from genmap.nmap.privileges import PrivilegeLevel, detect_privilege_level
from genmap.nmap.version import NmapVersion, parse_version_output

log = logging.getLogger(__name__)


@dataclass
class NmapEnvironment:
    executable: Optional[Path] = None
    executable_source: Optional[str] = None
    version: Optional[NmapVersion] = None
    version_output: str = ""
    data_directory: Optional[Path] = None
    capture_driver: Optional[CaptureDriverInfo] = None
    privileges: PrivilegeLevel = PrivilegeLevel.UNKNOWN
    interfaces: Optional[InterfaceList] = None
    capabilities: CapabilitySet = field(default_factory=CapabilitySet)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.executable is not None and self.version is not None

    @property
    def worst_level(self) -> DiagnosticLevel:
        return worst_level(self.diagnostics)

    def raw_packet_support(self) -> Optional[bool]:
        return self.capabilities.is_available("raw_packets")


def _subprocess_flags() -> dict:
    if sys.platform.startswith("win"):
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {}


def run_nmap_quietly(executable: Path, arguments: list[str], timeout: float) -> tuple[int, str, str]:
    """Run Nmap for a diagnostic query. Returns (exit code, stdout, stderr)."""
    completed = subprocess.run(
        [str(executable), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        **_subprocess_flags(),
    )
    return completed.returncode, completed.stdout, completed.stderr


def probe_environment(
    configured_path: Optional[str] = None,
    *,
    timeout: float = 20.0,
    include_interfaces: bool = True,
) -> NmapEnvironment:
    env = NmapEnvironment()
    env.privileges = detect_privilege_level()

    located: Optional[LocatedNmap] = locate_nmap(configured_path)
    if located is None:
        if configured_path:
            problem = validate_executable_path(Path(configured_path).expanduser()) or "The configured path is not usable."
            env.diagnostics.append(
                Diagnostic(
                    DiagnosticLevel.ERROR,
                    "Configured Nmap path is not usable",
                    problem,
                    "Correct the path under Settings, Nmap, or clear it to search automatically.",
                )
            )
        else:
            env.diagnostics.append(
                Diagnostic(
                    DiagnosticLevel.ERROR,
                    "Nmap executable was not found",
                    "Genmap looked on PATH, in the Windows registry, and in the usual install folders.",
                    "Install Nmap from https://nmap.org/download.html, or point Genmap at nmap.exe under Settings, Nmap.",
                )
            )
        env.capture_driver = detect_capture_driver()
        _add_driver_diagnostics(env)
        _add_privilege_diagnostics(env)
        return env

    env.executable = located.path
    env.executable_source = located.source

    try:
        code, out, err = run_nmap_quietly(located.path, ["--version"], timeout)
    except subprocess.TimeoutExpired:
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.ERROR,
                "Nmap did not respond",
                f"{located.path} did not return its version within {int(timeout)} seconds.",
                "Check whether security software is blocking Nmap.",
            )
        )
        return env
    except OSError as exc:
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.ERROR,
                "Nmap could not be started",
                f"{located.path}: {exc}",
                "Make sure the file is a working Nmap build for this operating system.",
            )
        )
        return env

    env.version_output = (out + ("\n" + err if err.strip() else "")).strip()
    env.version = parse_version_output(out) or parse_version_output(err)
    if env.version is None:
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.ERROR,
                "The executable does not look like Nmap",
                f"{located.path} exited with code {code} and did not print an Nmap version banner.",
                "Select the real nmap executable under Settings, Nmap.",
            )
        )
        return env

    env.diagnostics.append(
        Diagnostic(
            DiagnosticLevel.OK,
            f"Nmap {env.version.raw} found",
            f"{located.path} (located via {located.source.replace('_', ' ')})",
        )
    )
    if env.version.is_development:
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.INFO,
                "Development build of Nmap",
                "This is a development snapshot; option behaviour may differ from the release notes.",
            )
        )

    env.data_directory = find_data_directory(located.path)
    if env.data_directory is None:
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.WARNING,
                "Nmap data directory not found",
                "The scripts folder and nmap-services file could not be located next to the executable.",
                "NSE script discovery will be unavailable until the data directory is set under Settings, Nmap.",
            )
        )

    env.capture_driver = detect_capture_driver(env.version.compiled_with)
    _add_driver_diagnostics(env)
    _add_privilege_diagnostics(env)

    env.capabilities = detect_capabilities(env.version, env.capture_driver, env.privileges)

    if include_interfaces:
        try:
            code, out, err = run_nmap_quietly(located.path, ["--iflist"], timeout)
            env.interfaces = parse_iflist_output(out)
            if not env.interfaces.interfaces:
                env.diagnostics.append(
                    Diagnostic(
                        DiagnosticLevel.WARNING,
                        "No network interfaces reported",
                        (err or out).strip()[:400] or "nmap --iflist returned no interfaces.",
                        "On Windows this usually means Npcap is missing or its service is not running.",
                    )
                )
        except (subprocess.TimeoutExpired, OSError) as exc:
            log.warning("nmap --iflist failed: %s", exc)
            env.diagnostics.append(
                Diagnostic(DiagnosticLevel.WARNING, "Interface listing failed", str(exc))
            )

    for capability in env.capabilities.unavailable():
        if capability.key in ("raw_packets",):
            continue
        if capability.key in ("nse", "ssl", "ssh_scripts"):
            env.diagnostics.append(
                Diagnostic(DiagnosticLevel.WARNING, f"{capability.label} unavailable", capability.detail)
            )
    return env


def _add_driver_diagnostics(env: NmapEnvironment) -> None:
    driver = env.capture_driver
    if driver is None:
        return
    if driver.status == CaptureDriverStatus.DETECTED:
        label = f"{driver.name} {driver.version}" if driver.version else driver.name
        level = DiagnosticLevel.OK
        remedy = None
        if driver.admin_only and env.privileges == PrivilegeLevel.STANDARD:
            level = DiagnosticLevel.WARNING
            remedy = "Run Genmap as Administrator, or reinstall Npcap without the administrator only option."
        env.diagnostics.append(Diagnostic(level, f"{label} detected", driver.detail, remedy))
    elif driver.status == CaptureDriverStatus.LEGACY:
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.WARNING,
                "Legacy WinPcap detected",
                driver.detail,
                "Install Npcap from https://npcap.com for reliable raw packet scanning.",
            )
        )
    elif driver.status == CaptureDriverStatus.MISSING:
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.WARNING if env.executable else DiagnosticLevel.INFO,
                "Npcap does not appear to be installed",
                driver.detail,
                "Install Npcap from https://npcap.com (the Nmap installer offers it). TCP connect scans still work without it.",
            )
        )
    elif driver.status == CaptureDriverStatus.NOT_APPLICABLE:
        env.diagnostics.append(Diagnostic(DiagnosticLevel.INFO, "Packet capture", driver.detail))


def _add_privilege_diagnostics(env: NmapEnvironment) -> None:
    windows = sys.platform.startswith("win")
    if env.privileges == PrivilegeLevel.ELEVATED:
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.OK,
                "Running with elevated privileges" if windows else "Running as root",
                "Raw packet scan types are available.",
            )
        )
    elif env.privileges == PrivilegeLevel.STANDARD:
        detail = (
            "Raw packet scans (SYN, UDP, OS detection) work on Windows as long as Npcap allows non administrators."
            if windows
            else "SYN, UDP, and OS detection scans normally require root. TCP connect scans work without it."
        )
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.INFO,
                "Running as a standard user",
                detail,
                None if windows else "Start Genmap with sudo, or give the nmap binary the CAP_NET_RAW capability.",
            )
        )
    else:
        env.diagnostics.append(
            Diagnostic(DiagnosticLevel.INFO, "Privilege level unknown", "Genmap could not determine whether it is elevated.")
        )

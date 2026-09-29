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
from genmap.nmap.capabilities import Capability, CapabilitySet, detect_capabilities
from genmap.nmap.datafiles import DataFileStatus, check_data_files, status_for
from genmap.nmap.interfaces import InterfaceList, parse_iflist_output
from genmap.nmap.locator import LocatedNmap, find_data_directory, locate_nmap, validate_executable_path
from genmap.nmap.npcap import CaptureDriverInfo, CaptureDriverStatus, detect_capture_driver
from genmap.nmap.nse import ScriptCatalog, load_script_catalog
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
    scripts: ScriptCatalog = field(default_factory=ScriptCatalog)
    data_files: list[DataFileStatus] = field(default_factory=list)
    configured_data_directory: Optional[Path] = None
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
    data_directory: Optional[str] = None,
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

    configured = Path(data_directory).expanduser() if data_directory else None
    if configured is not None and not configured.is_dir():
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.WARNING,
                "Configured data directory does not exist",
                str(configured),
                "Correct or clear the data directory under Settings, Nmap. Nmap falls back to its usual folders meanwhile.",
            )
        )
        configured = None
    env.configured_data_directory = configured
    # Genmap passes the configured folder to Nmap as --datadir, so the files
    # are resolved exactly as Nmap will resolve them.
    env.data_files = check_data_files(located.path, configured, env.version)
    script_db = status_for(env.data_files, "scripts/script.db")
    services = status_for(env.data_files, "nmap-services")
    if script_db is not None and script_db.path is not None:
        env.data_directory = script_db.path.parent.parent
    elif services is not None and services.path is not None:
        env.data_directory = services.path.parent
    else:
        env.data_directory = configured or find_data_directory(located.path)
    if env.data_directory is not None:
        env.scripts = load_script_catalog(env.data_directory)
    _add_data_file_diagnostics(env)

    env.capture_driver = detect_capture_driver(env.version.compiled_with)
    _add_driver_diagnostics(env)
    _add_privilege_diagnostics(env)

    env.capabilities = detect_capabilities(env.version, env.capture_driver, env.privileges)
    _apply_data_file_capabilities(env)

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


def _add_data_file_diagnostics(env: NmapEnvironment) -> None:
    found = [s for s in env.data_files if s.found]
    folders = sorted({str(s.path.parent) for s in found if s.path is not None and "/" not in s.spec.name})
    if found:
        counted = [f"{s.spec.name}: {s.summary}" for s in found if s.summary]
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.OK,
                f"{len(found)} of {len(env.data_files)} Nmap data files found",
                ("Read from " + ", ".join(folders) + ". " if folders else "") + "; ".join(counted),
            )
        )
    if len(folders) > 1:
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.INFO,
                "Data files come from more than one folder",
                "Nmap picks each file separately, so a copy in an earlier folder overrides the installed one: "
                + "; ".join(f"{s.spec.name} from {s.path.parent} ({s.origin})" for s in found if s.path is not None and "/" not in s.spec.name),
                "This is expected if you keep customised files in NMAPDIR or your user Nmap folder.",
            )
        )
    assumed = [s for s in found if s.assumed_location]
    if assumed:
        env.diagnostics.append(
            Diagnostic(
                DiagnosticLevel.INFO,
                "Data files found in a standard location",
                f"Nmap was not found next to its data files, so Genmap assumed it was built for {assumed[0].path.parent}.",
                "If scans report missing files, set the data directory under Settings, Nmap.",
            )
        )
    levels = {"error": DiagnosticLevel.ERROR, "warning": DiagnosticLevel.WARNING, "info": DiagnosticLevel.INFO}
    for status in env.data_files:
        if status.found:
            continue
        env.diagnostics.append(
            Diagnostic(
                levels[status.spec.missing_level],
                f"{status.spec.name} {'missing' if status.path is None else 'unusable'}",
                f"{status.problem} Needed for: {status.spec.needed_for}.",
                "Reinstall Nmap, or point Settings, Nmap, Data directory at a folder that holds the complete set of data files.",
            )
        )


def _apply_data_file_capabilities(env: NmapEnvironment) -> None:
    if not env.data_files:
        return

    def missing(name: str) -> bool:
        status = status_for(env.data_files, name)
        return status is not None and not status.found

    probes = status_for(env.data_files, "nmap-service-probes")
    env.capabilities.add(
        Capability(
            "version_detection",
            "Version detection",
            not missing("nmap-service-probes"),
            probes.summary if probes is not None and probes.found else "nmap-service-probes was not found; -sV cannot run.",
        )
    )
    if missing("nmap-os-db"):
        env.capabilities.add(Capability("os_detection", "OS detection", False, "nmap-os-db was not found; -O cannot run."))
    if missing("nse_main.lua"):
        env.capabilities.add(Capability("nse", "Nmap Scripting Engine", False, "nse_main.lua was not found; NSE scripts cannot run."))
    services = status_for(env.data_files, "nmap-services")
    env.capabilities.add(
        Capability(
            "port_frequencies",
            "Port names and --top-ports",
            not missing("nmap-services"),
            services.summary if services is not None and services.found else "nmap-services was not found; Nmap falls back to the system services list.",
        )
    )
    env.capabilities.add(
        Capability(
            "resolve_all",
            "--resolve-all",
            env.version.at_least(7, 70) if env.version else None,
            "" if env.version is None or env.version.at_least(7, 70) else "Requires Nmap 7.70 or newer.",
            minimum_version="7.70",
        )
    )
    env.capabilities.add(
        Capability(
            "unique_addresses",
            "--unique",
            env.version.at_least(7, 92) if env.version else None,
            "" if env.version is None or env.version.at_least(7, 92) else "Requires Nmap 7.92 or newer.",
            minimum_version="7.92",
        )
    )

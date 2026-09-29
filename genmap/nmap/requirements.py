"""Checks a configuration against what the installed Nmap can actually do.

These produce warnings, never errors: Genmap's view of the installation can
be wrong (a set-uid binary, files added after the last check), and Nmap
itself gives the final answer when the scan runs.
"""

from __future__ import annotations

from typing import Optional

from genmap.core.scan_config import PortSelectionMode, ScanConfiguration, ScanMode
from genmap.nmap.datafiles import status_for
from genmap.nmap.environment import NmapEnvironment


def environment_warnings(config: ScanConfiguration, env: Optional[NmapEnvironment]) -> list[str]:
    if env is None or not env.usable:
        return []
    warnings: list[str] = []
    caps = env.capabilities
    port_scan = config.techniques.mode == ScanMode.PORT_SCAN

    raw = caps.get("raw_packets")
    needs_raw = config.techniques.uses_raw_packets or (port_scan and (config.os_detection.enabled or config.aggressive))
    if needs_raw and raw is not None and raw.available is False:
        warnings.append("Raw packet access looks unavailable, so Nmap will probably refuse this scan: " + raw.detail)

    def file_missing(name: str) -> bool:
        status = status_for(env.data_files, name)
        return status is not None and not status.found

    if port_scan and (config.service_detection.enabled or config.aggressive) and file_missing("nmap-service-probes"):
        warnings.append("Version detection needs nmap-service-probes, which was not found in any folder Nmap searches.")
    if port_scan and (config.os_detection.enabled or config.aggressive) and file_missing("nmap-os-db"):
        warnings.append("OS detection needs nmap-os-db, which was not found in any folder Nmap searches.")
    if port_scan and config.ports.mode in (PortSelectionMode.TOP, PortSelectionMode.FAST) and file_missing("nmap-services"):
        warnings.append("Top ports and fast mode rank ports using nmap-services, which was not found.")

    wants_scripts = bool(config.scripts.scripts) or (port_scan and config.aggressive)
    nse = caps.get("nse")
    if wants_scripts and nse is not None and nse.available is False:
        warnings.append("NSE scripts were selected but cannot run: " + nse.detail)

    for enabled, key in ((config.dns.resolve_all, "resolve_all"), (config.dns.unique_addresses, "unique_addresses")):
        capability = caps.get(key)
        if enabled and capability is not None and capability.available is False:
            warnings.append(f"{capability.label}: {capability.detail} Nmap will stop with an unrecognised option error.")
    return warnings

"""A plain text summary of the Nmap installation for bug reports.

Interface addresses and MAC addresses are left out on purpose: they are not
needed to diagnose an installation and people often paste these reports in
public issue trackers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from genmap.nmap.environment import NmapEnvironment
from genmap.nmap.privileges import privilege_label


def _section(title: str) -> list[str]:
    return ["", title, "-" * len(title)]


def render_diagnostic_report(env: Optional[NmapEnvironment], about: Iterable[tuple[str, str]] = ()) -> str:
    lines = [f"Genmap diagnostic report, {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC"]
    lines += _section("Application")
    lines += [f"{key}: {value}" for key, value in about]
    if env is None:
        lines += _section("Nmap")
        lines.append("The installation has not been checked yet.")
        return "\n".join(lines) + "\n"

    lines += _section("Nmap")
    lines.append(f"Executable: {env.executable or 'not found'}")
    if env.executable_source:
        lines.append(f"Found via: {env.executable_source.replace('_', ' ')}")
    lines.append(f"Version: {env.version.raw if env.version else 'unknown'}")
    lines.append(f"Configured data directory: {env.configured_data_directory or 'none'}")
    lines.append(f"Data directory in use: {env.data_directory or 'not found'}")
    lines.append(f"Privileges: {privilege_label(env.privileges)}")
    if env.capture_driver is not None:
        driver = env.capture_driver
        lines.append(f"Packet capture: {driver.name} ({driver.status.value.replace('_', ' ')}) {driver.detail}".rstrip())
    if env.version_output:
        lines += _section("nmap --version")
        lines += env.version_output.splitlines()

    lines += _section("Data files")
    if not env.data_files:
        lines.append("Not checked.")
    for status in env.data_files:
        if status.found:
            where = f"{status.path} ({status.origin}{', assumed location' if status.assumed_location else ''})"
            lines.append(f"{status.spec.name}: {where}" + (f", {status.summary}" if status.summary else ""))
        else:
            lines.append(f"{status.spec.name}: {status.problem}")

    lines += _section("Capabilities")
    for capability in env.capabilities:
        state = {True: "yes", False: "no", None: "unknown"}[capability.available]
        lines.append(f"{capability.label}: {state}" + (f" ({capability.detail})" if capability.detail else ""))

    lines += _section("Diagnostics")
    for diagnostic in env.diagnostics:
        lines.append(f"[{diagnostic.level.value}] {diagnostic.title}")
        if diagnostic.detail:
            lines.append(f"    {diagnostic.detail}")
        if diagnostic.remedy:
            lines.append(f"    Suggested: {diagnostic.remedy}")

    lines += _section("Interfaces (addresses omitted)")
    interfaces = env.interfaces.interfaces if env.interfaces else []
    if not interfaces:
        lines.append("None reported.")
    for iface in interfaces:
        lines.append(f"{iface.device}: {iface.interface_type}, {'up' if iface.is_up else 'down'}")
    return "\n".join(lines) + "\n"

"""Report generation.

Reports describe what Nmap reported. They never grade risk or assert that a
host is vulnerable; interpretation is left to the reader, and every value
comes from the stored Nmap XML or the run record.
"""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from genmap import APP_NAME, __version__
from genmap.core.results import Host, Port, ScanResult
from genmap.engine.run_store import RunRecord
from genmap.errors import GenmapError

REPORT_FORMATS: dict[str, tuple[str, str]] = {
    "html": ("HTML report", ".html"),
    "json": ("JSON data", ".json"),
    "csv": ("CSV, one row per port", ".csv"),
    "xml": ("Original Nmap XML", ".xml"),
}


class ReportError(GenmapError):
    default_message = "The report could not be created."


@dataclass
class ReportOptions:
    include_closed_ports: bool = False
    include_down_hosts: bool = False
    include_script_output: bool = True
    include_configuration: bool = True
    title: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "include_closed_ports": self.include_closed_ports,
            "include_down_hosts": self.include_down_hosts,
            "include_script_output": self.include_script_output,
            "include_configuration": self.include_configuration,
        }


@dataclass
class ReportSource:
    result: ScanResult
    xml_path: Optional[Path] = None
    record: Optional[RunRecord] = None
    warnings: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        if self.record is not None:
            return f"Nmap scan of {self.record.target_summary}"
        return f"Nmap scan {self.xml_path.name}" if self.xml_path else "Nmap scan"


def _visible_ports(host: Host, options: ReportOptions) -> list[Port]:
    if options.include_closed_ports:
        return list(host.ports)
    return [p for p in host.ports if p.state not in ("closed", "filtered", "closed|filtered")]


def _visible_hosts(result: ScanResult, options: ReportOptions) -> list[Host]:
    return list(result.hosts) if options.include_down_hosts else [h for h in result.hosts if h.is_up]


def _fmt_time(value: Optional[datetime]) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") if value else ""


def _metadata(source: ReportSource) -> list[tuple[str, str]]:
    result, record = source.result, source.record
    stats = result.statistics
    rows: list[tuple[str, str]] = []
    if record is not None:
        rows.append(("Targets", record.target_summary))
        if record.profile_name:
            rows.append(("Profile", record.profile_name))
        rows.append(("Genmap status", record.status.label + (f" (exit code {record.exit_code})" if record.exit_code is not None else "")))
        rows.append(("Genmap run", record.run_id))
    rows.append(("Nmap version", result.nmap_version or "Not recorded"))
    rows.append(("Started", _fmt_time(result.started_at) or (_fmt_time(record.started_at) if record else "")))
    rows.append(("Finished", _fmt_time(stats.finished_at) or (_fmt_time(record.finished_at) if record else "")))
    if stats.elapsed_seconds is not None:
        rows.append(("Elapsed", f"{stats.elapsed_seconds:.2f} seconds"))
    rows.append(("Command", result.command_line or (record.command.display if record and record.command else "")))
    for info in result.scan_infos:
        rows.append((f"Scan type ({info.protocol})", f"{info.scan_type}, {info.number_of_services} ports" if info.number_of_services is not None else info.scan_type))
    if stats.summary:
        rows.append(("Nmap summary", stats.summary))
    return [(k, v) for k, v in rows if v]


def _summary(result: ScanResult) -> dict[str, Any]:
    stats = result.statistics
    return {
        "hosts_up": stats.hosts_up or len(result.hosts_up),
        "hosts_down": stats.hosts_down,
        "hosts_total": stats.hosts_total or len(result.hosts),
        "open_ports": result.total_open_ports,
        "identified_services": sorted(result.identified_services),
        "port_table_service_names": sorted(result.distinct_services - result.identified_services),
        "complete": not result.truncated and stats.exit_status in (None, "success"),
    }


def _all_warnings(source: ReportSource) -> list[str]:
    warnings = list(source.result.warnings)
    if source.result.truncated:
        warnings.insert(0, "Nmap did not finish writing its output; hosts it had not finished are missing from this report.")
    stats = source.result.statistics
    if stats.exit_status == "error":
        warnings.append(f"Nmap reported an error: {stats.error_message or 'no message'}")
    record = source.record
    if record is not None:
        for text in (record.error_message, record.error_remedy, *record.warnings):
            if text and text not in warnings:
                warnings.append(text)
    for text in source.warnings:
        if text not in warnings:
            warnings.append(text)
    return warnings


# JSON ----------------------------------------------------------------------------


def render_json(source: ReportSource, options: ReportOptions) -> str:
    result = source.result
    hosts = []
    for host in _visible_hosts(result, options):
        data = host.model_dump(mode="json")
        data["ports"] = [p.model_dump(mode="json") for p in _visible_ports(host, options)]
        if not options.include_script_output:
            data["host_scripts"] = []
            for port in data["ports"]:
                port["scripts"] = []
        hosts.append(data)
    payload: dict[str, Any] = {
        "generator": f"{APP_NAME} {__version__}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_options": options.as_dict(),
        "scan": dict(_metadata(source)),
        "summary": _summary(result),
        "warnings": _all_warnings(source),
        "hosts": hosts,
    }
    if options.include_script_output:
        payload["pre_scripts"] = [s.model_dump(mode="json") for s in result.pre_scripts]
        payload["post_scripts"] = [s.model_dump(mode="json") for s in result.post_scripts]
    if options.include_configuration and source.record is not None:
        payload["configuration"] = source.record.configuration
    return json.dumps(payload, indent=2)


# CSV -----------------------------------------------------------------------------


CSV_HEADER = ["host", "hostname", "host_state", "port", "protocol", "state", "reason", "service", "service_method", "product", "version", "extra_info", "cpe", "scripts"]


def result_to_csv(result: ScanResult, options: Optional[ReportOptions] = None) -> str:
    options = options or ReportOptions(include_closed_ports=True, include_down_hosts=True)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_HEADER)
    for host in _visible_hosts(result, options):
        for port in _visible_ports(host, options):
            service = port.service
            writer.writerow([
                host.primary_address or "",
                host.primary_hostname or "",
                host.status.state,
                port.port_id,
                port.protocol,
                port.state,
                port.reason or "",
                (service.name or "") if service else "",
                (service.method or "") if service else "",
                (service.product or "") if service else "",
                (service.version or "") if service else "",
                (service.extra_info or "") if service else "",
                " ".join(service.cpe) if service else "",
                " ".join(s.script_id for s in port.scripts) if options.include_script_output else "",
            ])
    return buffer.getvalue()


# HTML ----------------------------------------------------------------------------

from genmap.reporting.html import render_html  # noqa: E402  (keeps HTML templating in its own module)


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".genmap-report-", suffix=path.suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def generate_report(source: ReportSource, fmt: str, path: Path, options: Optional[ReportOptions] = None) -> Path:
    options = options or ReportOptions()
    if fmt not in REPORT_FORMATS:
        raise ReportError(f"Unknown report format '{fmt}'.")
    try:
        if fmt == "xml":
            if source.xml_path is None or not source.xml_path.is_file():
                raise ReportError("The original Nmap XML file is not available for this scan.")
            path.parent.mkdir(parents=True, exist_ok=True)
            if source.xml_path.resolve() != path.resolve():
                shutil.copyfile(source.xml_path, path)
        elif fmt == "json":
            _write_atomic(path, render_json(source, options))
        elif fmt == "csv":
            _write_atomic(path, result_to_csv(source.result, options))
        else:
            _write_atomic(path, render_html(source, options))
    except OSError as exc:
        raise ReportError(f"The report could not be written to {path}.", remedy="Choose a folder you can write to.", details=str(exc)) from exc
    return path

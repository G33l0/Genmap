"""Normalised scan result models.

These mirror the information Nmap exposes in its XML output without being
tied to the XML structure. Unknown attributes are kept in ``extra`` fields so
newer Nmap releases do not lose data on the way through the parser.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ResultModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Address(ResultModel):
    address: str
    address_type: str = "ipv4"
    vendor: Optional[str] = None


class Hostname(ResultModel):
    name: str
    hostname_type: Optional[str] = None


class HostStatus(ResultModel):
    state: str = "unknown"
    reason: Optional[str] = None
    reason_ttl: Optional[int] = None


class ScriptResult(ResultModel):
    script_id: str
    output: str = ""
    structured: dict[str, Any] | list[Any] | None = None


class Service(ResultModel):
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    method: Optional[str] = None
    confidence: Optional[int] = None
    tunnel: Optional[str] = None
    os_type: Optional[str] = None
    device_type: Optional[str] = None
    hostname: Optional[str] = None
    service_fingerprint: Optional[str] = None
    cpe: list[str] = Field(default_factory=list)
    extra: dict[str, str] = Field(default_factory=dict)

    def display_name(self) -> str:
        parts = [p for p in (self.product, self.version, self.extra_info) if p]
        if parts:
            return " ".join(parts)
        return self.name or ""


class Port(ResultModel):
    protocol: str
    port_id: int
    state: str = "unknown"
    reason: Optional[str] = None
    reason_ttl: Optional[int] = None
    reason_ip: Optional[str] = None
    service: Optional[Service] = None
    scripts: list[ScriptResult] = Field(default_factory=list)
    owner: Optional[str] = None

    @property
    def label(self) -> str:
        return f"{self.port_id}/{self.protocol}"


class ExtraPorts(ResultModel):
    state: str
    count: int
    reasons: dict[str, int] = Field(default_factory=dict)


class OsClass(ResultModel):
    os_type: Optional[str] = None
    vendor: Optional[str] = None
    os_family: Optional[str] = None
    os_generation: Optional[str] = None
    accuracy: Optional[int] = None
    cpe: list[str] = Field(default_factory=list)


class OsMatch(ResultModel):
    name: str
    accuracy: Optional[int] = None
    line: Optional[int] = None
    classes: list[OsClass] = Field(default_factory=list)


class OsPortUsed(ResultModel):
    state: str
    protocol: str
    port_id: int


class OsDetection(ResultModel):
    ports_used: list[OsPortUsed] = Field(default_factory=list)
    matches: list[OsMatch] = Field(default_factory=list)
    fingerprints: list[str] = Field(default_factory=list)

    @property
    def best_match(self) -> Optional[OsMatch]:
        return self.matches[0] if self.matches else None


class TracerouteHop(ResultModel):
    ttl: int
    ip_address: Optional[str] = None
    rtt: Optional[float] = None
    hostname: Optional[str] = None


class Traceroute(ResultModel):
    port: Optional[int] = None
    protocol: Optional[str] = None
    hops: list[TracerouteHop] = Field(default_factory=list)


class Uptime(ResultModel):
    seconds: int
    last_boot: Optional[str] = None


class SequenceInfo(ResultModel):
    tcp_sequence_index: Optional[int] = None
    tcp_sequence_difficulty: Optional[str] = None
    ip_id_sequence_class: Optional[str] = None
    tcp_timestamp_class: Optional[str] = None


class HostTimes(ResultModel):
    srtt: Optional[int] = None
    rtt_variance: Optional[int] = None
    timeout: Optional[int] = None


class Host(ResultModel):
    status: HostStatus = Field(default_factory=HostStatus)
    addresses: list[Address] = Field(default_factory=list)
    hostnames: list[Hostname] = Field(default_factory=list)
    ports: list[Port] = Field(default_factory=list)
    extra_ports: list[ExtraPorts] = Field(default_factory=list)
    os: Optional[OsDetection] = None
    host_scripts: list[ScriptResult] = Field(default_factory=list)
    traceroute: Optional[Traceroute] = None
    uptime: Optional[Uptime] = None
    distance: Optional[int] = None
    sequences: Optional[SequenceInfo] = None
    times: Optional[HostTimes] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    comment: Optional[str] = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def primary_address(self) -> Optional[str]:
        for wanted in ("ipv4", "ipv6"):
            for address in self.addresses:
                if address.address_type == wanted:
                    return address.address
        return self.addresses[0].address if self.addresses else None

    @property
    def mac_address(self) -> Optional[Address]:
        for address in self.addresses:
            if address.address_type == "mac":
                return address
        return None

    @property
    def primary_hostname(self) -> Optional[str]:
        for preferred in ("user", "PTR"):
            for hostname in self.hostnames:
                if hostname.hostname_type == preferred:
                    return hostname.name
        return self.hostnames[0].name if self.hostnames else None

    @property
    def display_name(self) -> str:
        address = self.primary_address or "unknown"
        hostname = self.primary_hostname
        if hostname and hostname != address:
            return f"{address} ({hostname})"
        return address

    @property
    def is_up(self) -> bool:
        return self.status.state == "up"

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def best_os_match(self) -> Optional[OsMatch]:
        return self.os.best_match if self.os else None


class ScanInfo(ResultModel):
    scan_type: str
    protocol: str
    number_of_services: Optional[int] = None
    services: Optional[str] = None
    scan_flags: Optional[str] = None


class RunStatistics(ResultModel):
    hosts_up: int = 0
    hosts_down: int = 0
    hosts_total: int = 0
    elapsed_seconds: Optional[float] = None
    summary: Optional[str] = None
    exit_status: Optional[str] = None
    error_message: Optional[str] = None
    finished_at: Optional[datetime] = None


class ScanResult(ResultModel):
    scanner: str = "nmap"
    nmap_version: Optional[str] = None
    xml_output_version: Optional[str] = None
    command_line: Optional[str] = None
    started_at: Optional[datetime] = None
    scan_infos: list[ScanInfo] = Field(default_factory=list)
    verbosity: Optional[int] = None
    debugging: Optional[int] = None
    hosts: list[Host] = Field(default_factory=list)
    pre_scripts: list[ScriptResult] = Field(default_factory=list)
    post_scripts: list[ScriptResult] = Field(default_factory=list)
    statistics: RunStatistics = Field(default_factory=RunStatistics)
    warnings: list[str] = Field(default_factory=list)
    truncated: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def hosts_up(self) -> list[Host]:
        return [h for h in self.hosts if h.is_up]

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def distinct_services(self) -> set[str]:
        names: set[str] = set()
        for host in self.hosts:
            for port in host.open_ports:
                if port.service and port.service.name:
                    names.add(port.service.name)
        return names

    def summary_line(self) -> str:
        up = len(self.hosts_up)
        return f"{up} host{'s' if up != 1 else ''} up, {self.total_open_ports} open ports"

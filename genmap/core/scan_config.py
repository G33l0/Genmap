"""Strongly typed scan configuration.

A ScanConfiguration captures what the user wants Nmap to do without any
knowledge of the command line. The Nmap command builder turns it into an
argument list, the UI binds forms to it, and profiles are stored as
serialised instances of it. Validation happens at the field level here and
across fields in ``validate_configuration``.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from genmap.core.ports import parse_port_specification
from genmap.core.targets import parse_target
from genmap.core.timespec import normalize_time_spec


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, str_strip_whitespace=True)


class ScanMode(str, Enum):
    """Top level mode. Only PORT_SCAN performs port scanning."""

    PORT_SCAN = "port_scan"
    PING_ONLY = "ping_only"
    LIST_ONLY = "list_only"


class TcpScanTechnique(str, Enum):
    AUTO = "auto"  # no flag: Nmap uses SYN when privileged, connect otherwise
    SYN = "syn"
    CONNECT = "connect"
    ACK = "ack"
    WINDOW = "window"
    MAIMON = "maimon"
    FIN = "fin"
    NULL = "null"
    XMAS = "xmas"
    CUSTOM_FLAGS = "custom_flags"
    IDLE = "idle"
    FTP_BOUNCE = "ftp_bounce"


class SctpScanTechnique(str, Enum):
    INIT = "init"
    COOKIE_ECHO = "cookie_echo"


class PortSelectionMode(str, Enum):
    DEFAULT = "default"
    SPECIFIC = "specific"
    TOP = "top"
    FAST = "fast"
    ALL = "all"


class DnsResolutionMode(str, Enum):
    DEFAULT = "default"
    ALWAYS = "always"
    NEVER = "never"


class ArpPingMode(str, Enum):
    AUTO = "auto"
    DISABLED = "disabled"


class TargetSpecification(StrictModel):
    targets: list[str] = Field(default_factory=list)
    target_file: Optional[str] = None
    exclusions: list[str] = Field(default_factory=list)
    exclude_file: Optional[str] = None
    random_targets: Optional[int] = Field(default=None, ge=1)

    @field_validator("targets", "exclusions")
    @classmethod
    def _validate_targets(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            parse_target(value)
            if value.strip() not in cleaned:
                cleaned.append(value.strip())
        return cleaned

    @property
    def has_targets(self) -> bool:
        return bool(self.targets or self.target_file or self.random_targets)


class ScanTechniques(StrictModel):
    mode: ScanMode = ScanMode.PORT_SCAN
    tcp: Optional[TcpScanTechnique] = TcpScanTechnique.AUTO
    udp: bool = False
    sctp: Optional[SctpScanTechnique] = None
    ip_protocol: bool = False
    custom_tcp_flags: Optional[str] = None
    idle_zombie: Optional[str] = None
    ftp_bounce_relay: Optional[str] = None

    @field_validator("custom_tcp_flags")
    @classmethod
    def _validate_flags(cls, value: Optional[str]) -> Optional[str]:
        if value is None or value == "":
            return None
        if value.isdigit():
            if int(value) > 255:
                raise ValueError("numeric TCP flags must be between 0 and 255")
            return value
        allowed = {"URG", "ACK", "PSH", "RST", "SYN", "FIN", "ECE", "CWR", "ALL", "NONE"}
        upper = value.upper()
        remaining = upper
        while remaining:
            for name in allowed:
                if remaining.startswith(name):
                    remaining = remaining[len(name):]
                    break
            else:
                raise ValueError(
                    "TCP flags must be a number or a combination of URG, ACK, PSH, RST, SYN, FIN, ECE, CWR"
                )
        return upper

    @property
    def uses_raw_packets(self) -> bool:
        if self.mode != ScanMode.PORT_SCAN:
            return False
        raw_tcp = self.tcp not in (
            None,
            TcpScanTechnique.AUTO,
            TcpScanTechnique.CONNECT,
            TcpScanTechnique.FTP_BOUNCE,
        )
        return raw_tcp or self.udp or self.sctp is not None or self.ip_protocol


class PortOptions(StrictModel):
    mode: PortSelectionMode = PortSelectionMode.DEFAULT
    specification: str = ""
    top_ports: int = Field(default=100, ge=1, le=65535)
    exclude_ports: str = ""
    sequential: bool = False

    @field_validator("specification", "exclude_ports")
    @classmethod
    def _validate_spec(cls, value: str) -> str:
        if value:
            parse_port_specification(value)
        return value


class HostDiscoveryOptions(StrictModel):
    skip_discovery: bool = False
    icmp_echo: bool = False
    icmp_timestamp: bool = False
    icmp_netmask: bool = False
    tcp_syn_ports: str = ""
    tcp_ack_ports: str = ""
    udp_ports: str = ""
    sctp_ports: str = ""
    ip_protocols: str = ""
    arp_ping: ArpPingMode = ArpPingMode.AUTO
    traceroute: bool = False

    @field_validator("tcp_syn_ports", "tcp_ack_ports", "udp_ports", "sctp_ports")
    @classmethod
    def _validate_ports(cls, value: str) -> str:
        if value:
            parse_port_specification(value)
        return value

    @field_validator("ip_protocols")
    @classmethod
    def _validate_protocols(cls, value: str) -> str:
        if value:
            parse_port_specification(value, protocol_scan=True)
        return value

    @property
    def has_custom_probes(self) -> bool:
        return any(
            (
                self.icmp_echo,
                self.icmp_timestamp,
                self.icmp_netmask,
                self.tcp_syn_ports,
                self.tcp_ack_ports,
                self.udp_ports,
                self.sctp_ports,
                self.ip_protocols,
            )
        )


class DnsOptions(StrictModel):
    resolution: DnsResolutionMode = DnsResolutionMode.DEFAULT
    servers: list[str] = Field(default_factory=list)
    use_system_resolver: bool = False
    resolve_all: bool = False
    unique_addresses: bool = False

    @field_validator("servers")
    @classmethod
    def _validate_servers(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_target(value)
        return values


class ServiceDetectionOptions(StrictModel):
    enabled: bool = False
    intensity: Optional[int] = Field(default=None, ge=0, le=9)
    trace: bool = False


class OsDetectionOptions(StrictModel):
    enabled: bool = False
    limit_to_promising: bool = False
    guess_aggressively: bool = False
    max_tries: Optional[int] = Field(default=None, ge=1, le=50)


class ScriptArgument(StrictModel):
    name: str = Field(min_length=1)
    value: str = ""

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if "=" in value or "," in value or any(c.isspace() for c in value):
            raise ValueError("script argument names cannot contain '=', ',' or whitespace")
        return value


class ScriptOptions(StrictModel):
    """NSE selection. ``scripts`` holds Nmap script expressions: names,
    categories, wildcards, or boolean expressions such as "default and safe"."""

    scripts: list[str] = Field(default_factory=list)
    arguments: list[ScriptArgument] = Field(default_factory=list)
    arguments_file: Optional[str] = None
    timeout: Optional[str] = None
    trace: bool = False
    update_database: bool = False

    @field_validator("scripts")
    @classmethod
    def _validate_scripts(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            item = value.strip()
            if not item:
                continue
            if "\n" in item or "\r" in item or "\x00" in item:
                raise ValueError("script expressions cannot contain control characters")
            if item not in cleaned:
                cleaned.append(item)
        return cleaned

    @field_validator("timeout")
    @classmethod
    def _validate_timeout(cls, value: Optional[str]) -> Optional[str]:
        if value:
            return normalize_time_spec(value, option="script timeout")
        return None

    @property
    def enabled(self) -> bool:
        return bool(self.scripts)


class TimingOptions(StrictModel):
    template: Optional[int] = Field(default=None, ge=0, le=5)
    host_timeout: Optional[str] = None
    min_rtt_timeout: Optional[str] = None
    max_rtt_timeout: Optional[str] = None
    initial_rtt_timeout: Optional[str] = None
    max_retries: Optional[int] = Field(default=None, ge=0, le=50)
    min_hostgroup: Optional[int] = Field(default=None, ge=1)
    max_hostgroup: Optional[int] = Field(default=None, ge=1)
    min_parallelism: Optional[int] = Field(default=None, ge=1)
    max_parallelism: Optional[int] = Field(default=None, ge=1)
    scan_delay: Optional[str] = None
    max_scan_delay: Optional[str] = None
    min_rate: Optional[int] = Field(default=None, ge=1)
    max_rate: Optional[int] = Field(default=None, ge=1)
    defeat_rst_ratelimit: bool = False
    defeat_icmp_ratelimit: bool = False
    nsock_engine: Optional[str] = None

    @field_validator(
        "host_timeout",
        "min_rtt_timeout",
        "max_rtt_timeout",
        "initial_rtt_timeout",
        "scan_delay",
        "max_scan_delay",
    )
    @classmethod
    def _validate_time(cls, value: Optional[str], info) -> Optional[str]:
        if value:
            return normalize_time_spec(value, option=info.field_name.replace("_", " "))
        return None


class EvasionOptions(StrictModel):
    fragment_packets: int = Field(default=0, ge=0, le=2)
    mtu: Optional[int] = Field(default=None, ge=8)
    decoys: list[str] = Field(default_factory=list)
    spoof_source: Optional[str] = None
    spoof_mac: Optional[str] = None
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    data_hex: Optional[str] = None
    data_string: Optional[str] = None
    data_length: Optional[int] = Field(default=None, ge=0, le=1400)
    ip_options: Optional[str] = None
    ttl: Optional[int] = Field(default=None, ge=1, le=255)
    bad_checksum: bool = False
    randomize_hosts: bool = False
    proxies: list[str] = Field(default_factory=list)
    adler32: bool = False

    @field_validator("mtu")
    @classmethod
    def _validate_mtu(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value % 8 != 0:
            raise ValueError("MTU must be a multiple of 8")
        return value

    @field_validator("decoys")
    @classmethod
    def _validate_decoys(cls, values: list[str]) -> list[str]:
        for value in values:
            if value == "ME" or value.startswith("RND"):
                continue
            parse_target(value)
        return values

    @field_validator("data_hex")
    @classmethod
    def _validate_hex(cls, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        candidate = value[2:] if value.lower().startswith("0x") else value
        candidate = candidate.replace("\\x", "")
        if not candidate or any(c not in "0123456789abcdefABCDEF" for c in candidate):
            raise ValueError("payload must be hexadecimal, for example 0xDEADBEEF")
        return value

    @field_validator("spoof_mac")
    @classmethod
    def _validate_mac(cls, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        if any(c.isspace() for c in value):
            raise ValueError("MAC specification cannot contain whitespace")
        return value

    @property
    def active(self) -> bool:
        return any(
            (
                self.fragment_packets,
                self.mtu,
                self.decoys,
                self.spoof_source,
                self.spoof_mac,
                self.source_port is not None,
                self.data_hex,
                self.data_string,
                self.data_length is not None,
                self.ip_options,
                self.ttl,
                self.bad_checksum,
                self.proxies,
            )
        )


class NetworkOptions(StrictModel):
    interface: Optional[str] = None
    ipv6: bool = False
    send_ethernet: bool = False
    send_ip: bool = False
    privileged: Optional[bool] = None

    @field_validator("interface")
    @classmethod
    def _validate_interface(cls, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        if any(c.isspace() for c in value):
            raise ValueError("interface names cannot contain whitespace")
        return value


def _clean_path(value: Optional[str]) -> Optional[str]:
    if value is None or not value.strip():
        return None
    value = value.strip()
    if any(ord(c) < 32 for c in value):
        raise ValueError("paths cannot contain control characters")
    if len(value) > 1024:
        raise ValueError("path is too long")
    return value


class DataFileOptions(StrictModel):
    """Where Nmap reads its databases from (--datadir, --servicedb, --versiondb)."""

    data_directory: Optional[str] = None
    services_file: Optional[str] = None
    version_probes_file: Optional[str] = None

    @field_validator("data_directory", "services_file", "version_probes_file")
    @classmethod
    def _validate_path(cls, value: Optional[str]) -> Optional[str]:
        return _clean_path(value)

    @property
    def active(self) -> bool:
        return bool(self.data_directory or self.services_file or self.version_probes_file)


class OutputOptions(StrictModel):
    verbosity: int = Field(default=1, ge=0, le=4)
    debugging: int = Field(default=0, ge=0, le=9)
    packet_trace: bool = False
    show_reason: bool = False
    open_only: bool = False
    stats_interval: Optional[str] = None

    @field_validator("stats_interval")
    @classmethod
    def _validate_stats(cls, value: Optional[str]) -> Optional[str]:
        if value:
            return normalize_time_spec(value, option="stats interval")
        return None


class ScanConfiguration(StrictModel):
    schema_version: int = 1
    name: str = ""
    description: str = ""
    targets: TargetSpecification = Field(default_factory=TargetSpecification)
    techniques: ScanTechniques = Field(default_factory=ScanTechniques)
    ports: PortOptions = Field(default_factory=PortOptions)
    discovery: HostDiscoveryOptions = Field(default_factory=HostDiscoveryOptions)
    dns: DnsOptions = Field(default_factory=DnsOptions)
    service_detection: ServiceDetectionOptions = Field(default_factory=ServiceDetectionOptions)
    os_detection: OsDetectionOptions = Field(default_factory=OsDetectionOptions)
    aggressive: bool = False
    scripts: ScriptOptions = Field(default_factory=ScriptOptions)
    timing: TimingOptions = Field(default_factory=TimingOptions)
    evasion: EvasionOptions = Field(default_factory=EvasionOptions)
    network: NetworkOptions = Field(default_factory=NetworkOptions)
    data_files: DataFileOptions = Field(default_factory=DataFileOptions)
    output: OutputOptions = Field(default_factory=OutputOptions)
    advanced_arguments: str = ""

    def copy_with_targets(self, targets: list[str]) -> "ScanConfiguration":
        clone = self.model_copy(deep=True)
        clone.targets.targets = targets
        return clone

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    @classmethod
    def from_json(cls, text: str) -> "ScanConfiguration":
        return cls.model_validate_json(text)


class ValidationIssue(StrictModel):
    severity: str  # "error" or "warning"
    message: str
    remedy: Optional[str] = None


def validate_configuration(config: ScanConfiguration) -> list[ValidationIssue]:
    """Cross field validation. Field level validation already ran in pydantic."""
    issues: list[ValidationIssue] = []

    def error(message: str, remedy: Optional[str] = None) -> None:
        issues.append(ValidationIssue(severity="error", message=message, remedy=remedy))

    def warning(message: str, remedy: Optional[str] = None) -> None:
        issues.append(ValidationIssue(severity="warning", message=message, remedy=remedy))

    if not config.targets.has_targets:
        error("No targets specified.", "Add at least one address, hostname, network, or target file.")

    tech = config.techniques
    if tech.mode == ScanMode.PORT_SCAN:
        if tech.tcp is None and not tech.udp and tech.sctp is None and not tech.ip_protocol:
            error(
                "No scan technique selected.",
                "Choose a TCP technique or enable UDP, SCTP, or IP protocol scanning.",
            )
        if tech.tcp == TcpScanTechnique.CUSTOM_FLAGS and not tech.custom_tcp_flags:
            error("Custom TCP flags scan requires the flags to be specified.")
        if tech.tcp == TcpScanTechnique.IDLE and not tech.idle_zombie:
            error("Idle scan requires a zombie host.", "Enter the zombie host, optionally with :port.")
        if tech.tcp == TcpScanTechnique.FTP_BOUNCE and not tech.ftp_bounce_relay:
            error("FTP bounce scan requires an FTP relay host.")
        if tech.tcp == TcpScanTechnique.IDLE and (tech.udp or tech.sctp or tech.ip_protocol):
            error("Idle scan cannot be combined with UDP, SCTP, or IP protocol scans.")
        if tech.tcp == TcpScanTechnique.AUTO and (tech.udp or tech.sctp or tech.ip_protocol):
            warning(
                "Nmap skips TCP when another scan type is given without a TCP technique.",
                "Choose SYN or connect explicitly to scan TCP as well.",
            )
    else:
        if config.ports.mode != PortSelectionMode.DEFAULT:
            warning("Port options are ignored in ping only and list only modes.")
        if config.service_detection.enabled or config.os_detection.enabled or config.aggressive:
            warning("Service and OS detection are ignored when no port scan is performed.")

    if config.ports.mode == PortSelectionMode.SPECIFIC and not config.ports.specification:
        error("Specific port mode requires a port list.", "Enter ports such as 22,80,443 or 1-1024.")

    if config.ports.mode == PortSelectionMode.FAST and config.ports.specification:
        warning("Fast mode ignores the explicit port list.")

    if tech.ip_protocol and config.ports.specification:
        try:
            parse_port_specification(config.ports.specification, protocol_scan=True)
        except Exception:
            warning(
                "IP protocol scan uses protocol numbers (0 to 255); the port list contains values above that."
            )

    if config.discovery.skip_discovery and config.discovery.has_custom_probes:
        warning("Discovery probes have no effect when host discovery is skipped.")

    if config.discovery.skip_discovery and tech.mode == ScanMode.PING_ONLY:
        error("Ping only mode and skip discovery contradict each other.")

    if config.service_detection.intensity is not None and not (
        config.service_detection.enabled or config.aggressive
    ):
        warning("Version intensity has no effect unless service detection is enabled.")

    if config.dns.resolution == DnsResolutionMode.NEVER and config.dns.servers:
        warning("Custom DNS servers are ignored when name resolution is disabled.")

    files = config.data_files
    if files.services_file:
        # Nmap turns on fast mode for --servicedb (nmap.cc), scanning the ports that file lists.
        if tech.mode != ScanMode.PORT_SCAN:
            error("A custom services file only applies to port scans.", "Clear the services file or switch to a port scan.")
        elif config.ports.mode not in (PortSelectionMode.DEFAULT, PortSelectionMode.FAST):
            error(
                "A custom services file makes Nmap scan the ports that file lists, so it cannot be combined with other port choices.",
                "Set the port selection back to Nmap's default, or clear the services file.",
            )
    if files.data_directory and not Path(files.data_directory).expanduser().is_dir():
        error(f"The data directory {files.data_directory} does not exist.", "Pick an existing folder or clear the field.")
    for value, what in ((files.services_file, "services file"), (files.version_probes_file, "version probes file")):
        if value and not Path(value).expanduser().is_file():
            error(f"The {what} {value} does not exist.", "Pick an existing file or clear the field.")

    timing = config.timing
    if timing.min_rate and timing.max_rate and timing.min_rate > timing.max_rate:
        error("Minimum packet rate is above the maximum packet rate.")
    if timing.min_hostgroup and timing.max_hostgroup and timing.min_hostgroup > timing.max_hostgroup:
        error("Minimum host group is above the maximum host group.")
    if timing.min_parallelism and timing.max_parallelism and timing.min_parallelism > timing.max_parallelism:
        error("Minimum parallelism is above the maximum parallelism.")

    evasion = config.evasion
    if evasion.fragment_packets and evasion.mtu:
        error("Choose either packet fragmentation or a custom MTU, not both.")
    if sum(1 for v in (evasion.data_hex, evasion.data_string, evasion.data_length) if v not in (None, "")) > 1:
        error("Only one payload option can be used at a time.")
    if evasion.active and tech.tcp in (TcpScanTechnique.CONNECT, TcpScanTechnique.AUTO) and not (
        tech.udp or tech.sctp or tech.ip_protocol
    ):
        warning(
            "Most evasion options only apply to raw packet scans; TCP connect scans ignore them.",
            "Select the SYN technique if you intend to use packet options.",
        )

    if config.network.send_ethernet and config.network.send_ip:
        error("Choose either raw Ethernet or raw IP sending, not both.")

    if config.network.ipv6:
        if tech.tcp == TcpScanTechnique.IDLE:
            error("Idle scan is not supported over IPv6.")
        if evasion.fragment_packets or evasion.decoys:
            warning("Fragmentation and decoys are not supported for IPv6 scans.")
        if config.discovery.icmp_timestamp or config.discovery.icmp_netmask:
            warning("ICMP timestamp and netmask probes do not exist in ICMPv6 and will be ignored.")

    return issues


def has_errors(issues: list[ValidationIssue]) -> bool:
    return any(issue.severity == "error" for issue in issues)


def issues_from_validation_error(exc: Exception) -> list[ValidationIssue]:
    """Translate a pydantic ValidationError into readable issues."""
    from pydantic import ValidationError

    if not isinstance(exc, ValidationError):
        return [ValidationIssue(severity="error", message=str(exc))]
    issues: list[ValidationIssue] = []
    for item in exc.errors():
        location = ".".join(str(part) for part in item.get("loc", ()))
        message = item.get("msg", "invalid value")
        if message.startswith("Value error, "):
            message = message[len("Value error, "):]
        issues.append(ValidationIssue(severity="error", message=f"{location}: {message}" if location else message))
    return issues

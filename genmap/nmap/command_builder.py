"""Translation of a ScanConfiguration into an Nmap argument list.

The builder never produces a shell string. It returns argument lists that
are handed to the process API directly, and separately reports which
arguments were added by Genmap itself so the command inspector can show
the person exactly what will run and why.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from genmap.core.scan_config import (
    ArpPingMode,
    DnsResolutionMode,
    PortSelectionMode,
    ScanConfiguration,
    ScanMode,
    SctpScanTechnique,
    TcpScanTechnique,
)
from genmap.nmap.arguments import review_arguments

_TCP_FLAGS = {
    TcpScanTechnique.SYN: "-sS",
    TcpScanTechnique.CONNECT: "-sT",
    TcpScanTechnique.ACK: "-sA",
    TcpScanTechnique.WINDOW: "-sW",
    TcpScanTechnique.MAIMON: "-sM",
    TcpScanTechnique.FIN: "-sF",
    TcpScanTechnique.NULL: "-sN",
    TcpScanTechnique.XMAS: "-sX",
}

_SCTP_FLAGS = {
    SctpScanTechnique.INIT: "-sY",
    SctpScanTechnique.COOKIE_ECHO: "-sZ",
}


@dataclass
class ManagedArgument:
    arguments: list[str]
    reason: str


@dataclass
class CommandPlan:
    program: Path
    user_arguments: list[str]
    managed_arguments: list[ManagedArgument]
    targets: list[str]
    warnings: list[str] = field(default_factory=list)
    working_directory: Optional[Path] = None

    @property
    def arguments(self) -> list[str]:
        managed = [arg for item in self.managed_arguments for arg in item.arguments]
        return self.user_arguments + managed + self.targets

    def display(self, *, program_name: Optional[str] = None) -> str:
        name = program_name or self.program.name
        return format_command([name] + self.arguments)

    def display_user_command(self) -> str:
        return format_command([self.program.name] + self.user_arguments + self.targets)


def format_command(parts: list[str]) -> str:
    """Render an argument list the way the current platform's shell would need it."""
    if sys.platform.startswith("win"):
        return subprocess.list2cmdline(parts)
    import shlex

    return shlex.join(parts)


def _quote_script_arg_value(value: str) -> str:
    if value == "":
        return '""'
    if any(c in value for c in ",{}=\"' "):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value


def build_user_arguments(config: ScanConfiguration) -> tuple[list[str], list[str]]:
    """Return (arguments, warnings) derived from the configuration.

    Targets are not included; ``build_targets`` handles those so callers can
    keep them at the end of the command line.
    """
    args: list[str] = []
    warnings: list[str] = []
    tech = config.techniques

    if tech.mode == ScanMode.LIST_ONLY:
        args.append("-sL")
    elif tech.mode == ScanMode.PING_ONLY:
        args.append("-sn")
    else:
        if tech.tcp == TcpScanTechnique.CUSTOM_FLAGS:
            args.extend(["--scanflags", tech.custom_tcp_flags or ""])
        elif tech.tcp == TcpScanTechnique.IDLE:
            args.extend(["-sI", tech.idle_zombie or ""])
        elif tech.tcp == TcpScanTechnique.FTP_BOUNCE:
            args.extend(["-b", tech.ftp_bounce_relay or ""])
        elif tech.tcp in _TCP_FLAGS:
            args.append(_TCP_FLAGS[tech.tcp])
        if tech.udp:
            args.append("-sU")
        if tech.sctp is not None:
            args.append(_SCTP_FLAGS[tech.sctp])
        if tech.ip_protocol:
            args.append("-sO")

        ports = config.ports
        if ports.mode == PortSelectionMode.SPECIFIC and ports.specification:
            args.extend(["-p", ports.specification])
        elif ports.mode == PortSelectionMode.TOP:
            args.extend(["--top-ports", str(ports.top_ports)])
        elif ports.mode == PortSelectionMode.FAST:
            args.append("-F")
        elif ports.mode == PortSelectionMode.ALL:
            args.append("-p-")
        if ports.exclude_ports:
            args.extend(["--exclude-ports", ports.exclude_ports])
        if ports.sequential:
            args.append("-r")

    disc = config.discovery
    if disc.skip_discovery:
        args.append("-Pn")
    else:
        if disc.icmp_echo:
            args.append("-PE")
        if disc.icmp_timestamp:
            args.append("-PP")
        if disc.icmp_netmask:
            args.append("-PM")
        if disc.tcp_syn_ports:
            args.append(f"-PS{disc.tcp_syn_ports}")
        if disc.tcp_ack_ports:
            args.append(f"-PA{disc.tcp_ack_ports}")
        if disc.udp_ports:
            args.append(f"-PU{disc.udp_ports}")
        if disc.sctp_ports:
            args.append(f"-PY{disc.sctp_ports}")
        if disc.ip_protocols:
            args.append(f"-PO{disc.ip_protocols}")
    if disc.arp_ping == ArpPingMode.DISABLED:
        args.append("--disable-arp-ping")
    if disc.traceroute:
        args.append("--traceroute")

    dns = config.dns
    if dns.resolution == DnsResolutionMode.ALWAYS:
        args.append("-R")
    elif dns.resolution == DnsResolutionMode.NEVER:
        args.append("-n")
    if dns.servers:
        args.extend(["--dns-servers", ",".join(dns.servers)])
    if dns.use_system_resolver:
        args.append("--system-dns")

    if config.aggressive:
        args.append("-A")
    svc = config.service_detection
    if svc.enabled and not config.aggressive:
        args.append("-sV")
    if svc.intensity is not None and (svc.enabled or config.aggressive):
        args.extend(["--version-intensity", str(svc.intensity)])
    if svc.trace:
        args.append("--version-trace")

    osd = config.os_detection
    if osd.enabled and not config.aggressive:
        args.append("-O")
    if osd.enabled or config.aggressive:
        if osd.limit_to_promising:
            args.append("--osscan-limit")
        if osd.guess_aggressively:
            args.append("--osscan-guess")
        if osd.max_tries is not None:
            args.extend(["--max-os-tries", str(osd.max_tries)])

    scripts = config.scripts
    if scripts.scripts:
        args.append("--script=" + ",".join(scripts.scripts))
    if scripts.arguments:
        rendered = ",".join(
            f"{arg.name}={_quote_script_arg_value(arg.value)}" if arg.value != "" else arg.name
            for arg in scripts.arguments
        )
        args.append("--script-args=" + rendered)
    if scripts.arguments_file:
        args.extend(["--script-args-file", scripts.arguments_file])
    if scripts.timeout:
        args.extend(["--script-timeout", scripts.timeout])
    if scripts.trace:
        args.append("--script-trace")
    if scripts.update_database:
        args.append("--script-updatedb")

    timing = config.timing
    if timing.template is not None:
        args.append(f"-T{timing.template}")
    for option, value in (
        ("--host-timeout", timing.host_timeout),
        ("--min-rtt-timeout", timing.min_rtt_timeout),
        ("--max-rtt-timeout", timing.max_rtt_timeout),
        ("--initial-rtt-timeout", timing.initial_rtt_timeout),
        ("--scan-delay", timing.scan_delay),
        ("--max-scan-delay", timing.max_scan_delay),
    ):
        if value:
            args.extend([option, value])
    for option, number in (
        ("--max-retries", timing.max_retries),
        ("--min-hostgroup", timing.min_hostgroup),
        ("--max-hostgroup", timing.max_hostgroup),
        ("--min-parallelism", timing.min_parallelism),
        ("--max-parallelism", timing.max_parallelism),
        ("--min-rate", timing.min_rate),
        ("--max-rate", timing.max_rate),
    ):
        if number is not None:
            args.extend([option, str(number)])
    if timing.defeat_rst_ratelimit:
        args.append("--defeat-rst-ratelimit")
    if timing.defeat_icmp_ratelimit:
        args.append("--defeat-icmp-ratelimit")
    if timing.nsock_engine:
        args.extend(["--nsock-engine", timing.nsock_engine])

    ev = config.evasion
    if ev.fragment_packets:
        args.extend(["-f"] * ev.fragment_packets)
    if ev.mtu is not None:
        args.extend(["--mtu", str(ev.mtu)])
    if ev.decoys:
        args.extend(["-D", ",".join(ev.decoys)])
    if ev.spoof_source:
        args.extend(["-S", ev.spoof_source])
    if ev.source_port is not None:
        args.extend(["-g", str(ev.source_port)])
    if ev.proxies:
        args.extend(["--proxies", ",".join(ev.proxies)])
    if ev.data_hex:
        args.extend(["--data", ev.data_hex])
    if ev.data_string:
        args.extend(["--data-string", ev.data_string])
    if ev.data_length is not None:
        args.extend(["--data-length", str(ev.data_length)])
    if ev.ip_options:
        args.extend(["--ip-options", ev.ip_options])
    if ev.ttl is not None:
        args.extend(["--ttl", str(ev.ttl)])
    if ev.spoof_mac:
        args.extend(["--spoof-mac", ev.spoof_mac])
    if ev.bad_checksum:
        args.append("--badsum")
    if ev.randomize_hosts:
        args.append("--randomize-hosts")
    if ev.adler32:
        args.append("--adler32")

    net = config.network
    if net.ipv6:
        args.append("-6")
    if net.interface:
        args.extend(["-e", net.interface])
    if net.send_ethernet:
        args.append("--send-eth")
    if net.send_ip:
        args.append("--send-ip")
    if net.privileged is True:
        args.append("--privileged")
    elif net.privileged is False:
        args.append("--unprivileged")

    out = config.output
    if out.verbosity:
        args.append("-" + "v" * out.verbosity)
    if out.debugging:
        args.append("-" + "d" * out.debugging)
    if out.packet_trace:
        args.append("--packet-trace")
    if out.show_reason:
        args.append("--reason")
    if out.open_only:
        args.append("--open")
    if out.stats_interval:
        args.extend(["--stats-every", out.stats_interval])

    if config.advanced_arguments.strip():
        review = review_arguments(config.advanced_arguments)
        args.extend(review.tokens)
        warnings.extend(review.warnings)

    return args, warnings


def build_targets(config: ScanConfiguration) -> list[str]:
    spec = config.targets
    args: list[str] = []
    if spec.exclusions:
        args.extend(["--exclude", ",".join(spec.exclusions)])
    if spec.exclude_file:
        args.extend(["--excludefile", spec.exclude_file])
    if spec.target_file:
        args.extend(["-iL", spec.target_file])
    if spec.random_targets:
        args.extend(["-iR", str(spec.random_targets)])
    args.extend(spec.targets)
    return args


def build_command_plan(
    program: Path,
    config: ScanConfiguration,
    *,
    xml_output: Optional[Path] = None,
    stats_interval: Optional[str] = None,
    noninteractive: bool = False,
    working_directory: Optional[Path] = None,
) -> CommandPlan:
    """Assemble the full plan including the arguments Genmap adds itself."""
    user_args, warnings = build_user_arguments(config)
    managed: list[ManagedArgument] = []
    if xml_output is not None:
        managed.append(ManagedArgument(["-oX", str(xml_output)], "Structured results are parsed from this XML file."))
    if stats_interval and not config.output.stats_interval:
        managed.append(
            ManagedArgument(
                ["--stats-every", stats_interval],
                "Periodic progress lines drive the live progress display.",
            )
        )
    if noninteractive:
        managed.append(
            ManagedArgument(["--noninteractive"], "Keeps Nmap from waiting on keyboard input.")
        )
    return CommandPlan(
        program=program,
        user_arguments=user_args,
        managed_arguments=managed,
        targets=build_targets(config),
        warnings=warnings,
        working_directory=working_directory,
    )

"""Extraction of live information from Nmap's text output.

Nmap prints progress only when asked (``--stats-every``) and per port
discoveries only at verbosity one or higher. Everything reported here comes
from those lines; nothing is estimated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

_STATS = re.compile(
    r"^Stats:\s+(?P<elapsed>\d+:\d{2}:\d{2}) elapsed;\s+(?P<completed>\d+) hosts completed "
    r"\((?P<up>\d+) up\),\s+(?P<undergoing>\d+) undergoing (?P<task>.+)$"
)
_TIMING = re.compile(
    r"^(?P<task>.+?) Timing:\s+About (?P<percent>\d+(?:\.\d+)?)% done(?:;\s+ETC:\s+(?P<etc>\d{1,2}:\d{2})"
    r"\s+\((?P<remaining>\d+:\d{2}:\d{2}) remaining\))?"
)
_DISCOVERED = re.compile(r"^Discovered (?P<state>open|closed|filtered|open\|filtered) port (?P<port>\d+)/(?P<proto>\w+) on (?P<host>\S+)$")
_REPORT = re.compile(r"^Nmap scan report for (?P<name>.+?)(?: \((?P<addr>[^)]+)\))?$")
_PORT_TABLE = re.compile(r"^(?P<port>\d+)/(?P<proto>tcp|udp|sctp|ip)\s+(?P<state>[a-z|]+)\s+(?P<service>\S+)")
_HOST_DOWN = re.compile(r"^Note: Host seems down|^Host .* seems down", re.IGNORECASE)
_HOST_UP = re.compile(r"^Host is up")
_DONE = re.compile(r"^Nmap done: (?P<addresses>\d+) IP address(?:es)? \((?P<up>\d+) hosts? up\) scanned in (?P<seconds>[\d.]+) seconds")
_WARNING_PREFIXES = ("WARNING:", "Warning:", "QUITTING!", "Failed to", "Error", "ERROR:", "RTTVAR has grown")

# Well known failure messages mapped to explanations a person can act on.
# Specific failure messages Nmap prints, mapped to explanations a person can
# act on. Patterns are anchored on Nmap's own wording so that script output or
# banners that merely mention a word like "Npcap" are not mistaken for errors.
_KNOWN_PROBLEMS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"requires root privileges|requires? (?:administrator|admin) privileges|You requested a scan type which requires", re.I),
        "This scan type needs elevated privileges.",
        "Run Genmap as Administrator (or root) or switch to a TCP connect scan.",
    ),
    (
        re.compile(
            r"^dnet: Failed to open device|^Failed to open device|pcap_open_live\(|"
            r"Could not import all necessary Npcap functions|^Npcap is not installed|WinPcap is not installed",
            re.I,
        ),
        "Nmap could not open a network interface for raw packet access.",
        "Check that Npcap is installed and its service is running, and that the selected interface exists.",
    ),
    (
        re.compile(r"^Failed to resolve \"", re.I),
        "One or more target names could not be resolved.",
        "Check the spelling of the hostname and your DNS settings.",
    ),
    (
        re.compile(r"^Your port specifications are illegal|Ports specified must be between|^Found no matches for the service mask|Illegal port", re.I),
        "Nmap rejected the port specification.",
        "Review the ports on the Ports tab.",
    ),
    (
        re.compile(r"failed to initialize the script engine|' did not match a category, filename, or directory", re.I),
        "Nmap could not load one of the requested scripts.",
        "Check the script names and categories on the Scripts tab.",
    ),
    (
        re.compile(r": unrecognized option '|: option '?[-\w]+'? requires an argument|^Invalid argument to|requires a positive", re.I),
        "Nmap did not understand one of the arguments.",
        "Review the advanced arguments; the installed Nmap version may not support them.",
    ),
    (
        re.compile(r"Only ethernet devices can be used for raw scans", re.I),
        "The selected interface cannot be used for raw packet scans.",
        "Choose an Ethernet interface, or use --unprivileged or a TCP connect scan.",
    ),
]


@dataclass(frozen=True)
class TaskProgress:
    task: str
    percent: float
    etc: Optional[str] = None
    remaining: Optional[str] = None


@dataclass(frozen=True)
class StatsLine:
    elapsed: str
    hosts_completed: int
    hosts_up: int
    hosts_undergoing: int
    task: str


@dataclass(frozen=True)
class DiscoveredPort:
    host: str
    port: int
    protocol: str
    state: str


@dataclass(frozen=True)
class ProblemHint:
    message: str
    remedy: str
    source_line: str


@dataclass
class LiveScanState:
    hosts_reported: list[str] = field(default_factory=list)
    hosts_up: int = 0
    ports: list[DiscoveredPort] = field(default_factory=list)
    services: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    problems: list[ProblemHint] = field(default_factory=list)
    progress: Optional[TaskProgress] = None
    stats: Optional[StatsLine] = None
    done_line: Optional[str] = None

    @property
    def open_port_count(self) -> int:
        return sum(1 for p in self.ports if p.state == "open")


class OutputMonitor:
    """Feeds Nmap output lines and accumulates a LiveScanState."""

    def __init__(self) -> None:
        self.state = LiveScanState()
        self._seen_ports: set[tuple[str, int, str]] = set()

    def feed(self, line: str) -> Optional[str]:
        """Process one line. Returns a short event name when something notable was parsed."""
        text = line.rstrip("\r\n")
        stripped = text.strip()
        if not stripped:
            return None

        match = _TIMING.match(stripped)
        if match:
            self.state.progress = TaskProgress(
                task=match.group("task"),
                percent=float(match.group("percent")),
                etc=match.group("etc"),
                remaining=match.group("remaining"),
            )
            return "progress"

        match = _STATS.match(stripped)
        if match:
            self.state.stats = StatsLine(
                elapsed=match.group("elapsed"),
                hosts_completed=int(match.group("completed")),
                hosts_up=int(match.group("up")),
                hosts_undergoing=int(match.group("undergoing")),
                task=match.group("task"),
            )
            self.state.hosts_up = max(self.state.hosts_up, self.state.stats.hosts_up)
            return "stats"

        match = _DISCOVERED.match(stripped)
        if match:
            key = (match.group("host"), int(match.group("port")), match.group("proto"))
            if key not in self._seen_ports:
                self._seen_ports.add(key)
                self.state.ports.append(
                    DiscoveredPort(key[0], key[1], key[2], match.group("state"))
                )
            return "port"

        match = _REPORT.match(stripped)
        if match:
            name = match.group("addr") or match.group("name")
            if name not in self.state.hosts_reported:
                self.state.hosts_reported.append(name)
            return "host"

        if _HOST_UP.match(stripped):
            return "host_up"

        match = _PORT_TABLE.match(stripped)
        if match:
            service = match.group("service")
            # Nmap marks uncertain names with "?"; those are not identifications.
            if match.group("state") == "open" and service != "unknown" and not service.endswith("?"):
                if service not in self.state.services:
                    self.state.services.add(service)
                    return "service"
            return None

        match = _DONE.match(stripped)
        if match:
            self.state.done_line = stripped
            self.state.hosts_up = max(self.state.hosts_up, int(match.group("up")))
            return "done"

        for pattern, message, remedy in _KNOWN_PROBLEMS:
            if pattern.search(stripped):
                if not any(p.message == message for p in self.state.problems):
                    self.state.problems.append(ProblemHint(message, remedy, stripped))
                self.state.warnings.append(stripped)
                return "problem"

        if stripped.startswith(_WARNING_PREFIXES):
            self.state.warnings.append(stripped)
            return "warning"
        return None

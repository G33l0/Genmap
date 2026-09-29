"""Comparison of two scans.

Every reported change rests on what Nmap reported in each scan. Genmap only
decides what is comparable, and it is conservative about that:

* A host counts as new or missing only if the other scan's targets covered
  its address. Otherwise it is noted as outside the other scan's scope.
* A port counts as opened or no longer open only if both scans probed that
  port. Nmap records the probed ports in its scaninfo element.
* Service and version changes are reported only when both scans identified
  the service by probing; names from Nmap's port table are never compared
  against probed names as if they were findings.
* Script output is compared with timestamps and durations masked, so
  scripts that print the current time do not change on every run.

Each change carries the values Nmap reported (``before`` and ``after``) and,
separately, Genmap's reading of what the difference could mean.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

from genmap.core.ports import parse_port_specification
from genmap.core.results import Host, Port, ScanResult
from genmap.core.targets import address_in_scope
from genmap.errors import GenmapError


class ChangeKind(str, Enum):
    HOST_NEW = "host_new"
    HOST_MISSING = "host_missing"
    HOST_STATE = "host_state"
    HOST_OUT_OF_SCOPE = "host_out_of_scope"
    PORT_OPENED = "port_opened"
    PORT_NO_LONGER_OPEN = "port_no_longer_open"
    PORT_STATE = "port_state"
    PORT_NOT_COVERED = "port_not_covered"
    SERVICE_CHANGED = "service_changed"
    VERSION_CHANGED = "version_changed"
    SERVICE_UNCONFIRMED = "service_unconfirmed"
    OS_CHANGED = "os_changed"
    MAC_CHANGED = "mac_changed"
    HOSTNAME_CHANGED = "hostname_changed"
    SCRIPT_ADDED = "script_added"
    SCRIPT_REMOVED = "script_removed"
    SCRIPT_CHANGED = "script_changed"


CHANGE_LABELS = {
    ChangeKind.HOST_NEW: "New host",
    ChangeKind.HOST_MISSING: "Host not seen",
    ChangeKind.HOST_STATE: "Host state changed",
    ChangeKind.HOST_OUT_OF_SCOPE: "Outside the other scan's targets",
    ChangeKind.PORT_OPENED: "Port newly open",
    ChangeKind.PORT_NO_LONGER_OPEN: "Port no longer open",
    ChangeKind.PORT_STATE: "Port state changed",
    ChangeKind.PORT_NOT_COVERED: "Port not probed in both scans",
    ChangeKind.SERVICE_CHANGED: "Service changed",
    ChangeKind.VERSION_CHANGED: "Version changed",
    ChangeKind.SERVICE_UNCONFIRMED: "Service identified in one scan only",
    ChangeKind.OS_CHANGED: "OS guess changed",
    ChangeKind.MAC_CHANGED: "MAC address changed",
    ChangeKind.HOSTNAME_CHANGED: "Hostname changed",
    ChangeKind.SCRIPT_ADDED: "Script output added",
    ChangeKind.SCRIPT_REMOVED: "Script output gone",
    ChangeKind.SCRIPT_CHANGED: "Script output changed",
}

# Informational kinds explain why something was not compared; they are not changes.
INFORMATIONAL = frozenset({ChangeKind.HOST_OUT_OF_SCOPE, ChangeKind.PORT_NOT_COVERED, ChangeKind.SERVICE_UNCONFIRMED})


@dataclass(frozen=True)
class Change:
    kind: ChangeKind
    address: str
    subject: str
    before: Optional[str]
    after: Optional[str]
    reading: str

    @property
    def significant(self) -> bool:
        return self.kind not in INFORMATIONAL

    @property
    def label(self) -> str:
        return CHANGE_LABELS[self.kind]


@dataclass
class HostComparison:
    address: str
    name: str
    status: str  # new, missing, changed, unchanged, out_of_scope
    changes: list[Change] = field(default_factory=list)

    @property
    def significant_changes(self) -> list[Change]:
        return [c for c in self.changes if c.significant]


@dataclass
class ScanSide:
    """One scan plus the targets it was asked to cover, when known."""

    result: ScanResult
    label: str
    targets: Optional[list[str]] = None
    exclusions: list[str] = field(default_factory=list)


@dataclass
class ComparisonResult:
    baseline_label: str
    current_label: str
    hosts: list[HostComparison]
    notes: list[str]

    def changes(self, *, include_informational: bool = False) -> list[Change]:
        return [c for h in self.hosts for c in h.changes if include_informational or c.significant]

    def count(self, kind: ChangeKind) -> int:
        return sum(1 for c in self.changes(include_informational=True) if c.kind == kind)

    @property
    def has_changes(self) -> bool:
        return bool(self.changes())


# Helpers -------------------------------------------------------------------------

_VOLATILE = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\s+\w+)?"),
    re.compile(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}(?:\s+\d{4})?"),
    re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b"),
    re.compile(r"\b\d+(?:\.\d+)?\s*(?:ms|s|sec|seconds?|minutes?|hours?|days?)\b", re.I),
    re.compile(r"clock-skew:[^\n]*", re.I),
    re.compile(r"\b\d{9,}\b"),
]


def mask_volatile(text: str) -> str:
    """Normalise output so that timestamps and durations do not count as changes."""
    masked = text
    for pattern in _VOLATILE:
        masked = pattern.sub("#", masked)
    return "\n".join(line.rstrip() for line in masked.strip().splitlines())


def covered_ports(result: ScanResult) -> dict[str, set[int]]:
    """Ports each protocol was probed on, from Nmap's scaninfo."""
    covered: dict[str, set[int]] = {}
    for info in result.scan_infos:
        if not info.services:
            continue
        protocol = "ip" if info.protocol == "ip" else info.protocol
        try:
            parsed = parse_port_specification(info.services, protocol_scan=protocol == "ip")
        except GenmapError:
            continue
        ports = covered.setdefault(protocol, set())
        for r in parsed.ranges:
            ports.update(range(r.start, r.end + 1))
    return covered


def _host_key(host: Host) -> Optional[str]:
    return host.primary_address or (host.mac_address.address if host.mac_address else None)


def _port_map(host: Host) -> dict[tuple[str, int], Port]:
    return {(p.protocol, p.port_id): p for p in host.ports}


def _service_text(port: Port) -> str:
    service = port.service
    if service is None:
        return ""
    parts = [f"{service.tunnel}/{service.name}" if service.tunnel and service.name else (service.name or "")]
    detail = " ".join(p for p in (service.product, service.version, service.extra_info) if p)
    return " ".join(p for p in (parts[0], f"({detail})" if detail else "") if p).strip()


def _not_listed_state(host: Host) -> str:
    states = sorted({x.state for x in host.extra_ports})
    if len(states) == 1:
        return f"{states[0]} (among {sum(x.count for x in host.extra_ports)} ports Nmap did not list)"
    return "closed or filtered (not listed individually)"


def _in_scope(side: ScanSide, host: Host) -> Optional[bool]:
    if side.targets is None:
        return None
    address = _host_key(host)
    if address is None:
        return None
    return address_in_scope(address, side.targets, side.exclusions, [h.name for h in host.hostnames])


def _has_scripts(result: ScanResult) -> bool:
    return bool(result.pre_scripts or result.post_scripts or any(h.host_scripts or any(p.scripts for p in h.ports) for h in result.hosts))


def _script_map(host: Host) -> dict[tuple[str, str], str]:
    mapping = {("host", s.script_id): s.output for s in host.host_scripts}
    for port in host.ports:
        for script in port.scripts:
            mapping[(port.label, script.script_id)] = script.output
    return mapping


# Comparison ------------------------------------------------------------------------


def _compare_ports(address: str, old: Host, new: Host, old_cov: dict[str, set[int]], new_cov: dict[str, set[int]]) -> list[Change]:
    changes: list[Change] = []
    old_ports, new_ports = _port_map(old), _port_map(new)
    for key in sorted(set(old_ports) | set(new_ports), key=lambda k: (k[0], k[1])):
        protocol, number = key
        label = f"{number}/{protocol}"
        before, after = old_ports.get(key), new_ports.get(key)
        if before is not None and after is not None:
            if before.state != after.state:
                if after.state == "open":
                    kind, reading = ChangeKind.PORT_OPENED, "Nmap now reports this port open; before it reported it " + before.state + "."
                elif before.state == "open":
                    kind, reading = ChangeKind.PORT_NO_LONGER_OPEN, "Nmap no longer reports this port open. A service may have stopped or a filter may now block it."
                else:
                    kind, reading = ChangeKind.PORT_STATE, "Nmap reports a different state for this port."
                changes.append(Change(kind, address, label, before.state, after.state, reading))
            if before.state == "open" and after.state == "open":
                changes.extend(_compare_service(address, label, before, after))
            continue
        port = before or after
        was_open = port.state == "open"
        if before is not None:
            # Listed before, not listed now.
            if number in new_cov.get(protocol, set()):
                if was_open:
                    changes.append(Change(
                        ChangeKind.PORT_NO_LONGER_OPEN, address, label, "open", _not_listed_state(new),
                        "The newer scan probed this port but did not list it, so Nmap found it closed or filtered.",
                    ))
            elif was_open:
                changes.append(Change(
                    ChangeKind.PORT_NOT_COVERED, address, label, "open", "not probed",
                    "The newer scan did not probe this port, so nothing can be said about it.",
                ))
        else:
            if number in old_cov.get(protocol, set()):
                if was_open:
                    changes.append(Change(
                        ChangeKind.PORT_OPENED, address, label, _not_listed_state(old), "open",
                        "The baseline scan probed this port and did not find it open.",
                    ))
            elif was_open:
                changes.append(Change(
                    ChangeKind.PORT_NOT_COVERED, address, label, "not probed", "open",
                    "The baseline scan did not probe this port, so this may not be new.",
                ))
    return changes


def _compare_service(address: str, label: str, before: Port, after: Port) -> list[Change]:
    old, new = before.service, after.service
    if old is None or new is None:
        return []
    if old.is_probed and new.is_probed:
        if (old.name, old.product, old.tunnel) != (new.name, new.product, new.tunnel):
            return [Change(ChangeKind.SERVICE_CHANGED, address, label, _service_text(before), _service_text(after),
                           "Version detection identified a different service or product on this port.")]
        if (old.version, old.extra_info) != (new.version, new.extra_info):
            return [Change(ChangeKind.VERSION_CHANGED, address, label, _service_text(before), _service_text(after),
                           "Same product, different version details. Software may have been updated or reconfigured.")]
        return []
    if old.is_probed != new.is_probed and (old.name or "") != (new.name or ""):
        return [Change(ChangeKind.SERVICE_UNCONFIRMED, address, label, _service_text(before), _service_text(after),
                       "Only one scan identified this service by probing; the other name comes from Nmap's port table, so they are not comparable.")]
    return []


def _compare_host(address: str, old: Host, new: Host, old_cov, new_cov, compare_scripts: bool) -> list[Change]:
    changes: list[Change] = []
    if old.status.state != new.status.state:
        changes.append(Change(ChangeKind.HOST_STATE, address, "host", old.status.state, new.status.state,
                              "Nmap reports a different host state." + (" The host may be offline, or discovery probes may now be filtered." if new.status.state != "up" else "")))
    old_mac, new_mac = old.mac_address, new.mac_address
    if old_mac and new_mac and old_mac.address.lower() != new_mac.address.lower():
        changes.append(Change(ChangeKind.MAC_CHANGED, address, "MAC",
                              f"{old_mac.address} {old_mac.vendor or ''}".strip(), f"{new_mac.address} {new_mac.vendor or ''}".strip(),
                              "A different network adapter answered at this address; it may be a different device."))
    old_names = sorted({h.name.lower() for h in old.hostnames if h.hostname_type != "user"})
    new_names = sorted({h.name.lower() for h in new.hostnames if h.hostname_type != "user"})
    if old_names and new_names and old_names != new_names:
        changes.append(Change(ChangeKind.HOSTNAME_CHANGED, address, "hostname", ", ".join(old_names), ", ".join(new_names),
                              "Reverse DNS returned different names."))
    if old.is_up and new.is_up:
        changes.extend(_compare_ports(address, old, new, old_cov, new_cov))
        old_os, new_os = old.best_os_match, new.best_os_match
        if old_os and new_os and old_os.name != new_os.name:
            changes.append(Change(ChangeKind.OS_CHANGED, address, "OS",
                                  f"{old_os.name} ({old_os.accuracy}%)", f"{new_os.name} ({new_os.accuracy}%)",
                                  "Nmap's best OS guess differs. OS detection is a fingerprint match, so small differences between runs are common."))
        if compare_scripts:
            changes.extend(_compare_scripts(address, old, new))
    return changes


def _compare_scripts(address: str, old: Host, new: Host) -> list[Change]:
    changes: list[Change] = []
    before, after = _script_map(old), _script_map(new)
    old_ports = {p.label for p in old.ports if p.state == "open"}
    new_ports = {p.label for p in new.ports if p.state == "open"}
    for key in sorted(set(before) | set(after)):
        where, script_id = key
        subject = f"{script_id} on {where}" if where != "host" else script_id
        if key in before and key in after:
            if mask_volatile(before[key]) != mask_volatile(after[key]):
                changes.append(Change(ChangeKind.SCRIPT_CHANGED, address, subject, before[key], after[key],
                                      "The script reported different output. Timestamps and durations are ignored in this comparison."))
        elif where != "host" and (where not in old_ports or where not in new_ports):
            continue  # the port itself changed; that is reported already
        elif key in after:
            changes.append(Change(ChangeKind.SCRIPT_ADDED, address, subject, None, after[key], "The script produced output only in the newer scan."))
        else:
            changes.append(Change(ChangeKind.SCRIPT_REMOVED, address, subject, before[key], None, "The script produced output only in the baseline scan."))
    return changes


def compare_scans(baseline: ScanSide, current: ScanSide) -> ComparisonResult:
    old_cov, new_cov = covered_ports(baseline.result), covered_ports(current.result)
    notes: list[str] = []
    old_version, new_version = baseline.result.nmap_version, current.result.nmap_version
    if old_version and new_version and old_version != new_version:
        notes.append(f"The scans used different Nmap versions ({old_version} and {new_version}); service and OS databases may differ.")
    old_types = sorted({(i.scan_type, i.protocol) for i in baseline.result.scan_infos})
    new_types = sorted({(i.scan_type, i.protocol) for i in current.result.scan_infos})
    if old_types != new_types:
        fmt = lambda items: ", ".join(f"{t} ({p})" for t, p in items) or "none"  # noqa: E731
        notes.append(f"Scan techniques differ: baseline {fmt(old_types)}, newer {fmt(new_types)}.")
    for protocol in sorted(set(old_cov) | set(new_cov)):
        a, b = old_cov.get(protocol, set()), new_cov.get(protocol, set())
        if a != b:
            notes.append(f"The scans probed different {protocol.upper()} ports ({len(a)} and {len(b)}); only ports probed by both are compared.")
    if not old_cov or not new_cov:
        notes.append("At least one scan did not scan ports, so port differences are not reported.")
    compare_scripts = _has_scripts(baseline.result) and _has_scripts(current.result)
    if _has_scripts(baseline.result) != _has_scripts(current.result):
        notes.append("Only one of the scans produced NSE output, so script output is not compared.")
    if baseline.targets is None or current.targets is None:
        notes.append("The target list of at least one scan is unknown, so hosts seen in only one scan cannot be checked against the other scan's scope.")
    elif sorted(baseline.targets) != sorted(current.targets) or sorted(baseline.exclusions) != sorted(current.exclusions):
        notes.append("The scans had different targets; hosts outside the other scan's targets are listed separately and not counted as changes.")

    old_hosts = {k: h for h in baseline.result.hosts if (k := _host_key(h))}
    new_hosts = {k: h for h in current.result.hosts if (k := _host_key(h))}
    comparisons: list[HostComparison] = []
    for address in sorted(set(old_hosts) | set(new_hosts), key=_address_sort_key):
        old, new = old_hosts.get(address), new_hosts.get(address)
        name = (new or old).display_name
        if old is not None and new is not None:
            changes = _compare_host(address, old, new, old_cov, new_cov, compare_scripts)
            significant = any(c.significant for c in changes)
            if not old.is_up and not new.is_up:
                continue
            comparisons.append(HostComparison(address, name, "changed" if significant else "unchanged", changes))
        elif new is not None:
            if not new.is_up:
                continue
            scope = _in_scope(baseline, new)
            if scope is False:
                comparisons.append(HostComparison(address, name, "out_of_scope", [Change(
                    ChangeKind.HOST_OUT_OF_SCOPE, address, "host", "not a baseline target", "up",
                    "The baseline scan did not target this address, so it cannot be called new.")]))
            else:
                reading = "Nmap did not report this host up in the baseline scan."
                if scope is None:
                    reading += " The baseline's targets could not be checked, so it may simply not have been scanned."
                comparisons.append(HostComparison(address, name, "new", [Change(ChangeKind.HOST_NEW, address, "host", "not seen", "up", reading)]))
        else:
            if not old.is_up:
                continue
            scope = _in_scope(current, old)
            if scope is False:
                comparisons.append(HostComparison(address, name, "out_of_scope", [Change(
                    ChangeKind.HOST_OUT_OF_SCOPE, address, "host", "up", "not a newer target",
                    "The newer scan did not target this address, so it cannot be called missing.")]))
            else:
                reading = "Nmap did not report this host up in the newer scan. It may be offline, or its responses may now be filtered."
                if scope is None:
                    reading += " The newer scan's targets could not be checked, so it may simply not have been scanned."
                comparisons.append(HostComparison(address, name, "missing", [Change(ChangeKind.HOST_MISSING, address, "host", "up", "not seen", reading)]))
    return ComparisonResult(baseline.label, current.label, comparisons, notes)


def _address_sort_key(address: str) -> tuple:
    import ipaddress

    try:
        ip = ipaddress.ip_address(address)
        return (ip.version, int(ip))
    except ValueError:
        return (9, address)


def summarize(result: ComparisonResult) -> dict[str, int]:
    return {
        "new_hosts": sum(1 for h in result.hosts if h.status == "new"),
        "missing_hosts": sum(1 for h in result.hosts if h.status == "missing"),
        "changed_hosts": sum(1 for h in result.hosts if h.status == "changed"),
        "unchanged_hosts": sum(1 for h in result.hosts if h.status == "unchanged"),
        "out_of_scope_hosts": sum(1 for h in result.hosts if h.status == "out_of_scope"),
        "ports_opened": result.count(ChangeKind.PORT_OPENED),
        "ports_no_longer_open": result.count(ChangeKind.PORT_NO_LONGER_OPEN),
        "service_changes": result.count(ChangeKind.SERVICE_CHANGED) + result.count(ChangeKind.VERSION_CHANGED),
        "os_changes": result.count(ChangeKind.OS_CHANGED),
        "script_changes": result.count(ChangeKind.SCRIPT_CHANGED) + result.count(ChangeKind.SCRIPT_ADDED) + result.count(ChangeKind.SCRIPT_REMOVED),
    }


def side_from(result: ScanResult, label: str, configuration: Optional[dict] = None) -> ScanSide:
    """Build a ScanSide, taking the target list from a stored configuration when available."""
    targets: Optional[list[str]] = None
    exclusions: list[str] = []
    if configuration:
        spec = configuration.get("targets", {}) if isinstance(configuration, dict) else {}
        if spec.get("target_file") or spec.get("random_targets"):
            targets = None
        else:
            targets = list(spec.get("targets", []))
            exclusions = list(spec.get("exclusions", []))
    return ScanSide(result=result, label=label, targets=targets, exclusions=exclusions)


def iter_significant(result: ComparisonResult) -> Iterable[Change]:
    return (c for c in result.changes() if c.significant)

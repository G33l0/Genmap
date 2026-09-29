"""Topology graph assembled from Nmap traceroute data."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

from genmap.core.results import Host, ScanResult

ORIGIN_KEY = "origin"


class NodeKind(str, Enum):
    ORIGIN = "origin"
    ROUTER = "router"
    TARGET = "target"
    NO_REPLY = "no_reply"


class EdgeKind(str, Enum):
    ROUTE = "route"            # consecutive hops Nmap recorded
    GAP = "gap"                # to or from hops that did not reply
    INCOMPLETE = "incomplete"  # the trace stopped before reaching the host
    SCANNED = "scanned"        # a scan target with no route recorded


NODE_LABELS = {
    NodeKind.ORIGIN: "Scan origin",
    NodeKind.ROUTER: "Router on a traced path",
    NodeKind.TARGET: "Scanned host",
    NodeKind.NO_REPLY: "Hops that did not reply",
}

EDGE_LABELS = {
    EdgeKind.ROUTE: "Consecutive traceroute hops",
    EdgeKind.GAP: "Path through hops that did not reply",
    EdgeKind.INCOMPLETE: "Trace ended before this host; the remaining path is unknown",
    EdgeKind.SCANNED: "Scanned without a traceroute; the path is unknown",
}


@dataclass
class TopologySource:
    result: ScanResult
    label: str
    run_id: Optional[str] = None


@dataclass
class HopObservation:
    source: str
    traced_host: str
    ttl: int
    rtt: Optional[float]


@dataclass
class TopologyNode:
    key: str
    kind: NodeKind
    address: Optional[str] = None
    hostnames: set[str] = field(default_factory=set)
    depth: int = 0
    sources: set[str] = field(default_factory=set)
    observations: list[HopObservation] = field(default_factory=list)
    target_summaries: dict[str, str] = field(default_factory=dict)  # source label -> summary
    relays: bool = False
    ttl_range: Optional[tuple[int, int]] = None  # for NO_REPLY nodes
    traced_host: Optional[str] = None            # for NO_REPLY nodes

    @property
    def label(self) -> str:
        if self.kind == NodeKind.ORIGIN:
            return "Scan origin"
        if self.kind == NodeKind.NO_REPLY and self.ttl_range:
            start, end = self.ttl_range
            return f"No reply (TTL {start})" if start == end else f"No reply (TTL {start} to {end})"
        return self.address or self.key

    @property
    def hostname(self) -> Optional[str]:
        return sorted(self.hostnames)[0] if self.hostnames else None

    @property
    def is_target(self) -> bool:
        return self.kind == NodeKind.TARGET


@dataclass
class TopologyEdge:
    source: str
    target: str
    kind: EdgeKind
    sources: set[str] = field(default_factory=set)
    traced_hosts: set[str] = field(default_factory=set)

    @property
    def key(self) -> tuple[str, str]:
        return (self.source, self.target)


@dataclass
class TopologyGraph:
    nodes: dict[str, TopologyNode]
    edges: dict[tuple[str, str], TopologyEdge]
    source_labels: list[str]
    traced_hosts: set[str]
    untraced_hosts: set[str]
    notes: list[str]

    def node(self, key: str) -> Optional[TopologyNode]:
        return self.nodes.get(key)

    def neighbours(self, key: str) -> tuple[list[TopologyNode], list[TopologyNode]]:
        before = [self.nodes[e.source] for e in self.edges.values() if e.target == key]
        after = [self.nodes[e.target] for e in self.edges.values() if e.source == key]
        return before, after

    def count(self, kind: NodeKind) -> int:
        return sum(1 for n in self.nodes.values() if n.kind == kind)

    @property
    def has_routes(self) -> bool:
        return bool(self.traced_hosts)

    def to_dict(self) -> dict:
        return {
            "sources": self.source_labels,
            "notes": self.notes,
            "nodes": [
                {
                    "id": node.key,
                    "kind": node.kind.value,
                    "address": node.address,
                    "hostnames": sorted(node.hostnames),
                    "depth": node.depth,
                    "relays_traffic": node.relays,
                    "ttl_range": list(node.ttl_range) if node.ttl_range else None,
                    "scans": sorted(node.sources),
                    "hops": [
                        {"scan": o.source, "traced_host": o.traced_host, "ttl": o.ttl, "rtt_ms": o.rtt}
                        for o in node.observations
                    ],
                    "target_summaries": node.target_summaries,
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "from": edge.source,
                    "to": edge.target,
                    "kind": edge.kind.value,
                    "meaning": EDGE_LABELS[edge.kind],
                    "scans": sorted(edge.sources),
                    "traced_hosts": sorted(edge.traced_hosts, key=address_sort_key),
                }
                for edge in self.edges.values()
            ],
        }


def address_sort_key(address: Optional[str]) -> tuple:
    if not address:
        return (9, "")
    try:
        ip = ipaddress.ip_address(address)
        return (ip.version, int(ip), "")
    except ValueError:
        return (8, 0, address)


def _target_summary(host: Host) -> str:
    parts = [f"{len(host.open_ports)} open port{'s' if len(host.open_ports) != 1 else ''}"]
    best = host.best_os_match
    if best is not None:
        parts.append(f"OS guess {best.name} ({best.accuracy}%)")
    if host.mac_address is not None:
        mac = host.mac_address
        parts.append(f"MAC {mac.address}" + (f" ({mac.vendor})" if mac.vendor else ""))
    return ", ".join(parts)


class _Builder:
    def __init__(self) -> None:
        self.nodes: dict[str, TopologyNode] = {
            ORIGIN_KEY: TopologyNode(ORIGIN_KEY, NodeKind.ORIGIN, depth=0),
        }
        self.edges: dict[tuple[str, str], TopologyEdge] = {}
        self.traced: set[str] = set()
        self.untraced: set[str] = set()
        self._gap_counter = 0
        self.fallback_depth: dict[str, int] = {}

    def ip_node(self, address: str, fallback_depth: Optional[int] = None) -> TopologyNode:
        key = f"ip:{address}"
        node = self.nodes.get(key)
        if node is None:
            node = self.nodes[key] = TopologyNode(key, NodeKind.ROUTER, address=address)
        if fallback_depth is not None:
            self.fallback_depth[key] = min(self.fallback_depth.get(key, fallback_depth), fallback_depth)
        return node

    def finish_depths(self) -> None:
        # A recorded TTL always wins; hosts reached only by an incomplete trace sit
        # one step past its last hop, and untraced hosts sit next to the origin.
        for key, node in self.nodes.items():
            if node.observations:
                node.depth = min(o.ttl for o in node.observations)
            elif key in self.fallback_depth:
                node.depth = self.fallback_depth[key]
            elif node.kind == NodeKind.TARGET:
                node.depth = 1

    def edge(self, a: str, b: str, kind: EdgeKind, source: str, traced_host: Optional[str]) -> None:
        if a == b:
            return
        edge = self.edges.get((a, b))
        if edge is None:
            edge = self.edges[(a, b)] = TopologyEdge(a, b, kind)
        elif _EDGE_RANK[kind] < _EDGE_RANK[edge.kind]:
            edge.kind = kind
        edge.sources.add(source)
        if traced_host:
            edge.traced_hosts.add(traced_host)

    def gap(self, source: str, traced_host: str, start: int, end: int) -> TopologyNode:
        # Silent hops are never merged: two paths that both lose a reply at the
        # same TTL are not evidence that they pass the same router.
        self._gap_counter += 1
        key = f"gap:{self._gap_counter}"
        node = TopologyNode(key, NodeKind.NO_REPLY, depth=start, ttl_range=(start, end), traced_host=traced_host)
        node.sources.add(source)
        self.nodes[key] = node
        return node

    def add_host(self, source: TopologySource, host: Host) -> None:
        address = host.primary_address
        if address is None or not host.is_up:
            return
        label = source.label
        hops = sorted({h.ttl: h for h in (host.traceroute.hops if host.traceroute else []) if h.ttl > 0 and h.ip_address}.values(),
                      key=lambda h: h.ttl)
        target = self.ip_node(address, hops[-1].ttl + 1 if hops and hops[-1].ip_address != address else None)
        target.kind = NodeKind.TARGET
        target.sources.add(label)
        target.hostnames.update(h.name for h in host.hostnames if h.name)
        target.target_summaries[label] = _target_summary(host)
        if not hops:
            self.untraced.add(address)
            self.edge(ORIGIN_KEY, target.key, EdgeKind.SCANNED, label, None)
            return
        self.traced.add(address)
        previous, previous_ttl = ORIGIN_KEY, 0
        for hop in hops:
            if hop.ttl > previous_ttl + 1:
                silent = self.gap(label, address, previous_ttl + 1, hop.ttl - 1)
                self.edge(previous, silent.key, EdgeKind.GAP, label, address)
                previous = silent.key
                kind = EdgeKind.GAP
            else:
                kind = EdgeKind.ROUTE
            node = self.ip_node(hop.ip_address)
            node.sources.add(label)
            node.observations.append(HopObservation(label, address, hop.ttl, hop.rtt))
            if hop.hostname:
                node.hostnames.add(hop.hostname)
            if hop.ip_address != address:
                node.relays = True
            self.edge(previous, node.key, kind, label, address)
            previous, previous_ttl = node.key, hop.ttl
        if hops[-1].ip_address != address:
            self.edge(previous, target.key, EdgeKind.INCOMPLETE, label, address)


_EDGE_RANK = {EdgeKind.ROUTE: 0, EdgeKind.GAP: 1, EdgeKind.INCOMPLETE: 2, EdgeKind.SCANNED: 3}


def build_topology(sources: Iterable[TopologySource], *, include_untraced: bool = True) -> TopologyGraph:
    sources = list(sources)
    builder = _Builder()
    for source in sources:
        for host in source.result.hosts:
            builder.add_host(source, host)

    builder.finish_depths()
    # A host traced in one scan and not in another keeps only its route.
    routed = {e.target for e in builder.edges.values() if e.kind != EdgeKind.SCANNED}
    for key in [k for k, e in builder.edges.items() if e.kind == EdgeKind.SCANNED and e.target in routed]:
        del builder.edges[key]
    untraced = {a for a in builder.untraced if f"ip:{a}" not in routed}
    if not include_untraced:
        for key in [k for k, e in builder.edges.items() if e.kind == EdgeKind.SCANNED]:
            del builder.edges[key]
        for address in untraced:
            builder.nodes.pop(f"ip:{address}", None)

    notes: list[str] = []
    if len(sources) > 1:
        notes.append(
            "Several scans are drawn from one scan origin. If they were run from different computers or networks, "
            "their paths start from different places."
        )
    if untraced:
        notes.append(
            f"{len(untraced)} scanned host{'s have' if len(untraced) != 1 else ' has'} no route data. "
            "Enable 'Trace the network path' on the Discovery tab (--traceroute) to record paths."
        )
    if any(n.kind == NodeKind.NO_REPLY for n in builder.nodes.values()):
        notes.append("Some hops did not reply to Nmap's probes. Each silent stretch is drawn separately because it is unknown which router it was.")
    return TopologyGraph(
        nodes=builder.nodes,
        edges=builder.edges,
        source_labels=[s.label for s in sources],
        traced_hosts=builder.traced,
        untraced_hosts=untraced,
        notes=notes,
    )

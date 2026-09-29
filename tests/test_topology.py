"""Topology is built only from recorded traceroute hops and scan targets."""

import pytest

from genmap.core.results import Address, Host, HostStatus, Hostname, ScanResult, Traceroute, TracerouteHop
from genmap.nmap.xml_parser import parse_nmap_xml_file
from genmap.topology import EdgeKind, NodeKind, TopologySource, build_topology, layered_layout


@pytest.fixture
def routed(fixtures):
    return parse_nmap_xml_file(fixtures / "routed_scan.xml")


def _host(address, hops=None, state="up", names=()):
    host = Host(status=HostStatus(state=state), addresses=[Address(address=address, address_type="ipv4")])
    host.hostnames = [Hostname(name=n, hostname_type="PTR") for n in names]
    if hops is not None:
        host.traceroute = Traceroute(hops=[TracerouteHop(ttl=t, ip_address=a) for t, a in hops])
    return host


def _edges(graph):
    return {(e.source, e.target): e.kind for e in graph.edges.values()}


def test_routes_follow_recorded_hops(routed):
    graph = build_topology([TopologySource(routed, "routed")])
    edges = _edges(graph)
    assert edges[("origin", "ip:192.168.1.1")] == EdgeKind.ROUTE
    assert edges[("ip:192.168.1.1", "ip:10.10.0.1")] == EdgeKind.ROUTE
    assert edges[("ip:198.51.100.1", "ip:203.0.113.10")] == EdgeKind.ROUTE
    assert graph.nodes["ip:192.168.1.1"].kind == NodeKind.ROUTER and graph.nodes["ip:192.168.1.1"].relays
    assert graph.nodes["ip:203.0.113.10"].kind == NodeKind.TARGET
    assert graph.nodes["ip:203.0.113.10"].depth == 5
    assert "ip:203.0.113.40" not in graph.nodes  # down hosts are not drawn
    assert graph.traced_hosts == {"203.0.113.10", "203.0.113.20", "203.0.113.30"}


def test_silent_hops_are_never_merged(routed):
    graph = build_topology([TopologySource(routed, "routed")])
    silent = [n for n in graph.nodes.values() if n.kind == NodeKind.NO_REPLY]
    # Both paths lose TTL 3 between the same two routers, yet stay separate.
    assert len(silent) == 2
    assert {n.traced_host for n in silent} == {"203.0.113.10", "203.0.113.20"}
    assert all(n.ttl_range == (3, 3) for n in silent)
    assert all(_edges(graph)[("ip:10.10.0.1", n.key)] == EdgeKind.GAP for n in silent)


def test_incomplete_trace_is_marked(routed):
    graph = build_topology([TopologySource(routed, "routed")])
    assert _edges(graph)[("ip:198.51.100.9", "ip:203.0.113.30")] == EdgeKind.INCOMPLETE
    assert graph.nodes["ip:203.0.113.30"].depth == 4


def test_untraced_hosts_hang_off_the_origin_and_can_be_hidden():
    result = ScanResult(hosts=[_host("10.0.0.5"), _host("10.0.0.6", [(1, "10.0.0.6")])])
    graph = build_topology([TopologySource(result, "a")])
    assert _edges(graph) == {("origin", "ip:10.0.0.5"): EdgeKind.SCANNED, ("origin", "ip:10.0.0.6"): EdgeKind.ROUTE}
    assert graph.untraced_hosts == {"10.0.0.5"}
    assert any("no route data" in n for n in graph.notes)
    hidden = build_topology([TopologySource(result, "a")], include_untraced=False)
    assert "ip:10.0.0.5" not in hidden.nodes and ("origin", "ip:10.0.0.5") not in _edges(hidden)


def test_no_links_are_inferred_from_addresses():
    # Neighbouring addresses in one subnet must not be linked to each other.
    result = ScanResult(hosts=[_host(f"10.0.0.{i}") for i in range(1, 6)])
    graph = build_topology([TopologySource(result, "a")])
    assert all(e.source == "origin" for e in graph.edges.values())


def test_merging_scans_keeps_route_over_scanned_edge_and_notes_origin():
    first = ScanResult(hosts=[_host("198.51.100.7")])
    second = ScanResult(hosts=[_host("198.51.100.7", [(1, "192.168.1.1"), (2, "198.51.100.7")])])
    graph = build_topology([TopologySource(first, "first"), TopologySource(second, "second")])
    edges = _edges(graph)
    assert ("origin", "ip:198.51.100.7") not in edges
    assert edges[("ip:192.168.1.1", "ip:198.51.100.7")] == EdgeKind.ROUTE
    assert graph.nodes["ip:198.51.100.7"].sources == {"first", "second"}
    assert graph.nodes["ip:198.51.100.7"].depth == 2
    assert graph.untraced_hosts == set()
    assert any("one scan origin" in n for n in graph.notes)


def test_router_depth_is_not_pulled_in_by_untraced_scan():
    # 10.0.0.1 is a hop at TTL 2 in one scan and an untraced target in another.
    a = ScanResult(hosts=[_host("198.51.100.9", [(1, "192.168.1.1"), (2, "10.0.0.1"), (3, "198.51.100.9")])])
    b = ScanResult(hosts=[_host("10.0.0.1")])
    graph = build_topology([TopologySource(b, "b"), TopologySource(a, "a")])
    node = graph.nodes["ip:10.0.0.1"]
    assert node.depth == 2 and node.kind == NodeKind.TARGET and node.relays


def test_routing_loops_do_not_create_self_edges():
    result = ScanResult(hosts=[_host("198.51.100.9", [(1, "192.168.1.1"), (2, "192.168.1.1"), (3, "198.51.100.9")])])
    graph = build_topology([TopologySource(result, "a")])
    assert all(e.source != e.target for e in graph.edges.values())


def test_layout_places_columns_by_hop_distance(routed):
    graph = build_topology([TopologySource(routed, "routed")])
    positions = layered_layout(graph, column_spacing=100, row_spacing=50)
    assert set(positions) == set(graph.nodes)
    for key, (x, _y) in positions.items():
        assert x == graph.nodes[key].depth * 100
    column = [positions[k][1] for k, n in graph.nodes.items() if n.depth == 3]
    assert len(column) == len(set(column))  # no two nodes on top of each other


def test_to_dict_is_json_ready(routed):
    import json

    data = json.loads(json.dumps(build_topology([TopologySource(routed, "routed")]).to_dict()))
    kinds = {n["kind"] for n in data["nodes"]}
    assert kinds == {"origin", "router", "target", "no_reply"}
    assert all("meaning" in e for e in data["edges"])

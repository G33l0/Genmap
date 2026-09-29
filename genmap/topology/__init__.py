"""Network topology built only from relationships Nmap actually recorded.

Two relationships are used and nothing else:

* consecutive traceroute hops, which Nmap records per host with --traceroute
* a host being a target of a scan, drawn from the scan origin when no route
  was recorded for it

Genmap never infers links from address ranges, hostnames, or MAC vendors.
This package has no Qt dependency; the user interface draws what it returns.
"""

from genmap.topology.graph import (
    EdgeKind,
    NodeKind,
    TopologyEdge,
    TopologyGraph,
    TopologyNode,
    TopologySource,
    build_topology,
)
from genmap.topology.layout import layered_layout

__all__ = [
    "EdgeKind",
    "NodeKind",
    "TopologyEdge",
    "TopologyGraph",
    "TopologyNode",
    "TopologySource",
    "build_topology",
    "layered_layout",
]

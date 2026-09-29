"""Layered layout: one column per hop distance from the scan origin."""

from __future__ import annotations

from collections import defaultdict

from genmap.topology.graph import TopologyGraph, address_sort_key


def layered_layout(graph: TopologyGraph, *, column_spacing: float = 230.0, row_spacing: float = 70.0) -> dict[str, tuple[float, float]]:
    """Return an (x, y) position for every node.

    Columns follow the hop distance Nmap recorded. Within a column nodes are
    ordered by the average position of the nodes linking to them, which keeps
    most edges from crossing, then by address.
    """
    layers: dict[int, list[str]] = defaultdict(list)
    for key, node in graph.nodes.items():
        layers[node.depth].append(key)
    incoming: dict[str, list[str]] = defaultdict(list)
    outgoing: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges.values():
        incoming[edge.target].append(edge.source)
        outgoing[edge.source].append(edge.target)

    order: dict[str, float] = {}

    def fallback(key: str) -> tuple:
        node = graph.nodes[key]
        return (address_sort_key(node.address), key)

    depths = sorted(layers)
    for depth in depths:
        keys = layers[depth]

        def by_parents(key: str) -> tuple:
            placed = [order[p] for p in incoming[key] if p in order]
            return (sum(placed) / len(placed) if placed else float("inf"), fallback(key))

        keys.sort(key=by_parents)
        for index, key in enumerate(keys):
            order[key] = index - (len(keys) - 1) / 2

    # One upward pass pulls routers towards the hosts they lead to.
    for depth in reversed(depths[:-1]):
        keys = layers[depth]

        def by_children(key: str) -> tuple:
            placed = [order[c] for c in outgoing[key] if c in order and graph.nodes[c].depth > depth]
            return (sum(placed) / len(placed) if placed else order[key], order[key])

        keys.sort(key=by_children)
        for index, key in enumerate(keys):
            order[key] = index - (len(keys) - 1) / 2

    return {key: (graph.nodes[key].depth * column_spacing, order[key] * row_spacing) for key in graph.nodes}

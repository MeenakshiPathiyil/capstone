"""Resource-level downstream reachability metrics.

The integrated demo derives a resource adjacency from the ``source`` and
``target`` fields in the supplied attack-graph edges. This is a useful
bootstrap for the included sample graph, but it is not a substitute for the
full normalized infrastructure dependency graph. Production callers should
pass the normalized infrastructure graph's resource edges here instead.
"""
from __future__ import annotations

from statistics import median
from typing import Iterable, Mapping


def compute_downstream_counts(
    edges: Iterable[Mapping],
    resource_ids: Iterable[str] = (),
) -> dict[str, int]:
    """Count unique resources reachable downstream from each resource.

    Self-reachability is excluded and cycles are handled safely.
    Edges without non-empty ``source`` and ``target`` resource identifiers
    are ignored.
    """
    adjacency: dict[str, set[str]] = {r: set() for r in resource_ids if r}
    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        source, target = edge.get("source"), edge.get("target")
        if not isinstance(source, str) or not source:
            continue
        if not isinstance(target, str) or not target:
            continue
        adjacency.setdefault(source, set()).add(target)
        adjacency.setdefault(target, set())

    counts: dict[str, int] = {}
    for resource in adjacency:
        visited: set[str] = set()
        stack = list(adjacency[resource])
        while stack:
            current = stack.pop()
            if current == resource or current in visited:
                continue
            visited.add(current)
            stack.extend(adjacency.get(current, ()))
        counts[resource] = len(visited)
    return counts


def compute_graph_median_reachable(downstream_counts: Mapping[str, int]) -> float:
    """Return the median downstream count, or 0.0 for an empty graph."""
    if not downstream_counts:
        return 0.0
    return float(median(downstream_counts.values()))

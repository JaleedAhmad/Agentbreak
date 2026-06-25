"""
path_finder.py

Enumerates every attack path in a ToolGraph: chains that start at an
untrusted/external source node and end at a node with at least one
sensitive sink.

Uses depth-first search with cycle detection.  Returns AttackPath objects
with no payload attached yet — payload_generator fills those in.
"""

from __future__ import annotations

from agentbreak.models.attack_path import AttackPath
from agentbreak.models.tool_graph import ToolGraph, ToolNode


def find_attack_paths(
    graph: ToolGraph,
    max_depth: int = 8,
    external_only: bool = False,
) -> list[AttackPath]:
    """
    Find all paths from source nodes to sink nodes in the ToolGraph.

    Parameters
    ----------
    graph : ToolGraph
        The normalised tool graph to scan.
    max_depth : int
        Maximum chain length to explore (prevents infinite loops in
        cyclic graphs and keeps scan time bounded).
    external_only : bool
        If True, only start paths from EXTERNAL sources (not UNTRUSTED).
        Default False = start from both.

    Returns
    -------
    list[AttackPath]
        All discovered source→sink chains, deduplicated.
        Paths are ordered by depth (shortest first).
    """
    sources = (
        graph.sources()
        if not external_only
        else [n for n in graph.nodes.values() if n.is_external_source()]
    )

    all_paths: list[AttackPath] = []
    seen_paths: set[tuple[str, ...]] = set()

    for source in sources:
        _dfs(
            graph       = graph,
            current     = source,
            path        = [source],
            visited     = {source.name},
            max_depth   = max_depth,
            all_paths   = all_paths,
            seen_paths  = seen_paths,
        )

    # Sort: shorter paths first, then alphabetically for determinism
    all_paths.sort(key=lambda p: (p.depth, p.describe()))
    return all_paths


def _dfs(
    graph:      ToolGraph,
    current:    ToolNode,
    path:       list[ToolNode],
    visited:    set[str],
    max_depth:  int,
    all_paths:  list[AttackPath],
    seen_paths: set[tuple[str, ...]],
) -> None:
    # If current node is a sink, record this path
    if current.is_sink() and len(path) > 1:
        key = tuple(n.name for n in path)
        if key not in seen_paths:
            seen_paths.add(key)
            all_paths.append(AttackPath(path=list(path)))

    # Stop recursing if we've hit max depth
    if len(path) >= max_depth:
        return

    # Explore neighbours
    for neighbour in graph.neighbors(current.name):
        if neighbour.name not in visited:
            visited.add(neighbour.name)
            path.append(neighbour)
            _dfs(graph, neighbour, path, visited, max_depth, all_paths, seen_paths)
            path.pop()
            visited.remove(neighbour.name)


def summarise_paths(paths: list[AttackPath]) -> str:
    """Return a compact human-readable summary of found paths."""
    if not paths:
        return "No attack paths found."
    lines = [f"Found {len(paths)} attack path(s):"]
    for i, p in enumerate(paths, 1):
        sink = p.target_sink
        sink_label = sink.highest_risk_sink().value if sink else "?"
        lines.append(f"  [{i}] {p.describe()}  (sink: {sink_label})")
    return "\n".join(lines)

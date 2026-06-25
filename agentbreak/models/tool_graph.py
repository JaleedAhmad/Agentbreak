from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


from agentbreak.models.enums import TrustLevel, SinkType


@dataclass
class ToolNode:
    """
    One tool in an agent's toolkit.

    name        - unique identifier within the graph (matches the function name)
    description - human-readable purpose; also used by payload_generator for
                  context-aware payload selection
    input_trust - the trust level of data this tool ingests
    sinks       - what sensitive actions this tool can perform
    metadata    - arbitrary extra info from the parser (framework, agent name…)
    """
    name:        str
    description: str                     = ""
    input_trust: TrustLevel              = TrustLevel.TRUSTED
    sinks:       list[SinkType]          = field(default_factory=list)
    metadata:    dict                    = field(default_factory=dict)

    def is_source(self) -> bool:
        """True if this tool ingests data from outside the trust boundary."""
        return self.input_trust in (TrustLevel.UNTRUSTED, TrustLevel.EXTERNAL)

    def is_external_source(self) -> bool:
        """True only for fully external inputs (web, email, files, third-party APIs)."""
        return self.input_trust == TrustLevel.EXTERNAL

    def is_sink(self) -> bool:
        """True if this tool can take a sensitive action."""
        return len(self.sinks) > 0

    def highest_risk_sink(self) -> Optional[SinkType]:
        """Return the most dangerous SinkType this tool exposes, or None."""
        priority = [
            SinkType.CODE_EXEC,
            SinkType.SHELL,
            SinkType.FILE_WRITE,
            SinkType.EMAIL_SEND,
            SinkType.DB_WRITE,
            SinkType.API_CALL,
            SinkType.MEMORY_WRITE,
        ]
        for s in priority:
            if s in self.sinks:
                return s
        return None

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return isinstance(other, ToolNode) and self.name == other.name


@dataclass
class ToolEdge:
    """
    A directed data-flow edge between two ToolNodes.

    source → target means: output of `source` can become input of `target`
    within the agent workflow, either directly (tool B receives tool A's
    output) or indirectly (both write/read shared state).

    label    - optional human note about what flows across (e.g. "web content")
    direct   - True if the data flows explicitly; False if via shared agent state
    """
    source:  str          # ToolNode.name
    target:  str          # ToolNode.name
    label:   str  = ""
    direct:  bool = True


@dataclass
class ToolGraph:
    """
    The normalized, framework-agnostic representation of an agent's tool set.

    Every parser (LangGraph, CrewAI, YAML schema) produces one of these.
    The scanner consumes one of these.  Nothing else matters.

    nodes  - dict keyed by tool name for O(1) lookup
    edges  - adjacency: edges[name] = list of ToolEdges leaving that node
    meta   - top-level metadata from the parser (framework name, agent name…)
    """
    nodes:  dict[str, ToolNode]        = field(default_factory=dict)
    edges:  dict[str, list[ToolEdge]]  = field(default_factory=dict)
    meta:   dict                        = field(default_factory=dict)

    # ── mutation helpers ──────────────────────────────────────────────────────

    def add_node(self, node: ToolNode) -> None:
        self.nodes[node.name] = node
        if node.name not in self.edges:
            self.edges[node.name] = []

    def add_edge(self, edge: ToolEdge) -> None:
        if edge.source not in self.edges:
            self.edges[edge.source] = []
        self.edges[edge.source].append(edge)

    # ── query helpers ─────────────────────────────────────────────────────────

    def sources(self) -> list[ToolNode]:
        """All nodes that accept untrusted / external input."""
        return [n for n in self.nodes.values() if n.is_source()]

    def sinks(self) -> list[ToolNode]:
        """All nodes that can perform a sensitive action."""
        return [n for n in self.nodes.values() if n.is_sink()]

    def neighbors(self, node_name: str) -> list[ToolNode]:
        """Direct successors of a node in the data-flow graph."""
        return [
            self.nodes[e.target]
            for e in self.edges.get(node_name, [])
            if e.target in self.nodes
        ]

    def has_path(self, source_name: str, sink_name: str) -> bool:
        """BFS reachability check."""
        visited = set()
        queue   = [source_name]
        while queue:
            current = queue.pop(0)
            if current == sink_name:
                return True
            if current in visited:
                continue
            visited.add(current)
            queue.extend(e.target for e in self.edges.get(current, []))
        return False

    def summary(self) -> str:
        return (
            f"ToolGraph: {len(self.nodes)} nodes, "
            f"{sum(len(v) for v in self.edges.values())} edges, "
            f"{len(self.sources())} sources, "
            f"{len(self.sinks())} sinks"
        )

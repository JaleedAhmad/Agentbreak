import re
from typing import Any

from agentbreak.models.enums import TrustLevel, SinkType
from agentbreak.models.tool_graph import ToolEdge, ToolGraph, ToolNode

try:
    import crewai
except ImportError:
    raise ImportError("Install crewai extra: pip install agentbreak[crewai]")


def parse(crew: Any, name: str = "crewai_agent") -> ToolGraph:
    """
    Inspect a compiled CrewAI Crew object and produce a ToolGraph.
    """
    tool_graph = ToolGraph(meta={"framework": "crewai", "name": name})
    
    external_kws = ["search", "fetch", "scrape", "browse", "web", "email", "file_read", "load", "retrieve"]
    untrusted_kws = ["user", "input", "query", "request"]
    
    sink_mappings = {
        SinkType.FILE_WRITE: ["file_write", "write", "save", "export"],
        SinkType.SHELL: ["exec", "run", "subprocess", "bash", "shell"],
        SinkType.EMAIL_SEND: ["send", "email", "smtp", "gmail"],
        SinkType.API_CALL: ["post", "request", "http", "api", "webhook"],
        SinkType.DB_WRITE: ["insert", "update", "db", "database", "sql"],
        SinkType.MEMORY_WRITE: ["memory", "store", "remember", "persist"],
    }
    
    if not hasattr(crew, "agents"):
        return tool_graph
        
    seen_names = set()
    
    for agent_idx, agent in enumerate(crew.agents):
        role = getattr(agent, "role", f"agent_{agent_idx}")
        
        for tool in getattr(agent, "tools", []):
            raw_name = getattr(tool, "name", f"tool_{len(seen_names)}")
            base_name = str(raw_name).lower().replace(" ", "_")
            
            node_name = base_name
            if node_name in seen_names:
                node_name = f"{base_name}_agent{agent_idx}"
            seen_names.add(node_name)
            
            desc = getattr(tool, "description", "")
            desc_str = str(desc) if desc else ""
            
            search_text = f"{base_name} {desc_str.lower()}"
            
            # Trust heuristics
            input_trust = TrustLevel.TRUSTED
            if any(kw in search_text for kw in external_kws):
                input_trust = TrustLevel.EXTERNAL
            elif any(kw in search_text for kw in untrusted_kws):
                input_trust = TrustLevel.UNTRUSTED
                
            # Sink heuristics
            sinks = set()
            for sink_type, keywords in sink_mappings.items():
                if any(kw in search_text for kw in keywords):
                    sinks.add(sink_type)
                    
            node = ToolNode(
                name=node_name,
                description=desc_str.strip(),
                input_trust=input_trust,
                sinks=list(sinks),
                metadata={"agent": role}
            )
            tool_graph.add_node(node)
            
    # Edges: connect every EXTERNAL/UNTRUSTED node to every TRUSTED node that has sinks
    sources = tool_graph.sources()
    trusted_sinks = [n for n in tool_graph.nodes.values() if n.input_trust == TrustLevel.TRUSTED and n.is_sink()]
    
    for src in sources:
        for tgt in trusted_sinks:
            if src.name != tgt.name:
                tool_graph.add_edge(ToolEdge(source=src.name, target=tgt.name, direct=False))
                
    return tool_graph

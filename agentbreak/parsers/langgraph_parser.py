import inspect
from typing import Any

from agentbreak.models.enums import TrustLevel, SinkType
from agentbreak.models.tool_graph import ToolEdge, ToolGraph, ToolNode

try:
    import langgraph
except ImportError:
    raise ImportError("Install parsers extra: pip install agentbreak[parsers]")


def parse(graph: Any, name: str = "langgraph_agent") -> ToolGraph:
    """
    Inspect a compiled LangGraph StateGraph and produce a ToolGraph.
    """
    tool_graph = ToolGraph(meta={"framework": "langgraph", "name": name})
    
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
    
    if not hasattr(graph, "nodes"):
        return tool_graph
        
    for node_name, node_obj in graph.nodes.items():
        # Skip LangGraph structural nodes
        if node_name.startswith("__"):
            continue
            
        func = None
        if hasattr(node_obj, "bound"):
            func = node_obj.bound
        elif hasattr(node_obj, "runnable"):
            func = node_obj.runnable
        else:
            func = node_obj
            
        func_name = getattr(func, "__name__", str(node_name))
        func_name_lower = func_name.lower()
        
        docstring = getattr(func, "__doc__", "")
        docstring = docstring if docstring else ""
        docstring_lower = docstring.lower()
        
        sig_str = ""
        if callable(func):
            try:
                sig_str = str(inspect.signature(func))
            except (ValueError, TypeError):
                pass
                
        # Trust labeling heuristics
        input_trust = TrustLevel.TRUSTED
        if any(kw in func_name_lower for kw in external_kws):
            input_trust = TrustLevel.EXTERNAL
        elif any(kw in func_name_lower for kw in untrusted_kws):
            input_trust = TrustLevel.UNTRUSTED
            
        # Sink labeling heuristics
        sinks = set()
        search_text = f"{func_name_lower} {docstring_lower}"
        
        for sink_type, keywords in sink_mappings.items():
            if any(kw in search_text for kw in keywords):
                sinks.add(sink_type)
                
        node = ToolNode(
            name=node_name,
            description=docstring.strip(),
            input_trust=input_trust,
            sinks=list(sinks),
            metadata={"signature": f"{func_name}{sig_str}"} if sig_str else {}
        )
        tool_graph.add_node(node)
        
    # Add edges: connect every EXTERNAL/UNTRUSTED node to every other node
    for src in tool_graph.sources():
        for tgt in tool_graph.nodes.values():
            if src.name != tgt.name:
                tool_graph.add_edge(ToolEdge(source=src.name, target=tgt.name, direct=False))
                
    return tool_graph

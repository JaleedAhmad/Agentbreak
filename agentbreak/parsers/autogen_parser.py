import inspect
import importlib.util
from typing import Any, List

from agentbreak.models.enums import TrustLevel, SinkType
from agentbreak.models.tool_graph import ToolEdge, ToolGraph, ToolNode

try:
    import autogen
except ImportError:
    raise ImportError("autogen is not installed. Install it with: pip install pyautogen")


def parse(filepath: str, name: str = "autogen_agent") -> ToolGraph:
    """
    Inspect an AutoGen script and produce a ToolGraph.
    """
    spec = importlib.util.spec_from_file_location("dynamic_module", filepath)
    if spec is None or spec.loader is None:
        raise ValueError(f"Could not load Python module from {filepath}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    
    agents = []
    for obj_name, obj in vars(module).items():
        if type(obj).__name__ in ("ConversableAgent", "AssistantAgent", "UserProxyAgent"):
            agents.append(obj)
            
    return _parse_agents(agents, name=name)


def _parse_agents(agents: List[Any], name: str = "autogen_agent") -> ToolGraph:
    """
    Internal parser logic that takes a list of agents (real or mock) 
    and returns a ToolGraph.
    """
    tool_graph = ToolGraph(meta={"framework": "autogen", "name": name})
    
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
    
    for agent in agents:
        agent_name = getattr(agent, "name", "UnnamedAgent")
        
        system_message = getattr(agent, "system_message", "")
        if not isinstance(system_message, str):
            system_message = str(system_message)
            
        description = getattr(agent, "description", "")
        if not isinstance(description, str):
            description = str(description)
            
        agent_desc = (system_message + " " + description).strip()
        
        # Tools could be in _function_map or tools or similar
        tools_dict = {}
        if hasattr(agent, "_function_map") and agent._function_map:
            tools_dict.update(agent._function_map)
        if hasattr(agent, "tools") and isinstance(agent.tools, dict):
            tools_dict.update(agent.tools)
            
        for tool_name, func in tools_dict.items():
            func_name = getattr(func, "__name__", str(tool_name))
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
                    
            node_id = f"{agent_name}_{func_name}"
            node_desc = f"Agent ({agent_name}) tool: {docstring}".strip()
            if agent_desc:
                node_desc = f"{agent_desc}\n\nTool Description: {node_desc}"
                
            node = ToolNode(
                name=node_id,
                description=node_desc,
                input_trust=input_trust,
                sinks=list(sinks),
                metadata={"signature": f"{func_name}{sig_str}", "agent": agent_name}
            )
            tool_graph.add_node(node)
            
    # Add edges: connect every EXTERNAL/UNTRUSTED node to every other node
    for src in tool_graph.sources():
        for tgt in tool_graph.nodes.values():
            if src.name != tgt.name:
                tool_graph.add_edge(ToolEdge(source=src.name, target=tgt.name, direct=False))
                
    return tool_graph

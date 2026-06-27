from pathlib import Path
from agentbreak.models.enums import TrustLevel, SinkType, Severity
from agentbreak.models.tool_graph import ToolNode, ToolEdge, ToolGraph
from agentbreak.models.attack_path import AttackPath, ExploitResult
from agentbreak.parsers import schema_parser
from agentbreak.scanner.path_finder import find_attack_paths
from agentbreak.scanner.payload_generator import generate_payloads, generate_all_payloads
from agentbreak.scanner import executor


def test_enums_exist():
    assert hasattr(TrustLevel, "TRUSTED")
    assert hasattr(TrustLevel, "UNTRUSTED")
    assert hasattr(TrustLevel, "EXTERNAL")
    
    assert hasattr(SinkType, "FILE_WRITE")
    assert hasattr(SinkType, "CODE_EXEC")
    assert hasattr(SinkType, "EMAIL_SEND")
    assert hasattr(SinkType, "API_CALL")
    assert hasattr(SinkType, "DB_WRITE")
    assert hasattr(SinkType, "SHELL")
    assert hasattr(SinkType, "MEMORY_WRITE")
    
    assert hasattr(Severity, "CRITICAL")
    assert hasattr(Severity, "HIGH")
    assert hasattr(Severity, "MEDIUM")
    assert hasattr(Severity, "LOW")
    assert hasattr(Severity, "INFO")


def test_tool_node_source_sink_flags():
    node_external = ToolNode(
        name="test_ext", 
        input_trust=TrustLevel.EXTERNAL, 
        sinks=[SinkType.EMAIL_SEND]
    )
    assert node_external.is_source() is True
    assert node_external.is_external_source() is True
    assert node_external.is_sink() is True

    node_trusted = ToolNode(
        name="test_trust", 
        input_trust=TrustLevel.TRUSTED, 
        sinks=[]
    )
    assert node_trusted.is_source() is False
    assert node_trusted.is_sink() is False


def test_tool_graph_add_and_query():
    graph = ToolGraph()
    
    n_src = ToolNode("source", input_trust=TrustLevel.EXTERNAL, sinks=[])
    n_mid = ToolNode("intermediate", input_trust=TrustLevel.TRUSTED, sinks=[])
    n_snk = ToolNode("sink", input_trust=TrustLevel.TRUSTED, sinks=[SinkType.EMAIL_SEND])
    
    graph.add_node(n_src)
    graph.add_node(n_mid)
    graph.add_node(n_snk)
    
    graph.add_edge(ToolEdge(source="source", target="intermediate"))
    graph.add_edge(ToolEdge(source="intermediate", target="sink"))
    
    assert len(graph.sources()) == 1
    assert len(graph.sinks()) == 1
    assert graph.has_path("source", "sink") is True
    assert graph.has_path("sink", "source") is False


def test_schema_parser_loads_email_agent():
    root_dir = Path(__file__).parent.parent
    schema_path = root_dir / "examples" / "email_agent.yaml"
    
    graph = schema_parser.parse(str(schema_path))
    
    assert len(graph.nodes) == 6
    assert len(graph.sinks()) == 2
    
    fetch_node = graph.nodes["fetch_emails"]
    assert fetch_node.input_trust == TrustLevel.EXTERNAL
    
    send_node = graph.nodes["send_email"]
    assert SinkType.EMAIL_SEND in send_node.sinks
    
    save_node = graph.nodes["save_to_notes"]
    assert SinkType.FILE_WRITE in save_node.sinks


def test_path_finder_finds_chains(parsed_email_graph):
    paths = find_attack_paths(parsed_email_graph)
    
    assert len(paths) >= 3
    assert any(p.path[0].name == "fetch_emails" for p in paths)
    for p in paths:
        assert p.target_sink is not None and p.target_sink.is_sink() is True
        assert p.depth <= 8


def test_payload_generator_matches_sink_type(parsed_email_graph):
    paths = find_attack_paths(parsed_email_graph)
    
    target_path = next(
        (p for p in paths 
         if p.target_sink and p.target_sink.name == "send_email" 
         and p.entry_tool and p.entry_tool.input_trust == TrustLevel.EXTERNAL),
        None
    )
    
    assert target_path is not None, "Could not find required AttackPath for test"
    
    results = generate_payloads(target_path)
    
    assert len(results) >= 1
    assert any(r.payload_name == "indirect_injection_email_exfil" for r in results)
    for r in results:
        assert r.payload != ""


def test_exploit_result_severity_assignment():
    entry = ToolNode("src", input_trust=TrustLevel.EXTERNAL)
    sink = ToolNode("snk", input_trust=TrustLevel.TRUSTED, sinks=[SinkType.EMAIL_SEND])
    path = AttackPath(path=[entry, sink])
    
    # 1. Exploited = True
    res_exploited = ExploitResult(attack_path=path, exploited=True)
    res_exploited.assign_severity()
    assert res_exploited.severity == Severity.HIGH
    
    # 2. Exploited = False
    res_unexploited = ExploitResult(attack_path=path, exploited=False)
    res_unexploited.assign_severity()
    assert res_unexploited.severity == Severity.INFO


def test_full_pipeline_email_agent(parsed_email_graph):
    graph = parsed_email_graph
    
    paths = find_attack_paths(graph)
    armed = generate_all_payloads(paths)
    
    results = executor.run(graph, armed, mode="mock")
    
    assert len(results) >= 4
    assert any(r.exploited for r in results)
    assert any(r.severity == Severity.HIGH for r in results)
    assert all(r.mock_mode for r in results)


import pytest
import os

def test_executor_live_mode_missing_api_key(monkeypatch, parsed_email_graph):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    paths = find_attack_paths(parsed_email_graph)
    armed = generate_all_payloads(paths)
    
    with pytest.raises(ValueError, match="GROQ_API_KEY"):
        executor.run(parsed_email_graph, armed, mode="live", backend="groq")


def test_executor_mock_mode_unchanged(monkeypatch, parsed_email_graph):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    paths = find_attack_paths(parsed_email_graph)
    armed = generate_all_payloads(paths)
    
    results = executor.run(parsed_email_graph, armed, mode="mock")
    assert len(results) >= 4
    assert any(r.exploited for r in results)
    assert all(r.mock_mode for r in results)

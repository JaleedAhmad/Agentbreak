import os
import pytest
import yaml
import tempfile
from pathlib import Path
from click.testing import CliRunner
from fastapi.testclient import TestClient

from agentbreak.parsers import schema_parser
from agentbreak.output.html_reporter import HTMLReporter
from agentbreak.models.attack_path import ExploitResult, AttackPath, ToolCallRecord
from agentbreak.models.enums import Severity
from agentbreak.cli import scan
from agentbreak.api.main import app

# --- Parser security tests ---

def test_schema_parser_rejects_yaml_exec():
    payload = "!!python/object/apply:os.system ['echo pwned']"
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        f.write(payload.encode("utf-8"))
        tmp_path = f.name
        
    try:
        with pytest.raises(yaml.YAMLError):
            schema_parser.parse(tmp_path)
    finally:
        os.unlink(tmp_path)

def test_schema_parser_handles_malformed_yaml():
    payload = "tools: [\n  - name: test\n"
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        f.write(payload.encode("utf-8"))
        tmp_path = f.name
        
    try:
        with pytest.raises((ValueError, yaml.YAMLError)):
            schema_parser.parse(tmp_path)
    finally:
        os.unlink(tmp_path)

def test_schema_parser_handles_empty_file():
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        tmp_path = f.name
        
    try:
        with pytest.raises(ValueError):
            schema_parser.parse(tmp_path)
    finally:
        os.unlink(tmp_path)

def test_schema_parser_handles_missing_tools_key():
    payload = "meta:\n  version: 1.0\n"
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        f.write(payload.encode("utf-8"))
        tmp_path = f.name
        
    try:
        with pytest.raises(ValueError):
            schema_parser.parse(tmp_path)
    finally:
        os.unlink(tmp_path)

# --- HTML reporter XSS tests ---

def test_html_reporter_escapes_payload_strings():
    attack_path = AttackPath(
        path=[],
        payload="<script>alert('xss')</script>",
        payload_name="test",
        owasp_category="Injection"
    )
    res = ExploitResult(
        attack_path=attack_path,
        exploited=True,
        severity=Severity.HIGH,
        evidence="",
        trace=[]
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "report.html"
        HTMLReporter([res]).generate(str(out_path))
        
        content = out_path.read_text(encoding="utf-8")
        assert "<script>" not in content
        assert "&lt;script&gt;" in content

def test_html_reporter_escapes_tool_names():
    attack_path = AttackPath(
        path=[],
        payload="test",
        payload_name="test",
        owasp_category="Injection"
    )
    trace = ToolCallRecord(
        tool_name="\"><img src=x onerror=alert(1)>",
        input_data="in",
        output_data="out",
        flagged=True
    )
    res = ExploitResult(
        attack_path=attack_path,
        exploited=True,
        severity=Severity.HIGH,
        evidence="",
        trace=[trace]
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "report.html"
        HTMLReporter([res]).generate(str(out_path))
        
        content = out_path.read_text(encoding="utf-8")
        assert "\"><img src=x onerror=alert(1)>" not in content
        assert "&quot;&gt;&lt;img" in content

# --- Path traversal tests ---

def test_output_path_rejects_system_dirs():
    runner = CliRunner()
    agent_path = Path(__file__).parent.parent / "examples" / "email_agent.yaml"
    result = runner.invoke(scan, ["--schema", str(agent_path), "--output", "/etc/passwd_dir"])
    assert result.exit_code == 1
    assert "Invalid output path" in result.output

# --- API security tests ---

client = TestClient(app)

def test_health_endpoint_unauthenticated():
    response = client.get("/health")
    assert response.status_code == 200

def test_scan_endpoint_requires_auth(monkeypatch):
    monkeypatch.setenv("AGENTBREAK_API_KEY", "test-secret")
    response = client.post("/scan", files={"schema": ("test.yaml", b"")})
    assert response.status_code == 401

def test_scan_endpoint_accepts_valid_auth(monkeypatch):
    monkeypatch.setenv("AGENTBREAK_API_KEY", "test-secret")
    agent_path = Path(__file__).parent.parent / "examples" / "email_agent.yaml"
    
    with open(agent_path, "rb") as f:
        response = client.post(
            "/scan",
            headers={"X-API-Key": "test-secret"},
            files={"schema": ("email_agent.yaml", f, "application/x-yaml")}
        )
        
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert "results" in data
    assert "exit_code" in data

def test_scan_endpoint_rejects_oversized_upload(monkeypatch):
    monkeypatch.setenv("AGENTBREAK_API_KEY", "test-secret")
    fake_data = b"x" * (2 * 1024 * 1024)
    
    response = client.post(
        "/scan",
        headers={"X-API-Key": "test-secret"},
        files={"schema": ("large.yaml", fake_data, "application/x-yaml")}
    )
    assert response.status_code == 413
    assert "Request body too large" in response.json()["detail"]

import pytest
from pathlib import Path
from agentbreak.parsers import schema_parser

@pytest.fixture
def parsed_email_graph():
    root_dir = Path(__file__).parent.parent
    schema_path = root_dir / "examples" / "email_agent.yaml"
    return schema_parser.parse(str(schema_path))

"""
Schema parser — the framework-agnostic input method.

Accepts a YAML or JSON file where the developer describes their agent's tools
manually.  This is both the fallback for unsupported frameworks and the fastest
way to test the scanner before any framework-specific parser is ready.

Minimal schema (YAML):

    meta:
      name: "My email assistant"
      framework: "custom"

    tools:
      - name: fetch_emails
        description: "Fetches unread emails from Gmail inbox"
        input_trust: external         # data comes from the internet
        sinks: []                     # read-only tool

      - name: summarise_email
        description: "Summarises email content using an LLM"
        input_trust: untrusted        # receives user-controlled content
        sinks: []

      - name: send_reply
        description: "Sends an email reply"
        input_trust: trusted          # only accepts developer-crafted text
        sinks:
          - email_send

    edges:
      - source: fetch_emails
        target: summarise_email
        label: "raw email body"
      - source: summarise_email
        target: send_reply
        label: "summary text"

The `edges` section is optional.  If omitted, AgentBreak infers a fully-
connected graph (every tool can flow into every other tool) — a conservative
worst-case assumption that over-reports paths but never under-reports them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

import yaml

from agentbreak.models.enums import TrustLevel, SinkType
from agentbreak.models.tool_graph import ToolEdge, ToolGraph, ToolNode


# ── trust level aliases accepted in YAML ─────────────────────────────────────

_TRUST_ALIASES: dict[str, TrustLevel] = {
    "trusted":   TrustLevel.TRUSTED,
    "untrusted": TrustLevel.UNTRUSTED,
    "external":  TrustLevel.EXTERNAL,
    "ext":       TrustLevel.EXTERNAL,
    "user":      TrustLevel.UNTRUSTED,
    "internet":  TrustLevel.EXTERNAL,
}

_SINK_ALIASES: dict[str, SinkType] = {
    "file_write":    SinkType.FILE_WRITE,
    "file":          SinkType.FILE_WRITE,
    "code_exec":     SinkType.CODE_EXEC,
    "exec":          SinkType.CODE_EXEC,
    "code":          SinkType.CODE_EXEC,
    "email_send":    SinkType.EMAIL_SEND,
    "email":         SinkType.EMAIL_SEND,
    "api_call":      SinkType.API_CALL,
    "api":           SinkType.API_CALL,
    "http":          SinkType.API_CALL,
    "db_write":      SinkType.DB_WRITE,
    "db":            SinkType.DB_WRITE,
    "database":      SinkType.DB_WRITE,
    "shell":         SinkType.SHELL,
    "bash":          SinkType.SHELL,
    "memory_write":  SinkType.MEMORY_WRITE,
    "memory":        SinkType.MEMORY_WRITE,
}


class SchemaParseError(ValueError):
    """Raised when the YAML/JSON schema is invalid or missing required fields."""


def _parse_trust(raw: str) -> TrustLevel:
    key = raw.strip().lower()
    if key not in _TRUST_ALIASES:
        raise SchemaParseError(
            f"Unknown input_trust value '{raw}'. "
            f"Valid values: {list(_TRUST_ALIASES.keys())}"
        )
    return _TRUST_ALIASES[key]


def _parse_sink(raw: str) -> SinkType:
    key = raw.strip().lower()
    if key not in _SINK_ALIASES:
        raise SchemaParseError(
            f"Unknown sink type '{raw}'. "
            f"Valid values: {list(_SINK_ALIASES.keys())}"
        )
    return _SINK_ALIASES[key]


def _load_raw(path: Union[str, Path]) -> dict:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Schema file not found: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(text)
    elif path.suffix == ".json":
        return json.loads(text)
    else:
        # try YAML first, then JSON
        try:
            return yaml.safe_load(text)
        except Exception:
            return json.loads(text)


def parse(path: Union[str, Path]) -> ToolGraph:
    """
    Parse a YAML or JSON tool schema file and return a ToolGraph.

    Parameters
    ----------
    path : str or Path
        Location of the schema file.

    Returns
    -------
    ToolGraph
        Normalised tool graph ready for the scanner.

    Raises
    ------
    FileNotFoundError, SchemaParseError
    """
    raw = _load_raw(path)

    graph = ToolGraph(meta=raw.get("meta", {}))

    # ── parse nodes ───────────────────────────────────────────────────────────
    tool_defs = raw.get("tools", [])
    if not tool_defs:
        raise SchemaParseError("Schema must contain at least one entry under 'tools:'")

    for i, tdef in enumerate(tool_defs):
        if "name" not in tdef:
            raise SchemaParseError(f"Tool at index {i} is missing a 'name' field.")

        trust_raw = tdef.get("input_trust", "trusted")
        trust     = _parse_trust(trust_raw)

        sinks_raw = tdef.get("sinks", [])
        sinks     = [_parse_sink(s) for s in sinks_raw]

        node = ToolNode(
            name        = tdef["name"],
            description = tdef.get("description", ""),
            input_trust = trust,
            sinks       = sinks,
            metadata    = {k: v for k, v in tdef.items()
                           if k not in ("name", "description", "input_trust", "sinks")},
        )
        graph.add_node(node)

    # ── parse edges ───────────────────────────────────────────────────────────
    edge_defs = raw.get("edges")

    if edge_defs is None:
        # No edges declared → infer fully-connected graph (conservative worst-case)
        names = list(graph.nodes.keys())
        for src in names:
            for tgt in names:
                if src != tgt:
                    graph.add_edge(ToolEdge(source=src, target=tgt, direct=False))
    else:
        for edef in edge_defs:
            if "source" not in edef or "target" not in edef:
                raise SchemaParseError(
                    "Each edge must have 'source' and 'target' fields."
                )
            src, tgt = edef["source"], edef["target"]
            if src not in graph.nodes:
                raise SchemaParseError(
                    f"Edge references unknown source tool '{src}'."
                )
            if tgt not in graph.nodes:
                raise SchemaParseError(
                    f"Edge references unknown target tool '{tgt}'."
                )
            graph.add_edge(ToolEdge(
                source = src,
                target = tgt,
                label  = edef.get("label", ""),
                direct = edef.get("direct", True),
            ))

    return graph

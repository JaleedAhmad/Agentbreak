from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import time

from agentbreak.models.enums import Severity, SinkType, TrustLevel
from agentbreak.models.tool_graph import ToolNode


@dataclass
class ToolCallRecord:
    """
    One tool invocation captured during sandbox execution.
    Forms the raw evidence trail in an ExploitResult.
    """
    tool_name:   str
    input_data:  str               # what the tool received
    output_data: str               # what the tool returned (or would return)
    timestamp:   float = field(default_factory=time.time)
    flagged:     bool  = False     # True if this call looks suspicious


@dataclass
class AttackPath:
    """
    A chain from an untrusted/external source node to a sensitive sink node.
    Produced by path_finder.py before execution.

    path     - ordered list of ToolNodes from source → sink
    payload  - the injection string placed at the source input
    entry_tool  - convenience: first node (the injection point)
    target_sink - convenience: last node (the damage point)
    """
    path:         list[ToolNode]
    payload:      str            = ""
    payload_name: str            = ""   # human name of the template used

    @property
    def entry_tool(self) -> Optional[ToolNode]:
        return self.path[0] if self.path else None

    @property
    def target_sink(self) -> Optional[ToolNode]:
        return self.path[-1] if self.path else None

    @property
    def path_names(self) -> list[str]:
        return [n.name for n in self.path]

    @property
    def depth(self) -> int:
        return len(self.path)

    def describe(self) -> str:
        return " → ".join(self.path_names)


@dataclass
class ExploitResult:
    """
    What happened when AgentBreak ran an AttackPath against the agent.
    Produced by executor.py after execution.
    """
    attack_path:   AttackPath
    exploited:     bool                   = False
    severity:      Severity               = Severity.INFO
    trace:         list[ToolCallRecord]   = field(default_factory=list)
    evidence:      str                    = ""    # one-line human summary
    mock_mode:     bool                   = True  # True = sandbox, False = live

    # ── severity auto-assignment ──────────────────────────────────────────────

    def assign_severity(self) -> None:
        """
        Set severity based on the sink type and source trust level.
        Call this after confirming exploited=True.
        """
        if not self.exploited:
            self.severity = Severity.INFO
            return

        sink_node = self.attack_path.target_sink
        source_node = self.attack_path.entry_tool

        if sink_node is None:
            self.severity = Severity.INFO
            return

        worst_sink = sink_node.highest_risk_sink()
        is_external = (
            source_node is not None
            and source_node.input_trust == TrustLevel.EXTERNAL
        )

        if worst_sink in (SinkType.CODE_EXEC, SinkType.SHELL):
            self.severity = Severity.CRITICAL if is_external else Severity.HIGH
        elif worst_sink in (SinkType.FILE_WRITE, SinkType.EMAIL_SEND, SinkType.DB_WRITE):
            self.severity = Severity.HIGH if is_external else Severity.MEDIUM
        elif worst_sink in (SinkType.API_CALL, SinkType.MEMORY_WRITE):
            self.severity = Severity.MEDIUM if is_external else Severity.LOW
        else:
            self.severity = Severity.LOW

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "attack_id":   id(self),
            "path":        self.attack_path.path_names,
            "payload":     self.attack_path.payload,
            "payload_name": self.attack_path.payload_name,
            "exploited":   self.exploited,
            "severity":    self.severity.value,
            "evidence":    self.evidence,
            "mock_mode":   self.mock_mode,
            "trace": [
                {
                    "tool":    r.tool_name,
                    "input":   r.input_data,
                    "output":  r.output_data,
                    "flagged": r.flagged,
                }
                for r in self.trace
            ],
        }

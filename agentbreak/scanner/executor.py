from __future__ import annotations

import logging
import time

from agentbreak.models.attack_path import AttackPath, ExploitResult, ToolCallRecord
from agentbreak.models.tool_graph import ToolGraph


logger = logging.getLogger(__name__)


class Executor:
    """
    Executes a list of AttackPaths against a target agent (mocked by default).
    """

    def __init__(self, graph: ToolGraph, mock_mode: bool = True):
        self.graph = graph
        self.mock_mode = mock_mode

    def run(self, attack_paths: list[AttackPath]) -> list[ExploitResult]:
        """
        Run all attack paths and return the results.
        """
        results = []
        for path in attack_paths:
            logger.info(f"Executing attack path: {path.describe()}")
            result = self._execute_path(path)
            results.append(result)
        return results

    def _execute_path(self, path: AttackPath) -> ExploitResult:
        """
        Executes a single AttackPath.
        In mock mode, this simulates the execution by tracking tool calls and 
        verifying if the payload makes it to the sink.
        """
        result = ExploitResult(
            attack_path=path,
            mock_mode=self.mock_mode,
        )

        if not path.path:
            logger.warning("Empty attack path provided.")
            return result

        if not self.mock_mode:
            # Live execution is not implemented yet.
            logger.error("Live execution is not yet supported. Falling back to mock mode.")
            result.mock_mode = True

        # Simulate execution
        current_payload = path.payload
        exploited = False

        for i, node in enumerate(path.path):
            is_sink = (i == len(path.path) - 1)
            
            # Simulate the tool call
            # In mock mode, we assume the tool passes the payload through if it's not a sink,
            # or 'triggers' if it is a sink.
            simulated_output = current_payload if not is_sink else f"Triggered sink: {node.name}"
            
            record = ToolCallRecord(
                tool_name=node.name,
                input_data=current_payload,
                output_data=simulated_output,
                flagged=is_sink, # Flag the call if it hits the sink
            )
            result.trace.append(record)

            # If we reached the final node (the sink) with a payload, consider it exploited.
            if is_sink and current_payload:
                 exploited = True
                 result.evidence = f"Payload successfully reached sink '{node.name}'."
                 break # Stop executing once the sink is hit
            
            # For the next node in the path, the input is the output of the current node
            current_payload = simulated_output

        result.exploited = exploited
        result.assign_severity()
        
        return result

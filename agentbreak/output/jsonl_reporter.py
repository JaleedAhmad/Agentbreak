import json
from pathlib import Path
from collections import defaultdict

from agentbreak.models.attack_path import ExploitResult
from agentbreak.models.enums import Severity


def summary(results: list[ExploitResult]) -> dict:
    """
    Generate a summary of the execution results.
    """
    exploited_count = sum(1 for r in results if r.exploited)
    by_severity = {sev.value: 0 for sev in Severity}
    
    for r in results:
        if r.exploited:
            by_severity[r.severity.value] += 1
            
    # Assuming if any test was mock mode, or all of them
    mock_mode = all(r.mock_mode for r in results) if results else True
    
    return {
        "total": len(results),
        "exploited_count": exploited_count,
        "by_severity": by_severity,
        "mock_mode": mock_mode
    }


def write_report(results: list[ExploitResult], output_path: str | Path) -> Path:
    """
    Writes one JSON object per line to a .jsonl file based on the ExploitResults.
    """
    out_path = Path(output_path)
    
    if out_path.is_dir():
        out_path = out_path / "agentbreak_report.jsonl"
        
    with out_path.open("w", encoding="utf-8") as f:
        for attack_id, result in enumerate(results, start=1):
            trace_data = []
            for record in result.trace:
                input_str = str(record.input_data) if record.input_data is not None else ""
                output_str = str(record.output_data) if record.output_data is not None else ""
                
                trace_data.append({
                    "tool": record.tool_name,
                    "input": input_str[:80],
                    "output": output_str[:80],
                    "flagged": record.flagged
                })
                
            payload_str = str(result.attack_path.payload) if result.attack_path.payload is not None else ""
            
            line_data = {
                "attack_id": attack_id,
                "path": result.attack_path.path_names,
                "payload_name": result.attack_path.payload_name,
                "payload": payload_str[:120],
                "exploited": result.exploited,
                "severity": result.severity.value,
                "evidence": result.evidence,
                "mock_mode": result.mock_mode,
                "trace": trace_data
            }
            
            f.write(json.dumps(line_data) + "\n")
            
    return out_path

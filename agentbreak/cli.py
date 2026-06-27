import sys
from pathlib import Path
import importlib.util

import click
from rich.console import Console
from rich.table import Table

from agentbreak.parsers import schema_parser
from agentbreak.scanner import path_finder, payload_generator
from agentbreak.scanner import executor
from agentbreak.output import jsonl_reporter
from agentbreak.output.html_reporter import HTMLReporter
from agentbreak.models.enums import Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}

@click.group()
def main():
    """AgentBreak: the framework-agnostic LLM agent vulnerability scanner."""
    pass

@main.command()
def info():
    """Print AgentBreak version and author info."""
    click.echo("AgentBreak v1.0.0")
    click.echo("Author: JaleedAhmad")
    click.echo("GitHub: https://github.com/JaleedAhmad/Agentbreak")

def _load_module_from_file(filepath: str):
    spec = importlib.util.spec_from_file_location("dynamic_module", filepath)
    if spec is None or spec.loader is None:
        raise ValueError(f"Could not load Python module from {filepath}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

@main.command()
@click.option("--schema", type=click.Path(exists=True, dir_okay=False), required=False, help="Path to a YAML/JSON tool schema file")
@click.option("--langgraph", type=click.Path(exists=True, dir_okay=False), required=False, help="Path to a Python file containing a LangGraph object")
@click.option("--crewai", type=click.Path(exists=True, dir_okay=False), required=False, help="Path to a Python file containing a CrewAI Crew object")
@click.option("--output", type=click.Path(file_okay=False), default="./agentbreak-report/", help="Output directory (default: ./agentbreak-report/)")
@click.option("--external-only", is_flag=True, default=False, help="Only trace paths from EXTERNAL sources (skip UNTRUSTED)")
@click.option("--max-depth", type=int, default=8, help="Max path depth (default: 8)")
@click.option("--no-html", is_flag=True, default=False, help="Skip HTML report, write JSONL only")
@click.option("--live", is_flag=True, default=False, help="Enable live execution mode using Groq (requires GROQ_API_KEY)")
@click.option("--smart-payloads", is_flag=True, default=False, help="Use Gemini to generate context-aware payloads")
def scan(schema, langgraph, crewai, output, external_only, max_depth, no_html, live, smart_payloads):
    """Scan an agent schema for vulnerabilities."""
    inputs = [i for i in [schema, langgraph, crewai] if i is not None]
    if len(inputs) != 1:
        console.print("[bold red]Error:[/] You must provide exactly one of --schema, --langgraph, or --crewai.")
        sys.exit(1)
        
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Parse input
    try:
        if schema:
            graph = schema_parser.parse(schema)
        elif langgraph:
            from agentbreak.parsers import langgraph_parser
            module = _load_module_from_file(langgraph)
            from langgraph.graph.state import StateGraph, CompiledStateGraph
            
            target_obj = None
            for obj in vars(module).values():
                if isinstance(obj, (StateGraph, CompiledStateGraph)):
                    target_obj = obj
                    break
                    
            if target_obj is None:
                console.print(f"[bold red]Error:[/] No StateGraph or CompiledStateGraph found in {langgraph}")
                sys.exit(1)
                
            graph = langgraph_parser.parse(target_obj)
        elif crewai:
            from agentbreak.parsers import crewai_parser
            module = _load_module_from_file(crewai)
            from crewai import Crew
            
            target_obj = None
            for obj in vars(module).values():
                if isinstance(obj, Crew):
                    target_obj = obj
                    break
                    
            if target_obj is None:
                console.print(f"[bold red]Error:[/] No Crew object found in {crewai}")
                sys.exit(1)
                
            graph = crewai_parser.parse(target_obj)
    except Exception as e:
        console.print(f"[bold red]Error parsing input:[/] {e}")
        sys.exit(1)
        
    console.print(f"[bold green]Parsed Schema:[/] {graph.summary()}")
    
    # 2. Find attack paths
    paths = path_finder.find_attack_paths(
        graph, 
        max_depth=max_depth, 
        external_only=external_only
    )
    
    if not paths:
        console.print("[yellow]No attack paths found.[/]")
        sys.exit(0)
        
    path_table = Table(title="Found Attack Paths")
    path_table.add_column("#", style="dim")
    path_table.add_column("Path Chain")
    path_table.add_column("Sink Type")
    
    for i, p in enumerate(paths, 1):
        sink_label = "Unknown"
        if p.target_sink:
            highest_risk = p.target_sink.highest_risk_sink()
            if highest_risk:
                sink_label = highest_risk.value
        path_table.add_row(str(i), p.describe(), sink_label)
        
    console.print(path_table)
    
    # 3. Generate payloads
    armed_paths = payload_generator.generate_all_payloads(paths)
    console.print(f"[dim]Generated {len(armed_paths)} hardcoded payloads to test.[/]")
    
    if smart_payloads:
        console.print("[bold]Generating smart payloads with Gemini...[/]")
        import os
        api_key = os.environ.get("GEMINI_API_KEY", "")
        try:
            armed_paths = payload_generator.generate_smart_payloads(graph, armed_paths, api_key)
            console.print(f"[dim]Re-armed {len(armed_paths)} payloads with Gemini.[/]")
        except (ValueError, ImportError) as e:
            console.print(f"[bold red]Error:[/] {e}")
            sys.exit(1)
    
    # 4. Execute
    if live:
        console.print("[bold]Running executor in live mode (Groq)...[/]")
        results = executor.run(graph, armed_paths, mode="live", backend="groq")
    else:
        console.print("[bold]Running executor in mock mode...[/]")
        results = executor.run(graph, armed_paths, mode="mock")
    
    # 5. Print results table
    res_table = Table(title="Scan Results")
    res_table.add_column("Path Chain")
    res_table.add_column("Payload Name")
    res_table.add_column("Exploited", justify="center")
    res_table.add_column("Severity")
    
    has_critical_or_high = False
    
    for r in results:
        exploited_mark = "[bold green]✓[/]" if r.exploited else "[bold red]✗[/]"
        sev_color = SEVERITY_COLORS.get(r.severity, "white")
        
        if r.exploited and r.severity in (Severity.CRITICAL, Severity.HIGH):
            has_critical_or_high = True
            
        res_table.add_row(
            r.attack_path.describe(),
            r.attack_path.payload_name,
            exploited_mark,
            f"[{sev_color}]{r.severity.name}[/]"
        )
        
    console.print(res_table)
    
    # 6. Write reports
    jsonl_reporter.write_report(results, out_dir)
    
    if not no_html:
        html_out = out_dir / "agentbreak_report.html"
        HTMLReporter(results).generate(str(html_out))
        
    console.print(f"\n[bold green]Report written to {out_dir}[/]")
    
    # Exit code based on findings
    if has_critical_or_high:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()

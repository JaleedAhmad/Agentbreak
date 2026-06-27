import sys
from pathlib import Path

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

@main.command()
@click.option("--schema", type=click.Path(exists=True, dir_okay=False), required=True, help="Path to a YAML/JSON tool schema file")
@click.option("--output", type=click.Path(file_okay=False), default="./agentbreak-report/", help="Output directory (default: ./agentbreak-report/)")
@click.option("--external-only", is_flag=True, default=False, help="Only trace paths from EXTERNAL sources (skip UNTRUSTED)")
@click.option("--max-depth", type=int, default=8, help="Max path depth (default: 8)")
@click.option("--no-html", is_flag=True, default=False, help="Skip HTML report, write JSONL only")
@click.option("--live", is_flag=True, default=False, help="Enable live execution mode using Groq (requires GROQ_API_KEY)")
def scan(schema, output, external_only, max_depth, no_html, live):
    """Scan an agent schema for vulnerabilities."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Parse schema
    try:
        graph = schema_parser.parse(schema)
    except Exception as e:
        console.print(f"[bold red]Error parsing schema:[/] {e}")
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
    console.print(f"[dim]Generated {len(armed_paths)} payloads to test.[/]")
    
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

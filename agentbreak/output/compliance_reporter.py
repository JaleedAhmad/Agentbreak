import time
from pathlib import Path
from collections import defaultdict
import logging

from agentbreak.models.attack_path import ExploitResult
from agentbreak.models.enums import Severity
from rich import print

logger = logging.getLogger(__name__)

try:
    import weasyprint
    _WEASYPRINT_AVAILABLE = True
except ImportError:
    _WEASYPRINT_AVAILABLE = False

try:
    import markdown
    _MARKDOWN_AVAILABLE = True
except ImportError:
    _MARKDOWN_AVAILABLE = False


def write_compliance_report(results: list[ExploitResult], output_dir: Path) -> Path:
    """
    Generates a Markdown compliance report grouped by OWASP category.
    If weasyprint is available, converts it to PDF and returns the PDF path.
    Otherwise, returns the Markdown path.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Group findings
    grouped: dict[str, list[ExploitResult]] = defaultdict(list)
    for r in results:
        # Default category if empty
        cat = r.attack_path.owasp_category or "Uncategorized"
        grouped[cat].append(r)
        
    # Calculate stats per category
    # categories: {cat: {"findings": int, "highest_severity": Severity}}
    stats = {}
    for cat, items in grouped.items():
        highest = Severity.INFO
        severity_order = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}
        for item in items:
            if severity_order.get(item.severity, 0) > severity_order.get(highest, 0):
                highest = item.severity
        stats[cat] = {
            "findings": len(items),
            "highest": highest.name
        }
        
    # Generate Markdown
    md_lines = [
        "# AgentBreak OWASP Agentic Top 10 Compliance Report\n",
        f"**Scan Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n",
        "## Summary\n",
        "| Category | Findings | Highest Severity |",
        "|---|---|---|"
    ]
    
    for cat, stat in stats.items():
        md_lines.append(f"| {cat} | {stat['findings']} | {stat['highest']} |")
        
    md_lines.append("\n## Detailed Findings\n")
    
    for cat, items in grouped.items():
        md_lines.append(f"### {cat}\n")
        # Sort items by severity descending
        severity_order = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}
        sorted_items = sorted(items, key=lambda x: severity_order.get(x.severity, 0), reverse=True)
        
        for idx, item in enumerate(sorted_items, 1):
            md_lines.append(f"**#{idx} | {item.severity.name}**")
            md_lines.append(f"- **Path:** `{item.attack_path.describe()}`")
            md_lines.append(f"- **Payload Template:** `{item.attack_path.payload_name}`")
            if item.evidence:
                ev = item.evidence.replace('\n', ' ')
                md_lines.append(f"- **Evidence:** {ev}")
            md_lines.append("")
            
    md_content = "\n".join(md_lines)
    md_path = output_dir / "compliance_report.md"
    md_path.write_text(md_content, encoding="utf-8")
    
    if not _WEASYPRINT_AVAILABLE or not _MARKDOWN_AVAILABLE:
        print("[yellow]Warning:[/] weasyprint or markdown not available — PDF skipped, Markdown written to compliance_report.md")
        return md_path
        
    # Convert to PDF
    html_body = markdown.markdown(md_content, extensions=['tables'])
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: sans-serif;
            line-height: 1.5;
            color: #333;
            margin: 2cm;
        }}
        h1, h2, h3 {{
            color: #1a1a1a;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        code {{
            background-color: #f8f9fa;
            padding: 2px 4px;
            border-radius: 4px;
            font-family: monospace;
        }}
    </style>
</head>
<body>
    {html_body}
</body>
</html>"""

    pdf_path = output_dir / "compliance_report.pdf"
    try:
        weasyprint.HTML(string=html_content).write_pdf(str(pdf_path))
        return pdf_path
    except Exception as e:
        logger.error(f"Failed to generate PDF: {e}")
        print(f"[yellow]Warning:[/] Failed to generate PDF ({e}) — Markdown written to compliance_report.md")
        return md_path

from __future__ import annotations

import html
from typing import List

from agentbreak.models.attack_path import ExploitResult
from agentbreak.models.enums import Severity


class HTMLReporter:
    """
    Renders a standalone HTML report from a list of ExploitResult objects.
    """

    def __init__(self, results: List[ExploitResult]):
        self.results = results

    def generate(self, output_path: str) -> None:
        """
        Generates the HTML string and writes it to the specified path.
        """
        html_content = self._build_html()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def _build_html(self) -> str:
        """
        Builds the standalone HTML content.
        """
        # Calculate statistics
        total = len(self.results)
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        for r in self.results:
            counts[r.severity.name] = counts.get(r.severity.name, 0) + 1

        stats_html = f"""
        <div class="header-stats">
            <div class="stat-box total">
                <div class="stat-title">Total Findings</div>
                <div class="stat-number">{total}</div>
            </div>
            <div class="stat-box critical">
                <div class="stat-title">CRITICAL</div>
                <div class="stat-number">{counts.get("CRITICAL", 0)}</div>
            </div>
            <div class="stat-box high">
                <div class="stat-title">HIGH</div>
                <div class="stat-number">{counts.get("HIGH", 0)}</div>
            </div>
            <div class="stat-box medium">
                <div class="stat-title">MEDIUM</div>
                <div class="stat-number">{counts.get("MEDIUM", 0)}</div>
            </div>
            <div class="stat-box low">
                <div class="stat-title">LOW</div>
                <div class="stat-number">{counts.get("LOW", 0)}</div>
            </div>
        </div>
        """

        results_html = ""
        # Sort results: CRITICAL > HIGH > MEDIUM > LOW > INFO
        # In Python enum, assuming they are defined with integer values. If not, we map them.
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_results = sorted(self.results, key=lambda x: severity_order.get(x.severity.name, 99))

        for idx, res in enumerate(sorted_results, 1):
            severity_name = res.severity.name
            path_chain = html.escape(res.attack_path.describe())
            payload = html.escape(res.attack_path.payload)
            evidence = html.escape(res.evidence)
            owasp_cat = html.escape(res.attack_path.owasp_category)
            
            trace_rows = ""
            for record in res.trace:
                flagged_class = "flagged-row" if record.flagged else ""
                t_name = html.escape(record.tool_name)
                t_in = html.escape(record.input_data)
                t_out = html.escape(record.output_data)
                
                trace_rows += f"""
                <tr class="{flagged_class}">
                    <td><strong>{t_name}</strong></td>
                    <td><div class="code-block">{t_in}</div></td>
                    <td><div class="code-block">{t_out}</div></td>
                </tr>
                """

            results_html += f"""
            <div class="result-card">
                <div class="result-header">
                    <h2>#{idx} <span class="badge {severity_name}">{severity_name}</span> <span class="badge OWASP" style="{'' if owasp_cat else 'display:none;'}">{owasp_cat}</span></h2>
                    <div class="path-chain">{path_chain}</div>
                </div>
                
                <div class="result-section">
                    <strong>Payload Used:</strong>
                    <div class="code-block">{payload}</div>
                </div>
                
                <div class="result-section">
                    <strong>Evidence:</strong>
                    <div class="evidence-text">{evidence if evidence else 'N/A'}</div>
                </div>
                
                <div class="result-section">
                    <h3>Execution Trace</h3>
                    <table>
                        <thead>
                            <tr>
                                <th width="15%">Tool</th>
                                <th width="42.5%">Input</th>
                                <th width="42.5%">Output</th>
                            </tr>
                        </thead>
                        <tbody>
                            {trace_rows}
                        </tbody>
                    </table>
                </div>
            </div>
            """

        full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AgentBreak Scan Report</title>
    <style>
        :root {{
            --bg-color: #0f1115;
            --panel-bg: #1e2128;
            --text-main: #e2e8f0;
            --text-muted: #94a3b8;
            --border-color: #334155;
            
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #64748b;
        }}

        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        h1, h2, h3 {{ color: #fff; margin-top: 0; }}

        .header-stats {{
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }}

        .stat-box {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            flex: 1;
            min-width: 150px;
            text-align: center;
        }}

        .stat-box.critical {{ border-top: 4px solid var(--critical); }}
        .stat-box.high {{ border-top: 4px solid var(--high); }}
        .stat-box.medium {{ border-top: 4px solid var(--medium); }}
        .stat-box.low {{ border-top: 4px solid var(--low); }}
        .stat-box.total {{ border-top: 4px solid #fff; }}

        .stat-title {{
            color: var(--text-muted);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .stat-number {{
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0.5rem 0 0 0;
            color: #fff;
        }}

        .result-card {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}

        .result-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }}

        .result-header h2 {{ margin: 0; display: flex; align-items: center; gap: 1rem; }}

        .path-chain {{
            font-family: monospace;
            background: rgba(0,0,0,0.3);
            padding: 0.5rem 1rem;
            border-radius: 4px;
            color: var(--low);
        }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge.CRITICAL {{ background: rgba(239, 68, 68, 0.1); color: var(--critical); border: 1px solid var(--critical); }}
        .badge.HIGH {{ background: rgba(249, 115, 22, 0.1); color: var(--high); border: 1px solid var(--high); }}
        .badge.MEDIUM {{ background: rgba(234, 179, 8, 0.1); color: var(--medium); border: 1px solid var(--medium); }}
        .badge.LOW {{ background: rgba(59, 130, 246, 0.1); color: var(--low); border: 1px solid var(--low); }}
        .badge.INFO {{ background: rgba(100, 116, 139, 0.1); color: var(--info); border: 1px solid var(--info); }}
        .badge.OWASP {{ background: #FFA500; color: #fff; border: 1px solid #e69500; }}

        .result-section {{
            margin-bottom: 1.5rem;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.5rem;
        }}

        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }}

        th {{
            background: rgba(0,0,0,0.2);
            color: var(--text-muted);
            font-weight: 600;
        }}
        
        tr.flagged-row td {{
            background: rgba(239, 68, 68, 0.05);
        }}

        .code-block {{
            background: rgba(0,0,0,0.3);
            padding: 0.5rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9rem;
            word-break: break-word;
            white-space: pre-wrap;
            color: #a7f3d0;
        }}
        
        .evidence-text {{
            color: #fca5a5;
            font-weight: 500;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AgentBreak Vulnerability Scan Report</h1>
        {stats_html}
        
        <h2>Detailed Findings</h2>
        {results_html if results_html else '<p style="color:var(--text-muted)">No vulnerabilities found.</p>'}
    </div>
</body>
</html>"""
        return full_html

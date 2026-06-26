# AgentBreak

Workflow-level security scanner for multi-agent AI systems.

AgentBreak is not a model scanner. It understands the graph of tools your agent can call, finds every chain from an untrusted input source to a sensitive action sink, and proves the exploit with a full tool-call trace. Built for developers who ship LangGraph, CrewAI, and AutoGen agents and want to know their attack surface before someone else finds it.

---

## The problem

Most production agents have three things simultaneously: access to external data (emails, web, files), an LLM that processes that data without sanitisation, and tools that take irreversible actions (send email, write file, call API). Existing scanners (garak, promptfoo) test models in isolation — they don't model what happens when a malicious payload injected through a web search result propagates through three tool calls and triggers an outbound email. AgentBreak tests the workflow, not the model. 

---

## Demo

```text
AgentBreak scan — Email Assistant Agent
ToolGraph: 6 nodes, 5 edges, 3 sources, 2 sinks

Found Attack Paths
┌───┬─────────────────────────────────────────────────────────┬────────────┐
│ # │ Path Chain                                              │ Sink Type  │
├───┼─────────────────────────────────────────────────────────┼────────────┤
│ 1 │ fetch_emails → summarise_and_plan → draft_reply →      │ email_send │
│   │ send_email                                              │            │
│ 2 │ web_search → summarise_and_plan → save_to_notes        │ file_write │
│ 3 │ fetch_emails → summarise_and_plan → save_to_notes      │ file_write │
│ 4 │ web_search → summarise_and_plan → draft_reply →        │ email_send │
│   │ send_email                                              │            │
│ 5 │ summarise_and_plan → draft_reply → send_email          │ email_send │
└───┴─────────────────────────────────────────────────────────┴────────────┘

Scan Results
┌──────────────────────────────────────┬──────────────────────────────────┬───────────┬──────────┐
│ Path Chain                           │ Payload Name                     │ Exploited │ Severity │
├──────────────────────────────────────┼──────────────────────────────────┼───────────┼──────────┤
│ fetch_emails → ... → send_email      │ indirect_injection_email_exfil   │     ✓     │ HIGH     │
│ fetch_emails → ... → send_email      │ search_result_prompt_injection   │     ✓     │ HIGH     │
│ web_search → ... → save_to_notes     │ web_content_file_write           │     ✓     │ HIGH     │
│ web_search → ... → send_email        │ search_result_prompt_injection   │     ✓     │ HIGH     │
│ summarise_and_plan → ... → send_email│ generic_override_fallback        │     ✓     │ MEDIUM   │
└──────────────────────────────────────┴──────────────────────────────────┴───────────┴──────────┘

Report written to agentbreak-report/
Exit code: 1 (HIGH findings present — fails CI/CD gate)
```

---

## Install

Because AgentBreak is a standalone CLI tool, we highly recommend installing it using **[`pipx`](https://pipx.pypa.io/)** to avoid PEP 668 `externally-managed-environment` errors on modern Linux systems (like Debian/Ubuntu).

```bash
pipx install git+https://github.com/JaleedAhmad/Agentbreak.git
```

For LangGraph support:
```bash
pipx install "agentbreak[langgraph] @ git+https://github.com/JaleedAhmad/Agentbreak.git"
```

For CrewAI support:
```bash
pipx install "agentbreak[crewai] @ git+https://github.com/JaleedAhmad/Agentbreak.git"
```

*(Alternatively, if you prefer `pip`, you must create and activate a virtual environment first: `python3 -m venv venv && source venv/bin/activate`, and then run `pip install ...`)*

Alternatively, for local development:
```bash
git clone https://github.com/JaleedAhmad/Agentbreak.git
cd Agentbreak
pip install -e ".[dev]"
```

---

## Project Structure

```text
agentbreak/
├── agentbreak/                  # Core package
│   ├── cli.py                   # CLI entry point
│   ├── models/                  # Core data models (ToolGraph, AttackPath)
│   ├── output/                  # JSONL and HTML report generators
│   ├── parsers/                 # Framework parsers (LangGraph, CrewAI, Schema)
│   └── scanner/                 # Analysis engine
│       ├── executor.py          # Execution and severity assignment
│       ├── path_finder.py       # Graph traversal and path extraction
│       └── payload_generator.py # Adversarial payload injection templates
├── examples/                    # Example schemas
│   └── email_agent.yaml
├── tests/                       # Pytest test suite
├── pyproject.toml               # Build configuration
└── requirements.txt             # Dependency definitions
```

---

## Usage

Three modes:

1. Schema mode (fastest, no framework dependency):
```bash
agentbreak scan --schema tools.yaml
```

2. LangGraph mode:
```bash
agentbreak scan --langgraph my_agent.py
```

3. CI/CD mode (exits 1 on HIGH or CRITICAL findings):
```bash
agentbreak scan --schema tools.yaml --output ./security-report/
```

---

## Tool schema format

```yaml
meta:
  name: "Sample Agent"
  framework: "custom" # Identifies the parsing framework context

tools:
  - name: web_scraper
    description: "Fetches text from a given URL." # Description helps contextualize the node
    input_trust: external # Data originates from outside the system boundary (e.g. internet)
    sinks: [] # This tool performs no dangerous actions

  - name: planner_llm
    description: "Analyzes scraped text and decides what to do."
    input_trust: untrusted # Data comes from an external source but via another tool
    sinks: []

  - name: send_email
    description: "Dispatches an email via SMTP."
    input_trust: trusted # Only accepts developer-crafted or heavily sanitized text
    sinks:
      - email_send # An irreversible outbound action that could exfiltrate data

  - name: save_log
    description: "Appends the operation result to a local file."
    input_trust: trusted
    sinks:
      - file_write # Modifies the local file system

edges:
  # Explicitly defines the data flow between tools
  - source: web_scraper
    target: planner_llm
  - source: planner_llm
    target: send_email
  - source: planner_llm
    target: save_log
```

---

## What AgentBreak tests

| Attack Template | Source Type | Sink Type |
| :--- | :--- | :--- |
| `indirect_injection_email_exfil` | EXTERNAL | EMAIL_SEND |
| `web_content_file_write` | EXTERNAL | FILE_WRITE |
| `document_code_exec` | EXTERNAL | CODE_EXEC, SHELL |
| `user_input_db_injection` | UNTRUSTED, EXTERNAL | DB_WRITE |
| `email_body_api_exfil` | EXTERNAL | API_CALL |
| `memory_poisoning_via_web` | EXTERNAL | MEMORY_WRITE |
| `search_result_prompt_injection` | EXTERNAL | EMAIL_SEND, API_CALL |
| `shell_injection_via_filename` | UNTRUSTED, EXTERNAL | SHELL, CODE_EXEC |

---

## What it does not test

- Live execution against a real LLM (mock mode only in V1)
- Runtime guardrail bypass (this is pre-deployment static analysis)
- Vulnerabilities in the model itself (use garak for that)

---

## Roadmap

* **V1 (now)**: Schema-based scanning, 8 payload templates, mock execution, JSONL + HTML reports
* **V2**: LangGraph and CrewAI native parsers, live execution mode (opt-in)
* **V3**: CI/CD GitHub Action, hosted scan API, compliance report export (OWASP Agentic Top 10)

---

## Author

Jaleed Ahmad ([GitHub](https://github.com/JaleedAhmad))

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

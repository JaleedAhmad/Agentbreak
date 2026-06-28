# CHANGELOG

## v0.3.1 (2026-06-28)
- Security: YAML `safe_load` audit confirmed across `schema_parser.py` and `api/main.py`
- Security: HTML reporter XSS escaping via `html.escape()` on all user-controlled output strings
- Security: Path traversal protection on `--output` flag blocking system-critical directories
- Security: API authentication via `X-API-Key` header and `AGENTBREAK_API_KEY` environment variable
- Security: In-memory sliding window rate limiting at 10 requests per minute per IP
- Security: `MaxBodySizeMiddleware` enforcing 1MB upload limit
- Security: CORS hardened via `AGENTBREAK_CORS_ORIGINS` environment variable
- Security: `/scan/langgraph` endpoint removed due to RCE risk in hosted context
- Testing: 11 new adversarial and API security tests bringing total test count to 27

## v0.3.0 (2026-06-28)
- AutoGen parser for Microsoft AutoGen ConversableAgent and AssistantAgent
- Judge LLM subsystem with Groq and Gemini backends and `--judge` CLI flag
- OWASP Agentic Top 10 mapping across all payload templates with compliance PDF reporter
- GitHub Actions composite action and sample CI workflow with `--fail-on` threshold flag
- Hosted Scan API via FastAPI with `/scan` and `/scan/langgraph` endpoints and Dockerfile

## v0.2.0
- Live execution mode via Groq
- Smart payload generation via Gemini Flash
- LangGraph and CrewAI CLI parsers
- dotenv API key loading

## v0.1.0
- Initial release, static scanner
- 8 payload templates
- YAML schema parser
- JSONL and HTML reporting

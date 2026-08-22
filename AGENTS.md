# JS Agent - Developer Guide

JS Agent is a local personal Agent Harness, not a chatbot. Echo is its only normal
runtime architecture: it wraps models, tools, memory, attachments, streaming, and
durable recovery behind one fail-closed execution boundary.

## Project Structure

```
js/
├── echo/                  # Authoritative Echo runtime, effects, gates, and ledger
│   ├── turn_runtime.py    # Single public turn boundary
│   ├── turn_loop.py       # Echo-owned model/tool loop
│   ├── effect_interpreter.py # Executes authorized effects and records receipts
│   └── ledger/            # MAC/hash journal, outbox, leases, and recovery
├── appshell/              # Single-host AppShell (Personal/Work in ONE app)
│   ├── routers.py         # Parent API: session, switch, inbox, artifacts, work-context
│   ├── work_context.py    # Work-context projection (closed DTOs, session/run bound)
│   ├── inbox.py           # Read-only Inbox/artifact projections
│   └── principal.py       # Parent session store (mode/workspace/epoch, CAS)
├── config.py              # Settings with Pydantic validation
├── agent/                 # Compatibility facade; delegates turns to Echo
├── setup_wizard.py        # Interactive first-time setup
├── core/                  # Shared core utilities
│   └── attachments.py     # PDF/Excel/text extraction + size formatting
├── security/              # Defense in depth
│   ├── audit.py           # Tamper-evident audit logs
│   ├── guard.py           # Behavioral guardrails
│   ├── strategies.py      # Pluggable defense strategies
│   ├── sandbox.py         # Resource-limited execution
│   └── secrets.py         # Encrypted secret management
├── tools/                 # Extensible tool system
│   ├── registry.py        # Schema + handler registry + parallel executor
│   ├── files.py           # Safe file operations with path sandboxing
│   ├── shell.py           # Sandboxed shell
│   ├── code.py            # Code execution
│   ├── browser.py         # Web fetching
│   ├── office.py          # Excel/PDF generation
│   └── discovery.py       # Tool auto-discovery
├── models/                # Model abstraction
│   ├── providers.py       # OpenAI-compatible adapter
│   ├── router.py          # Fallback routing
│   ├── provider_manager.py# Dynamic provider hot-plug
│   └── circuit_breaker.py # Resilience patterns
├── memory/                # Persistent memory
│   ├── store.py           # SQLite-backed working memory
│   ├── enhanced_store.py  # Three-layer memory (working/episodic/semantic)
│   ├── scheduler.py       # Dreaming consolidation cycle
│   └── embeddings.py      # Hybrid embedder with circuit-breaker fallback
├── skills/                # Skill ecosystem
│   ├── manager.py         # Unified skill lifecycle
│   ├── executor.py        # Code/prompt/workflow/meta execution
│   ├── creator.py         # Interactive skill scaffolding
│   ├── validator.py       # Deep validation engine
│   ├── tester.py          # Test generation + execution
│   ├── packager.py        # Packaging + signing + publishing
│   ├── spec.py            # Skill specification
│   ├── security.py        # Skill scanning
│   ├── hermes_bridge.py   # Hermes skill compatibility
│   └── builtin/           # Built-in prompt-type skills
├── web/                   # FastAPI server
│   ├── server.py          # REST + WebSocket endpoints
│   ├── auth.py            # Auth dependency (no-arg, reads _settings internally)
│   ├── deps.py            # FastAPI dependency injection
│   ├── static/            # Web UI assets
│   │   ├── css/           # tokens.css (light/dark design tokens) + shell.css + legacy.css
│   │   ├── js/            # theme-init/theme/shell/work_context/icons modules
│   │   └── vendor/lucide/ # offline ISC line-icon set (LICENSE included)
│   ├── templates/         # Jinja2 templates (single unified shell)
│   └── routers/           # Modular routers (chat, cron, fleet, plugins, system)
├── ui/                    # Rich CLI
│   └── cli.py             # Interactive shell + commands
├── tui/                   # Textual TUI (terminal UI)
│   └── app.py             # Textual-based interactive dashboard
├── cron/                  # Cron job scheduling
│   ├── scheduler.py       # Job scheduling engine
│   └── templates.py       # Natural language → cron expression parser
├── daemon/                # 24/7 background daemon
│   └── core.py            # Scheduled tasks + heartbeat
├── compression/           # Context compression
│   ├── compressor.py      # Dual-threshold compressor
│   └── feedback.py        # Auto-tuning feedback loop
├── evolution/             # Self-improvement
│   ├── metacognition.py   # System reflection
│   ├── optimizer.py       # Prompt A/B testing
│   ├── learner.py         # Pattern extraction
│   └── evolver.py         # Skill rewriting
├── checkpoints/           # (currently removed — was git shadow repo)
├── integrations/          # Messaging bots
│   └── telegram_bot.py    # Telegram integration
├── mcp/                   # Model Context Protocol
│   ├── client.py          # MCP client (stdio + SSE)
│   └── tools.py           # MCP tool adapter
├── pipeline/              # Auto-Fetch pipeline (experimental)
│   ├── orchestrator.py
│   ├── chunker.py
│   ├── connector.py
│   └── connectors/        # Gmail, Slack, Drive, Calendar, GitHub, Notion (mock/experimental)
└── utils/
    ├── log.py             # Structured logging
    ├── metrics.py         # Prometheus metrics
    └── db.py              # SQLite helpers

benchmarks/                # Deterministic benchmark suite
├── runner.py              # Mock provider + YAML task loader + scoring
├── baseline.json          # Regression baseline
└── tasks/                 # 11 YAML task definitions

demos/                     # Self-contained usage demos
└── factory/               # Factory documentation demo
```

## Design Principles

1. **One Runtime Boundary**: HTTP, WebSocket, CLI, TUI, Telegram, Work,
   Fleet, cron, model calls, and tools enter through Echo. Direct provider or
   tool-handler execution is forbidden in normal operation.
2. **Fail Closed**: A missing, unhealthy, or ambiguous security gate blocks the
   model call, tool, attachment, or side effect. Availability must never be
   recovered by bypassing Echo authorization or its durable ledger.
3. **Least Authority**: Tool leases bind product, owner, session, run, tool,
   arguments, filesystem/network grants, budget, and single-use consumption.
4. **Minimal Surprises**: All destructive operations are explicit. Path resolution is predictable.
5. **Observability**: Every tool call, model request, and security decision is logged.

## Adding a New Tool

```python
from js.tools.registry import ToolRegistry, ToolSpec, ToolParam

async def my_tool(query: str) -> ToolResult:
    return ToolResult(success=True, output=f"Result for {query}")

spec = ToolSpec(
    name="my_tool",
    description="Does something useful",
    parameters=[ToolParam("query", "string", "Search query")],
)
registry.register(spec, my_tool)
```

Registration only declares a tool. Production execution must still come from an
Echo-authorized turn and a single-use capability lease; never call a registry
handler directly.

## Running Tests

```bash
# Full suite
pytest tests/ -v --cov=js

# Benchmark regression check
python -m benchmarks.runner --mock

# Lint + type check
ruff check js/ tests/
mypy js/ --no-error-summary
```

## Code Style

- Python 3.12+ with `from __future__ import annotations`
- Strict mypy mode (131 files clean, zero errors)
- Ruff for linting (`E501`, `B008`, `SIM105`, `SIM108`, `TC001`, `TC003` ignored)
- Max line length: 100

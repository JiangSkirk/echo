# JS Agent - Developer Guide

## Project Structure

```
js/
├── config.py              # Settings with Pydantic validation
├── agent.py               # Core reasoning loop (~1270 lines)
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
│   ├── templates/         # Jinja2 templates
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

1. **Security First**: Every operation passes through `BehaviorGuard`. Defense in depth with audit logging.
2. **Fail-Open + Fail-Safe**:
   - *Fail-Open*: 安全子系统自身崩溃/故障时不阻断主系统（防止安全成为单点故障）。
   - *Fail-Safe*: 安全子系统正常工作时，对无法判断的情况默认阻断（保守策略）。
3. **Minimal Surprises**: All destructive operations are explicit. Path resolution is predictable.
4. **Observability**: Every tool call, model request, and security decision is logged.

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

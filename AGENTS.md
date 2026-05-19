# JS Agent - Developer Guide

## Project Structure

```
js/
├── config.py          # Settings with Pydantic validation
├── agent.py           # Core reasoning loop
├── security/          # Defense in depth
│   ├── audit.py       # Tamper-evident audit logs
│   ├── guard.py       # Behavioral guardrails
│   ├── sandbox.py     # Resource-limited execution
│   └── secrets.py     # Encrypted secret management
├── tools/             # Extensible tool system
│   ├── registry.py    # Schema + handler registry
│   ├── files.py       # Safe file operations
│   └── shell.py       # Sandboxed shell
├── models/            # Model abstraction
│   ├── providers.py   # OpenAI-compatible adapter
│   └── router.py      # Fallback routing
├── memory/            # Persistent memory
│   └── store.py       # SQLite-backed with LRU
├── plugins/           # Hot-reloadable plugins
│   └── manager.py
├── ui/                # Rich CLI
│   ├── cli.py         # Interactive shell
│   └── format.py      # Output formatting
└── utils/
    └── log.py         # Structured logging
```

## Design Principles

1. **Security First**: Every operation passes through `BehaviorGuard`. Defense in depth with audit logging.
2. **Fail Safe**: If a model provider fails, automatically fallback. If security can't decide, block.
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
pytest tests/ -v --cov=js
```

## Code Style

- Python 3.12+ with `from __future__ import annotations`
- Strict mypy mode
- Ruff for linting
- Max line length: 100

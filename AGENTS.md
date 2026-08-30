# JS Agent - Developer Guide

JS Agent is a local personal Agent Harness, not a chatbot. Echo is its only normal
runtime architecture: it wraps models, tools, memory, attachments, streaming, and
durable recovery behind one fail-closed execution boundary.

## 生产路径（读这个再改代码）

- **回合权威**：`run_echo_turn` / `EchoRuntime` / `execute_tool_effect`。模型、工具、附件、副作用只从这里进。
- **`JSAgent` 是 facade + 子系统装配**，不是第二套 loop。回合状态机在 `js/echo/turn_loop/`。
- **Fleet** = 一次性集群（`js/orchestration/fleet/`，UI 仍可切集群）。**Bots** = 命名机器人 + 房间 + Goal（`js/bots/`，`product_id` 仍是 `js-agent`）。Bots 不复用 Fleet。
- **对外信任模型**：`SECURITY.md` / `SECURITY_en.md`。对抗性模型的承重边界是 OS 隔离；Echo/lease/guard 是授权与纵深。多 owner 威胁模型与外部审计入口见 `docs/security/THREAT_MODEL.md` / `AUDIT_PACK.md`。
- **Orin 三层**：配置默认 `orin.enabled=false`；AppShell 启动打开 **Stage A**（lease/policy）；**Stage C / cells / `orin.enforce` 默认关**。完成声明见 `docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md`（`not_implemented`）。
- **`pulse()` 只观察背压**（ADR 0005），不 Exec，不是第二套运行时。
- **Gateway** 是渠道表面不是运行时（ADR 0008，`gateway.enabled=false`）。未配对发件人丢弃；回合仍走 Echo。
- **预留模块**（`pipeline` / `mobile`）默认不进 Host 冷启动。mobile 正式声明见 [`docs/mobile/MOBILE_CLOSEOUT.md`](docs/mobile/MOBILE_CLOSEOUT.md)（`not_implemented`）。`friends_enabled` 默认 false，未启用不 import `js.friends`。`scenarios` 是 bots goal 模板；`/api/tasks` 是 bots goals 只读视图。
- **测试密度**：M1 硬验收 `tests/`（`.py`+`.jsonl`+`.yaml`）/ (`js/`+`js_work/` `.py`) ≥ 1.2；纯 `.py` 口径 ≥ 0.94。棘轮脚本 `scripts/test_density_report.py`。覆盖率 M1 棘轮 `js/security` ≥86%、`js/echo` ≥85%、全库 branch ≥65%；90/85/75 为 M2 方向。安全承重面变异测试见 [`docs/quality/mutation-2026-08-29.md`](docs/quality/mutation-2026-08-29.md)（本地 mutmut，不进 CI）。

## Project Structure

```
js/
├── echo/                  # Authoritative Echo runtime, effects, gates, and ledger
│   ├── turn_runtime.py    # Single public turn boundary
│   ├── turn_loop/         # Echo-owned model/tool loop
│   ├── effect_interpreter.py # Executes authorized effects and records receipts
│   └── ledger/            # MAC/hash journal, outbox, leases, and recovery
├── appshell/              # Single-host AppShell (Personal/Work in ONE app)
│   ├── server.py          # Parent FastAPI app + child runtime wiring
│   ├── routers.py         # Parent API: session, switch, inbox, artifacts, work-context
│   ├── routing.py         # Mode routing + lazy Work boot
│   ├── work_context.py    # Work-context projection (closed DTOs, session/run bound)
│   ├── inbox.py           # Read-only Inbox/artifact projections
│   └── principal.py       # Parent session store (mode/workspace/epoch, CAS)
├── orin/                  # Sidecar client (Stage A leases; Stage C cells are harness)
├── orind/                 # Local orind daemon — not a second Agent runtime
├── bots/                  # Named bots + rooms + goal harness (Echo turns only)
├── gateway/               # Messaging surface (pairing/router/adapters; Echo turns only)
├── runtime/               # Resource governor (WAL allowlist, retention)
├── orchestration/         # Fleet one-shot cluster (not Bots, not a second turn runtime)
├── config.py              # Settings with Pydantic validation
├── agent/                 # Compatibility facade; delegates turns to Echo
├── setup_wizard.py        # Interactive first-time setup
├── security/              # Defense in depth
│   ├── audit.py           # Tamper-evident audit logs
│   ├── guard.py           # Behavioral guardrails
│   ├── strategies.py      # Pluggable defense strategies
│   ├── sandbox.py         # Re-export of js/echo/os_sandbox.py (real OS isolation)
│   └── secrets.py         # Encrypted secret management
├── tools/                 # Extensible tool system
│   ├── registry.py        # Schema + handler registry + parallel executor
│   ├── files.py           # Safe file operations with path sandboxing
│   ├── shell.py           # Sandboxed shell
│   ├── code.py            # Code execution
│   ├── browser.py         # Web fetching
│   └── office/            # Excel/PDF generation
├── models/                # Model abstraction
│   ├── providers.py       # OpenAI-compatible adapter
│   ├── router.py          # Fallback routing
│   ├── provider_manager.py# Dynamic provider hot-plug
│   └── circuit_breaker.py # Resilience patterns
├── memory/                # Persistent memory
│   ├── store.py           # SQLite-backed working memory
│   ├── enhanced_store/    # Three-layer memory (working/episodic/semantic)
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
│   ├── evolver.py         # Skill rewriting
│   └── builtin/           # Built-in prompt-type skills
├── web/                   # Local AppShell Host: REST/WS API + window UI (desktop, not a browser product)
│   ├── server.py          # REST + WebSocket endpoints
│   ├── auth.py            # Auth dependency (no-arg, reads _settings internally)
│   ├── deps.py            # FastAPI dependency injection
│   ├── static/            # Window UI assets (loaded by the desktop app)
│   │   ├── css/           # tokens.css (light/dark design tokens) + shell.css + legacy.css
│   │   ├── js/            # theme-init/theme/shell/work_context/icons modules
│   │   └── vendor/lucide/ # offline ISC line-icon set (LICENSE included)
│   ├── templates/         # Jinja2 templates (single unified shell)
│   └── routers/           # Modular routers (chat, cron, fleet, bots, plugins, system)
├── ui/                    # Rich CLI
│   └── cli.py             # Interactive shell + commands
├── tui/                   # Textual TUI (terminal UI)
│   └── app.py             # Textual-based interactive dashboard
├── cron/                  # Cron job scheduling
│   ├── engine.py          # Job scheduling engine
│   └── templates.py       # Natural language → cron expression parser
├── daemon/                # 24/7 background daemon
│   └── core.py            # Scheduled tasks + heartbeat
├── compression/           # Context compression
│   ├── compressor.py      # Dual-threshold compressor
│   └── feedback.py        # Auto-tuning feedback loop
├── evolution/             # Self-improvement (proposal-only cycle; never unattended)
│   ├── metacognition.py   # System reflection
│   ├── optimizer.py       # Prompt A/B testing
│   ├── learner.py         # Pattern extraction
│   └── quality_scorer.py  # Turn quality scoring
├── integrations/          # Messaging bots
│   └── telegram_bot.py    # Telegram integration
├── mcp/                   # Model Context Protocol
│   ├── client.py          # MCP client (stdio + SSE)
│   └── tools.py           # MCP tool adapter
├── pipeline/              # Auto-Fetch pipeline (reserved; not Host cold-start)
│   ├── orchestrator.py
│   ├── chunker.py
│   ├── connector.py
│   └── connectors/        # Gmail, Slack, Drive, Calendar, GitHub, Notion (mock/experimental)
└── utils/
    ├── attachments.py     # PDF/Excel/text extraction + size formatting
    ├── log.py             # Structured logging
    ├── metrics.py         # Prometheus metrics
    └── db.py              # SQLite helpers + PRODUCT_STATE_DB_NAMES

benchmarks/                # Deterministic benchmark suite
├── runner.py              # Mock provider + YAML task loader + scoring
├── baseline.json          # Regression baseline
└── tasks/                 # 11 YAML task definitions

demos/                     # Self-contained usage demos
└── factory/               # Factory documentation demo
```

## Design Principles

1. **One Runtime Boundary**: HTTP, WebSocket, CLI, TUI, Telegram, Work,
   Fleet, Bots, cron, model calls, and tools enter through Echo. Direct
   provider or tool-handler execution is forbidden in normal operation.
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
- Strict mypy mode (`uv run mypy js` is the source of truth; keep zero errors)
- Ruff for linting (`E501`, `B008`, `SIM105`, `SIM108`, `TC001`, `TC003` ignored)
- Max line length: 100
- Inventory review stamps: `quality/rubric.yaml` + `quality/labels.yaml`. Ask “到顶了吗” via `uv run python scripts/check_quality_labels.py --peak` — do not invent extra bars.

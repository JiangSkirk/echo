# JS Agent — Local Personal Agent Harness

An AI agent harness, not a chatbot. JS Agent wraps your chosen model with persistent memory, context capsules, tool execution, safety guardrails, test feedback, model switching, and task recovery—so the engine can do real work safely, continuously, and reproducibly.

The model is the engine. The harness is the complete frame that lets the engine work.

> **Status**: v0.1.3-alpha — APIs may change. Feedback welcome!

## Core Harness Capabilities

### 🧠 Memory & Context Capsules
- **Three-layer memory**: Working (immediate) → Episodic (session history) → Semantic (long-term knowledge), all stored locally in SQLite
- **Session Capsule Lite (experimental)**: Long sessions above the threshold get a short per-session summary; later calls inject "capsule + recent 6 turns" instead of full history to reduce prompt tokens. This is short-term context memory, not a complete long-term memory system
- **Dream consolidation**: Nightly automatic merging of fragmented memories, deduplication, distillation, and association indexing
- **Fully local**: Memory data stored under `~/.js/`, owner-isolated, never uploaded to the cloud

### 🔧 Tool Execution & Orchestration
- **File operations**: Safe file read/write with path sandboxing; writes outside Workspace require confirmation
- **Shell execution**: Tiered sandbox environment with whitelist/blacklist policies
- **Code execution**: Resource-limited Python script execution with timeout/memory limits
- **Browser**: Web page fetching and content extraction
- **Office**: Excel/PDF generation and parsing
- **Parallel execution**: Independent tools can be called concurrently to reduce latency

### 🛡️ Safety Guardrails (Defense in Depth)
- **Strategy-pattern defense**: Tool-call defenses are injectable, ordered strategy objects—not hardcoded if-else chains
- **Fail-Open semantics**: When the security subsystem itself crashes/fails, it does not block the main system (prevents security from becoming a single point of failure)
- **Behavior audit**: Immutable hash-chained audit log of every tool call; tampering/truncation detectable
- **Path protection**: Prevents accidental deletion of system files; writes outside workspace require confirmation
- **Secret management**: Auto-detects and redacts API keys, tokens, and passwords; stores them encrypted at rest

### 🔄 Model Switching & Resilience
- **Local model auto-discovery**: LM Studio (port 1234) and Ollama (port 11434) auto-detected
- **Multi-provider support**: OpenAI / DeepSeek / DashScope / SiliconFlow and other OpenAI-compatible endpoints
- **Failover**: Automatic downgrade to backup provider when the primary model is unavailable
- **Circuit breaker**: Fast-fail on service outages with automatic recovery probes
- **Context-window awareness**: Automatic inference of model context length; compression triggered before overflow

### ✅ Approval & Task Recovery
- **Tiered approval**: Manual / Auto-approve / Auto-reject / Cron-task reject
- **Async queue**: Non-blocking approval over WebSocket sessions
- **Checkpoint resume**: Automatic checkpoint after each turn; resume from breakpoint after interruption
- **Task state persistence**: SQLite-backed session state with "continue conversation" support

### 🧩 Skill System (Extensible Workflows)
- **Three types**: Code (executable scripts), Prompt (LLM instruction documents), Workflow (lightweight automation chains)
- **Security scan**: Automatic detection of eval/exec, subprocess, network, and file-deletion risk patterns during installation
- **Four trust levels**: builtin → trusted → community → quarantine
- **Hermes compatible**: Direct installation and execution of Hermes-format skills

### 🌐 Local Web Interface
- **FastAPI + WebSocket**: Real-time streaming chat without heavy Next.js dependencies
- **Model management panel**: View local model status, health checks, one-click switching
- **Memory browser**: View, search, and manage persistent memories
- **Audit log**: Complete tool-call history with traceability
- **Skill panel**: Install, uninstall, adjust trust levels, and view content online

## Quick Start

```bash
# Core install (no heavy Office/PDF deps)
pip install -e .

# Optional extras
pip install -e ".[office]"  # openpyxl + pandas (Excel read/write)
pip install -e ".[pdf]"     # pypdf + pdfplumber + reportlab (PDF read/generate)
pip install -e ".[dev]"     # dev tooling

# One-shot setup (auto-detects LM Studio / Ollama)
js setup

# CLI interactive mode
js

# Web UI
js web --port 8000

# Search
js search "latest AI developments"
```

## Architecture Comparison

| Capability | OpenClaw | Hermes | **JS Agent** |
|---|---|---|---|
| Runtime | Node.js (3700 chunks) | Python + Node UI | **Unified Python 3.12** |
| Security | External plugin (ClawAegis) | Tirith + approval | **Built-in + Strategy pattern + Fail-Open** |
| Context Compression | ❌ | ✅ Best-in-class | ✅ **Hermes-style compressor + Context capsules** |
| Checkpoint | ❌ | ✅ Git Shadow | ✅ **Git Shadow Repo** |
| Circuit Breaker | ❌ | ❌ | ✅ **Auto-recovery probes** |
| Model Discovery | ❌ Manual | ❌ Manual | ✅ **Auto-detection** |
| Search | ❌ Plugin needed | Tavily (config needed) | ✅ **DuckDuckGo out-of-box** |
| Web UI | Next.js heavy | Next.js + Python RPC | ✅ **FastAPI + lightweight native JS** |
| MCP | ❌ | Relatively new | ✅ **Native stdio/SSE** |
| Skills | Static files | ❌ | ✅ **Code/Prompt/Workflow + security scan + installable** |
| Multi-Agent | Simple sub-agent | Delegation thread pool | ✅ **Role system + parallel orchestration** |
| Self-Learning | ❌ | ❌ | ✅ **Interaction learning + A/B testing** |
| Install Experience | JSON manual config | YAML 388-line | ✅ **`js setup` one-shot** |

## Testing

```bash
ruff check js/ tests/ scripts/
mypy js/ --no-error-summary
pytest tests/ -q --tb=short
python -m benchmarks.runner --mock
python scripts/release_smoke.py --all
```

The release gate covers lint, typing, full tests, mock benchmarks, and release smoke.

## Known Limits

- **Session Capsule Lite is experimental**: the API/UI currently support view, refresh, and clear only. Failures fall back to full history; it does not provide complex editing, cross-session planning, or full long-term memory guarantees.
- **Auto-Fetch Pipeline is experimental**: Gmail / Slack / Drive / Calendar / GitHub / Notion connectors are mock/experimental for architecture demos.
- **Tool output budget**: each tool call is capped at `ToolLimits.tool_output_budget_chars` (default 20k chars). Two code paths handle oversize: `file_read` checks after `offset`/`limit` paging — if still oversize it returns empty `output` with `metadata.too_large=True` plus a paging suggestion (`js/tools/files.py`); all other tools fall through to the registry, which truncates `output` to the budget, appends an `[output truncated: N chars; ...]` notice and sets `metadata.truncated=True` / `metadata.original_len=N` (`js/tools/registry.py`). Neither path stuffs the full payload into the prompt.
- **Task Review Capsule (deterministic MVP)**: each run persists an owner-scoped, deterministic record (first user message, last assistant message, tool-call summary, token/turn counts, exit status) to `review_capsules.db`. **This is a deterministic post-run summary, not an LLM-generated reflection or learning signal.**
- **Abnormal-exit recovery is a status marker, not auto-resume**: on startup, sessions whose heartbeat has gone stale are marked `aborted` with `exit_reason="abnormal_exit_recovery"`. **The agent does not automatically re-run, re-tool, or continue an aborted session from its last checkpoint.** Users still need to start a new run; the existing checkpoint-resume APIs are unchanged.
- **Optional extras**: Office/PDF tools require `pip install -e ".[office]"` / `".[pdf]"`; without them the related tools fail with a clear error and core agent still works.

## Production Deployment

> Note: binding to `0.0.0.0` exposes the service beyond localhost. Production, LAN, or public deployments must require an API key; never expose no-auth mode outside the local machine.

```bash
# Web UI
js web --host 0.0.0.0 --port 8000

# Or Docker
docker run -p 8000:8000 -e OPENAI_API_KEY=xxx js-agent

# Or Gunicorn + Uvicorn
gunicorn "js.web:create_app()" -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

## License

MIT License — see [LICENSE](LICENSE) for details.

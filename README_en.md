# JS Agent

An AI Agent framework synthesizing the best of OpenClaw and Hermes, leading in architectural modernity and actively growing its ecosystem.

> **Status**: v0.1.3-alpha — APIs may change. Feedback welcome!

## Core Features

### 🔒 Security-First
- **Layered Sandbox**: All commands execute in an isolated environment with whitelist/blacklist support.
- **Strategy-Pattern Defense** (from OpenClaw): Tool-call defenses are injectable, ordered strategy objects—not hardcoded if-else chains.
- **Fail-Open Semantics** (from OpenClaw): When the security subsystem itself crashes/fails, it does not block the main system (prevents security from becoming a single point of failure).
- **Secret Management**: Auto-detects and redacts API keys, tokens, and passwords; stores them encrypted at rest.
- **Behavior Audit**: Immutable hash-chained audit log of every tool call, model response, and security event.
- **Path Protection**: Prevents accidental deletion of system files; writes outside the workspace require confirmation.

### 🛡️ Extreme Stability
- **Process Isolation**: Sub-agent crashes do not affect the main process.
- **Circuit Breaker** (from OpenClaw): Fast-fail on service outages with automatic recovery probes.
- **Auto-Recovery**: Model call failures are retried automatically with multi-provider fallback.
- **Stale-Code Auto-Restart** (from Hermes): Detects code updates and self-restarts.
- **Graceful Drain** (from OpenClaw): SIGTERM waits for active tasks to complete.
- **State Persistence**: SQLite-backed storage with checkpoint resume.
- **Resource Monitoring**: Memory/CPU limits trigger automatic protection.

### 🧠 Context Compressor (from Hermes)
- **Head Protection**: System prompt and initial context are never compressed.
- **Tail Protection**: Recent N conversation turns are kept intact.
- **Middle Compression**: Older turns are summarized with handoff framing to prevent misinterpretation.
- **Tool Output Truncation**: Overly long tool results are truncated before compression.
- **Multimodal Awareness**: Images are accounted for with fixed token estimates.

### ✅ Enhanced Approval System (from Hermes)
- **Tiered Modes**: Manual / Auto-approve / Auto-reject / Cron-task reject.
- **Async Queue**: Non-blocking approval over WebSocket sessions.
- **Session Callbacks**: UI pop-up confirmation support.

### 🔍 Local Model Auto-Discovery
- **LM Studio**: Auto-detects port 1234.
- **Ollama**: Auto-detects port 11434.
- **Model List Pulling**: Fetches available models and infers context windows automatically.

### 🔍 Web Search
- **DuckDuckGo**: Free, no API key, works out of the box.
- **Tavily**: High-quality AI search (optional).
- **Serper**: Google search (optional).
- **Auto-Fallback**: Switches to the next engine if one fails.

### 🚀 App-Level Install Experience
- **One-Shot Setup**: `js setup` auto-detects everything.
- **Non-Interactive Mode**: `js setup -y` for CI/CD.

### 🌐 Web UI
- **FastAPI + WebSocket**: Real-time streaming chat.
- **Model Management**: View local model status and health checks.
- **Network Search**: Standalone search panel.
- **File Browser / Audit / Skills / Multi-Agent / Evolution Dashboard**.

### 🤖 Multi-Agent Collaboration + 🧬 Self-Learning + 🧩 Skill Evolution
- **Role System**: Coder, Reviewer, Researcher, Tester.
- **A/B Testing**: Automatic survival-of-the-fittest for prompts and skills.
- **Interaction Learning**: Extracts patterns from successes and failures.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

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
| Context Compression | ❌ | ✅ Best-in-class | ✅ **Hermes-style compressor** |
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
pytest tests/ -v
```

**608 tests** covering all modules. Ruff zero errors, mypy zero new errors.

## Production Deployment

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

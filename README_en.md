# JS Agent — Local Personal Agent Harness

An AI agent harness, not a chatbot. JS Agent wraps your chosen model with persistent memory, context capsules, tool execution, safety guardrails, test feedback, model switching, and task recovery—so the engine can do real work safely, continuously, and reproducibly.

The model is the engine. The harness is the complete frame that lets the engine work.

> **Status**: v0.1.5 local release candidate / controlled trial — feedback welcome!
>
> [Security policy / trust model](SECURITY_en.md) · [中文安全政策](SECURITY.md)

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
- **Trust model**: The load-bearing boundary against an adversarial model is OS isolation; Echo/lease/guard are authorization and depth. See [SECURITY_en.md](SECURITY_en.md)
- **Strategy-pattern defense**: Tool-call defenses are injectable, ordered strategy objects—not hardcoded if-else chains
- **Fail-Closed semantics**: Echo authorization and the durable ledger fail closed when missing, unhealthy, or unverifiable — side effects are not bypassed
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

### 💻 Desktop app
- **Primary surface**: Tauri window loading the local AppShell Host (not the system browser)
- **CLI / TUI**: `js`, `js tui`, `js daemon` remain available in the terminal
- **Local Host**: `js appshell` starts the local service without opening a browser

## Skill Promotion Gate (v0.1.5)

Auto curator and evolver **no longer** mutate trust levels or overwrite entry files directly. Both record `proposed` events in `skill_promotions.db`, which an operator must explicitly approve. Approval runs a 5-step gate (`protected → validate → security → tests → smoke`, smoke bounded by a 30 s timeout). A failed gate changes nothing — no trust flip, no file overwrite, no `skill_usage` pollution.

| Action | CLI | Web | Auth |
|---|---|---|---|
| List open proposals | `js skill promote list` | `GET /api/skills/promotions` | normal auth |
| Show event detail | `js skill promote show <event_id>` | `GET /api/skills/promotions/{event_id}` | normal auth |
| Approve + run gate | `js skill promote approve <event_id>` | `POST .../{event_id}/approve` | admin |
| Reject (status only) | `js skill promote reject <event_id>` | `POST .../{event_id}/reject` | admin |
| Roll back an applied event | `js skill promote revert <event_id>` | `POST .../{event_id}/revert` | admin |

Troubleshooting starts at `event.details.failed_step` (one of `protected/validate/security/tests/smoke`); smoke timeouts also carry `details.timeout=True` and `details.smoke_error`. Web responses **never** expose `owner_key_hash` — isolation is enforced server-side via `memory_owner(auth)`. See [`docs/deployment.md`](docs/deployment.md) → *Skill Promotion Operations* for the full operator runbook.

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

# Desktop app is the main UI; local Host (does not open a browser):
js appshell

# Search
js search "latest AI developments"
```

Dev-machine troubleshooting only (**not for everyday product use**): the desktop app and `js appshell` still start orind by default so leases stay in a separate gatekeeper process. To temporarily cut processes while debugging a noisy machine:

```bash
JS_ORIND=0 js appshell
```

That moves leases back in-process and changes the daily security boundary. Do not set `JS_ORIND=0` as a product default.

## Architecture Comparison

| Capability | OpenClaw | Hermes | **JS Agent** |
|---|---|---|---|
| Runtime | Node.js (3700 chunks) | Python + Node UI | **Unified Python 3.12** |
| Security | External plugin (ClawAegis) | Tirith + approval | **Per-tool OS sandbox + Echo fail-closed** ([SECURITY_en.md](SECURITY_en.md); optional whole-process container; `orin.enforce` off by default) |
| Context Compression | ❌ | ✅ Best-in-class | ✅ **Hermes-style compressor + Context capsules** |
| Checkpoint | ❌ | ✅ Git Shadow | ⚠️ **Checkpoints removed — not shipped in this package** |
| Circuit Breaker | ❌ | ❌ | ✅ **Auto-recovery probes** |
| Model Discovery | ❌ Manual | ❌ Manual | ✅ **Auto-detection** |
| Search | ❌ Plugin needed | Tavily (config needed) | ✅ **DuckDuckGo out-of-box** |
| Web UI | Next.js heavy | Next.js + Python RPC | ✅ **Desktop app (Tauri) + local Host** |
| MCP | ❌ | Relatively new | ✅ **Native stdio/SSE** |
| Skills | Static files | ❌ | ✅ **Code/Prompt/Workflow + security scan + installable** |
| Multi-Agent | Simple sub-agent | Delegation thread pool | ✅ **Role system + parallel orchestration** |
| Self-Learning | ❌ | ❌ | ✅ **Proposal loop** (generate → human approve → apply → mock benchmark rollback; never unattended) |
| Test density | mid | 3.2:1 | ⚠️ **M1 ≥ 1.2:1** (ratchet; coverage floors in CI; M2/M3 directional) |
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
M1 density is hard-gated at 1.2:1 via `scripts/test_density_report.py`. CI also enforces
M1 coverage ratchets: `js/security` ≥86%, `js/echo` ≥85%, whole-library branch ≥65%
(plan targets 90/85/75 stay directional for M2).

## Known Limits

- **Session Capsule Lite is experimental**: the API/UI currently support view, refresh, and clear only. Failures fall back to full history; it does not provide complex editing, cross-session planning, or full long-term memory guarantees.
- **Auto-Fetch Pipeline is experimental**: Gmail / Slack / Drive / Calendar / GitHub / Notion connectors are mock/experimental for architecture demos.
- **Tool output budget**: each tool call is capped at `ToolLimits.tool_output_budget_chars` (default 20k chars). Two code paths handle oversize: `file_read` checks after `offset`/`limit` paging — if still oversize it returns empty `output` with `metadata.too_large=True` plus a paging suggestion (`js/tools/files.py`); all other tools fall through to the registry, which truncates `output` to the budget, appends an `[output truncated: N chars; ...]` notice and sets `metadata.truncated=True` / `metadata.original_len=N` (`js/tools/registry.py`). Neither path stuffs the full payload into the prompt.
- **Task Review Capsule (deterministic MVP)**: each run persists an owner-scoped, deterministic record (first user message, last assistant message, tool-call summary, token/turn counts, exit status) to `review_capsules.db`. **This is a deterministic post-run summary, not an LLM-generated reflection or learning signal.**
- **Abnormal-exit recovery is a status marker, not auto-resume**: on startup, sessions whose heartbeat has gone stale are marked `aborted` with `exit_reason="abnormal_exit_recovery"`. **The agent does not automatically re-run, re-tool, or continue an aborted session from its last checkpoint.** Users still need to start a new run; the existing checkpoint-resume APIs are unchanged.
- **Optional extras**: Office/PDF tools require `pip install -e ".[office]"` / `".[pdf]"`; without them the related tools fail with a clear error and core agent still works.

## Daily use

The main path is the **JS Agent desktop app**. Use `js` / `js tui` / `js daemon` in the terminal. `js appshell` only starts the local Host for the desktop app or development; it does not open a browser.

## Docker

```bash
docker compose up -d js-agent
```

The image and compose file set `JS_APPSHELL_PROVISION_KEY=1` by default. On first start, if no admin exists, a shared recovery key is written to `./state/bootstrap_admin_key.txt` (mode 0600). Use that key to sign in before calling `/api/*`. **The plaintext file is deleted after the first successful `/api/appshell/session` or `/api/auth/session` login**; `/api/appshell/bootstrap` leaves it in place so headless operators can still read it. The published port is loopback-only (`127.0.0.1:8000`). See [docs/deployment.md](docs/deployment.md).

## License

MIT License — see [LICENSE](LICENSE) for details.

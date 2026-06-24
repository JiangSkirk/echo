# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2026-06-24

### Added

- **`[office]` / `[pdf]` install extras**: heavy parsing/generation libraries are now optional.
  - `pip install -e ".[office]"` installs `openpyxl>=3.1` and `pandas>=2.2` (Excel read/write).
  - `pip install -e ".[pdf]"` installs `pypdf>=5.0`, `pdfplumber>=0.11`, `reportlab>=4.0` (PDF read/generate).
  - Core install no longer requires these libraries; the related Office/PDF tools degrade with a clear error when the extra is not installed.
- **Tool output budget (default 20k chars)**: `ToolLimits.tool_output_budget_chars` (default `20_000`) caps the size of any single tool result returned to the model. Two code paths handle oversize:
  - `file_read` checks early (after `offset`/`limit` paging) and, if still oversize, returns `success=True` with empty `output` and `metadata.too_large=True` plus a paging suggestion (`js/tools/files.py`).
  - All other tools fall through to the registry, which truncates `output` to the budget, appends a `... [output truncated: N chars; ...]` notice, and sets `metadata.truncated=True` + `metadata.original_len=N` (`js/tools/registry.py`).
  Both paths keep `success` consistent with the underlying tool outcome and never stuff the full payload into the prompt.
- **Task Review Capsule (deterministic MVP, no LLM)**: at the end of every run the agent stores a lightweight, owner-scoped record in `review_capsules.db` containing the first user message, last assistant message, tool-call summary, token totals, turn count and exit status. Secrets are redacted before storage. This is a deterministic post-run summary, **not** an LLM-generated reflection.
- **Session lifecycle tracking + abnormal-exit recovery (marker only)**: `SessionLifecycleStore` records `running` / `completed` / `aborted` state with heartbeats. On startup, runs whose heartbeats have gone stale beyond the configured threshold are marked as `aborted` with `exit_reason="abnormal_exit_recovery"`. **This is a status marker, not full task resumption**: the agent does not automatically re-run, re-tool, or continue an aborted session from its last checkpoint. Resuming work after an abnormal exit still requires the user to start a new run (existing checkpoint-resume APIs unchanged).
- **Tool batch telemetry**: after each tool batch the agent emits a `TOOL_BATCH` audit event recording `turn`, `tool_names`, `all_failed`, `batch_size`, `total_output_chars`, `owner_key_hash`, plus `session_id` / `run_id`, and increments a `tool_batches_total{all_failed,tool_count}` Prometheus counter. Per-tool **latency** is *not* in this batch event — per-tool latency continues to flow through the existing `js.utils.metrics` histograms/counters. `TOOL_BATCH` only describes batch shape and outcome.
- **Skill Promotion Gate CLI/Web controls**: auto curator and evolver no longer mutate trust levels or overwrite entry files directly — both produce `proposed` events in `skill_promotions.db`, which an operator then reviews and applies through a 5-step gate (`protected → validate → security → tests → smoke`; smoke is bounded by a 30 s `asyncio.wait_for`). New surfaces:
  - **CLI**: `js skill promote list | show <event_id> | approve <event_id> | reject <event_id> | revert <event_id>`. `approve` runs the gate via `SkillManager.apply_proposal`; `reject` only flips event status (never touches trust or files); `revert` rolls back trust + entry file via `SkillManager.revert_promotion`.
  - **Web**: `GET /api/skills/promotions` and `/api/skills/promotions/{event_id}` require normal auth and are scoped by `memory_owner(auth)`. `POST /api/skills/promotions/{event_id}/{approve|reject|revert}` all require `require_admin`. Responses never include `owner_key_hash`. Routes are registered before `/api/skills/{skill_id}` so the wildcard cannot swallow them.
  - **Failure surfaces**: every gate decision emits an `AuditEventType.SKILL_PROMOTION_GATE` audit row and a `skill_promotion_events_total{decision,failed_step}` Prometheus counter. Failure context lives in `event.details.failed_step` (one of `protected/validate/security/tests/smoke`) and, for smoke timeouts, `event.details.timeout=True` + `event.details.smoke_error`.

### Changed

- **Owner isolation hardened across persistence layers**: `SessionLifecycleStore`, `ReviewStore`, and `StateStore` now use a composite `(session_id, owner_key_hash)` primary key. `owner_key_hash=None` is normalized to the `__legacy_local__` sentinel everywhere; `list_active(None)` / `list_recent(None)` / `list_sessions(None)` no longer return rows belonging to authenticated owners. Existing tables migrate in place on first open.
- **`TurnExecutor` owner field**: the per-run owner key hash is now stored on the executor instance instead of a shared attribute on the agent, so concurrent runs for different users cannot race on heartbeats.
- **`StateStore.load()`** now returns `owner_key_hash` in its result dict.

### Fixed

- **`file_read` budget vs. paging order**: paging by `offset`/`limit` is applied before the 20k char budget check, so requested line slices on large files no longer get rejected as oversized.

### Verified

- `ruff check js/ tests/ scripts/` → All checks passed
- `mypy js/ --no-error-summary` → zero errors
- `pytest tests/ -q --tb=short` → 1321 passed, 3 skipped, 11 deselected
- `python -m benchmarks.runner --mock` → Overall score 1.000 / Baseline 1.000
- `python scripts/release_smoke.py --all` → passed
- `python -m js --help` → CLI loads cleanly

## [0.1.3-alpha] - 2026-06-22

### Added

- **Session Capsule (Lite MVP, experimental)**: per-session short context summary stored in `session_capsules`, injected as "capsule + recent 6 turns" for long sessions to reduce prompt tokens.
  - Short-term context memory only; not a complete long-term memory system.
  - Triggered when total run tokens exceed `memory.capsule_token_threshold` (default 1500).
  - Owner-isolated via `owner_key_hash`; configurable via `MemoryConfig`.
  - Minimal API (`/api/sessions/{session_id}/capsule`) and Status Tab UI.
  - Automatic fallback to full history on any error.

### Fixed

- **Benchmark regression**: Removed `/` from default `protected_paths` so normal workspace file writes are no longer incorrectly blocked by the `path_protection` defense strategy.
- **Release smoke failures**: Updated `scripts/release_smoke.py` to send the required `Origin` header for state-changing POST requests in local no-auth mode.
- **Pytest warnings**:
  - Fixed an `AsyncMock` "never awaited" warning in `tests/test_net_guard_rebinding.py` by mocking HTTP responses with `MagicMock` instead of `AsyncMock`.
  - Added `httpx2` to dev dependencies so Starlette's `TestClient` no longer emits a deprecation warning when using plain `httpx`.
- **Clean release smoke output**: `MemoryOrganizer` now prints a short Chinese degrade message instead of a full Rich traceback when no model is configured.
- **Session owner isolation**: runtime session-history loading now enforces the current `owner_key_hash`, and capsule persistence uses the current request owner instead of shared agent state.

### Changed

- `.gitignore` now excludes `.playwright-mcp/` runtime cache files.
- `uv.lock` synchronized with the new `httpx2` dev dependency.
- Version metadata remains `0.1.3` for PEP 440 compliance; release is tagged `v0.1.3-alpha`. README/TUI display the alpha release name.

### Verified

- `pytest tests/ -q --tb=short` → 1276 passed, 2 skipped, 11 deselected
- `ruff check js/ tests/ scripts/` → All checks passed
- `mypy js/ --no-error-summary` → zero errors
- `python -m benchmarks.runner --mock` → Overall score 1.000 / Baseline 1.000
- `python scripts/release_smoke.py --all` → passed

## [0.1.2-alpha] - 2026-05-30

### Added

- **Stronger multi-agent runtime**: Added event/task stores, lane queues, fleet strategies, fleet tools, and richer multi-agent orchestration controls.
- **Model connection upgrades**: Added model discovery/transports and improved OpenAI-compatible provider handling for LM Studio, Ollama, and cloud providers.
- **Dream memory and evolution polish**: Added dream auto-trigger coverage, quality scoring, semantic snapshots, and expanded evolution/front-end validation tests.
- **Web UI modularization**: Split large front-end behavior into tab-specific modules for agents, audit, cron, dashboard, evolution, files, memory, models, search, skills, stats, and status.
- **WebBridge and tool improvements**: Added WebBridge tooling, attachment helpers, stable ID utilities, fleet tools, and expanded tool tests.
- **Release safety**: Added local secret ignore rules and converted static fake API-key test strings to runtime-built values to reduce false positive secret-scanner blocks.

### Changed

- **macOS-first positioning remains**: This release continues to prioritize a simple macOS install and Web UI experience.
- **Version consistency**: Updated package, README, and module version display to `0.1.2`.

### Verified

- `ruff check js tests scripts pyproject.toml`
- `pytest -q -p no:cacheprovider` -> 964 passed, 11 skipped.
- `python -m build --sdist --wheel`
- `python scripts/release_smoke.py --all`

## [0.1.1-alpha] - 2026-05-25

### Added

- **macOS first-run script**: Added `scripts/macos_start.sh` for a one-command macOS startup path. It creates `.venv`, installs runtime dependencies, runs setup when needed, and opens the Web UI.
- **Release smoke workflow**: Added `.github/workflows/release-smoke.yml` to verify package, Web UI, model provider switching, OpenClaw/Hermes skill compatibility, dream memory, evolution, and multi-agent fleet behavior.
- **Release smoke script**: Added `scripts/release_smoke.py` for local and CI release validation.
- **Office builtin skills**: Moved Excel/PDF helper skills into the real loaded builtin skill directory as `excel-helper` and `pdf-helper`.
- **macOS-focused README quick start**: Documented the recommended macOS path and model-provider setup flow.

### Fixed

- **DuckDuckGo search parsing**: Decodes DuckDuckGo `uddg` redirect URLs so real external results are no longer filtered out as internal DuckDuckGo links.
- **CLI search command**: Fixed `js search` Click parameter mismatch that caused `TypeError: search() got an unexpected keyword argument 'engine'`.
- **Web upload dependency**: Ensured `python-multipart` is included so FastAPI upload routes can start correctly.
- **Local model provider discovery**: Avoids environment proxy interference for local provider model discovery.
- **Web model list refresh**: `/api/models` now refreshes local LM Studio/Ollama model lists more reliably.
- **Version consistency**: Updated package/UI/server version display to `0.1.1`.
- **Generated artifact cleanup**: `.mypy_cache/` and `.ruff_cache/` are ignored, and stale cache/log/build artifacts were removed.
- **Windows installer removal**: Removed the old PowerShell installer path after narrowing this release to macOS-first distribution.

### Changed

- **Release positioning**: This is now a macOS-first alpha release rather than a cross-platform desktop/app release.
- **CI matrix**: CI and release smoke workflows target Python 3.12, 3.13, and 3.14.
- **Skill loading**: Builtin skill count is now 12, including office helper prompt skills.

### Verified

- `ruff check js tests scripts pyproject.toml`
- `mypy js`
- `pytest -q` → 856 tests passed locally on macOS + Python 3.12.
- `python scripts/release_smoke.py --all`
- `python -m js search "OpenAI"`
- `python -m build`
- Fresh temporary macOS virtual environment installing the built wheel and running release smoke checks.

### Known Limitations

- The release is intended as an alpha/public testing build.
- macOS + Python 3.12 is the locally verified path.
- Python 3.13/3.14 are configured in CI, but should be confirmed by GitHub Actions before calling the release broadly stable.
- Windows installer/app packaging is intentionally out of scope for this release.

## [0.1.0] - 2026-05-24

### Added

- **Benchmark Suite**: 11 deterministic benchmark tasks with mock provider covering file I/O, multi-step reasoning, security boundaries, error recovery, large file handling, and memory pressure. `python -m benchmarks.runner --mock` for CI regression detection.
- **Comprehensive Integration Tests**: 40 new tests in `tests/test_comprehensive_integration.py` covering 11 subsystems end-to-end.
- **I/O Boundary Tests**: 13 tests in `tests/test_io_boundaries.py` for path traversal, nonexistent files, empty directories, offset/limit reads, and DB rollback behavior.
- **Web Router Tests**: 50 dedicated tests across `tests/web/` for chat, cron, fleet, plugins, and system routers.
- **Core Attachments Module**: Extracted `js/core/attachments.py` from `js/agent.py` for PDF/Excel/text extraction and size formatting.
- **TUI Dashboard**: Textual-based terminal UI (`js/tui/`) with chat log, sidebar, status bar, and tool panel widgets.
- **Cron & Daemon**: Natural language → cron expression parser (`js/cron/`) and 24/7 background daemon (`js/daemon/`).
- **Web Routers**: Modular FastAPI routers for chat, cron, fleet, plugins, and system endpoints.
- **First-Start Wizard**: Web UI modal that guides new users through model selection on first visit. Stores completion in config (`first_run_completed`).
- **Model Switcher**: Active model displayed in header and Models tab; switch without server restart via `POST /api/models/switch`.
- **Transparent Editable Memory**: Memory tab shows `source` citations, `category` badges, and inline Edit/Delete buttons for semantic memories.
- **Factory Documentation Demo**: Self-contained `demos/factory/` with real product specs, SOPs, and QC checklists plus `ingest.py` script.
- **Stability Recovery Tests**: 9 new tests covering model disconnect/reconnect, task interruption/checkpoint survival, database corruption recovery, and Web restart resume.
- **Hermes Skill Bridge**: Seamlessly load and execute 93+ Hermes-format skills with automatic namespace isolation (`hermes:` prefix).
- **Hardline Security Blocklist**: Irreversible operations (`rm -rf /`, `dd`, `mkfs`, `fork bomb`, shutdown) are blocked unconditionally, even in `defense_mode=off`.
- **Repeated Failure Guard**: Hermes-style guardrail that blocks a tool after 3+ consecutive failures in the same run, preventing failure spirals.
- **Tool Result Caching**: LRU cache with TTL for idempotent read-only tools (`file_read`, `browser_fetch`, `web_search`, etc.), reducing redundant LLM API calls.
- **Automatic Parameter Inference**: Scans Python scripts for `argparse` definitions and manual `sys.argv` parsers to build JSON schema for skill tool registration.
- **Runtime Security Check**: Lightweight integrity hash + quarantine path detection + sensitive path scanning on every skill execution.
- **Hermes Bridge Refresh**: `POST /api/skills/hermes/refresh` for runtime hot-reload without server restart.
- **Strategy-Based Defense**: Pluggable `DefenseStrategy` registry for tool-call guardrails (command block, path protection, loop guard).
- **Secret Redaction**: Automatic detection and masking of API keys, tokens, passwords in user input and tool outputs.
- **Behavior Audit**: Immutable hash-chained audit log of every tool call, model response, and security event.
- **Context Compression**: Hermes-style compressor that preserves head/tail context while summarizing the middle.
- **Checkpoint Snapshots**: Transparent Git shadow repo for safe rollback after agent operations.
- **Local Model Auto-Discovery**: Automatically detects LM Studio (port 1234) and Ollama (port 11434).
- **Web UI**: FastAPI + WebSocket server with skills management, memory browser, audit trail, and model configuration.
- **Self-Learning & Evolution**: A/B prompt optimization, skill auto-evolution, metacognition loop, and composition chain discovery.
- **MCP Support**: Native stdio/SSE Model Context Protocol client integration.

### Fixed

- **FastAPI auth dependency body-parsing interference**: `require_auth()` no longer declares `settings` parameter, preventing FastAPI from wrapping POST bodies in `{"payload": ..., "settings": ...}`. Reads `_settings` internally instead.
- **File path traversal uncaught exception**: `js/tools/files.py` now wraps `_resolve()` and `guard.check_path_operation()` in try/except, returning `ToolResult(success=False, error=...)` instead of raising on traversal.
- **Cancel token race condition**: Cancel check in `agent.run()` now happens *before* `turn_count += 1`, preventing off-by-one turn accounting when cancelled.
- **StateStore corruption recovery**: `_ensure_db()` now deletes and recreates corrupted SQLite files instead of crashing.
- **Circuit breaker deadlock**: `get_stats()` inlined `can_execute` logic to avoid recursive `asyncio.Lock` deadlock.
- **Memory store SQL parameter type**: `get_working()` and `get_episodes()` now correctly bind `session_id` as string parameter.
- **Pipeline deprecation warnings**: Replaced all `datetime.utcnow()` with `datetime.now(timezone.utc)` across 9 pipeline files.
- **Config save clobbering**: `JSSettings.save()` now merges with existing file instead of overwriting, preserving providers/models.
- **Duplicate providers**: `LocalModelDiscovery` deduplicates by `base_url` (prevents `127.0.0.1` + `localhost` duplicates).
- **Unloaded models in list**: LM Studio discovery now filters to `state == "loaded"` via `/api/v0/models`.
- **Embedder auto-discovery**: `_setup_embedder()` probes LM Studio when providers are empty; auto-detects embedding model name.
- **Cross-platform signal handling**: Windows `SIGTERM`/`SIGINT` unsupported → catch `NotImplementedError`/`ValueError`/`RuntimeError` in `web/server.py`, `daemon/core.py`, and `telegram_bot.py`.
- **Web UI auth hardening**: Added `X-API-Key` requirement to `/ws`, `/api/chat`, `/api/providers/discover`, `/api/providers/scan-lan`; removed bootstrap admin creation vulnerability.
- **Circuit breaker half-open recovery**: Single success now correctly closes the circuit; health check decoupled from circuit breaker failure counting.
- **Sandbox safety**: Linux `unshare` command injection fixed via `shlex.quote`; `_kill_process_tree` hardened against `AccessDenied`/`OSError`; `_monitor_memory` silently handles `CancelledError`.
- **Fleet isolation**: Each spawned fleet agent gets independent `state_dir` under `fleet/{uuid}/` to prevent SQLite contention.
- **Search empty-result fallback**: Empty results no longer trigger unnecessary engine fallback.
- **Skill integrity**: `compute_hash()` now covers all code files (`.py`, `.sh`, `.js`, `scripts/`) not just `SKILL.md`.
- **Workflow shell**: Switched from `create_subprocess_exec(*shlex.split(...))` to `sh -c` to support pipes and redirections.
- **DreamScheduler consolidation**: Implemented `force_consolidation()` so cron dream tasks work correctly.
- **Collaborate deadlock prevention**: Added 10-minute timeout via `asyncio.wait_for(self._bus.get(), timeout=...)`.
- **Test suite reliability**: `test_sandbox.py::test_network_allowed_true_can_fetch` rewritten with deterministic short timeouts and auto-close server lifecycle; `test_orchestration.py` fleet fixture uses `tmp_path` isolation; `test_integration_e2e.py` replaced `JSSettings.from_file()` with `tmp_path`-based settings.

### Changed

- **TUI type completeness**: `js/tui/` no longer excluded from mypy; 5 type errors fixed. 131 files now pass strict mypy.
- **Tests**: 849 passed covering security (red-team + fuzz + sandbox), skills, Hermes bridge, tool execution, memory quality, provider failover, Auto-Fetch pipeline, checkpoint/resume, benchmark, web API, orchestration, and E2E integration.
- **Build tooling**: `build>=1.2` added to dev dependencies; `python -m build` verified producing `js_agent-0.1.0.tar.gz` and `js_agent-0.1.0-py3-none-any.whl`.
- **Agent refactoring**: `js/agent.py` slimmed from ~1526 to ~1270 lines. `_build_system_message()` cached with `TTLCache`. `_execute_tool_call()` and `_finalize_run()` extracted as dedicated methods.
- **Auto-Fetch connectors marked experimental**: Gmail/Slack/Drive/Calendar/GitHub/Notion are mock/experimental. Documented in README.
- **Windows installer**: `install.ps1` now supports `-NoShortcut`, `-NoStart`, `-ProjectDir` parameters.
- **Multi-device test checklist**: Added `MULTI_DEVICE_TEST_CHECKLIST.md` with macOS/Windows/Docker/Recovery steps.

### Security

- 6 risk pattern categories for skill scanning: network_exfil, credential_access, code_execution, file_deletion, obfuscation, sensitive_path_access.
- 4-tier trust level system: builtin → trusted → community → quarantine.
- Sandbox execution for community/quarantine code skills with timeout, memory, and output limits.

### Testing

- **831 tests** with **Ruff** linting and **mypy** strict type checking passing with zero errors.

[0.1.0]: https://github.com/JiangSkirk/titan-agent/releases/tag/v0.1.0
[0.1.1-alpha]: https://github.com/JiangSkirk/titan-agent/releases/tag/v0.1.1-alpha
[0.1.2-alpha]: https://github.com/JiangSkirk/titan-agent/releases/tag/v0.1.2-alpha
[0.1.3-alpha]: https://github.com/JiangSkirk/titan-agent/releases/tag/v0.1.3-alpha
[0.1.5]: https://github.com/JiangSkirk/titan-agent/releases/tag/v0.1.5

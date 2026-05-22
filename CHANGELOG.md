# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-18

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

### Changed

- **TUI type completeness**: `js/tui/` no longer excluded from mypy; 5 type errors fixed. 131 files now pass strict mypy.
- **Tests**: 831 passed covering security (red-team + fuzz + sandbox), skills, Hermes bridge, tool execution, memory quality, provider failover, Auto-Fetch pipeline, checkpoint/resume, benchmark, web API, and orchestration.
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

[0.1.0]: https://github.com/yourusername/js-agent/releases/tag/v0.1.0

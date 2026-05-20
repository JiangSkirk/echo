# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-05-20

### Added

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

### Security

- 6 risk pattern categories for skill scanning: network_exfil, credential_access, code_execution, file_deletion, obfuscation, sensitive_path_access.
- 4-tier trust level system: builtin → trusted → community → quarantine.
- Sandbox execution for community/quarantine code skills with timeout, memory, and output limits.

### Testing

- 319 tests covering security, skills, Hermes bridge, tool execution, memory, evolution, web API, and orchestration.
- Ruff linting and mypy strict type checking pass with zero errors.

[0.1.0]: https://github.com/yourusername/js-agent/releases/tag/v0.1.0

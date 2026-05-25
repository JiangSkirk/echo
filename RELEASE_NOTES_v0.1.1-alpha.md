# JS Agent v0.1.1-alpha

This is a macOS-first public testing release of JS Agent.

JS Agent is an AI agent framework focused on long-term memory, reliable local model access, convenient setup, skill compatibility, and practical Web UI usage. This alpha release is meant for early users who want to try the project on macOS and help validate real-world installation and model-provider workflows.

## Release Positioning

This is **not a final stable release** yet. It is an alpha build prepared for public testing.

Recommended environment:

- macOS
- Python 3.12
- LM Studio or Ollama for local OpenAI-compatible models

Python 3.13 and 3.14 are included in the CI matrix, but Python 3.12 is the path verified locally before this release.

## Quick Start

```bash
git clone https://github.com/JiangSkirk/titan-agent.git
cd titan-agent
./scripts/macos_start.sh
```

The startup script will:

- create `.venv` if needed
- install runtime dependencies
- run initial setup if no config exists
- open the Web UI

Manual start:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
js setup
js web --port 8000
```

## Highlights

- macOS-first one-command startup through `scripts/macos_start.sh`
- Web UI with model management, skills, memory, audit, fleet, and evolution panels
- Local model provider support for LM Studio and Ollama
- OpenAI-compatible provider configuration for cloud or local models
- Dream memory consolidation with light / REM / deep phases
- Autonomous evolution entrypoint for profile update, dreaming, and skill evolution
- Multi-agent fleet support with role-based agents
- Skill system with prompt/code/workflow support
- OpenClaw-style and Hermes-style skill compatibility smoke-tested
- 12 builtin skills, including `file-search`, `code-review`, `excel-helper`, and `pdf-helper`
- DuckDuckGo web search fixed and verified through both API and CLI paths
- Release smoke test script for package, Web, model, skills, dream memory, evolution, and fleet checks

## Fixes In This Release

- Fixed DuckDuckGo result parsing when results are wrapped in `uddg` redirect URLs.
- Fixed `js search` CLI crash caused by a Click parameter mismatch.
- Added `python-multipart` so FastAPI upload routes start correctly.
- Improved local provider discovery by avoiding environment proxy interference.
- Improved `/api/models` refresh behavior for local model providers.
- Moved stale Excel/PDF helper skills into the real builtin skill directory.
- Removed stale Windows installer path from this macOS-first release.
- Added generated cache ignores for `.mypy_cache/` and `.ruff_cache/`.

## Verification

This release was checked locally on macOS with Python 3.12:

```bash
ruff check js tests scripts pyproject.toml
mypy js
pytest -q
python scripts/release_smoke.py --all
python -m js search "OpenAI"
python -m build
```

Observed result:

- Ruff: passed
- mypy: passed across 131 source files
- Tests: 856 passed
- Functional smoke: passed
- Release smoke: passed
- Wheel build: passed
- Fresh temporary macOS virtual environment installing the built wheel: passed

Functional smoke covered:

- scheduled tasks
- dream memory
- autonomous evolution
- multi-agent fleet
- web search
- skill execution
- Web/model release paths

## Known Limitations

- This release is alpha quality.
- macOS is the primary target for this version.
- Windows installer/app packaging is intentionally not included in this release.
- Python 3.13/3.14 support should be confirmed by GitHub Actions before marking the project stable.
- Some Auto-Fetch connectors are still experimental/mock-level.

## Feedback Wanted

Please report:

- macOS installation failures
- LM Studio / Ollama model detection problems
- Web UI connection issues
- skill installation or execution failures
- memory reliability issues
- confusing setup steps

This release is intended to validate whether JS Agent can become a convenient, reliable agent that ordinary users can install and run without heavy manual configuration.

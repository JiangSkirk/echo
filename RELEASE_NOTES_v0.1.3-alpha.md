# JS Agent v0.1.3-alpha

This alpha release is a quality-gate and release-hardening patch on top of v0.1.2-alpha.

## Fixed

- **Benchmark regression**: Removed `/` from default `protected_paths` so that normal workspace file writes are no longer incorrectly blocked by the `path_protection` defense strategy.
- **Release smoke failures**: Updated `scripts/release_smoke.py` to send the required `Origin` header for state-changing POST requests in local no-auth mode.
- **Pytest warnings**:
  - Fixed an `AsyncMock` "never awaited" warning in `tests/test_net_guard_rebinding.py` by mocking HTTP responses with `MagicMock` instead of `AsyncMock`.
  - Added `httpx2` to dev dependencies so Starlette's `TestClient` no longer emits a deprecation warning when using plain `httpx`.
- **Clean release smoke output**: `MemoryOrganizer` now prints a short Chinese degrade message instead of a full Rich traceback when no model is configured.

## Changed

- `.gitignore` now excludes `.playwright-mcp/` runtime cache files.
- `uv.lock` synchronized with the new `httpx2` dev dependency.
- Version bumped to `0.1.3-alpha` across package metadata, CLI, TUI, and README.

## Verified

- `pytest tests/ -q --tb=short` → 1230 passed, 2 skipped, 11 deselected
- `ruff check js/ tests/ scripts/` → All checks passed
- `mypy js/ --no-error-summary` → zero errors
- `python -m benchmarks.runner --mock` → Overall score 1.000 / Baseline 1.000
- `python scripts/release_smoke.py --all` → passed
- Fresh-install acceptance (isolated throwaway HOME) → passed

## Install

```bash
git clone https://github.com/JiangSkirk/titan-agent.git
cd titan-agent
./scripts/macos_start.sh
```

## Status

This remains an alpha/macOS-first public testing build.

# syntax=docker/dockerfile:1

# ---- base: system dependencies + runtime source (shared by all targets) ----
FROM python:3.12-slim AS base

# Install git (needed for checkpoints) and other system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Pinned uv for frozen, hash-locked dependency installs (same pin as
# scripts/deploy.sh) so the image runs the audited uv.lock resolution
# instead of re-resolving from PyPI at build time.
COPY --from=ghcr.io/astral-sh/uv:0.11.24 /uv /uvx /usr/local/bin/

# Set working directory
WORKDIR /app

# Copy project metadata + lockfile first for better layer caching
COPY pyproject.toml README.md uv.lock ./

# Copy runtime source code; resources/tokenizer is force-included into the
# wheel build (pyproject.toml [tool.hatch.build.targets.wheel]) and must be
# present or the build fails
COPY js/ ./js/
COPY js_work/ ./js_work/
COPY resources/ ./resources/

# ---- dev: editable install with dev extras and tests (compose profile: dev) ----
FROM base AS dev

# Copy the test suite for in-image development
COPY tests/ ./tests/

# Install the project (editable by default) with development extras, frozen
RUN uv sync --frozen --extra dev

ENV PATH="/app/.venv/bin:$PATH"
# AppShell skips Host lifespan key minting; Docker cannot use loopback
# POST /api/appshell/bootstrap (bridge traffic is not 127.0.0.1).
ENV JS_APPSHELL_PROVISION_KEY=1

# Expose the application port
EXPOSE 8000

# Default command: local AppShell Host (does not open a browser)
CMD ["js", "appshell", "--host", "0.0.0.0", "--port", "8000", "--no-browser"]

# ---- production: frozen non-editable install, non-root (DEFAULT target) ----
# Keep this stage LAST so a bare `docker build .` produces the hardened
# image rather than the root-running dev variant.
FROM base AS production

# Frozen, hash-verified install without dev extras, non-editable
RUN uv sync --frozen --no-dev --no-editable

ENV PATH="/app/.venv/bin:$PATH"
ENV JS_APPSHELL_PROVISION_KEY=1

# Create non-root user for security
RUN useradd -m appuser

# Switch to non-root user
USER appuser

# Work home defaults to /home/appuser/.js-work (credentials, memory, ledger).
# Persist it with a host volume; JS_STATE_DIR only covers Personal.

# Expose the application port
EXPOSE 8000

# Default command: local AppShell Host (does not open a browser)
CMD ["js", "appshell", "--host", "0.0.0.0", "--port", "8000", "--no-browser"]

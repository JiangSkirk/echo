# syntax=docker/dockerfile:1

FROM python:3.12-slim

# Install git (needed for checkpoints) and other system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m appuser

# Set working directory
WORKDIR /app

# Copy project metadata first for better layer caching
COPY pyproject.toml README.md ./

# Copy source code and tests
COPY js/ ./js/
COPY js_work/ ./js_work/
COPY tests/ ./tests/

# Install the package with development dependencies
RUN pip install --no-cache-dir -e ".[dev]"

# Switch to non-root user
USER appuser

# Expose the application port
EXPOSE 8000

# Default command: run the web server
CMD ["js", "web", "--host", "0.0.0.0", "--port", "8000"]

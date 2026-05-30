"""Structured logging configuration."""

from __future__ import annotations

import logging
import os
import sys

import structlog


def configure_logging(level: str = "INFO") -> None:
    """Configure structured logging for the application.

    By default logs are written to *stderr* only.  If the environment
    variable ``JS_LOG_FILE`` is set, a ``RotatingFileHandler`` is also
    attached so logs are persisted to disk with automatic rotation.

    Rotation parameters can be controlled via:
    - ``JS_LOG_MAX_BYTES`` — max size of a single log file (default 10 MiB)
    - ``JS_LOG_BACKUP_COUNT`` — number of rotated files to keep (default 5)
    """
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]

    log_file = os.getenv("JS_LOG_FILE")
    if log_file:
        from logging.handlers import RotatingFileHandler

        max_bytes = int(os.getenv("JS_LOG_MAX_BYTES", "10485760"))
        backup_count = int(os.getenv("JS_LOG_BACKUP_COUNT", "5"))
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handlers.append(file_handler)

    logging.basicConfig(
        format="%(message)s",
        handlers=handlers,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer() if not sys.stderr.isatty() else structlog.dev.ConsoleRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]

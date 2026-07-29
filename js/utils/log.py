"""Structured logging configuration."""

from __future__ import annotations

import logging
import os
import sys
import threading
import traceback
from collections.abc import Callable, MutableMapping
from typing import Any, cast

import structlog

_MAX_LOG_TEXT_CHARS = 20_000
_MAX_LOG_COLLECTION_ITEMS = 128
_MAX_LOG_NESTING = 8
_LOG_CONFIGURATION_LOCK = threading.Lock()
_LOG_REDACTOR: Callable[[str], str] | None = None


def _redact_log_text(value: str) -> str:
    """Load the shared scanner lazily to avoid security/log import cycles."""
    global _LOG_REDACTOR
    if _LOG_REDACTOR is None:
        try:
            from js.security.secrets import redact_known_secrets
        except (AttributeError, ImportError):
            return "[REDACTED:log-scan-unavailable]"
        _LOG_REDACTOR = redact_known_secrets
    try:
        return _LOG_REDACTOR(value)
    except Exception:
        return "[REDACTED:log-scan-failed]"


def _redact_log_value(value: Any, *, depth: int = 0) -> Any:
    """Secret-scan and bound one value immediately before log rendering."""
    if depth > _MAX_LOG_NESTING:
        return "[truncated:nesting]"
    if isinstance(value, str):
        return _redact_log_text(value)[:_MAX_LOG_TEXT_CHARS]
    if isinstance(value, bytes):
        return f"[bytes:{len(value)}]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, dict):
        items = list(value.items())
        redacted = {
            _redact_log_text(str(key))[:256]: _redact_log_value(
                item,
                depth=depth + 1,
            )
            for key, item in items[:_MAX_LOG_COLLECTION_ITEMS]
        }
        if len(items) > _MAX_LOG_COLLECTION_ITEMS:
            redacted["[truncated]"] = len(items) - _MAX_LOG_COLLECTION_ITEMS
        return redacted
    if isinstance(value, list | tuple | set | frozenset):
        items = list(value)
        redacted_items = [
            _redact_log_value(item, depth=depth + 1)
            for item in items[:_MAX_LOG_COLLECTION_ITEMS]
        ]
        if len(items) > _MAX_LOG_COLLECTION_ITEMS:
            redacted_items.append(
                f"[truncated:{len(items) - _MAX_LOG_COLLECTION_ITEMS}]"
            )
        return redacted_items
    return _redact_log_text(str(value))[:_MAX_LOG_TEXT_CHARS]


def _redact_log_event(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> dict[str, Any]:
    """Structlog processor enforcing secret scanning on the final event."""
    return cast("dict[str, Any]", _redact_log_value(event_dict))


def _format_exception_for_log_redaction(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Format exception data as a normal field before the secret scanner."""
    existing = event_dict.pop("exception", None)
    if existing is not None:
        event_dict["error_traceback"] = existing
    raw_exc_info = event_dict.pop("exc_info", None)
    exc_info: tuple[type[BaseException], BaseException, Any] | None = None
    if raw_exc_info is True:
        current = sys.exc_info()
        if current[0] is not None and current[1] is not None:
            exc_info = (current[0], current[1], current[2])
    elif isinstance(raw_exc_info, BaseException):
        exc_info = (
            type(raw_exc_info),
            raw_exc_info,
            raw_exc_info.__traceback__,
        )
    elif (
        isinstance(raw_exc_info, tuple)
        and len(raw_exc_info) == 3
        and isinstance(raw_exc_info[0], type)
        and isinstance(raw_exc_info[1], BaseException)
    ):
        exc_info = raw_exc_info
    if exc_info is not None:
        event_dict["error_traceback"] = "".join(
            traceback.format_exception(*exc_info)
        )
    return event_dict


def _ensure_default_log_redaction() -> None:
    """Install redaction even for programmatic users that skip CLI setup."""
    with _LOG_CONFIGURATION_LOCK:
        config = structlog.get_config()
        processors = list(config["processors"])
        if _redact_log_event in processors:
            return
        renderer_index = max(0, len(processors) - 1)
        processors.insert(renderer_index, _format_exception_for_log_redaction)
        renderer_index += 1
        processors.insert(renderer_index, _redact_log_event)
        structlog.configure(
            processors=processors,
            context_class=config["context_class"],
            wrapper_class=config["wrapper_class"],
            logger_factory=config["logger_factory"],
            cache_logger_on_first_use=config["cache_logger_on_first_use"],
        )


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
            _format_exception_for_log_redaction,
            structlog.processors.UnicodeDecoder(),
            _redact_log_event,
            structlog.processors.JSONRenderer() if not sys.stderr.isatty() else structlog.dev.ConsoleRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    _ensure_default_log_redaction()
    return structlog.get_logger(name)  # type: ignore[no-any-return]

"""Central logging redaction regressions."""

from __future__ import annotations

import json

import structlog

from js.utils.log import _redact_log_event, get_logger


def test_log_processor_redacts_nested_messages_and_formatted_exceptions() -> None:
    secret = "sk-" + "a" * 24
    event = {
        "event": f"provider failed with {secret}",
        "exception": f"RuntimeError: credential={secret}",
        "nested": {
            "items": [f"token={secret}", {"detail": secret}],
        },
    }

    redacted = _redact_log_event(None, "error", event)
    serialized = json.dumps(redacted, ensure_ascii=False)

    assert secret not in serialized
    assert "[REDACTED:openai_key]" in serialized


def test_log_processor_bounds_untrusted_values_and_binary_data() -> None:
    event = {
        "event": "x" * 30_000,
        "payload": b"private binary payload",
        "items": [str(index) for index in range(140)],
    }

    redacted = _redact_log_event(None, "info", event)

    assert len(redacted["event"]) <= 20_000
    assert redacted["payload"] == "[bytes:22]"
    assert len(redacted["items"]) == 129
    assert redacted["items"][-1] == "[truncated:12]"


def test_programmatic_logger_installs_redaction_without_cli_bootstrap() -> None:
    get_logger("programmatic-test")

    assert _redact_log_event in structlog.get_config()["processors"]

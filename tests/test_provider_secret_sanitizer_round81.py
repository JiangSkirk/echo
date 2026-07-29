"""Round 8.1 A: provider secret scrub must not use ambiguous ``\\1`` backrefs."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

import pytest

from js.config import ModelConfig, ModelProviderConfig
from js.models.capability import (
    SafeProviderError,
    redact_api_key,
    sanitize_provider_error,
)
from js.models.providers import ChatMessage, OpenAICompatibleProvider

_DIGIT_KEY = "1234567890123456"
_GROUP_REF_KEY = "9876abcdefXYZ"
_MIXED_PCT_KEY = "AbCdEf%2f%2FMix"
_BACKSLASH_KEY = r"sk-TEST\slash%2Fmix"


@pytest.mark.parametrize(
    "key",
    [_DIGIT_KEY, _GROUP_REF_KEY, _MIXED_PCT_KEY, _BACKSLASH_KEY],
)
def test_query_param_scrub_handles_digit_and_group_ref_keys(key: str) -> None:
    url = f"https://example.test/v1?api_key={key}&q=1"
    out = sanitize_provider_error(url, api_key=key, query_param_name="api_key")
    redacted = redact_api_key(key)
    assert key not in out
    assert redacted in out
    assert f"api_key={redacted}" in out
    assert not out.startswith("https://example.test/v1?J")


@pytest.mark.asyncio
async def test_provider_metrics_secondary_failure_does_not_leak_secret(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    secret = _DIGIT_KEY
    provider = object.__new__(OpenAICompatibleProvider)
    provider.config = ModelProviderConfig(
        name="round81-provider",
        base_url="https://example.test/v1",
        api_key=secret,
        auth_adapter="query_param",
        query_param_name="api_key",
        default_model="m",
        models=[ModelConfig(id="m", name="M", context_window=1024)],
    )
    provider._is_local = False

    class _BoomCircuit:
        async def can_execute(self) -> bool:
            return True

        async def execute(self, coro: Any) -> Any:
            return await coro

    provider.circuit = _BoomCircuit()  # type: ignore[assignment]

    async def _fail_create(**kwargs: Any) -> Any:
        del kwargs
        raise RuntimeError(f"upstream failed key={secret} url=https://x/?api_key={secret}")

    provider.client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=_fail_create))
    )

    class _BrokenMetric:
        def labels(self, **kwargs: Any) -> Any:
            del kwargs
            raise RuntimeError("metrics unavailable")

        def observe(self, *_a: Any, **_k: Any) -> None:
            raise RuntimeError("metrics unavailable")

        def inc(self, *_a: Any, **_k: Any) -> None:
            raise RuntimeError("metrics unavailable")

    class _BrokenMetrics:
        model_requests_total = _BrokenMetric()
        model_latency_seconds = _BrokenMetric()
        model_errors_total = _BrokenMetric()

    monkeypatch.setattr("js.models.providers.get_metrics", lambda: _BrokenMetrics())

    with caplog.at_level(logging.WARNING), pytest.raises(SafeProviderError) as caught:
        await provider.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="m",
        )

    err = caught.value
    blob = " | ".join(
        [
            str(err),
            repr(err),
            repr(err.__cause__),
            repr(err.__context__),
            caplog.text,
        ]
    )
    assert secret not in blob
    assert err.__cause__ is None
    assert err.__context__ is None

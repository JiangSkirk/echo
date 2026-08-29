from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from js.config import ModelConfig, ModelProviderConfig
from js.models.providers import ChatMessage, OpenAICompatibleProvider


class _Circuit:
    async def can_execute(self) -> bool:
        return True

    async def record_success(self) -> None:
        return None

    async def record_failure(self) -> None:
        return None


@pytest.mark.asyncio
async def test_provider_stream_performs_one_transport_attempt_and_delegates_retry_to_router(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    async def fail_create(**_kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("temporary transport failure")

    async def no_wait(_delay: float) -> None:
        return None

    provider = object.__new__(OpenAICompatibleProvider)
    provider.config = ModelProviderConfig(
        name="provider-a",
        base_url="https://invalid.example/v1",
        max_retries=3,
        default_model="model-a",
    )
    provider._is_local = False
    provider._last_stream_usage = None
    provider.circuit = _Circuit()
    provider.client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=fail_create))
    )
    monkeypatch.setattr("js.models.providers.asyncio.sleep", no_wait)

    events = [
        event
        async for event in provider.chat_stream_events(
            messages=[ChatMessage(role="user", content="hello")],
            model="model-a",
        )
    ]

    assert calls == 1
    assert len(events) == 1 and events[0].kind == "error"
    assert events[0].meta["retryable"] is True


def test_openai_provider_defers_http_client_until_first_use() -> None:
    provider = OpenAICompatibleProvider(
        ModelProviderConfig(
            name="lazy",
            base_url="http://127.0.0.1:9/v1",
            default_model="model-a",
            models=[ModelConfig(id="model-a", name="model-a")],
        )
    )
    assert provider._client is None
    client = provider.client
    assert client is not None
    assert provider._client is client

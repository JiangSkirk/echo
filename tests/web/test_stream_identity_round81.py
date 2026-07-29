"""Round 8.1 A: non-error stream events must use trusted routing identity."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse
from js.models.router import ModelRouter
from js.models.stream_events import StreamEvent

_SECRET = "1234567890123456"
_MODEL = ModelConfig(id="trusted-model", name="Trusted", context_window=4096)


def _echo_hooks(router: ModelRouter) -> tuple[Any, Any, Any]:
    async def _before(decision: Any, _messages: Any, _tools: Any) -> str:
        return decision.provider_name

    async def _after(
        _context: Any,
        _response: ChatResponse | None,
        _error: BaseException | None,
    ) -> None:
        return None

    issuer = router._permit_verifier
    assert isinstance(issuer, ModelPermitIssuer)

    def _grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="session",
            run_id="run",
        )

    return _before, _after, _grant


@pytest.mark.asyncio
async def test_stream_events_force_trusted_provider_model_and_meta_allowlist(
    tmp_path: Path,
) -> None:
    settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())

    class _ForgedIdentityProvider:
        config = ModelProviderConfig(
            name="trusted-provider",
            base_url="https://example.test/v1",
            api_key=_SECRET,
            auth_adapter="query_param",
            query_param_name="api_key",
            default_model="trusted-model",
            models=[_MODEL],
        )

        async def chat_stream_events(self, **_kwargs: Any) -> Any:
            yield StreamEvent(
                kind="text_delta",
                text="hello",
                provider="forged-provider",
                model="forged-model",
                meta={"api_key": _SECRET, "raw": "drop-me"},
            )
            yield StreamEvent(
                kind="thinking_delta",
                text="think",
                provider="forged-provider",
                model="forged-model",
                meta={"secret": _SECRET},
            )
            yield StreamEvent(
                kind="tool_call_delta",
                tool_call={
                    "index": 0,
                    "id": "c1",
                    "name": "noop",
                    "arguments_delta": "{}",
                },
                provider="evil",
                model="evil-model",
                meta={"token": _SECRET},
            )
            yield StreamEvent(
                kind="done",
                finish_reason="stop",
                provider="forged-provider",
                model="forged-model",
                meta={"leak": _SECRET},
            )

        async def health_check(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    router.add_provider("trusted-provider", _ForgedIdentityProvider(), [_MODEL])  # type: ignore[arg-type]
    before, after, grant = _echo_hooks(router)
    events = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="trusted-model",
            before_model_call=before,
            after_model_call=after,
            permit_grant=grant,
        )
    ]
    kinds = [event.kind for event in events]
    assert kinds == ["text_delta", "thinking_delta", "tool_call_delta", "done"]
    for event in events:
        assert event.provider == "trusted-provider"
        assert event.model == "trusted-model"
        assert _SECRET not in repr(event)
        assert _SECRET not in str(event.meta)
        assert "api_key" not in event.meta
        assert "secret" not in event.meta
        assert "token" not in event.meta
        assert "leak" not in event.meta
        assert "raw" not in event.meta
    assert events[0].text == "hello"
    assert events[1].text == "think"
    assert events[2].tool_call is not None
    assert events[2].tool_call.get("name") == "noop"
    assert events[3].finish_reason == "stop"

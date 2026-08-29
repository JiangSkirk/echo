"""Provider-via-cell transport keeps tokens out of Echo."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.models.cell_transport import (
    CellBackedChatProvider,
    ModelConnectorRequest,
    destination_is_allowed,
)
from js.models.providers import ChatMessage, ChatResponse
from js.orin.process_split import (
    provider_tokens_out_of_echo,
    reset_process_split_observations,
)
from js.orind.cells.services import SecretStore, relay_model_chat


def test_destination_allowlist() -> None:
    assert destination_is_allowed("https://api.example.com/v1", allowlist=("api.example.com",))
    assert not destination_is_allowed("https://evil.test/v1", allowlist=("api.example.com",))
    assert not destination_is_allowed("file:///etc/passwd", allowlist=())


@pytest.mark.asyncio
async def test_cell_backed_provider_has_no_api_key() -> None:
    reset_process_split_observations()

    async def relay(request: ModelConnectorRequest) -> ChatResponse:
        assert request.secret_handle == "secret:demo"
        return ChatResponse(
            content="ok",
            tool_calls=[],
            model=request.model,
            usage={},
            finish_reason="stop",
        )

    provider = CellBackedChatProvider(
        destination="https://api.example.com/v1/chat",
        secret_handle="secret:demo",
        relay=relay,
        allowlist=("api.example.com",),
    )
    assert provider.api_key is None
    assert provider_tokens_out_of_echo() is True
    response = await provider.chat(
        [ChatMessage(role="user", content="hi")],
        model="demo",
    )
    assert response.content == "ok"
    reset_process_split_observations()


def test_relay_model_chat_uses_secret_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SecretStore(tmp_path)
    store.put("secret:demo", "tok-secret")
    captured: dict[str, object] = {}

    class _Resp:
        status_code = 200
        headers = {"content-type": "application/json"}
        text = "{}"

        def json(self) -> dict[str, str]:
            return {"content": "ok"}

    class _Client:
        def __init__(self, timeout: float) -> None:
            del timeout

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def post(self, url: str, json: dict[str, object], headers: dict[str, str]) -> _Resp:
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return _Resp()

    monkeypatch.setattr("js.orind.cells.services.httpx.Client", _Client)
    result = relay_model_chat(
        state_dir=tmp_path,
        destination="https://api.example.com/v1/chat",
        secret_handle="secret:demo",
        body={"model": "demo"},
        allowlist=frozenset({"api.example.com"}),
    )
    assert result["status"] == "COMMITTED"
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "Bearer tok-secret"
    assert "tok-secret" not in str(result)

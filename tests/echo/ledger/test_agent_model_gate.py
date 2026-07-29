from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.agent import JSAgent
from js.config import JSSettings, ModelConfig, SecurityConfig
from js.echo.attachment_gate import owner_slug, session_slug
from js.echo.durable_thread import (
    DurableClaim,
    EchoDurableExecutor,
    claim_to_thread,
    durable_to_thread,
)
from js.echo.ledger.journal import FileEchoLedger
from js.echo.ledger.service import EchoBlockedError, EchoUnavailableError
from js.echo.turn_context import (
    RuntimeContext,
    current_runtime_context,
    reset_current_owner_key_hash,
    reset_runtime_context,
    set_current_owner_key_hash,
    set_runtime_context,
)
from js.echo.turn_loop import EchoTurnLoop
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter, RoutingDecision
from js.models.stream_events import StreamEvent
from js.tools.images import MAX_IMAGE_SIZE, create_image_message

_TEST_DURABLE_EXECUTOR = EchoDurableExecutor(thread_name_prefix="echo-model-gate-test")


def _grant(router: ModelRouter) -> Any:
    """Issue a fresh single-use permit per provider attempt, like the runtime."""
    issuer = router._permit_verifier
    assert isinstance(issuer, ModelPermitIssuer)

    def grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="session",
            run_id="run",
        )

    return grant


class _Provider(ModelProvider):
    def __init__(self) -> None:
        self.calls: list[list[ChatMessage]] = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls.append(messages)
        return ChatResponse(
            content="ok",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        async def _stream() -> AsyncIterator[str]:
            self.calls.append(messages)
            yield "ok"

        return _stream()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class _Router(ModelRouter):
    def __init__(self, provider: _Provider, permit_verifier: Any | None = None) -> None:
        self.settings = JSSettings()
        self._providers = {"mock": provider}
        self._model_map = {}
        self._permit_verifier = permit_verifier

    async def select_model(
        self,
        _task_complexity: str = "medium",
        preferred: str | None = None,
    ) -> RoutingDecision:
        return RoutingDecision(
            provider=self._providers["mock"],
            model=preferred or "mock-model",
            provider_name="mock",
            reason="test",
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        before_model_call: Any = None,
        after_model_call: Any = None,
        permit_grant: Any = None,
    ) -> ChatResponse:
        decision = await self.select_model(preferred=model)
        if permit_grant is None:
            raise AssertionError("test router requires a runtime permit grant")
        self._consume_model_permit(permit_grant, decision, messages, tools)
        context = None
        if before_model_call is not None:
            context = await before_model_call(decision, messages, tools)
        try:
            response = await decision.provider.chat(
                messages,
                decision.model,
                tools,
                temperature,
                max_tokens,
            )
        except Exception as exc:
            if after_model_call is not None:
                await after_model_call(context, None, exc)
            raise
        if after_model_call is not None:
            await after_model_call(context, response, None)
        return response


class _OpaqueRouter:
    def __init__(self) -> None:
        self.calls: list[list[ChatMessage]] = []
        self.stream_calls: list[list[ChatMessage]] = []

    def get_model_config(self, model: str = "") -> ModelConfig:
        return ModelConfig(id=model or "opaque-model", name="Opaque", provider="opaque")

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls.append(messages)
        return ChatResponse(
            content="opaque ok",
            tool_calls=[],
            model=model or "opaque-model",
            usage={"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
            finish_reason="stop",
        )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        async def _stream() -> AsyncIterator[str]:
            self.stream_calls.append(messages)
            yield "opaque"
            yield " stream"

        return _stream()


class _LegacySelectRouter:
    """Legacy router shape that can select a provider but cannot carry a permit."""

    def __init__(self, provider: _Provider) -> None:
        self.provider = provider

    async def select_model(
        self,
        _task_complexity: str = "medium",
        preferred: str | None = None,
    ) -> RoutingDecision:
        return RoutingDecision(
            provider=self.provider,
            model=preferred or "legacy-model",
            provider_name="legacy",
            reason="legacy test router",
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        raise AssertionError("legacy router.chat() must not be used in Echo on-mode")


class _StreamEventsProvider(ModelProvider):
    def __init__(self, events: list[StreamEvent]) -> None:
        self.events = events
        self.calls: list[str] = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        raise AssertionError("chat() should not be called by stream-events test")

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        raise AssertionError("chat_stream() should not be called by stream-events test")

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[StreamEvent]:
        self.calls.append(model)
        for event in self.events:
            yield event

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class _BlockingProvider(_Provider):
    def __init__(self) -> None:
        super().__init__()
        self.entered = asyncio.Event()

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        del model, tools, temperature, max_tokens
        self.calls.append(messages)
        self.entered.set()
        await asyncio.Event().wait()
        raise AssertionError("blocking provider was not cancelled")


def _agent(tmp_path: Path) -> tuple[JSAgent, _Provider]:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    provider = _Provider()
    agent = JSAgent(settings)
    agent.router = _Router(provider, permit_verifier=agent._model_permit_issuer)
    return agent, provider


def _owned_upload(agent: JSAgent, owner: str, session_id: str, name: str) -> str:
    """Return a workspace-relative owner/session-scoped upload path."""
    return str(Path("uploads") / owner_slug(owner) / session_slug(session_id) / name)


@pytest.mark.asyncio
async def test_model_output_is_redacted_before_entering_agent_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent, provider = _agent(tmp_path)
    secret = "sk-test12345678901234567890"

    async def leaking_chat(
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        del messages, tools, temperature, max_tokens
        return ChatResponse(
            content=f"answer contains {secret}",
            reasoning_content=f"reasoning contains {secret}",
            tool_calls=[
                {
                    "id": "secret-tool-call",
                    "type": "function",
                    "function": {
                        "name": "missing_tool",
                        "arguments": json.dumps({"token": secret}),
                    },
                }
            ],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1},
            finish_reason="tool_calls",
        )

    monkeypatch.setattr(provider, "chat", leaking_chat)
    try:
        state = await agent.run("hello", session_id="model-output-redaction")
        assistant = next(message for message in state.messages if message.role == "assistant")
        assert secret not in str(assistant.content)
        assert secret not in str(assistant.reasoning_content)
        assert secret not in str(assistant.tool_calls)
        assert "[REDACTED" in str(assistant.content)
        assert "[REDACTED" in str(assistant.reasoning_content)
        assert "[REDACTED" in str(assistant.tool_calls)
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_model_gate_blocks_secret_in_attachment_before_provider_call(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(tmp_path)
    owner = "owner-a"
    relative = _owned_upload(agent, owner, "session-a", "leak.txt")
    attachment = agent.settings.workspace / relative
    attachment.parent.mkdir(parents=True)
    attachment.write_text("api_key = sk-test-1234567890abcdef", encoding="utf-8")

    token = set_current_owner_key_hash(owner)
    try:
        with pytest.raises(EchoBlockedError, match="secret-like"):
            await agent.run(
                "summarize the attachment",
                session_id="session-a",
                attachments=[relative],
            )
    finally:
        reset_current_owner_key_hash(token)

    assert provider.calls == []


@pytest.mark.asyncio
async def test_model_gate_rejects_attachment_path_outside_workspace(tmp_path: Path) -> None:
    agent, provider = _agent(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside workspace", encoding="utf-8")

    with pytest.raises(PermissionError):
        await agent.run("read attachment", attachments=[str(outside)])

    assert provider.calls == []


@pytest.mark.asyncio
async def test_model_gate_rejects_plain_workspace_attachment_in_echo_on(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(tmp_path)
    attachment = agent.settings.workspace / "notes.txt"
    attachment.write_text("plain workspace attachment", encoding="utf-8")

    with pytest.raises(PermissionError, match="workspace attachment"):
        await agent.run("read attachment", attachments=["notes.txt"])

    assert provider.calls == []


@pytest.mark.asyncio
async def test_chat_stream_uses_same_model_gate_for_attachment_secrets(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(tmp_path)
    owner = "owner-a"
    relative = _owned_upload(agent, owner, "session-a", "stream-leak.txt")
    attachment = agent.settings.workspace / relative
    attachment.parent.mkdir(parents=True)
    attachment.write_text("Bearer abcdef1234567890", encoding="utf-8")

    token = set_current_owner_key_hash(owner)
    try:
        with pytest.raises(PermissionError):
            async for _token in agent.chat_stream(
                "stream the attachment",
                session_id="session-a",
                attachments=[relative],
            ):
                pass
    finally:
        reset_current_owner_key_hash(token)

    assert provider.calls == []


@pytest.mark.asyncio
async def test_text_attachment_preview_and_basename_enter_provider_prompt(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(tmp_path)
    owner = "owner-a"
    relative = _owned_upload(agent, owner, "session-a", "note.txt")
    attachment = agent.settings.workspace / relative
    attachment.parent.mkdir(parents=True)
    attachment.write_text("plain attachment preview", encoding="utf-8")

    token = set_current_owner_key_hash(owner)
    try:
        state = await agent.run("summarize", session_id="session-a", attachments=[relative])
    finally:
        reset_current_owner_key_hash(token)

    assert state.status == "completed"
    user_message = provider.calls[0][-1]
    assert isinstance(user_message.content, str)
    assert "summarize" in user_message.content
    assert "## 附件文件" in user_message.content
    assert "note.txt" in user_message.content
    assert "plain attachment preview" in user_message.content
    assert str(tmp_path) not in user_message.content


@pytest.mark.asyncio
async def test_direct_agent_run_rejects_upload_from_other_session(tmp_path: Path) -> None:
    agent, provider = _agent(tmp_path)
    owner = "owner-a"
    attachment = (
        agent.settings.workspace
        / "uploads"
        / owner_slug(owner)
        / session_slug("session-b")
        / "note.txt"
    )
    attachment.parent.mkdir(parents=True)
    attachment.write_text("cross-session attachment", encoding="utf-8")

    token = set_current_owner_key_hash(owner)
    try:
        with pytest.raises(PermissionError, match="session"):
            await agent.run(
                "summarize",
                session_id="session-a",
                attachments=[str(attachment.relative_to(agent.settings.workspace))],
            )
    finally:
        reset_current_owner_key_hash(token)

    assert provider.calls == []


@pytest.mark.asyncio
async def test_vision_env_vars_cannot_bypass_echo_vision_block(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """F-24/F-25 regression: setting the legacy env vars must NOT weaken the
    unconditional vision-upload and workspace-attachment gates."""
    agent, provider = _agent(tmp_path)
    monkeypatch.setenv("JS_ECHO_ALLOW_WORKSPACE_ATTACHMENTS", "1")
    monkeypatch.setenv("JS_ECHO_ALLOW_VISION_MODEL_UPLOADS", "1")
    agent.router._model_map["vision-model"] = (
        "mock",
        ModelConfig(id="vision-model", provider="mock", supports_vision=True),
    )
    owner = "owner-a"
    png_relative = _owned_upload(agent, owner, "session-a", "pixel.png")
    txt_relative = _owned_upload(agent, owner, "session-a", "note.txt")
    png = agent.settings.workspace / png_relative
    png.parent.mkdir(parents=True)
    png.write_bytes(b"\x89PNG\r\n\x1a\n")
    (agent.settings.workspace / txt_relative).write_text(
        "text preview survives vision", encoding="utf-8"
    )

    token = set_current_owner_key_hash(owner)
    try:
        with pytest.raises(PermissionError, match="Vision attachments"):
            await agent.run(
                "inspect both",
                model="vision-model",
                session_id="session-a",
                attachments=[png_relative, txt_relative],
            )
    finally:
        reset_current_owner_key_hash(token)

    assert provider.calls == []


@pytest.mark.asyncio
async def test_vision_attachment_blocks_by_default_without_vision_safety_approval(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent, provider = _agent(tmp_path)
    agent.router._model_map["vision-model"] = (
        "mock",
        ModelConfig(id="vision-model", provider="mock", supports_vision=True),
    )
    owner = "owner-a"
    relative = _owned_upload(agent, owner, "session-a", "pixel.png")
    attachment = agent.settings.workspace / relative
    attachment.parent.mkdir(parents=True)
    attachment.write_bytes(b"\x89PNG\r\n\x1a\n")

    def fail_if_encoded(_path: Path) -> dict[str, Any]:
        raise AssertionError("vision image was encoded before Echo approval")

    monkeypatch.setattr("js.tools.images.create_image_message", fail_if_encoded)

    token = set_current_owner_key_hash(owner)
    try:
        with pytest.raises(PermissionError, match="Vision attachments"):
            await agent.run(
                "inspect image",
                model="vision-model",
                session_id="session-a",
                attachments=[relative],
            )
    finally:
        reset_current_owner_key_hash(token)

    assert provider.calls == []


@pytest.mark.asyncio
async def test_vision_attachment_raw_bytes_secret_blocks_before_provider_call(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("JS_ECHO_ALLOW_WORKSPACE_ATTACHMENTS", "1")
    monkeypatch.setenv("JS_ECHO_ALLOW_VISION_MODEL_UPLOADS", "1")
    agent, provider = _agent(tmp_path)
    agent.router._model_map["vision-model"] = (
        "mock",
        ModelConfig(id="vision-model", provider="mock", supports_vision=True),
    )
    owner = "owner-a"
    relative = _owned_upload(agent, owner, "session-a", "leak.png")
    attachment = agent.settings.workspace / relative
    attachment.parent.mkdir(parents=True)
    attachment.write_bytes(
        b"\x89PNG\r\n\x1a\nnot-really-a-pixel sk-test-1234567890abcdef"
    )

    token = set_current_owner_key_hash(owner)
    try:
        with pytest.raises(PermissionError):
            await agent.run(
                "inspect image",
                model="vision-model",
                session_id="session-a",
                attachments=[relative],
            )
    finally:
        reset_current_owner_key_hash(token)

    assert provider.calls == []


def test_create_image_message_rejects_oversized_image_before_reading_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    image = tmp_path / "huge.png"
    with image.open("wb") as handle:
        handle.truncate(MAX_IMAGE_SIZE + 1)
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda self: (_ for _ in ()).throw(AssertionError("oversized image was read")),
    )

    with pytest.raises(ValueError, match="Image too large"):
        create_image_message(image)


@pytest.mark.asyncio
async def test_context_summary_uses_current_owner_tenant_journal(tmp_path: Path) -> None:
    agent, _provider = _agent(tmp_path)

    token = agent._push_summary_tenant("owner-summary")
    try:
        summary = await agent._summarize_context([ChatMessage(role="user", content="hello")])
    finally:
        agent._reset_summary_tenant(token)

    assert summary == "ok"
    owner_records = FileEchoLedger(
        agent.echo_safety_service.journal_path_for_scope(
            "owner-summary",
            product_id="js-agent",
            session_id="background-summary",
        ),
        mac_key=agent.echo_safety_service.journal_key_for_scope(
            "owner-summary",
            product_id="js-agent",
            session_id="background-summary",
        ),
    ).records
    assert owner_records
    default_records = (
        FileEchoLedger(
            agent.echo_safety_service.journal_path,
            mac_key=agent.echo_safety_service.journal_key,
        ).records
        if agent.echo_safety_service.journal_path.exists()
        else []
    )
    assert not [record for record in default_records if record.type == "model_call_requested"]


@pytest.mark.asyncio
async def test_real_model_router_propagates_echo_block_instead_of_fallback(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    provider = _Provider()
    agent = JSAgent(settings)
    router = ModelRouter(settings, permit_verifier=agent._model_permit_issuer)
    router.add_provider(
        "mock",
        provider,
        [ModelConfig(id="mock-model", name="Mock", provider="mock")],
    )
    agent.router = router
    owner = "owner-a"
    relative = _owned_upload(agent, owner, "session-a", "leak.txt")
    attachment = agent.settings.workspace / relative
    attachment.parent.mkdir(parents=True)
    attachment.write_text("token = sk-test-1234567890abcdef", encoding="utf-8")

    token = set_current_owner_key_hash(owner)
    try:
        with pytest.raises(PermissionError, match="secret"):
            await agent.run("summarize", session_id="session-a", attachments=[relative])
    finally:
        reset_current_owner_key_hash(token)

    assert provider.calls == []


@pytest.mark.asyncio
async def test_router_stream_events_authorizes_and_finalizes_fallback_provider(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    first = _StreamEventsProvider([StreamEvent(kind="error", error="first failed")])
    fallback = _StreamEventsProvider(
        [
            StreamEvent(kind="text_delta", text="fallback "),
            StreamEvent(kind="text_delta", text="ok"),
            StreamEvent(kind="usage", usage={"prompt_tokens": 7, "completion_tokens": 2}),
            StreamEvent(kind="done", finish_reason="stop"),
        ]
    )
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())
    router.add_provider("first", first, [ModelConfig(id="first-model", provider="first")])
    router.add_provider(
        "fallback",
        fallback,
        [ModelConfig(id="fallback-model", provider="fallback")],
    )
    before_models: list[str] = []
    after_results: list[tuple[str, str | None, str | None]] = []

    async def before(decision: RoutingDecision, messages: list[ChatMessage], tools: Any) -> str:
        before_models.append(decision.model)
        return decision.model

    async def after(
        context: str,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        after_results.append(
            (
                context,
                response.content if response is not None else None,
                str(error) if error is not None else None,
            )
        )

    events = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hello")],
            before_model_call=before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    assert [event.kind for event in events] == ["text_delta", "text_delta", "usage", "done"]
    assert before_models == ["first-model", "fallback-model"]
    assert after_results == [
        ("first-model", None, "first failed"),
        ("fallback-model", "fallback ok", None),
    ]


@pytest.mark.asyncio
async def test_router_stream_events_skips_failed_fallback_before_terminal_error(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    first = _StreamEventsProvider([StreamEvent(kind="error", error="first failed")])
    bad_fallback = _StreamEventsProvider([StreamEvent(kind="error", error="fallback failed")])
    good_fallback = _StreamEventsProvider(
        [
            StreamEvent(kind="text_delta", text="second "),
            StreamEvent(kind="text_delta", text="ok"),
            StreamEvent(kind="done", finish_reason="stop"),
        ]
    )
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())
    router.add_provider("first", first, [ModelConfig(id="first-model", provider="first")])
    router.add_provider("bad", bad_fallback, [ModelConfig(id="bad-model", provider="bad")])
    router.add_provider("good", good_fallback, [ModelConfig(id="good-model", provider="good")])

    async def before(
        _decision: Any,
        _messages: list[ChatMessage],
        _tools: list[dict[str, Any]] | None,
    ) -> str:
        return "ctx"

    async def after(
        _context: Any,
        _response: ChatResponse | None,
        _error: BaseException | None,
    ) -> None:
        return None

    events = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hello")],
            before_model_call=before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    assert [event.kind for event in events] == ["text_delta", "text_delta", "done"]
    assert [event.text for event in events if event.kind == "text_delta"] == ["second ", "ok"]


@pytest.mark.asyncio
async def test_echo_block_finalizes_run_as_error_not_running(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(tmp_path)
    owner = "owner-a"
    relative = _owned_upload(agent, owner, "session-a", "leak.txt")
    attachment = agent.settings.workspace / relative
    attachment.parent.mkdir(parents=True)
    attachment.write_text("Bearer abcdef1234567890", encoding="utf-8")
    finalized_statuses: list[tuple[str, str | None]] = []
    original_finalize = agent._finalize_run

    async def capture_finalize(*args: Any, **kwargs: Any) -> Any:
        state = args[0]
        finalized_statuses.append((state.status, state.error_message))
        return await original_finalize(*args, **kwargs)

    agent._finalize_run = capture_finalize  # type: ignore[method-assign]

    token = set_current_owner_key_hash(owner)
    try:
        with pytest.raises(PermissionError):
            await agent.run("summarize", session_id="session-a", attachments=[relative])
    finally:
        reset_current_owner_key_hash(token)

    assert provider.calls == []
    assert finalized_statuses
    assert finalized_statuses[-1][0] == "error"
    assert "blocked" in (finalized_statuses[-1][1] or "").lower()


@pytest.mark.asyncio
async def test_opaque_router_without_select_model_fails_closed_in_echo_on(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    agent = JSAgent(settings)
    router = _OpaqueRouter()
    agent.router = router  # type: ignore[assignment]
    streamed: list[str] = []

    state = await agent.run(
        "opaque run", stream_callback=lambda token: _append_async(streamed, token)
    )

    assert not router.calls
    assert streamed == []
    assert state.status == "error"
    assert "Echo model stream effect requires" in (state.error_message or "")


@pytest.mark.asyncio
async def test_opaque_router_stream_without_select_model_fails_closed_in_echo_on(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    agent = JSAgent(settings)
    router = _OpaqueRouter()
    agent.router = router  # type: ignore[assignment]

    with pytest.raises(EchoUnavailableError):
        async for _token in agent.chat_stream("opaque stream"):
            pass

    assert not router.stream_calls


@pytest.mark.asyncio
async def test_legacy_select_router_fails_closed_before_provider_chat_in_echo_on(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    provider = _Provider()
    agent = JSAgent(settings)
    agent.router = _LegacySelectRouter(provider)  # type: ignore[assignment]

    try:
        try:
            with pytest.raises(
                EchoUnavailableError,
                match="Echo on-mode requires model gate callbacks and runtime permit support",
            ):
                await agent.authorized_model_chat(
                    [ChatMessage(role="user", content="legacy fallback must be blocked")],
                    tenant_id="tenant-a",
                    session_id="session-a",
                    run_id="legacy-router",
                )
        finally:
            assert provider.calls == [], "legacy router reached provider.chat without a permit"
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_opaque_router_old_fallback_configuration_is_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="Echo is the only supported architecture"):
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=1,
            echo_engine="off",
            security=SecurityConfig(api_key_required=False),
        )


@pytest.mark.asyncio
async def test_direct_model_router_chat_stream_fails_closed_when_echo_on(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    provider = _Provider()
    router = ModelRouter(settings)
    router.add_provider("mock", provider, [ModelConfig(id="mock-model", provider="mock")])

    with pytest.raises(RuntimeError, match="Echo-gated chat_stream_events"):
        async for _token in router.chat_stream(
            [ChatMessage(role="user", content="hello")],
            model="mock-model",
        ):
            pass

    assert provider.calls == []


@pytest.mark.asyncio
async def test_direct_model_router_chat_stream_removed_off_configuration_is_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="Echo is the only supported architecture"):
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            echo_engine="off",
            security=SecurityConfig(api_key_required=False),
        )


@pytest.mark.asyncio
async def test_authorized_background_chat_blocks_secret_before_provider_call(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(tmp_path)

    with pytest.raises(PermissionError):
        await agent.authorized_model_chat(
            [
                ChatMessage(role="system", content="Summarize safely."),
                ChatMessage(role="user", content="token = sk-test-1234567890abcdef"),
            ],
            tenant_id="tenant-a",
            run_id="background-secret",
        )

    assert provider.calls == []


@pytest.mark.asyncio
async def test_authorized_background_chat_authorization_does_not_block_event_loop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent, _provider = _agent(tmp_path)
    original_authorize = agent.echo_safety_service.authorize_model_call

    def slow_authorize(**kwargs: Any) -> Any:
        time.sleep(0.2)
        return original_authorize(**kwargs)

    monkeypatch.setattr(agent.echo_safety_service, "authorize_model_call", slow_authorize)
    started_at = time.perf_counter()
    ticker_elapsed: list[float] = []

    async def ticker() -> None:
        await asyncio.sleep(0.02)
        ticker_elapsed.append(time.perf_counter() - started_at)

    response, _ = await asyncio.gather(
        agent.authorized_model_chat(
            [ChatMessage(role="user", content="hello")],
            tenant_id="tenant-a",
            run_id="background-responsive",
        ),
        ticker(),
    )

    assert response.content == "ok"
    assert ticker_elapsed[0] < 0.12


@pytest.mark.asyncio
async def test_background_completion_callback_failure_finalizes_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent, _provider = _agent(tmp_path)
    statuses: list[str] = []
    original_finish = agent.echo_safety_service.finish_chat_turn

    def recording_finish(*args: Any, **kwargs: Any) -> Any:
        statuses.append(str(kwargs["status"]))
        return original_finish(*args, **kwargs)

    def fail_completion_budget(_completion_tokens: int) -> None:
        raise RuntimeError("completion accounting failed")

    monkeypatch.setattr(agent.echo_safety_service, "finish_chat_turn", recording_finish)
    with pytest.raises(RuntimeError, match="completion accounting failed"):
        await agent.authorized_model_chat(
            [ChatMessage(role="user", content="hello")],
            tenant_id="tenant-a",
            run_id="background-budget-callback",
            completion_budget_callback=fail_completion_budget,
        )

    assert statuses == ["failed"]
    assert agent.echo_safety_service.health().claimed_effect_count == 0
    await agent.close()


@pytest.mark.asyncio
async def test_close_waits_for_unregistered_background_model_claim_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent, _provider = _agent(tmp_path)
    authorization_started = threading.Event()
    authorization_release = threading.Event()
    finished: list[str] = []
    original_authorize = agent.echo_safety_service.authorize_model_call
    original_finish = agent.echo_safety_service.finish_chat_turn

    def blocking_authorize(**kwargs: Any) -> Any:
        authorization_started.set()
        assert authorization_release.wait(timeout=1)
        return original_authorize(**kwargs)

    def recording_finish(*args: Any, **kwargs: Any) -> Any:
        finished.append(str(kwargs["status"]))
        return original_finish(*args, **kwargs)

    monkeypatch.setattr(agent.echo_safety_service, "authorize_model_call", blocking_authorize)
    monkeypatch.setattr(agent.echo_safety_service, "finish_chat_turn", recording_finish)
    model_task = asyncio.create_task(
        agent.authorized_model_chat(
            [ChatMessage(role="user", content="wait")],
            tenant_id="tenant-a",
            run_id="background-close",
        )
    )
    assert await asyncio.to_thread(authorization_started.wait, 1)
    close_task = asyncio.create_task(agent.close())
    try:
        await asyncio.sleep(0.02)
        assert not close_task.done()
        authorization_release.set()
        await close_task
        with pytest.raises(asyncio.CancelledError):
            await model_task
        assert finished == ["cancelled"]
        assert agent.echo_safety_service.health().claimed_effect_count == 0
    finally:
        authorization_release.set()
        await asyncio.gather(close_task, model_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_close_waits_for_turn_during_setup_admission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent, provider = _agent(tmp_path)
    setup_started = asyncio.Event()
    setup_release = asyncio.Event()

    async def blocking_attachment_context(
        _attachments: list[str],
        session_id: str | None = None,
    ) -> str:
        del session_id
        setup_started.set()
        await setup_release.wait()
        return ""

    monkeypatch.setattr(agent, "_build_attachment_context", blocking_attachment_context)
    run_task = asyncio.create_task(
        agent.run("wait during setup", session_id="setup-close-race")
    )
    await asyncio.wait_for(setup_started.wait(), timeout=1)
    close_task = asyncio.create_task(agent.close())
    try:
        await asyncio.sleep(0.02)
        assert not close_task.done()
        setup_release.set()
        state = await asyncio.wait_for(run_task, timeout=1)
        await asyncio.wait_for(close_task, timeout=1)
        assert state.status == "cancelled"
        assert provider.calls == []
    finally:
        setup_release.set()
        await asyncio.gather(close_task, run_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_new_turn_is_rejected_after_agent_close(tmp_path: Path) -> None:
    agent, provider = _agent(tmp_path)
    await agent.close()

    with pytest.raises(EchoUnavailableError, match="shutting down"):
        await agent.run("must not start", session_id="after-close")
    assert provider.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_via", ["task", "request"])
async def test_non_stream_model_cancel_finalizes_echo_claim_and_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    cancel_via: str,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    provider = _BlockingProvider()
    agent = JSAgent(settings)
    router = ModelRouter(settings, permit_verifier=agent._model_permit_issuer)
    router.add_provider("blocking", provider, [ModelConfig(id="blocking", provider="blocking")])
    agent.router = router
    finished: list[str] = []
    original_finish = agent.echo_safety_service.finish_chat_turn

    def finish_chat_turn(*args: Any, **kwargs: Any) -> Any:
        finished.append(str(kwargs["status"]))
        return original_finish(*args, **kwargs)

    monkeypatch.setattr(agent.echo_safety_service, "finish_chat_turn", finish_chat_turn)
    session_id = f"non-stream-cancel-{cancel_via}"
    if cancel_via == "task":
        run_task = asyncio.create_task(
            agent.authorized_model_chat(
                [ChatMessage(role="user", content="wait")],
                tenant_id="local",
                run_id=session_id,
            )
        )
    else:
        run_task = asyncio.create_task(agent.run("wait", session_id=session_id))
    await asyncio.wait_for(provider.entered.wait(), timeout=1)

    if cancel_via == "task":
        run_task.cancel("non-stream model cancellation")
        with pytest.raises(asyncio.CancelledError, match="non-stream model cancellation"):
            await run_task
    else:
        assert agent.request_cancel(session_id) is True
        state = await asyncio.wait_for(run_task, timeout=1)
        assert state.status == "cancelled"

    assert finished == ["cancelled"]
    tenant_id = "local" if cancel_via == "task" else "local-user"
    journal_path = agent.echo_safety_service.journal_path_for_scope(
        tenant_id,
        product_id="js-agent",
        session_id=session_id,
    )
    records = FileEchoLedger(
        journal_path,
        mac_key=agent.echo_safety_service.journal_key_for_scope(
            tenant_id,
            product_id="js-agent",
            session_id=session_id,
        ),
    ).records
    receipt_statuses = [
        str(record.payload["status"])
        for record in records
        if record.record_type == "receipt"
    ]
    assert receipt_statuses == ["cancelled"]
    assert agent.echo_safety_service.health().claimed_effect_count == 0
    assert agent.echo_safety_service._claim_lock_fds == {}
    claims_dir = journal_path.parent / "claims"
    assert list(claims_dir.glob("*.lock")) == []
    await agent.close()


@pytest.mark.asyncio
async def test_stream_model_authorization_does_not_block_other_async_work() -> None:
    class _SlowSafetyService:
        def authorize_model_call(self, **_kwargs: Any) -> object:
            time.sleep(0.2)
            return object()

    loop = object.__new__(EchoTurnLoop)
    loop.agent = SimpleNamespace(
        echo_safety_service=_SlowSafetyService(),
        settings=SimpleNamespace(product_id="product-a", workspace=Path.cwd()),
        _echo_durable_executor=_TEST_DURABLE_EXECUTOR,
    )
    loop.owner_key_hash = "owner-a"
    loop.session_id = "session-a"
    loop.run_id = "run-a"
    loop.model = "mock-model"
    loop.attachments = []
    loop.attachment_manifest = ()
    loop._reserve_model_attempt = lambda: None
    ticked = threading.Event()
    second_request_advanced = threading.Event()
    started_at = time.perf_counter()
    ticker_elapsed: list[float] = []
    second_request_elapsed: list[float] = []

    async def ticker() -> None:
        await asyncio.sleep(0.02)
        ticker_elapsed.append(time.perf_counter() - started_at)
        ticked.set()

    async def second_request() -> None:
        await asyncio.sleep(0.03)
        second_request_elapsed.append(time.perf_counter() - started_at)
        second_request_advanced.set()

    claim, _, _ = await asyncio.gather(
        loop._authorize_model_call(
            SimpleNamespace(provider_name="provider-a", model="mock-model"),
            [],
            None,
        ),
        ticker(),
        second_request(),
    )
    await durable_to_thread(lambda: None, claim=claim)

    assert ticked.is_set()
    assert second_request_advanced.is_set()
    assert ticker_elapsed[0] < 0.12
    assert second_request_elapsed[0] < 0.12


def _stream_loop_for_service(service: Any) -> EchoTurnLoop:
    loop = object.__new__(EchoTurnLoop)
    loop.agent = SimpleNamespace(
        echo_safety_service=service,
        settings=SimpleNamespace(product_id="product-a", workspace=Path.cwd()),
        _echo_durable_executor=_TEST_DURABLE_EXECUTOR,
    )
    loop.owner_key_hash = "owner-a"
    loop.session_id = "session-a"
    loop.run_id = "run-a"
    loop.model = "mock-model"
    loop.attachments = []
    loop.attachment_manifest = ()
    loop._reserve_model_attempt = lambda: None
    loop._reserve_echo_budget = lambda **_kwargs: None
    return loop


async def _claim_test_context(value: object | None = None) -> DurableClaim[object]:
    context = object() if value is None else value
    return await claim_to_thread(
        lambda: context,
        on_cancel=lambda _value: None,
        executor=_TEST_DURABLE_EXECUTOR,
    )


@pytest.mark.asyncio
async def test_stream_model_authorization_failure_maps_to_echo_unavailable() -> None:
    class _FailingSafetyService:
        def authorize_model_call(self, **_kwargs: Any) -> object:
            raise OSError("journal unavailable")

    loop = _stream_loop_for_service(_FailingSafetyService())

    with pytest.raises(EchoUnavailableError, match="unavailable before model execution"):
        await loop._authorize_model_call(
            SimpleNamespace(provider_name="provider-a", model="mock-model"),
            [],
            None,
        )


@pytest.mark.asyncio
async def test_stream_model_authorization_cancellation_finishes_claim_with_context(
    tmp_path: Path,
) -> None:
    authorization_started = threading.Event()
    authorization_release = threading.Event()
    finish_started = threading.Event()
    finish_release = threading.Event()
    context = object()
    seen_contexts: list[tuple[str, str, str, str]] = []
    statuses: list[str] = []

    class _BlockingSafetyService:
        def authorize_model_call(self, **_kwargs: Any) -> object:
            runtime_context = current_runtime_context()
            assert runtime_context is not None
            seen_contexts.append(
                (
                    runtime_context.owner_key_hash,
                    runtime_context.session_id,
                    runtime_context.run_id,
                    runtime_context.product_id,
                )
            )
            authorization_started.set()
            assert authorization_release.wait(timeout=1)
            return context

        def finish_chat_turn(self, received_context: object, **kwargs: Any) -> None:
            runtime_context = current_runtime_context()
            assert runtime_context is not None
            assert received_context is context
            seen_contexts.append(
                (
                    runtime_context.owner_key_hash,
                    runtime_context.session_id,
                    runtime_context.run_id,
                    runtime_context.product_id,
                )
            )
            statuses.append(str(kwargs["status"]))
            finish_started.set()
            assert finish_release.wait(timeout=1)

    runtime_context = RuntimeContext(
        product_id="product-a",
        channel="websocket",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        role="local-user",
        profile="default",
        capabilities=(),
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
    )
    token = set_runtime_context(runtime_context)
    try:
        task = asyncio.create_task(
            _stream_loop_for_service(_BlockingSafetyService())._authorize_model_call(
                SimpleNamespace(provider_name="provider-a", model="mock-model"),
                [],
                None,
            )
        )
        assert await asyncio.to_thread(authorization_started.wait, 1)
        task.cancel("cancel authorization")
        authorization_release.set()
        assert await asyncio.to_thread(finish_started.wait, 1)
        task.cancel("cancel durable cleanup")
        await asyncio.sleep(0)
        assert not task.done()
        finish_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        reset_runtime_context(token)

    assert statuses == ["cancelled"]
    assert seen_contexts == [
        ("owner-a", "session-a", "run-a", "product-a"),
        ("owner-a", "session-a", "run-a", "product-a"),
    ]


@pytest.mark.asyncio
async def test_stream_model_authorization_cancellation_retrieves_thread_failure() -> None:
    authorization_started = threading.Event()
    authorization_release = threading.Event()

    class _FailingSafetyService:
        def authorize_model_call(self, **_kwargs: Any) -> object:
            authorization_started.set()
            assert authorization_release.wait(timeout=1)
            raise OSError("journal unavailable")

    task = asyncio.create_task(
        _stream_loop_for_service(_FailingSafetyService())._authorize_model_call(
            SimpleNamespace(provider_name="provider-a", model="mock-model"),
            [],
            None,
        )
    )
    assert await asyncio.to_thread(authorization_started.wait, 1)
    task.cancel("cancel authorization before ledger failure")
    authorization_release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0)
    assert task.done()


@pytest.mark.asyncio
async def test_stream_model_finish_is_durable_before_cancellation_and_maps_failure() -> None:
    finish_started = threading.Event()
    finish_release = threading.Event()
    statuses: list[str] = []

    class _BlockingSafetyService:
        def finish_chat_turn(self, _context: object, **kwargs: Any) -> None:
            statuses.append(str(kwargs["status"]))
            finish_started.set()
            assert finish_release.wait(timeout=1)

    response = ChatResponse(
        content="complete",
        tool_calls=[],
        model="mock-model",
        usage={"prompt_tokens": 1, "completion_tokens": 1},
        finish_reason="stop",
    )
    context = await _claim_test_context()
    task = asyncio.create_task(
        _stream_loop_for_service(_BlockingSafetyService())._finish_model_call(
            context,
            response,
            None,
        )
    )
    assert await asyncio.to_thread(finish_started.wait, 1)
    task.cancel("cancel finish")
    await asyncio.sleep(0)
    assert not task.done()
    finish_release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert statuses == ["completed"]

    class _FailingSafetyService:
        def finish_chat_turn(self, _context: object, **_kwargs: Any) -> None:
            raise OSError("journal unavailable")

    with pytest.raises(EchoUnavailableError, match="failed to finalize"):
        await _stream_loop_for_service(_FailingSafetyService())._finish_model_call(
            await _claim_test_context(),
            response,
            None,
        )


@pytest.mark.asyncio
async def test_stream_completion_accounting_failure_finalizes_claim() -> None:
    statuses: list[str] = []

    class _RecordingSafetyService:
        def finish_chat_turn(self, _context: object, **kwargs: Any) -> None:
            statuses.append(str(kwargs["status"]))

    loop = _stream_loop_for_service(_RecordingSafetyService())

    def fail_completion_budget(**_kwargs: Any) -> None:
        raise RuntimeError("stream completion accounting failed")

    loop._reserve_echo_budget = fail_completion_budget
    response = ChatResponse(
        content="complete",
        tool_calls=[],
        model="mock-model",
        usage={"prompt_tokens": 1, "completion_tokens": 1},
        finish_reason="stop",
    )
    with pytest.raises(RuntimeError, match="stream completion accounting failed"):
        await loop._finish_model_call(
            await _claim_test_context(),
            response,
            None,
        )

    assert statuses == ["failed"]
    assert _TEST_DURABLE_EXECUTOR.outstanding_claims == 0


@pytest.mark.asyncio
async def test_stream_failure_accounting_error_still_finalizes_claim() -> None:
    statuses: list[str] = []

    class _RecordingSafetyService:
        def finish_chat_turn(self, _context: object, **kwargs: Any) -> None:
            statuses.append(str(kwargs["status"]))

    loop = _stream_loop_for_service(_RecordingSafetyService())

    def fail_remaining_budget() -> int:
        raise RuntimeError("failure accounting unavailable")

    loop._remaining_completion_tokens = fail_remaining_budget
    provider_error = RuntimeError("provider stream failed")
    provider_error.completion_tokens = 1  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="failure accounting unavailable"):
        await loop._finish_model_call(
            await _claim_test_context(),
            None,
            provider_error,
        )

    assert statuses == ["failed"]
    assert _TEST_DURABLE_EXECUTOR.outstanding_claims == 0


@pytest.mark.asyncio
async def test_stream_done_event_waits_for_durable_model_finish(tmp_path: Path) -> None:
    finish_started = threading.Event()
    finish_release = threading.Event()

    class _BlockingSafetyService:
        def finish_chat_turn(self, _context: object, **_kwargs: Any) -> None:
            finish_started.set()
            assert finish_release.wait(timeout=1)

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    provider = _StreamEventsProvider([StreamEvent(kind="done", finish_reason="stop")])
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())
    router.add_provider("mock", provider, [ModelConfig(id="mock-model", provider="mock")])
    loop = _stream_loop_for_service(_BlockingSafetyService())

    async def before(
        _decision: RoutingDecision,
        _messages: list[ChatMessage],
        _tools: list[dict[str, Any]] | None,
    ) -> DurableClaim[object]:
        return await _claim_test_context()

    async def after(
        context: object,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        await loop._finish_model_call(context, response, error)

    async def consume() -> list[StreamEvent]:
        return [
            event
            async for event in router.chat_stream_events(
                [ChatMessage(role="user", content="hello")],
                before_model_call=before,
                after_model_call=after,
                permit_grant=_grant(router),
            )
        ]

    task = asyncio.create_task(consume())
    assert await asyncio.to_thread(finish_started.wait, 1)
    await asyncio.sleep(0)
    assert not task.done()
    finish_release.set()
    events = await task

    assert [event.kind for event in events] == ["done"]

    class _FailingSafetyService:
        def finish_chat_turn(self, _context: object, **_kwargs: Any) -> None:
            raise OSError("journal unavailable")

    failing_loop = _stream_loop_for_service(_FailingSafetyService())

    async def failing_after(
        context: object,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        await failing_loop._finish_model_call(context, response, error)

    delivered: list[StreamEvent] = []
    with pytest.raises(EchoUnavailableError, match="failed to finalize"):
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hello")],
            before_model_call=before,
            after_model_call=failing_after,
            permit_grant=_grant(router),
        ):
            delivered.append(event)
    assert delivered == []


async def _append_async(items: list[str], value: str) -> None:
    items.append(value)

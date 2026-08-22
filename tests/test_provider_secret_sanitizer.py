"""F-13: provider boundary must scrub query-param API keys from observable errors.

Secrets use arbitrary shapes (not ``sk-`` prefixes) so tests prove scrubbing is
not merely a final-string regex on OpenAI-style keys.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import quote

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.agent import JSAgent
from js.config import JSSettings, ModelConfig, ModelProviderConfig, SecurityConfig
from js.echo.effect_interpreter import ModelEffect
from js.echo.state import AgentState as EchoAgentState
from js.echo.turn_context import reset_runtime_context, set_runtime_context
from js.echo.turn_loop import EchoTurnLoop
from js.echo.turn_runtime import EchoRuntime, TurnRequest
from js.models.capability import (
    SafeProviderError,
    raise_safe_provider_error,
    safe_provider_error,
    sanitize_provider_error,
)
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider, OpenAICompatibleProvider
from js.models.router import ModelRouter
from js.web.auth import AuthManager
from js.web.routers.chat import router as chat_router

# Arbitrary-format secret — must NOT match sk-/sk-ant- redaction regexes.
_SECRET = "xYz-NOT_A_SK_PREFIX_9876543210!@#"
_MODEL = ModelConfig(id="leak-model", name="Leak Model", context_window=4096)


def _leaky_message(secret: str = _SECRET) -> str:
    return (
        f"Client error '401' for url "
        f"'https://generativelanguage.googleapis.com/v1beta/models?key={secret}' "
        f"For more information check: detail={secret}"
    )


def _assert_secret_absent(secret: str, *values: Any) -> None:
    for value in values:
        text = value if isinstance(value, str) else repr(value)
        assert secret not in text
        assert quote(secret, safe="") not in text


def _assert_exception_secret_free(exc: BaseException, secret: str) -> None:
    _assert_secret_absent(secret, str(exc), repr(exc), getattr(exc, "args", ()))
    assert getattr(exc, "__cause__", None) is None
    context = getattr(exc, "__context__", None)
    if context is not None:
        _assert_secret_absent(secret, str(context), repr(context))


# ---------------------------------------------------------------------------
# Unit: sanitizer + SafeProviderError
# ---------------------------------------------------------------------------


def test_sanitize_provider_error_scrubs_arbitrary_secret_shapes() -> None:
    raw = (
        f"Client error '401' for url 'https://example.test/v1/models?key={_SECRET}'\n"
        f"Authorization: Bearer {_SECRET}\n"
        f"detail={_SECRET}"
    )
    cleaned = sanitize_provider_error(raw, api_key=_SECRET, query_param_name="key")
    _assert_secret_absent(_SECRET, cleaned)
    assert "xYz-NOT_A_SK_PREFIX" not in cleaned


def test_sanitize_provider_error_scrubs_url_encoded_secret() -> None:
    secret = "abc/def+ghi=123"
    encoded = quote(secret, safe="")
    raw = f"https://example.test/v1?key={encoded}"
    cleaned = sanitize_provider_error(raw, api_key=secret, query_param_name="key")
    _assert_secret_absent(secret, cleaned)
    assert encoded not in cleaned


def test_sanitize_provider_error_scrubs_mixed_case_percent_triplets() -> None:
    """Each %HH triplet matches hex case-insensitively (not whole-string variants)."""
    secret = "a/b+c=d"
    mixed = "%61%2f%62%2B%63%3d%64"  # lowercase hex throughout
    raw = f"https://example.test/v1?key={mixed} body={mixed}"
    cleaned = sanitize_provider_error(raw, api_key=secret, query_param_name="key")
    _assert_secret_absent(secret, cleaned)
    assert mixed not in cleaned
    assert "%2f" not in cleaned
    assert "%2B" not in cleaned
    assert "%3d" not in cleaned


def test_sanitize_provider_error_clears_query_param_value_with_encoded_equals() -> None:
    secret = "token-with/special=chars"
    encoded_key = f"key%3D{quote(secret, safe='')}"
    raw = f"GET https://example.test/v1/models?{encoded_key}&other=1"
    cleaned = sanitize_provider_error(raw, api_key=secret, query_param_name="key")
    _assert_secret_absent(secret, cleaned)
    assert quote(secret, safe="") not in cleaned
    assert "key%3d" in cleaned.lower()


def test_sanitize_provider_error_scrubs_quote_plus_and_case_variants() -> None:
    from urllib.parse import quote_plus

    secret = "a b/c+d=e&f"
    quoted = quote(secret, safe="")
    plus = quote_plus(secret)
    variants = (
        quoted,
        plus,
        quoted.upper(),
        plus.upper(),
        "".join(
            ch.lower() if i > 0 and quoted[i - 1] == "%" and ch.isalpha() else ch
            for i, ch in enumerate(quoted)
        ),
    )
    for variant in variants:
        raw = f"https://example.test/v1?key={variant} detail={variant}"
        cleaned = sanitize_provider_error(raw, api_key=secret, query_param_name="key")
        _assert_secret_absent(secret, cleaned)
        assert variant not in cleaned
        assert plus not in cleaned
        assert quoted not in cleaned


def test_safe_provider_error_has_no_cause_chain() -> None:
    original = RuntimeError(_leaky_message())
    safe = safe_provider_error(
        original,
        api_key=_SECRET,
        query_param_name="key",
        retryable=True,
    )
    assert isinstance(safe, SafeProviderError)
    assert safe.retryable is True
    _assert_exception_secret_free(safe, _SECRET)
    with pytest.raises(SafeProviderError) as raised:
        raise_safe_provider_error(
            original,
            api_key=_SECRET,
            query_param_name="key",
            retryable=False,
        )
    _assert_exception_secret_free(raised.value, _SECRET)


# ---------------------------------------------------------------------------
# Provider adapter first-exit
# ---------------------------------------------------------------------------


class _Circuit:
    async def can_execute(self) -> bool:
        return True

    async def record_success(self) -> None:
        return None

    async def record_failure(self) -> None:
        return None

    async def execute(self, coro: Any) -> Any:
        return await coro


def _provider_with_failing_client(secret: str = _SECRET) -> OpenAICompatibleProvider:
    provider = object.__new__(OpenAICompatibleProvider)
    provider.config = ModelProviderConfig(
        name="gemini-like",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        api_key=secret,
        auth_adapter="query_param",
        query_param_name="key",
        default_model="leak-model",
        models=[_MODEL],
    )
    provider._is_local = False
    provider._last_stream_usage = None
    provider._stream_options_supported = True
    provider.circuit = _Circuit()

    async def fail_create(**_kwargs: Any) -> Any:
        raise RuntimeError(_leaky_message(secret))

    provider.client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=fail_create))
    )
    return provider


@pytest.mark.asyncio
async def test_provider_chat_raises_safe_error_without_query_param_secret() -> None:
    provider = _provider_with_failing_client()
    with pytest.raises(SafeProviderError) as raised:
        await provider.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="leak-model",
        )
    _assert_exception_secret_free(raised.value, _SECRET)


@pytest.mark.asyncio
async def test_provider_chat_stream_raises_safe_error_without_secret() -> None:
    provider = _provider_with_failing_client()
    with pytest.raises(SafeProviderError) as raised:
        async for _ in provider.chat_stream(
            messages=[ChatMessage(role="user", content="hi")],
            model="leak-model",
        ):
            pass
    _assert_exception_secret_free(raised.value, _SECRET)


@pytest.mark.asyncio
async def test_provider_chat_stream_events_error_text_is_safe() -> None:
    provider = _provider_with_failing_client()
    events = [
        event
        async for event in provider.chat_stream_events(
            messages=[ChatMessage(role="user", content="hi")],
            model="leak-model",
        )
    ]
    assert len(events) == 1 and events[0].kind == "error"
    _assert_secret_absent(_SECRET, events[0].error, events[0])


# ---------------------------------------------------------------------------
# Router: non-stream chat, fallback aggregation, logs
# ---------------------------------------------------------------------------


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
async def test_router_chat_explicit_model_does_not_leak_query_param_secret(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())
    provider = _provider_with_failing_client()
    router.add_provider("gemini-like", provider, [_MODEL])
    before, after, grant = _echo_hooks(router)

    with caplog.at_level(logging.DEBUG), pytest.raises(SafeProviderError) as raised:
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="leak-model",
            before_model_call=before,
            after_model_call=after,
            permit_grant=grant,
        )

    _assert_exception_secret_free(raised.value, _SECRET)
    _assert_secret_absent(_SECRET, caplog.text)
    assert "Requested model" in str(raised.value)


@pytest.mark.asyncio
async def test_router_fallback_aggregation_scrubs_query_param_secrets(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())

    primary = _provider_with_failing_client(_SECRET)
    primary.config.name = "primary"
    backup_secret = "backup-QUERY_SECRET_neq_sk_prefix_445566"
    backup = _provider_with_failing_client(backup_secret)
    backup.config.name = "backup"
    backup_model = ModelConfig(id="backup-model", name="Backup", context_window=4096)

    router._providers = {"primary": primary, "backup": backup}
    router._model_map = {
        "leak-model": ("primary", _MODEL),
        "backup-model": ("backup", backup_model),
        "primary/leak-model": ("primary", _MODEL),
        "backup/backup-model": ("backup", backup_model),
    }
    # Force select_model toward primary for the first attempt.
    router._routing_cache.clear()
    original_select = router.select_model

    async def select_primary(preferred: str | None = None, **kwargs: Any) -> Any:
        if preferred:
            return await original_select(preferred=preferred, **kwargs)
        from js.models.router import RoutingDecision

        return RoutingDecision(
            provider=primary,
            model="leak-model",
            provider_name="primary",
            reason="test primary",
        )

    router.select_model = select_primary  # type: ignore[method-assign]
    before, after, grant = _echo_hooks(router)

    with caplog.at_level(logging.DEBUG), pytest.raises(SafeProviderError) as raised:
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model=None,
            before_model_call=before,
            after_model_call=after,
            permit_grant=grant,
        )

    _assert_exception_secret_free(raised.value, _SECRET)
    _assert_exception_secret_free(raised.value, backup_secret)
    _assert_secret_absent(_SECRET, caplog.text)
    _assert_secret_absent(backup_secret, caplog.text)
    assert "All providers failed" in str(raised.value)


# ---------------------------------------------------------------------------
# Echo + Web sinks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_echo_finalizer_events_logs_omit_query_param_secret(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=1,
        )
    )
    provider = _provider_with_failing_client()
    audit_records: list[Any] = []
    emitted_events: list[Any] = []
    finalized_states: list[dict[str, Any]] = []
    checkpoint_states: list[dict[str, Any]] = []

    async def model_effect(
        _effect: ModelEffect,
        _context: Any,
    ) -> ChatResponse:
        # Cross the real provider adapter boundary (first exit conversion).
        return await provider.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="leak-model",
        )

    async def save_checkpoint(state: EchoAgentState) -> None:
        checkpoint_states.append(state.to_dict())

    async def finalize_run(
        state: EchoAgentState,
        _session_id: str,
        _run_id: str,
        _user_input: str,
        _history_ua_count: int,
    ) -> None:
        finalized_states.append(state.to_dict())
        await agent.save_checkpoint(state)

    agent.audit.log = lambda *a, **k: audit_records.append((a, k))  # type: ignore[method-assign]
    agent.event_store.emit = emitted_events.append  # type: ignore[method-assign]
    agent.echo_runtime.execute_model_effect = model_effect  # type: ignore[method-assign]
    agent.save_checkpoint = save_checkpoint  # type: ignore[method-assign]
    agent._finalize_run = finalize_run  # type: ignore[method-assign]
    agent._check_degraded = AsyncMock()  # type: ignore[method-assign]

    loop = EchoTurnLoop(agent, "hello", "session-secret", None, None, None, None, None)
    context_token = set_runtime_context(
        agent.echo_runtime.build_context(
            channel="test",
            owner_key_hash="owner-a",
            session_id="session-secret",
            run_id="run-secret",
            capabilities=(),
        )
    )
    try:
        with caplog.at_level(logging.DEBUG):
            state = await loop.execute()
    finally:
        reset_runtime_context(context_token)
        await agent.close()

    captured = capsys.readouterr()
    sinks = [
        state.error_message,
        repr(state.to_dict()),
        repr(finalized_states),
        repr(checkpoint_states),
        repr(audit_records),
        repr(emitted_events),
        caplog.text,
        captured.out + captured.err,
    ]
    for sink in sinks:
        _assert_secret_absent(_SECRET, sink)
    assert state.status == "error"
    assert finalized_states


def test_web_chat_response_omits_query_param_secret(tmp_path: Path) -> None:
    class _AdmitPulse:
        def observe(self, **_kwargs: Any) -> Any:
            return MagicMock(admitted=True)

    class _AgentRunLoop:
        def __init__(self, agent: Any, request: TurnRequest) -> None:
            self._agent = agent
            self._request = request

        async def execute(self) -> Any:
            request = self._request
            return await self._agent.run(
                request.message,
                session_id=request.context.session_id or None,
                model=request.model,
                attachments=list(request.attachments),
                stream_callback=request.stream_callback,
                progress_callback=request.progress_callback,
                event_callback=request.event_callback,
                disable_tools=request.disable_tools,
            )

    provider = _provider_with_failing_client()

    async def run_with_provider_failure(*_args: Any, **_kwargs: Any) -> Any:
        try:
            await provider.chat(
                messages=[ChatMessage(role="user", content="hi")],
                model="leak-model",
            )
        except SafeProviderError as exc:
            state = MagicMock()
            state.status = "error"
            state.error_message = f"{type(exc).__name__}: {exc}"
            state.session_id = "sess-secret-1"
            state.turn_count = 0
            state.total_tokens = {"input": 0, "output": 0}
            state.messages = []
            # Prove the exception object itself is secret-free for the web layer.
            _assert_exception_secret_free(exc, _SECRET)
            return state
        raise AssertionError("expected SafeProviderError")

    agent = MagicMock()
    agent.settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
    )
    agent._shutdown_requested = False
    agent._lane_executor = None
    agent.run = AsyncMock(side_effect=run_with_provider_failure)
    agent.echo_runtime = EchoRuntime(
        agent,
        pulse_runtime=_AdmitPulse(),
        turn_loop_factory=lambda runtime_agent, request: _AgentRunLoop(runtime_agent, request),
    )

    app = FastAPI()
    app.include_router(chat_router)
    key = AuthManager(tmp_path / "state").create_key("secret-test", role="user")
    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": key},
    )

    with (
        patch("js.web.server._settings", agent.settings),
        patch("js.web.deps._stats_store", None),
        patch("js.web.routers.chat.get_agent", return_value=agent),
        patch("js.web.routers.chat.get_stats_store", return_value=MagicMock()),
    ):
        resp = client.post(
            "/api/chat",
            json={"message": "hello", "session_id": "sess-secret-1"},
        )

    assert resp.status_code == 500
    _assert_secret_absent(_SECRET, resp.text)
    if resp.headers.get("content-type", "").startswith("application/json"):
        _assert_secret_absent(_SECRET, resp.json())


@pytest.mark.asyncio
async def test_default_chat_stream_events_uses_provider_config_secret() -> None:
    """Default ModelProvider.chat_stream_events must scrub via current config."""

    class _Legacy(ModelProvider):
        def __init__(self) -> None:
            self.config = ModelProviderConfig(
                name="legacy",
                base_url="https://example.test/v1",
                api_key=_SECRET,
                auth_adapter="query_param",
                query_param_name="key",
                default_model="leak-model",
                models=[_MODEL],
            )

        async def chat(self, *args: Any, **kwargs: Any) -> ChatResponse:
            raise NotImplementedError

        async def chat_stream(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError(_leaky_message())
            yield  # pragma: no cover — make this an async generator

        async def health_check(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    provider = _Legacy()
    events = [
        event
        async for event in ModelProvider.chat_stream_events(
            provider,
            messages=[ChatMessage(role="user", content="hi")],
            model="leak-model",
        )
    ]
    assert len(events) == 1 and events[0].kind == "error"
    _assert_secret_absent(_SECRET, events[0].error, events[0])


@pytest.mark.asyncio
async def test_router_rescrubs_custom_provider_error_event(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Router must not trust custom/legacy error event text."""
    settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())

    class _LeakyStreamProvider:
        config = ModelProviderConfig(
            name="custom",
            base_url="https://example.test/v1",
            api_key=_SECRET,
            auth_adapter="query_param",
            query_param_name="key",
            default_model="leak-model",
            models=[_MODEL],
        )

        async def chat_stream_events(self, **_kwargs: Any) -> Any:
            from js.models.stream_events import StreamEvent

            yield StreamEvent(kind="error", error=_leaky_message(), model="leak-model")

        async def health_check(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    provider = _LeakyStreamProvider()
    router.add_provider("custom", provider, [_MODEL])  # type: ignore[arg-type]
    before, _after, grant = _echo_hooks(router)
    after_errors: list[BaseException | None] = []

    async def tracking_after(
        _context: Any,
        _response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        after_errors.append(error)

    with caplog.at_level(logging.DEBUG):
        events = [
            event
            async for event in router.chat_stream_events(
                [ChatMessage(role="user", content="hi")],
                model="leak-model",
                before_model_call=before,
                after_model_call=tracking_after,
                permit_grant=grant,
            )
        ]
    assert events and events[0].kind == "error"
    _assert_secret_absent(_SECRET, events[0].error, events[0], caplog.text)
    assert after_errors and isinstance(after_errors[0], SafeProviderError)
    _assert_exception_secret_free(after_errors[0], _SECRET)


@pytest.mark.asyncio
async def test_router_rebuild_error_event_strips_free_form_meta(
    tmp_path: Path,
) -> None:
    """Router must drop arbitrary provider diagnostic metadata from error events."""
    settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())

    class _LeakyMetaStreamProvider:
        config = ModelProviderConfig(
            name="custom",
            base_url="https://example.test/v1",
            api_key=_SECRET,
            auth_adapter="query_param",
            query_param_name="key",
            default_model="leak-model",
            models=[_MODEL],
        )

        async def chat_stream_events(self, **_kwargs: Any) -> Any:
            from js.models.stream_events import StreamEvent

            yield StreamEvent(
                kind="error",
                error=_leaky_message(),
                model="leak-model",
                meta={
                    "retryable": True,
                    "completion_tokens": 42,
                    "api_key": _SECRET,
                    "raw_url": f"https://example.test?key={_SECRET}",
                    "diagnostic_blob": _leaky_message(),
                },
            )

        async def health_check(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    provider = _LeakyMetaStreamProvider()
    router.add_provider("custom", provider, [_MODEL])  # type: ignore[arg-type]
    before, _after, grant = _echo_hooks(router)

    events = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="leak-model",
            before_model_call=before,
            after_model_call=_after,
            permit_grant=grant,
        )
    ]
    assert events and events[0].kind == "error"
    ev = events[0]
    _assert_secret_absent(_SECRET, ev.error, ev.meta, repr(ev.meta))
    assert set(ev.meta.keys()) <= {
        "retryable",
        "completion_tokens",
        "prompt_tokens",
        "token_source",
        "echo_error_code",
        "provider_reported_prompt_tokens",
        "provider_reported_completion_tokens",
        "provider_reported_total_tokens",
    }
    assert "api_key" not in ev.meta
    assert "raw_url" not in ev.meta
    assert "diagnostic_blob" not in ev.meta
    assert ev.provider == "custom"
    assert ev.model == "leak-model"
    assert isinstance(ev.meta.get("completion_tokens"), int)


@pytest.mark.asyncio
async def test_router_raw_stream_exception_is_safe_before_after_hook(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())

    class _RaisingStreamProvider:
        config = ModelProviderConfig(
            name="raising",
            base_url="https://example.test/v1",
            api_key=_SECRET,
            auth_adapter="query_param",
            query_param_name="key",
            default_model="leak-model",
            models=[_MODEL],
        )

        async def chat_stream_events(self, **_kwargs: Any) -> Any:
            raise RuntimeError(_leaky_message())
            yield  # pragma: no cover

        async def health_check(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    provider = _RaisingStreamProvider()
    router.add_provider("raising", provider, [_MODEL])  # type: ignore[arg-type]
    before, _after, grant = _echo_hooks(router)
    after_errors: list[BaseException | None] = []

    async def tracking_after(
        _context: Any,
        _response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        after_errors.append(error)
        if error is not None:
            _assert_exception_secret_free(error, _SECRET)

    with caplog.at_level(logging.DEBUG), pytest.raises(SafeProviderError) as raised:
        async for _ in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="leak-model",
            before_model_call=before,
            after_model_call=tracking_after,
            permit_grant=grant,
        ):
            pass

    _assert_exception_secret_free(raised.value, _SECRET)
    _assert_secret_absent(_SECRET, caplog.text)
    assert after_errors and isinstance(after_errors[0], SafeProviderError)


@pytest.mark.asyncio
async def test_http_ws_echo_router_stream_omits_secret(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real HTTP+WS path through Echo→router streaming must not leak secrets."""
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager

    from starlette.websockets import WebSocketDisconnect

    monkeypatch.setenv("JS_ALLOWED_ORIGINS", "http://localhost")
    import js.web.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_ALLOWED_ORIGINS", None)

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        echo_engine="on",
        max_turns=1,
    )
    (tmp_path / "workspace").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)

    agent = JSAgent(settings)
    provider = _provider_with_failing_client()
    agent.router._providers = {"gemini-like": provider}
    agent.router._model_map = {
        "leak-model": ("gemini-like", _MODEL),
        "gemini-like/leak-model": ("gemini-like", _MODEL),
    }
    agent.router._routing_cache.clear()

    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    with patch("js.web.server.lifespan", _noop_lifespan):
        from js.web.server import create_app

        app = create_app()

    from js.web.deps import set_globals

    set_globals(agent, settings)
    with (
        patch("js.web.server._settings", settings),
        patch("js.web.server._agent", agent),
        patch("js.web.server.get_agent", lambda: agent),
        patch("js.web.deps._agent", agent),
        patch("js.web.deps._settings", settings),
    ):
        client = TestClient(
            app, base_url="http://localhost", headers={"Origin": "http://localhost"}
        )
        with caplog.at_level(logging.DEBUG):
            resp = client.post(
                "/api/chat",
                json={
                    "message": "hello",
                    "session_id": "sess-f13-http",
                    "model": "leak-model",
                },
            )
        _assert_secret_absent(_SECRET, resp.text, caplog.text)

        ws_payloads: list[str] = []
        with client.websocket_connect("/ws", headers={"Origin": "http://localhost"}) as ws:
            ws.send_json(
                {
                    "type": "message",
                    "content": "hello",
                    "session_id": "sess-f13-ws",
                    "model": "leak-model",
                }
            )
            deadline = time.time() + 5.0
            while time.time() < deadline:
                try:
                    msg = ws.receive_json()
                except WebSocketDisconnect:
                    break
                ws_payloads.append(repr(msg))
                if msg.get("type") in {"error", "done", "result"}:
                    break

    await agent.close()
    for payload in ws_payloads:
        _assert_secret_absent(_SECRET, payload)
    _assert_secret_absent(_SECRET, caplog.text)

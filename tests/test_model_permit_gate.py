"""P0-1: model authorization must be an unforgeable per-attempt runtime permit.

Attack reproduced on 2026-07-20 against digest
914b48fc61f20655db486f02234af23c7355c5dcc55a02c01e5116a0a0959d17:

1. ``ModelRouter.bind_echo_callbacks`` was public and repeatable.
2. Attacker rebound forged callbacks after the genuine Echo pair.
3. ``chat_stream_events`` accepted them (identity compare against the
   overwritten attributes) -> forged before/after executed, Echo bypassed.

These tests encode the required end state:

- no public rebind API exists at all;
- every provider attempt (retry/fallback/stream reconnect) requires a fresh
  single-use permit signed by the runtime-owned issuer;
- permits bind provider, model, messages hash, tools schema hash, owner,
  session and run;
- direct router calls without a valid permit fail closed.
"""

from __future__ import annotations

import asyncio
import pathlib
import time
from collections.abc import AsyncGenerator
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from js.config import JSSettings, ModelConfig
from js.models.permit import ModelPermitError, ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter
from js.models.stream_events import StreamEvent


class _StubProvider(ModelProvider):
    def __init__(self, name: str = "stub", *, fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.chat_calls = 0
        self.stream_calls = 0

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.chat_calls += 1
        if self.fail:
            raise ConnectionError("provider exploded")
        return ChatResponse(
            content="stub",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )

    def chat_stream(self, messages, model, tools=None, temperature=0.7, max_tokens=None) -> Any:
        raise NotImplementedError

    async def chat_stream_events(
        self,
        *,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncGenerator[StreamEvent, None]:
        self.stream_calls += 1
        yield StreamEvent(kind="text_delta", text="hello")
        yield StreamEvent(kind="done", finish_reason="stop")

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def _router_with_stub(
    issuer: ModelPermitIssuer | None = None,
    *,
    providers: dict[str, _StubProvider] | None = None,
) -> ModelRouter:
    settings = JSSettings(workspace=pathlib.Path("/tmp/x"), providers=[])
    router = ModelRouter(settings, permit_verifier=issuer)
    for name, provider in (providers or {"stub": _StubProvider()}).items():
        router.add_provider(name, provider, [ModelConfig(id="m1", name="m1", provider=name)])
    return router


def _grant(issuer: ModelPermitIssuer, *, owner: str = "owner", session: str = "sess", run: str = "run"):
    def grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash=owner,
            session_id=session,
            run_id=run,
        )

    return grant


async def _noop_before(*_a: Any, **_kw: Any) -> Any:
    return {"claim": "ok"}


async def _noop_after(*_a: Any, **_kw: Any) -> None:
    return None


async def _instant_sleep(_delay: float) -> None:
    return None


# ---------------------------------------------------------------------------
# Gate shape
# ---------------------------------------------------------------------------


def test_router_has_no_public_callback_rebind_api() -> None:
    """The rebind attack surface must not exist at all."""
    assert not hasattr(ModelRouter, "bind_echo_callbacks")
    router = _router_with_stub(ModelPermitIssuer())
    assert not hasattr(router, "bind_echo_callbacks")


@pytest.mark.asyncio
async def test_rebind_attack_cannot_bypass_echo() -> None:
    """The exact P0-1 attack: rebind forged callbacks, then stream.

    Against the unfixed source this succeeds and the forged callbacks run.
    """
    issuer = ModelPermitIssuer()
    router = _router_with_stub(issuer)
    calls = {"genuine_before": 0, "genuine_after": 0, "forged_before": 0, "forged_after": 0}

    async def genuine_before(*_a: Any, **_kw: Any) -> Any:
        calls["genuine_before"] += 1
        return None

    async def genuine_after(*_a: Any, **_kw: Any) -> None:
        calls["genuine_after"] += 1

    async def forged_before(*_a: Any, **_kw: Any) -> Any:
        calls["forged_before"] += 1
        return None

    async def forged_after(*_a: Any, **_kw: Any) -> None:
        calls["forged_after"] += 1

    # Step 1+2 of the original attack: bind genuine, then publicly rebind forged.
    bind = getattr(router, "bind_echo_callbacks", None)
    assert bind is None, "public callback rebind API still exists"

    # Step 3: drive the router with forged callbacks and no valid permit.
    with pytest.raises((RuntimeError, ModelPermitError)):
        async for _ in router.chat_stream_events(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=forged_before,
            after_model_call=forged_after,
        ):
            pass
    assert calls["forged_before"] == 0
    assert calls["forged_after"] == 0
    assert calls["genuine_before"] == 0
    assert calls["genuine_after"] == 0


# ---------------------------------------------------------------------------
# Permit enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chat_without_permit_grant_fails_closed() -> None:
    router = _router_with_stub(ModelPermitIssuer())
    with pytest.raises(RuntimeError):
        await router.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
        )


@pytest.mark.asyncio
async def test_chat_with_valid_permit_grant_succeeds() -> None:
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})
    response = await router.chat(
        messages=[ChatMessage(role="user", content="hi")],
        model="stub/m1",
        before_model_call=_noop_before,
        after_model_call=_noop_after,
        permit_grant=_grant(issuer),
    )
    assert response.content == "stub"
    assert provider.chat_calls == 1


@pytest.mark.asyncio
async def test_forged_permit_rejected_and_provider_never_called() -> None:
    issuer = ModelPermitIssuer()
    attacker = ModelPermitIssuer()  # different signing key
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})

    def forged_grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return attacker.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="sess",
            run_id="run",
        )

    with pytest.raises(ModelPermitError):
        await router.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=forged_grant,
        )
    assert provider.chat_calls == 0


@pytest.mark.asyncio
async def test_tampered_permit_mac_rejected() -> None:
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})

    def tampered_grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        permit = issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="sess",
            run_id="run",
        )
        return replace(permit, mac="deadbeef" * 8)

    with pytest.raises(ModelPermitError):
        await router.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=tampered_grant,
        )
    assert provider.chat_calls == 0


@pytest.mark.asyncio
async def test_permit_replay_rejected() -> None:
    """A permit is single-use: the same permit must not authorize twice."""
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})
    reused: list[Any] = []

    def replaying_grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        if not reused:
            reused.append(
                issuer.issue(
                    provider_name=decision.provider_name,
                    model=decision.model,
                    messages=messages,
                    tools=tools,
                    owner_key_hash="owner",
                    session_id="sess",
                    run_id="run",
                )
            )
        return reused[0]

    messages = [ChatMessage(role="user", content="hi")]
    await router.chat(
        messages=messages,
        model="stub/m1",
        before_model_call=_noop_before,
        after_model_call=_noop_after,
        permit_grant=replaying_grant,
    )
    assert provider.chat_calls == 1
    with pytest.raises(ModelPermitError):
        await router.chat(
            messages=messages,
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=replaying_grant,
        )
    assert provider.chat_calls == 1


@pytest.mark.asyncio
async def test_permit_binds_exact_messages() -> None:
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})

    def wrong_messages_grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=[ChatMessage(role="user", content="different")],
            tools=tools,
            owner_key_hash="owner",
            session_id="sess",
            run_id="run",
        )

    with pytest.raises(ModelPermitError):
        await router.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=wrong_messages_grant,
        )
    assert provider.chat_calls == 0


@pytest.mark.asyncio
async def test_expired_permit_rejected() -> None:
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})

    def expired_grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        permit = issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="sess",
            run_id="run",
        )
        shifted = replace(permit, expires_at=time.time() - 1.0)
        # expiry is part of the signed payload; even an honestly re-signed but
        # expired permit must be rejected.
        return replace(shifted, mac=issuer._mac(shifted))

    with pytest.raises(ModelPermitError):
        await router.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=expired_grant,
        )
    assert provider.chat_calls == 0


class _FlakyProvider(_StubProvider):
    """Fails the first call with a retryable transport error, then succeeds."""

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.chat_calls += 1
        if self.chat_calls == 1:
            import httpx

            raise httpx.ConnectError("transient transport failure")
        return ChatResponse(
            content="stub",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )


@pytest.mark.asyncio
async def test_fallback_issues_fresh_permit_per_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every provider attempt (retry/fallback) must re-issue and re-verify."""
    # Keep the retry backoff fast without weakening the assertions.
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)
    issuer = ModelPermitIssuer()
    flaky = _FlakyProvider("flaky")
    flaky.config = SimpleNamespace(max_retries=3)  # enable the router retry loop
    router = _router_with_stub(issuer, providers={"flaky": flaky})
    issued: list[str] = []

    def counting_grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        permit = issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="sess",
            run_id="run",
        )
        issued.append(permit.nonce)
        return permit

    response = await router.chat(
        messages=[ChatMessage(role="user", content="hi")],
        model="flaky/m1",
        before_model_call=_noop_before,
        after_model_call=_noop_after,
        permit_grant=counting_grant,
    )
    assert response.content == "stub"
    assert flaky.chat_calls == 2
    # each attempt consumed a distinct single-use nonce.
    assert len(issued) == 2
    assert len(set(issued)) == 2


@pytest.mark.asyncio
async def test_stream_events_requires_valid_permit() -> None:
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})

    with pytest.raises(RuntimeError):
        async for _ in router.chat_stream_events(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
        ):
            pass
    assert provider.stream_calls == 0

    kinds = []
    async for ev in router.chat_stream_events(
        messages=[ChatMessage(role="user", content="hi")],
        model="stub/m1",
        before_model_call=_noop_before,
        after_model_call=_noop_after,
        permit_grant=_grant(issuer),
    ):
        kinds.append(ev.kind)
    assert "text_delta" in kinds
    assert "done" in kinds
    assert provider.stream_calls == 1


@pytest.mark.asyncio
async def test_stream_forged_permit_rejected_before_provider() -> None:
    issuer = ModelPermitIssuer()
    attacker = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})

    def forged_grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return attacker.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="sess",
            run_id="run",
        )

    with pytest.raises(ModelPermitError):
        async for _ in router.chat_stream_events(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=forged_grant,
        ):
            pass
    assert provider.stream_calls == 0

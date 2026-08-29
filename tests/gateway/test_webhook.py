"""HMAC webhook channel: signature, replay, and unpaired drop."""

from __future__ import annotations

import json
import time

import pytest

from js.config import GatewayChannelConfig, GatewayConfig, JSSettings
from js.gateway.adapter import ChannelPeer
from js.gateway.channels.webhook import (
    WebhookAuthError,
    WebhookReplayCache,
    parse_webhook_body,
    verify_webhook,
    webhook_signature,
)
from js.gateway.service import GatewayService
from js.security.posture import IsolationLevel, IsolationPosture


def _body(sender: str = "peer-1", text: str = "hello") -> bytes:
    return json.dumps({"sender": sender, "text": text, "message_id": "m1"}).encode("utf-8")


def test_valid_signature_accepts() -> None:
    secret = "s3cret"
    timestamp = str(int(time.time()))
    body = _body()
    signature = webhook_signature(secret, timestamp, body)
    verify_webhook(secret=secret, timestamp=timestamp, signature=signature, body=body)


def test_bad_signature_rejected() -> None:
    timestamp = str(int(time.time()))
    with pytest.raises(WebhookAuthError, match="invalid webhook signature"):
        verify_webhook(
            secret="s3cret",
            timestamp=timestamp,
            signature="00" * 32,
            body=_body(),
        )


def test_stale_timestamp_rejected() -> None:
    secret = "s3cret"
    timestamp = str(int(time.time()) - 1_000)
    body = _body()
    signature = webhook_signature(secret, timestamp, body)
    with pytest.raises(WebhookAuthError, match="replay window"):
        verify_webhook(secret=secret, timestamp=timestamp, signature=signature, body=body)


def test_replay_rejected() -> None:
    secret = "s3cret"
    timestamp = str(int(time.time()))
    body = _body()
    signature = webhook_signature(secret, timestamp, body)
    replay = WebhookReplayCache()
    verify_webhook(
        secret=secret,
        timestamp=timestamp,
        signature=signature,
        body=body,
        replay=replay,
    )
    with pytest.raises(WebhookAuthError, match="replayed"):
        verify_webhook(
            secret=secret,
            timestamp=timestamp,
            signature=signature,
            body=body,
            replay=replay,
        )


def test_parse_requires_sender() -> None:
    with pytest.raises(WebhookAuthError, match="sender"):
        parse_webhook_body(b'{"text":"hi"}', received_at=1.0)


@pytest.mark.asyncio
async def test_webhook_unpaired_does_not_run_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = JSSettings()
    settings.gateway = GatewayConfig(
        enabled=True,
        webhook_secret="s3cret",
        channels=[
            GatewayChannelConfig(
                name="webhook",
                enabled=True,
                bot_id="bot-1",
                owner="owner-a",
            )
        ],
    )
    called = {"n": 0}

    async def _boom(*_args, **_kwargs):
        called["n"] += 1
        raise AssertionError("echo must not run for unpaired sender")

    monkeypatch.setattr("js.echo.turn_runtime.run_echo_turn", _boom)
    service = GatewayService(settings)
    envelope = parse_webhook_body(_body(), received_at=1.0)
    decision = await service.dispatch_echo(object(), envelope)
    assert decision.accepted is False
    assert decision.reason == "unpaired"
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_webhook_paired_dispatches_tainted_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = JSSettings()
    settings.gateway = GatewayConfig(
        enabled=True,
        webhook_secret="s3cret",
        channels=[
            GatewayChannelConfig(
                name="webhook",
                enabled=True,
                bot_id="bot-1",
                owner="owner-a",
            )
        ],
    )
    seen: dict[str, object] = {}

    async def _fake_turn(_agent, text, **kwargs):
        seen["text"] = text
        seen["channel"] = kwargs["channel"]
        seen["owner"] = kwargs["owner_key_hash"]
        seen["session"] = kwargs["session_id"]
        return object()

    monkeypatch.setattr("js.echo.turn_runtime.run_echo_turn", _fake_turn)
    service = GatewayService(settings)
    peer = ChannelPeer(channel="webhook", peer_id="peer-1")
    service.pairing.allow(peer, "owner-a")
    decision = await service.dispatch_echo(
        object(),
        parse_webhook_body(_body(), received_at=1.0),
    )
    assert decision.accepted is True
    assert seen["channel"] == "gateway:webhook"
    assert seen["owner"] == "owner-a"
    assert seen["text"] == "hello"


@pytest.mark.asyncio
async def test_dispatch_echo_enforce_blocks_native_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = JSSettings()
    settings.gateway = GatewayConfig(
        enabled=True,
        channels=[
            GatewayChannelConfig(
                name="webhook",
                enabled=True,
                bot_id="bot-1",
                owner="owner-a",
            )
        ],
    )
    settings.security.untrusted_ingestion_policy = "enforce"  # type: ignore[assignment]
    monkeypatch.setattr(
        "js.security.posture.detect_posture",
        lambda **_kwargs: IsolationPosture(
            level=IsolationLevel.NATIVE_TOOL_SANDBOX,
            in_container=False,
            sandbox_exec=True,
            bwrap=False,
            unshare=False,
            rlimit_as=False,
            platform_name="Darwin",
            untrusted_ingestion_policy="enforce",
        ),
    )
    called = {"n": 0}

    async def _boom(*_args, **_kwargs):
        called["n"] += 1
        raise AssertionError("echo must not run when enforce blocks the surface")

    monkeypatch.setattr("js.echo.turn_runtime.run_echo_turn", _boom)
    service = GatewayService(settings)
    service.pairing.allow(ChannelPeer(channel="webhook", peer_id="peer-1"), "owner-a")
    with pytest.raises(RuntimeError, match="container-full"):
        await service.dispatch_echo(object(), parse_webhook_body(_body(), received_at=1.0))
    assert called["n"] == 0

"""Mock Discord transport: inbound → pairing → Echo → outbound."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from js.config import GatewayChannelConfig, GatewayConfig, JSSettings
from js.gateway.adapter import ChannelPeer, InboundEnvelope
from js.gateway.channels.discord import DiscordChannelAdapter, MockDiscordTransport
from js.gateway.service import GatewayService


def _settings() -> JSSettings:
    settings = JSSettings()
    settings.gateway = GatewayConfig(
        enabled=True,
        channels=[
            GatewayChannelConfig(
                name="discord",
                enabled=True,
                bot_id="bot-1",
                owner="owner-a",
                dm_scope="per-peer",
            )
        ],
    )
    return settings


@pytest.mark.asyncio
async def test_mock_discord_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = MockDiscordTransport()
    adapter = DiscordChannelAdapter(transport)
    service = GatewayService(_settings())
    service.register_adapter(adapter)
    service.bind_inbound(adapter, agent=object())
    service.pairing.allow(ChannelPeer(channel="discord", peer_id="user-1"), "owner-a")

    async def _fake_turn(_agent, text, **kwargs):
        return SimpleNamespace(messages=[SimpleNamespace(role="assistant", content=f"echo:{text}")])

    monkeypatch.setattr("js.echo.turn_runtime.run_echo_turn", _fake_turn)
    await service.start()
    await transport.inject(
        InboundEnvelope(
            peer=ChannelPeer(channel="discord", peer_id="user-1"),
            text="hello",
            message_id="d1",
            received_at=1.0,
        )
    )
    assert transport.outbound == [("user-1", "echo:hello")]
    await service.stop()


@pytest.mark.asyncio
async def test_unpaired_discord_does_not_echo_or_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = MockDiscordTransport()
    adapter = DiscordChannelAdapter(transport)
    service = GatewayService(_settings())
    service.register_adapter(adapter)
    service.bind_inbound(adapter, agent=object())

    async def _boom(*_args, **_kwargs):
        raise AssertionError("unpaired discord must not reach Echo")

    monkeypatch.setattr("js.echo.turn_runtime.run_echo_turn", _boom)
    await service.start()
    await transport.inject(
        InboundEnvelope(
            peer=ChannelPeer(channel="discord", peer_id="stranger"),
            text="hello",
            message_id="d2",
            received_at=1.0,
        )
    )
    assert transport.outbound == []
    await service.stop()


@pytest.mark.asyncio
async def test_discord_start_retries_then_succeeds() -> None:
    class _Flaky:
        def __init__(self) -> None:
            self.attempts = 0
            self.started = False

        async def start(self, handler) -> None:
            self.attempts += 1
            if self.attempts < 3:
                raise ConnectionError("offline")
            self.started = True

        async def stop(self) -> None:
            self.started = False

        async def send(self, peer_id: str, text: str) -> None:
            return None

    transport = _Flaky()
    adapter = DiscordChannelAdapter(transport, max_retries=4, base_delay_seconds=0.01)
    adapter.set_inbound_handler(lambda _env: None)  # type: ignore[arg-type]
    await adapter.start()
    assert transport.started is True
    assert transport.attempts == 3

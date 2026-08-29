"""Cron gateway push uses the lease-gated control tool and whitelist."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from js.config import GatewayConfig, JSSettings
from js.cron.engine import ScheduledJob
from js.daemon.core import JSDaemon
from js.gateway.adapter import ChannelPeer
from js.gateway.push import PushTemplateError


class _FakeAdapter:
    name = "discord"

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def send(self, peer: ChannelPeer, text: str) -> None:
        self.sent.append((peer.key(), text))


@pytest.mark.asyncio
async def test_cron_push_unknown_template_never_sends() -> None:
    daemon = object.__new__(JSDaemon)
    job = ScheduledJob(
        name="bad",
        cron_expr="0 9 * * *",
        task_type="gateway_push",
        payload={"template": "not-a-template", "channel": "discord", "peer_id": "1"},
        owner_key_hash="owner-a",
    )
    with pytest.raises(PushTemplateError):
        await JSDaemon._cb_gateway_push(daemon, job)


@pytest.mark.asyncio
async def test_cron_push_goes_through_execute_tool_effect() -> None:
    seen: dict[str, object] = {}

    class _Runtime:
        def build_context(self, **kwargs):
            seen["context"] = kwargs
            return SimpleNamespace()

        async def execute_tool_effect(self, effect, _context):
            import json

            seen["tool"] = effect.tool_name
            seen["args"] = json.loads(effect.arguments_json)
            return None, SimpleNamespace(success=True, output="sent", error=None)

    daemon = object.__new__(JSDaemon)
    settings = JSSettings()
    settings.gateway = GatewayConfig(enabled=True)
    daemon.agent = SimpleNamespace(echo_runtime=_Runtime(), settings=settings)
    job = ScheduledJob(
        name="brief",
        cron_expr="0 9 * * *",
        task_type="gateway_push",
        payload={"template": "daily_brief", "channel": "discord", "peer_id": "42"},
        owner_key_hash="owner-a",
    )
    output = await JSDaemon._cb_gateway_push(daemon, job)
    assert output == "sent"
    assert seen["tool"] == "control_gateway_push"
    assert seen["args"]["template_id"] == "daily_brief"
    assert seen["context"]["channel"] == "cron_gateway_push"

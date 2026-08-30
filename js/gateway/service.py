"""Gateway lifecycle. Disabled by default; unpaired inbound is dropped."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from js.config import JSSettings
from js.gateway.adapter import ChannelAdapter, ChannelPeer, InboundEnvelope
from js.gateway.pairing import PairingStore
from js.gateway.router import GatewayRouter, RouteBinding
from js.security.posture import require_untrusted_surface
from js.utils.log import get_logger

logger = get_logger("js.gateway")


@dataclass(frozen=True, slots=True)
class DispatchDecision:
    accepted: bool
    reason: str
    route: RouteBinding | None = None
    owner: str | None = None


class GatewayService:
    """Host-owned surface. Does not call a model or tool handler itself."""

    def __init__(
        self,
        settings: JSSettings,
        *,
        pairing: PairingStore | None = None,
        router: GatewayRouter | None = None,
    ) -> None:
        self._settings = settings
        self.pairing = pairing or PairingStore(
            ttl_seconds=settings.gateway.pairing_ttl_seconds,
            discard_log_min_interval_seconds=settings.gateway.discard_log_min_interval_seconds,
            max_attempts_per_peer=settings.gateway.max_pairing_attempts_per_peer,
        )
        self.router = router or GatewayRouter()
        self._adapters: dict[str, ChannelAdapter] = {}
        self._started = False
        for channel in settings.gateway.channels:
            if not channel.enabled or not channel.bot_id:
                continue
            self.router.set_channel_default(
                channel.name,
                owner=channel.owner,
                bot_id=channel.bot_id,
                dm_scope=channel.dm_scope,
            )

    @property
    def enabled(self) -> bool:
        return bool(self._settings.gateway.enabled)

    def register_adapter(self, adapter: ChannelAdapter) -> None:
        if adapter.name in self._adapters:
            raise ValueError(f"adapter already registered: {adapter.name}")
        self._adapters[adapter.name] = adapter

    async def start(self) -> None:
        if not self.enabled:
            raise RuntimeError("gateway.enabled=false; refusing to start adapters")
        require_untrusted_surface(self._settings, "gateway")
        for adapter in self._adapters.values():
            await adapter.start()
        self._started = True
        logger.info("gateway started adapters=%s", sorted(self._adapters))

    async def stop(self) -> None:
        for adapter in self._adapters.values():
            await adapter.stop()
        self._started = False

    def handle_inbound(self, envelope: InboundEnvelope) -> DispatchDecision:
        """Pair, route, and accept. Echo construction is the caller's job."""

        if not self.enabled:
            self.pairing.record_discard(envelope.peer, reason="disabled")
            return DispatchDecision(accepted=False, reason="disabled")
        text = envelope.text.strip()
        if text.startswith("/pair "):
            code = text.split(maxsplit=1)[1]
            owner = self.pairing.redeem(code, envelope.peer)
            if owner is None:
                self.pairing.record_discard(envelope.peer, reason="bad_pairing_code")
                return DispatchDecision(accepted=False, reason="bad_pairing_code")
            return DispatchDecision(accepted=False, reason="paired", owner=owner)
        owner = self.pairing.owner_of(envelope.peer)
        if owner is None:
            self.pairing.record_discard(envelope.peer, reason="unpaired")
            return DispatchDecision(accepted=False, reason="unpaired")
        route = self.router.resolve(envelope.peer)
        if route is None:
            self.pairing.record_discard(envelope.peer, reason="unrouted")
            return DispatchDecision(accepted=False, reason="unrouted", owner=owner)
        if route.owner != owner:
            self.pairing.record_discard(envelope.peer, reason="owner_mismatch")
            return DispatchDecision(accepted=False, reason="owner_mismatch", owner=owner)
        return DispatchDecision(accepted=True, reason="routed", route=route, owner=owner)

    async def dispatch_echo(self, agent: Any, envelope: InboundEnvelope) -> DispatchDecision:
        """Pair, route, then run one tainted Echo turn. Returns the inbound decision."""

        decision = self.handle_inbound(envelope)
        if not decision.accepted or decision.route is None or decision.owner is None:
            return decision
        require_untrusted_surface(self._settings, f"gateway:{envelope.peer.channel}")
        # gateway:* defaults to plan-commit unless echo_plan_commit.enabled
        # is explicitly false (that explicit off is a documented degrade).
        from js.echo.turn_runtime import run_echo_turn

        state = await run_echo_turn(
            agent,
            envelope.text,
            channel=f"gateway:{envelope.peer.channel}",
            owner_key_hash=decision.owner,
            session_id=decision.route.session_key,
            attachments=list(envelope.attachments) or None,
        )
        reply = _assistant_text(state)
        if reply:
            await self.send(envelope.peer, reply)
        return decision

    def bind_inbound(self, adapter: ChannelAdapter, agent: Any) -> None:
        """Wire adapter inbound into a tainted Echo turn and optional reply."""

        async def _on_inbound(envelope: InboundEnvelope) -> None:
            await self.dispatch_echo(agent, envelope)

        setter = getattr(adapter, "set_inbound_handler", None)
        if callable(setter):
            setter(_on_inbound)

    async def send(self, peer: ChannelPeer, text: str) -> None:
        adapter = self._adapters.get(peer.channel)
        if adapter is None:
            raise RuntimeError(f"no adapter for channel {peer.channel}")
        await adapter.send(peer, text)

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "started": self._started,
            "adapters": sorted(self._adapters),
        }


def _assistant_text(state: Any) -> str:
    for msg in reversed(getattr(state, "messages", ())):
        content = getattr(msg, "content", None)
        if getattr(msg, "role", "") == "assistant" and isinstance(content, str) and content:
            return content
    return ""

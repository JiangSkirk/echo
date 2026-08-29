"""Whitelist-only proactive gateway push. Outbound text is never model-authored."""

from __future__ import annotations

from typing import Any, Final

from js.gateway.adapter import ChannelPeer

PUSH_TEMPLATES: Final[dict[str, str]] = {
    "daily_brief": "JS Agent daily brief: Host is healthy. Open the desktop app for details.",
    "health_ok": "JS Agent health check: isolation posture is being monitored.",
}


class PushTemplateError(ValueError):
    """Unknown or empty push template."""


def render_push_template(template_id: str) -> str:
    key = template_id.strip()
    text = PUSH_TEMPLATES.get(key)
    if text is None:
        raise PushTemplateError(f"gateway push template is not allowlisted: {template_id!r}")
    return text


def authorize_push(service: Any, *, owner: str, peer: ChannelPeer) -> str | None:
    """Return an error if the peer is unpaired or belongs to another owner."""

    paired = service.pairing.owner_of(peer)
    if paired is None:
        return "peer is not paired"
    if paired != owner:
        return "owner mismatch"
    return None


def push_peer_from_payload(payload: dict[str, object]) -> ChannelPeer:
    channel = str(payload.get("channel") or "").strip()
    peer_id = str(payload.get("peer_id") or "").strip()
    if not channel or not peer_id:
        raise PushTemplateError("gateway push requires channel and peer_id")
    return ChannelPeer(channel=channel, peer_id=peer_id)

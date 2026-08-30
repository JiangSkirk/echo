"""Derive whether plan-commit / mid-turn narrowing apply to a turn.

Callers must not invent a second gate. ``require_untrusted_surface`` is a
Host ingestion policy and is not consulted here.
"""

from __future__ import annotations

from typing import Any, Final

from js.orin.taint import AUTO_TASK, INBOX_CONTENT, WEB_CONTENT, current_entry_source_taint

READONLY_GATEWAY_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "file_read",
        "list_dir",
        "glob",
        "grep",
        "memory_search",
    }
)

_UNTRUSTED_ENTRY_BITS: Final[int] = INBOX_CONTENT | WEB_CONTENT | AUTO_TASK


def gateway_tool_allowlist(settings: Any) -> frozenset[str]:
    """Return the gateway advertised-tool freeze set.

    Empty ``gateway.tool_allowlist`` means the built-in read-only set, not
    the full registry.
    """

    raw = getattr(getattr(settings, "gateway", None), "tool_allowlist", None) or ()
    names = [item.strip() for item in raw if isinstance(item, str) and item.strip()]
    return frozenset(names) if names else READONLY_GATEWAY_TOOLS


def plan_commit_explicitly_disabled(settings: Any) -> bool:
    """True when the operator set ``echo_plan_commit.enabled=false`` (not default)."""

    cfg = getattr(settings, "echo_plan_commit", None)
    if cfg is None:
        return False
    fields_set: set[str] = set(getattr(cfg, "model_fields_set", set()))
    return "enabled" in fields_set and cfg.enabled is False


def plan_commit_surface_enabled(*, settings: Any, channel: str) -> bool:
    """Whether this channel's plan-commit / narrowing switch is on.

    Global ``echo_plan_commit.enabled=true`` turns the feature on for every
    channel. A running gateway defaults the ``gateway:*`` surface on unless
    the operator explicitly disabled plan-commit.
    """

    if plan_commit_explicitly_disabled(settings):
        return False
    cfg = getattr(settings, "echo_plan_commit", None)
    if cfg is not None and bool(cfg.enabled):
        return True
    gateway = getattr(settings, "gateway", None)
    return bool(gateway is not None and gateway.enabled and channel.startswith("gateway:"))


def plan_commit_turn_active(*, settings: Any, channel: str) -> bool:
    """Whole-turn PLAN→BIND→EXECUTE: untrusted entry and the surface switch."""

    if not plan_commit_surface_enabled(settings=settings, channel=channel):
        return False
    return bool(current_entry_source_taint() & _UNTRUSTED_ENTRY_BITS)


def midturn_narrowing_active(*, settings: Any, channel: str) -> bool:
    """Light-path remaining-iteration write/egress narrowing."""

    return plan_commit_surface_enabled(settings=settings, channel=channel)


def remaining_rebind_active(*, settings: Any, channel: str) -> bool:
    """Mid-turn dirty upgrades remaining iterations to plan-commit BIND.

    Explicit ``remaining_rebind=false`` falls back to P0 write/egress schema drop.
    """

    if not plan_commit_surface_enabled(settings=settings, channel=channel):
        return False
    cfg = getattr(settings, "echo_plan_commit", None)
    if cfg is None:
        return True
    fields_set: set[str] = set(getattr(cfg, "model_fields_set", set()))
    return not ("remaining_rebind" in fields_set and cfg.remaining_rebind is False)

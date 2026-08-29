"""Bots tools are classified. Unregistered names stay deny-in-enforce."""

from __future__ import annotations

from js.orin.inventory import (
    ENFORCE_DISABLED_TOOL_NAMES,
    MEMORY_CELL_TOOL_NAMES,
    PINNED_INVENTORY_DIGEST,
    inventory_digest,
    inventory_digest_matches,
    tool_disabled_under_enforce,
    unclassified_registered_tools,
)


def test_inventory_digest_is_re_pinned() -> None:
    assert inventory_digest() == PINNED_INVENTORY_DIGEST
    assert inventory_digest_matches() is True


def test_bots_tools_are_classified_disabled_in_enforce() -> None:
    for name in ("bots_ask", "rooms_create", "ask_user"):
        assert name in ENFORCE_DISABLED_TOOL_NAMES
        assert name in MEMORY_CELL_TOOL_NAMES
        assert tool_disabled_under_enforce(name) is True
    assert unclassified_registered_tools({"bots_ask", "rooms_create", "ask_user"}) == ()


def test_unknown_bots_tool_is_unclassified() -> None:
    assert unclassified_registered_tools({"bots_exfiltrate"}) == ("bots_exfiltrate",)

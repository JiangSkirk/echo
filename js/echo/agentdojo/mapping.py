"""AgentDojo function names → js-agent ToolSpec names.

This is the P1-1 adapter surface. It is not a drop-in of the AgentDojo
Python package; unknown names fail closed so a suite cannot silently
evaluate an unmapped side effect as a no-op.
"""

from __future__ import annotations

from typing import Final

from js.orin.sinks import TOOL_SINKS

# AgentDojo suite tool → js-agent registry name.
# Workspace / slack / gmail / calendar / banking / travel names from
# Debenedetti et al., NeurIPS 2024 (AgentDojo).
_AGENTDOJO_TO_JS: Final[dict[str, str]] = {
    "create_file": "file_write",
    "append_to_file": "file_write",
    "delete_file": "file_delete",
    "get_file_by_id": "file_read",
    "list_files": "list_dir",
    "search_files": "grep",
    "send_email": "send_mail",
    "send_email_to_contacts": "send_mail",
    "search_emails": "grep",
    "get_unread_emails": "file_read",
    "delete_email": "file_delete",
    "send_direct_message": "send_mail",
    "send_channel_message": "send_mail",
    "get_channels": "list_dir",
    "read_channel_messages": "file_read",
    "add_user_to_channel": "send_mail",
    "get_users_in_channel": "file_read",
    "create_calendar_event": "file_write",
    "cancel_calendar_event": "file_delete",
    "get_day_calendar_events": "file_read",
    "search_calendar_events": "grep",
    "send_money": "shell",
    "schedule_transaction": "shell",
    "update_scheduled_transaction": "shell",
    "get_balance": "file_read",
    "get_most_recent_transactions": "file_read",
    "get_hotels": "web_search",
    "get_flight_information": "web_search",
    "get_user_information": "file_read",
    "get_product_details": "web_search",
    "add_to_cart": "file_write",
}


class MappingError(ValueError):
    """AgentDojo tool has no js-agent mapping."""


def map_agentdojo_tool(name: str) -> str:
    key = str(name or "").strip()
    if not key:
        raise MappingError("AgentDojo tool name is empty")
    mapped = _AGENTDOJO_TO_JS.get(key)
    if mapped is None:
        raise MappingError(f"unmapped AgentDojo tool: {key}")
    if mapped not in TOOL_SINKS:
        raise MappingError(f"mapped js-agent tool has no sink table row: {mapped}")
    return mapped


def mapped_js_tools() -> frozenset[str]:
    return frozenset(_AGENTDOJO_TO_JS.values())


def agentdojo_tools() -> frozenset[str]:
    return frozenset(_AGENTDOJO_TO_JS)

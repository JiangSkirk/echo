"""Clarify keeps the full tools schema and leases only ask_user."""

from __future__ import annotations

import pytest

from js.bots.exceptions import BotsStateError
from js.bots.harness import require_clarify_lease
from js.models.usage import sorted_tools_schema, tools_schema_digest


def test_clarify_lease_is_ask_user_only() -> None:
    require_clarify_lease(("ask_user",))
    with pytest.raises(BotsStateError):
        require_clarify_lease(("ask_user", "shell"))
    with pytest.raises(BotsStateError):
        require_clarify_lease(None)


def test_lease_allowlist_does_not_change_tools_schema() -> None:
    schema = [
        {"function": {"name": "shell", "parameters": {"type": "object"}}},
        {"function": {"name": "ask_user", "parameters": {"type": "object"}}},
        {"function": {"name": "file_read", "parameters": {"type": "object"}}},
    ]
    frozen = sorted_tools_schema(schema)
    lease_tool_allowlist = ("ask_user",)
    names = {item["function"]["name"] for item in frozen}
    allowed = names & set(lease_tool_allowlist)
    assert tools_schema_digest(frozen) == tools_schema_digest(sorted_tools_schema(schema))
    assert allowed == {"ask_user"}
    assert {item["function"]["name"] for item in frozen} == {"ask_user", "file_read", "shell"}

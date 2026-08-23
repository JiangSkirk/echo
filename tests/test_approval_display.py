"""Approval display sanitization must not change binding hashes."""

from __future__ import annotations

from js.orin import taint as t
from js.security.approval_display import sanitize_approval_display
from js.security.approvals import ApprovalQueue


def test_display_truncates_escapes_and_badges() -> None:
    card = sanitize_approval_display(
        tool_name="shell",
        arguments={"command": "<script>alert(1)</script>" + ("z" * 400)},
        context_taint=t.WEB_CONTENT | t.SECRET,
        clearance=t.CLEARANCE_SECRET,
    )
    assert "<script>" not in card
    assert "&lt;script&gt;" in card
    assert "secret-context" in card
    assert "triggered-by-web" in card
    assert "If approved" in card
    assert "canary" not in card.lower()


def test_display_does_not_change_arguments_hash() -> None:
    arguments = {"path": "a.txt", "content": "hello"}
    before = ApprovalQueue.arguments_hash(arguments)
    sanitize_approval_display(tool_name="file_write", arguments=arguments)
    assert ApprovalQueue.arguments_hash(arguments) == before

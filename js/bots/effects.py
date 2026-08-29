"""Bots tool effects. Destinations stay handle-scoped; Echo does not issue Intent."""

from __future__ import annotations

from js.bots.authority import refuse_ask_depth, refuse_echo_issuance, refuse_unknown_commit_replay
from js.orin.handles import echo_cannot_issue_handle, echo_cannot_issue_intent

__all__ = [
    "echo_cannot_issue_handle",
    "echo_cannot_issue_intent",
    "refuse_ask_depth",
    "refuse_echo_issuance",
    "refuse_unknown_commit_replay",
]

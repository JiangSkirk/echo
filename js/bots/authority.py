"""Fail-closed authority helpers for Bots. Taint never authorizes."""

from __future__ import annotations

from js.bots.exceptions import BotsStateError
from js.orin.handles import echo_cannot_issue_handle, echo_cannot_issue_intent


def refuse_unknown_commit_replay(state: str) -> None:
    """UNKNOWN_COMMIT may only reconcile. It must not dispatch again."""

    if state == "UNKNOWN_COMMIT":
        raise BotsStateError("UNKNOWN_COMMIT must reconcile; blind replay is refused")


def refuse_ask_depth(depth: int) -> None:
    if not isinstance(depth, int) or isinstance(depth, bool) or depth > 1:
        raise BotsStateError("bots_ask depth exceeds 1")


def refuse_echo_issuance(*, kind: str) -> None:
    if kind == "intent":
        echo_cannot_issue_intent()
    echo_cannot_issue_handle()

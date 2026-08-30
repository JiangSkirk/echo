"""Bind-time slot labels and remaining-step policy."""

from __future__ import annotations

from js.echo.plan_commit.labels import bind_context_taint, remaining_step_allowed
from js.echo.plan_commit.plan import PlanStep, parse_plan
from js.models.providers import ChatMessage
from js.orin.taint import INBOX_CONTENT, WEB_CONTENT


def test_parse_plan_derives_source_label_from_fill_source() -> None:
    plan = parse_plan(
        '{"steps":[{"tool":"file_read","arguments":{},'
        '"slots":[{"name":"path","taint_policy":"trusted","fill_source":"literal"}]}]}'
    )
    assert plan.steps[0].slots[0].source_label == "user"


def test_remaining_read_allowed_when_dirty() -> None:
    step = PlanStep(tool="file_read", arguments={"path": "a.txt"})
    assert remaining_step_allowed(step, context_taint=WEB_CONTENT) is True


def test_remaining_write_refused_when_dirty() -> None:
    step = PlanStep(
        tool="file_write",
        arguments={"path": "a.txt", "content": "x"},
    )
    assert remaining_step_allowed(step, context_taint=WEB_CONTENT) is False
    assert remaining_step_allowed(step, context_taint=0) is True


def test_remaining_write_refused_when_local_only_deny_write() -> None:
    step = PlanStep(
        tool="file_write",
        arguments={"path": "a.txt", "content": "x"},
    )
    assert remaining_step_allowed(step, context_taint=0, deny_write=True) is False
    read = PlanStep(tool="file_read", arguments={"path": "a.txt"})
    assert remaining_step_allowed(read, context_taint=0, deny_write=True) is True


def test_user_entry_taint_is_not_midturn_dirty() -> None:
    user = ChatMessage(
        role="user",
        content="write notes.txt",
        taint=INBOX_CONTENT | WEB_CONTENT,
    )
    assert bind_context_taint([user]) == 0
    tool = ChatMessage(role="tool", content="html", name="browser_fetch", taint=WEB_CONTENT)
    assert bind_context_taint([user, tool]) & WEB_CONTENT

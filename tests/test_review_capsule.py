"""Tests for Task Review Capsule MVP."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from js.agent.finalizer import FinalizerMixin
from js.agent.state import AgentState
from js.echo.turn_context import reset_current_owner_key_hash, set_current_owner_key_hash
from js.models.providers import ChatMessage
from js.persistence.review_store import ReviewStore
from js.security.secrets import SecretManager


class _DummyFinalizer(FinalizerMixin):
    async def _summarize_context(self, messages: list[ChatMessage]) -> str:
        return ""


def _make_finalizer(tmp_path):
    obj = _DummyFinalizer()
    obj.secrets = SecretManager(tmp_path / "state")
    obj.settings = MagicMock()
    obj.settings.memory.capsule_enabled = False
    obj.memory = MagicMock()
    obj._dream_scheduler = MagicMock()
    obj._quality_scorer = None
    obj.learner = MagicMock()
    obj.compression_feedback = MagicMock()
    obj.optimizer = MagicMock()
    obj.metacognition = MagicMock()
    obj.curator = MagicMock()
    obj.curator.should_run.return_value = False
    obj.evolver = None
    obj.skills = MagicMock()
    obj.guard = MagicMock()
    obj.logger = MagicMock()
    obj.lifecycle_store = MagicMock()
    obj.review_store = ReviewStore(tmp_path / "state" / "review.db")
    return obj


@pytest.mark.asyncio
async def test_review_capsule_created(tmp_path):
    finalizer = _make_finalizer(tmp_path)
    state = AgentState(session_id="s1", run_id="r1")
    state.messages = [
        ChatMessage(role="user", content="hello"),
        ChatMessage(role="assistant", content="world"),
    ]
    state.tool_results = [MagicMock(success=True, metadata={"tool_name": "echo"})]
    state.total_tokens = {"input": 5, "output": 5}
    state.turn_count = 1
    state.status = "completed"

    token = set_current_owner_key_hash("owner_a")
    try:
        await finalizer._finalize_run(state, "s1", "r1", "hello", 0)
    finally:
        reset_current_owner_key_hash(token)

    capsule = finalizer.review_store.get("s1", "r1", "owner_a")
    assert capsule is not None
    assert capsule.first_user_message == "hello"
    assert capsule.last_assistant_message == "world"
    assert capsule.tools_used == [{"name": "echo", "success": True}]
    assert capsule.total_tokens == 10
    assert capsule.turn_count == 1
    assert capsule.status == "completed"
    assert capsule.owner_key_hash == "owner_a"


@pytest.mark.asyncio
async def test_review_capsule_owner_isolation(tmp_path):
    finalizer = _make_finalizer(tmp_path)
    state = AgentState(session_id="s2", run_id="r2")
    state.messages = [ChatMessage(role="user", content="hi")]
    state.status = "completed"

    token = set_current_owner_key_hash("owner_a")
    try:
        await finalizer._finalize_run(state, "s2", "r2", "hi", 0)
    finally:
        reset_current_owner_key_hash(token)

    assert finalizer.review_store.get("s2", "r2", "owner_a") is not None
    assert finalizer.review_store.get("s2", "r2", "owner_b") is None


@pytest.mark.asyncio
async def test_review_capsule_same_session_run_different_owners(tmp_path):
    finalizer = _make_finalizer(tmp_path)
    for owner in ("owner_a", "owner_b"):
        state = AgentState(session_id="same", run_id="same_run")
        state.messages = [ChatMessage(role="user", content=f"hi {owner}")]
        state.status = "completed"
        token = set_current_owner_key_hash(owner)
        try:
            await finalizer._finalize_run(state, "same", "same_run", f"hi {owner}", 0)
        finally:
            reset_current_owner_key_hash(token)

    cap_a = finalizer.review_store.get("same", "same_run", "owner_a")
    cap_b = finalizer.review_store.get("same", "same_run", "owner_b")
    assert cap_a is not None
    assert cap_b is not None
    assert cap_a.first_user_message == "hi owner_a"
    assert cap_b.first_user_message == "hi owner_b"


def test_review_list_recent_none_does_not_leak_authenticated_owners(tmp_path):
    """list_recent(None) must NOT return capsules from authenticated owners."""
    from js.persistence.review_store import ReviewCapsule

    def _cap(session_id: str, run_id: str, owner: str, first_user: str) -> ReviewCapsule:
        return ReviewCapsule(
            session_id=session_id,
            run_id=run_id,
            first_user_message=first_user,
            last_assistant_message="",
            tools_used=[],
            total_tokens=0,
            turn_count=0,
            status="completed",
            error_message="",
            owner_key_hash=owner,
        )

    store = ReviewStore(tmp_path / "review.db")
    store.store(_cap("s_auth_a", "r_a", "owner_a", "auth_a"))
    store.store(_cap("s_auth_b", "r_b", "owner_b", "auth_b"))

    leaked = store.list_recent(None)
    assert leaked == []
    # Default arg behaves identically — legacy-local sentinel, not wildcard.
    assert store.list_recent() == []

    # Owner-scoped reads still work.
    assert [c.run_id for c in store.list_recent("owner_a")] == ["r_a"]


@pytest.mark.asyncio
async def test_review_capsule_redacts_secrets(tmp_path):
    finalizer = _make_finalizer(tmp_path)
    state = AgentState(session_id="s3", run_id="r3")
    secret = "sk-test12345678901234567890"
    state.messages = [
        ChatMessage(role="user", content=f"key is {secret}"),
        ChatMessage(role="assistant", content=f"use {secret}"),
    ]
    state.status = "completed"

    await finalizer._finalize_run(state, "s3", "r3", f"key is {secret}", 0)

    capsule = finalizer.review_store.get("s3", "r3")
    assert secret not in capsule.first_user_message
    assert secret not in capsule.last_assistant_message
    assert "[REDACTED" in capsule.first_user_message

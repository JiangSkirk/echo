"""Tests for Task Review Capsule MVP."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from js.agent.finalizer import FinalizerMixin
from js.agent.state import AgentState
from js.models.providers import ChatMessage
from js.persistence.review_store import ReviewStore
from js.security.secrets import SecretManager
from js.web.auth import _session_owner_hash


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

    token = _session_owner_hash.set("owner_a")
    try:
        await finalizer._finalize_run(state, "s1", "r1", "hello", 0)
    finally:
        _session_owner_hash.reset(token)

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

    token = _session_owner_hash.set("owner_a")
    try:
        await finalizer._finalize_run(state, "s2", "r2", "hi", 0)
    finally:
        _session_owner_hash.reset(token)

    assert finalizer.review_store.get("s2", "r2", "owner_a") is not None
    assert finalizer.review_store.get("s2", "r2", "owner_b") is None


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

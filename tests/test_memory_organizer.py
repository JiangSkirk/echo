"""Tests for MemoryOrganizer: structured extraction → proposal queue.

Uses a fake router (no real LLM) so extraction is deterministic.  Verifies the
confirmation gate (sensitive identity/family → pending, everything else
auto-applied), provenance (evidence/session_id/confidence), the conversation
summary, robust JSON parsing, and graceful failure.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from js.config import MemoryConfig
from js.memory.organizer import MemoryOrganizer
from js.memory.store import MemoryStore


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeRouter:
    """Returns a canned response, recording the last messages it received."""

    def __init__(self, content: str) -> None:
        self._content = content
        self.last_messages: list[Any] | None = None

    async def chat(self, messages: list[Any], temperature: float = 0.7, **kw: Any) -> _FakeResponse:
        self.last_messages = messages
        return _FakeResponse(self._content)


def _payload(facts: list[dict[str, Any]], summary: str = "一次对话") -> str:
    return json.dumps({"summary": summary, "facts": facts}, ensure_ascii=False)


@pytest.fixture
def memory(tmp_path: Path) -> MemoryStore:
    mem = MemoryStore(tmp_path, MemoryConfig())
    yield mem
    mem.close()


_FACTS = [
    {"key": "老婆姓名", "value": "小红", "category": "fact", "confidence": 0.95, "evidence": "我老婆叫小红"},
    {"key": "喜欢的语言", "value": "Python", "category": "preference", "confidence": 0.9, "evidence": "我平时写 Python"},
    {"key": "当前项目", "value": "电商重构", "category": "fact", "confidence": 0.85, "evidence": "在做电商重构"},
    {"key": "生日", "value": "1990-05-01", "category": "fact", "confidence": 0.92, "evidence": "我90年生"},
]


async def _run(memory: MemoryStore, content: str, **kw: Any) -> dict[str, Any]:
    org = MemoryOrganizer(memory, _FakeRouter(content), MemoryConfig())
    buf = [{"user": "聊了家庭和工作", "assistant": "好的"}]
    return await org.extract(buf, session_id=kw.get("session_id", "s1"),
                             owner_key_hash=kw.get("owner_key_hash"))


class TestExtraction:
    @pytest.mark.asyncio
    async def test_extracts_and_gates_sensitive(self, memory: MemoryStore) -> None:
        rep = await _run(memory, _payload(_FACTS), owner_key_hash="U1")
        assert rep["ok"] is True
        assert rep["proposed"] == 4
        # family + birthday(identity) are sensitive → pending; the rest auto-apply.
        assert rep["auto_applied"] == 2
        assert rep["pending"] == 2
        pending = {p["key"] for p in memory.list_proposals(owner_key_hash="U1")}
        assert pending == {"老婆姓名", "生日"}

    @pytest.mark.asyncio
    async def test_auto_applied_facts_are_stored(self, memory: MemoryStore) -> None:
        await _run(memory, _payload(_FACTS), owner_key_hash="U1")
        keys = {m["key"] for m in memory.get_all_semantic(owner_key_hash="U1")}
        assert "喜欢的语言" in keys
        assert "当前项目" in keys
        # Sensitive ones are NOT yet stored (await confirmation).
        assert "老婆姓名" not in keys
        assert "生日" not in keys

    @pytest.mark.asyncio
    async def test_evidence_and_provenance_persisted(self, memory: MemoryStore) -> None:
        await _run(memory, _payload(_FACTS), owner_key_hash="U1", session_id="sess-42")
        pref = next(m for m in memory.get_all_semantic(owner_key_hash="U1")
                    if m["key"] == "喜欢的语言")
        assert pref["evidence"] == "我平时写 Python"
        assert pref["session_id"] == "sess-42"
        assert pref["source"] == "organizer"
        assert 0.0 <= pref["confidence"] <= 1.0

    @pytest.mark.asyncio
    async def test_conversation_summary_written_to_history(self, memory: MemoryStore) -> None:
        await _run(memory, _payload(_FACTS, summary="讨论了家庭与项目"),
                   owner_key_hash="U1", session_id="sess-42")
        hist = memory.get_by_block("/history/chats", owner_key_hash="U1")
        summaries = [h for h in hist if h["key"] == "chat_summary_sess-42"]
        assert summaries and summaries[0]["value"] == "讨论了家庭与项目"

    @pytest.mark.asyncio
    async def test_approve_pending_commits_to_library(self, memory: MemoryStore) -> None:
        await _run(memory, _payload(_FACTS), owner_key_hash="U1")
        fam = next(p for p in memory.list_proposals(owner_key_hash="U1")
                   if p["key"] == "老婆姓名")
        res = memory.approve_proposal(fam["id"], owner_key_hash="U1")
        assert res["success"] is True
        family_block = memory.get_by_block("/people/family", owner_key_hash="U1")
        committed = [m for m in family_block if m["key"] == "老婆姓名"]
        assert committed
        # User approval marks the memory as verified.
        assert committed[0]["last_verified_at"] > 0

    @pytest.mark.asyncio
    async def test_duplicate_pending_skipped_on_rerun(self, memory: MemoryStore) -> None:
        first = await _run(memory, _payload(_FACTS), owner_key_hash="U1")
        assert first["pending"] == 2
        # Re-organizing the same conversation must not double-stage pending items.
        second = await _run(memory, _payload(_FACTS), owner_key_hash="U1")
        assert second["duplicate"] == 2
        assert second["pending"] == 0
        pending = memory.list_proposals(owner_key_hash="U1")
        sensitive = [p for p in pending if p["key"] in ("老婆姓名", "生日")]
        assert len(sensitive) == 2  # still exactly the originals, no duplicates

    @pytest.mark.asyncio
    async def test_approve_with_overrides_edits_before_commit(self, memory: MemoryStore) -> None:
        await _run(memory, _payload(_FACTS), owner_key_hash="U1")
        fam = next(p for p in memory.list_proposals(owner_key_hash="U1")
                   if p["key"] == "老婆姓名")
        res = memory.approve_proposal(
            fam["id"], owner_key_hash="U1",
            overrides={"value": "小芳", "memory_path": "/people/family"},
        )
        assert res["success"] is True
        family_block = memory.get_by_block("/people/family", owner_key_hash="U1")
        committed = [m for m in family_block if m["key"] == "老婆姓名"]
        assert committed and committed[0]["value"] == "小芳"


class TestRobustness:
    @pytest.mark.asyncio
    async def test_parses_fenced_json_with_prose(self, memory: MemoryStore) -> None:
        fenced = "Here you go:\n```json\n" + _payload(_FACTS[:1]) + "\n```\nDone."
        rep = await _run(memory, fenced, owner_key_hash="U1")
        assert rep["proposed"] == 1

    @pytest.mark.asyncio
    async def test_unparseable_output_is_graceful(self, memory: MemoryStore) -> None:
        rep = await _run(memory, "I could not find anything structured.", owner_key_hash="U1")
        assert rep["ok"] is False
        assert rep["proposed"] == 0
        assert rep["error"]

    @pytest.mark.asyncio
    async def test_empty_buffer_is_noop(self, memory: MemoryStore) -> None:
        org = MemoryOrganizer(memory, _FakeRouter(_payload(_FACTS)), MemoryConfig())
        rep = await org.extract([], session_id="s1", owner_key_hash="U1")
        assert rep["ok"] is True
        assert rep["proposed"] == 0

    @pytest.mark.asyncio
    async def test_auto_extract_disabled_skips(self, memory: MemoryStore) -> None:
        cfg = MemoryConfig(auto_extract=False)
        org = MemoryOrganizer(memory, _FakeRouter(_payload(_FACTS)), cfg)
        rep = await org.extract([{"user": "hi", "assistant": "yo"}],
                                session_id="s1", owner_key_hash="U1")
        assert rep["ok"] is True
        assert rep["proposed"] == 0

    @pytest.mark.asyncio
    async def test_llm_failure_is_graceful(self, memory: MemoryStore) -> None:
        class _BoomRouter:
            async def chat(self, *a: Any, **k: Any) -> Any:
                raise RuntimeError("model offline")

        org = MemoryOrganizer(memory, _BoomRouter(), MemoryConfig())
        rep = await org.extract([{"user": "hi", "assistant": "yo"}],
                                session_id="s1", owner_key_hash="U1")
        assert rep["ok"] is False
        assert "model offline" in (rep["error"] or "")

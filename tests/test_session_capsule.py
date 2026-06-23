"""Tests for Session Capsule (lite MVP)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from js.agent import JSAgent
from js.config import JSSettings, MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore
from js.models.providers import ChatMessage, ChatResponse, ModelProvider


class MockProvider(ModelProvider):
    """Provider that captures the messages sent to the model."""

    def __init__(self, responses: list[ChatResponse]) -> None:
        self.responses = responses
        self.index = 0
        self.last_messages: list[ChatMessage] | None = None

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.last_messages = messages
        resp = (
            self.responses[self.index]
            if self.index < len(self.responses)
            else ChatResponse(
                content="done", tool_calls=[], model=model, usage={}, finish_reason="stop"
            )
        )
        self.index += 1
        return resp

    def chat_stream(self, *args: Any, **kwargs: Any) -> Any:
        async def _gen():
            yield "done"

        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


@pytest.fixture
def tmp_store(tmp_path: Path) -> EnhancedMemoryStore:
    return EnhancedMemoryStore(tmp_path / "state", MemoryConfig())


def test_capsule_crud(tmp_store: EnhancedMemoryStore) -> None:
    capsule = tmp_store.get_capsule("s1")
    assert capsule is None

    tmp_store.store_capsule("s1", "summary one", owner_key_hash="owner-a")
    capsule = tmp_store.get_capsule("s1", owner_key_hash="owner-a")
    assert capsule is not None
    assert capsule["capsule_text"] == "summary one"
    assert capsule["owner_key_hash"] == "owner-a"
    assert capsule["updated_at"] > 0

    tmp_store.store_capsule("s1", "summary two", owner_key_hash="owner-a")
    capsule = tmp_store.get_capsule("s1", owner_key_hash="owner-a")
    assert capsule["capsule_text"] == "summary two"

    assert tmp_store.delete_capsule("s1", owner_key_hash="owner-a") is True
    assert tmp_store.get_capsule("s1", owner_key_hash="owner-a") is None
    assert tmp_store.delete_capsule("s1", owner_key_hash="owner-a") is False


def test_capsule_owner_isolation(tmp_store: EnhancedMemoryStore) -> None:
    tmp_store.store_capsule("s1", "owner a capsule", owner_key_hash="owner-a")
    tmp_store.store_capsule("s1", "owner b capsule", owner_key_hash="owner-b")

    assert (
        tmp_store.get_capsule("s1", owner_key_hash="owner-a")["capsule_text"] == "owner a capsule"
    )
    assert (
        tmp_store.get_capsule("s1", owner_key_hash="owner-b")["capsule_text"] == "owner b capsule"
    )
    # No owner → only the legacy/shared NULL-owner row is visible.
    assert tmp_store.get_capsule("s1") is None

    # Updating one owner's capsule must not touch the other owner's row.
    tmp_store.store_capsule("s1", "owner a updated", owner_key_hash="owner-a")
    assert (
        tmp_store.get_capsule("s1", owner_key_hash="owner-b")["capsule_text"] == "owner b capsule"
    )

    # Deleting one owner's capsule must not touch the other owner's row.
    assert tmp_store.delete_capsule("s1", owner_key_hash="owner-a") is True
    assert tmp_store.get_capsule("s1", owner_key_hash="owner-a") is None
    assert tmp_store.get_capsule("s1", owner_key_hash="owner-b") is not None

    assert tmp_store.delete_capsule("s1", owner_key_hash="owner-b") is True
    assert tmp_store.get_capsule("s1", owner_key_hash="owner-b") is None


def test_capsule_owner_partition_delete_isolation(tmp_store: EnhancedMemoryStore) -> None:
    """Deleting one owner's capsule must leave the other owner's capsule intact."""
    tmp_store.store_capsule("shared-session", "owner a", owner_key_hash="owner-a")
    tmp_store.store_capsule("shared-session", "owner b", owner_key_hash="owner-b")

    assert tmp_store.delete_capsule("shared-session", owner_key_hash="owner-a") is True
    assert tmp_store.get_capsule("shared-session", owner_key_hash="owner-a") is None
    assert (
        tmp_store.get_capsule("shared-session", owner_key_hash="owner-b")["capsule_text"]
        == "owner b"
    )

    assert tmp_store.delete_capsule("shared-session", owner_key_hash="owner-b") is True
    assert tmp_store.get_capsule("shared-session", owner_key_hash="owner-b") is None


@pytest.mark.asyncio
async def test_run_rejects_cross_owner_session_history(tmp_path: Path) -> None:
    """A user must not be able to reuse another owner's session_id."""
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
    )
    agent = JSAgent(settings)
    agent.memory.store_messages(
        "private-session",
        [{"role": "user", "content": "owner-a private context"}],
        owner_key_hash="owner-a",
    )
    agent.memory.store_episode(
        "private-session",
        "private summary",
        ["private"],
        owner_key_hash="owner-a",
    )

    provider = MockProvider(
        [
            ChatResponse(
                content="should not run",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                finish_reason="stop",
            ),
        ]
    )
    from js.config import ModelConfig

    agent.router.add_provider(
        "mock", provider, [ModelConfig(id="mock", name="Mock", context_window=4096)]
    )

    from js.web.auth import _session_owner_hash

    token = _session_owner_hash.set("owner-b")
    try:
        await agent.run("hello", session_id="private-session", model="mock/mock")
    finally:
        _session_owner_hash.reset(token)
        await agent.close()

    # owner-b's run must not see owner-a's private context.
    assert provider.last_messages is not None
    contents = "\n".join(str(m.content) for m in provider.last_messages)
    assert "owner-a private context" not in contents

    # owner-a's isolated session data must remain intact.
    assert len(agent.memory.get_session_messages("private-session", owner_key_hash="owner-a")) == 1
    assert agent.memory.get_episodes(owner_key_hash="owner-a")[0].session_id == "private-session"


@pytest.mark.asyncio
async def test_capsule_injection_keeps_recent_turns(tmp_path: Path) -> None:
    """When a capsule exists, only the most recent N user/assistant turns are kept verbatim."""
    state_dir = tmp_path / "state"
    workspace = tmp_path / "workspace"
    settings = JSSettings(
        workspace=workspace,
        state_dir=state_dir,
        memory=MemoryConfig(
            capsule_enabled=True,
            capsule_recent_turns=4,
        ),
        max_turns=3,
    )
    agent = JSAgent(settings)
    # Disable compression so we can verify exact message counts.
    agent.compressor.config.enable_compression = False

    # Seed session history: 10 user/assistant pairs
    store = agent.memory
    history: list[dict[str, str]] = []
    for i in range(10):
        history.append({"role": "user", "content": f"user message {i}"})
        history.append({"role": "assistant", "content": f"assistant reply {i}"})
    store.store_messages("session-x", history)

    # Store a capsule
    store.store_capsule("session-x", "This is the long capsule summary.")

    # Mock provider: use a context window that keeps dynamic recent_turns at the base value.
    provider = MockProvider(
        [
            ChatResponse(
                content="ok",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                finish_reason="stop",
            ),
        ]
    )
    from js.config import ModelConfig

    agent.router.add_provider(
        "mock", provider, [ModelConfig(id="mock", name="Mock", context_window=32000)]
    )

    await agent.run("hello", session_id="session-x", model="mock/mock")

    assert provider.last_messages is not None
    roles = [m.role for m in provider.last_messages]

    # System message + recent 4 user + recent 4 assistant + current user
    assert roles[0] == "system"
    assert "Session Capsule" in provider.last_messages[0].content
    assert "This is the long capsule summary." in provider.last_messages[0].content

    user_count = sum(1 for r in roles if r == "user")
    assistant_count = sum(1 for r in roles if r == "assistant")
    # 4 recent pairs + current user input
    assert user_count == 5
    assert assistant_count == 4

    # Verify older turns are not present
    contents = "\n".join(str(m.content) for m in provider.last_messages)
    assert "user message 0" not in contents
    assert "user message 9" in contents

    await agent.close()


@pytest.mark.asyncio
async def test_capsule_refresh_uses_current_owner_context(tmp_path: Path) -> None:
    """Capsule persistence should use the request owner, not stale agent state."""
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        memory=MemoryConfig(capsule_enabled=True, capsule_token_threshold=1),
        max_turns=1,
    )
    agent = JSAgent(settings)
    agent._session_owner = "stale-owner"  # type: ignore[attr-defined]

    provider = MockProvider(
        [
            ChatResponse(
                content="ok",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="stop",
            ),
            ChatResponse(
                content="fresh owner capsule",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
                finish_reason="stop",
            ),
        ]
    )
    from js.config import ModelConfig

    agent.router.add_provider(
        "mock", provider, [ModelConfig(id="mock", name="Mock", context_window=4096)]
    )

    from js.web.auth import _session_owner_hash

    token = _session_owner_hash.set("fresh-owner")
    try:
        await agent.run("hello", session_id="owner-session", model="mock/mock")
    finally:
        _session_owner_hash.reset(token)
        await agent.close()

    capsule = agent.memory.get_capsule("owner-session", owner_key_hash="fresh-owner")
    assert capsule is not None
    assert capsule["capsule_text"] == "fresh owner capsule"
    assert agent.memory.get_capsule("owner-session", owner_key_hash="stale-owner") is None


@pytest.mark.asyncio
async def test_capsule_disabled_uses_full_history(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        memory=MemoryConfig(capsule_enabled=False),
        max_turns=3,
    )
    agent = JSAgent(settings)

    store = agent.memory
    store.store_capsule("session-y", "capsule")
    history: list[dict[str, str]] = []
    for i in range(10):
        history.append({"role": "user", "content": f"msg {i}"})
        history.append({"role": "assistant", "content": f"reply {i}"})
    store.store_messages("session-y", history)

    provider = MockProvider(
        [
            ChatResponse(
                content="ok",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                finish_reason="stop",
            ),
        ]
    )
    from js.config import ModelConfig

    agent.router.add_provider(
        "mock", provider, [ModelConfig(id="mock", name="Mock", context_window=4096)]
    )

    await agent.run("hello", session_id="session-y", model="mock/mock")

    assert provider.last_messages is not None
    # Full history (up to 50) is kept; capsule should not appear.
    contents = "\n".join(str(m.content) for m in provider.last_messages)
    assert "capsule" not in contents
    assert "msg 0" in contents

    await agent.close()


@pytest.mark.asyncio
async def test_capsule_load_failure_fallback(tmp_path: Path) -> None:
    """If get_capsule raises, the agent still runs with full history."""
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        memory=MemoryConfig(capsule_enabled=True),
        max_turns=3,
    )
    agent = JSAgent(settings)

    # Monkey-patch get_capsule to raise
    original = agent.memory.get_capsule
    agent.memory.get_capsule = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]

    history = [
        {"role": "user", "content": "old user"},
        {"role": "assistant", "content": "old assistant"},
    ]
    agent.memory.store_messages("session-z", history)

    provider = MockProvider(
        [
            ChatResponse(
                content="ok",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                finish_reason="stop",
            ),
        ]
    )
    from js.config import ModelConfig

    agent.router.add_provider(
        "mock", provider, [ModelConfig(id="mock", name="Mock", context_window=4096)]
    )

    state = await agent.run("hello", session_id="session-z", model="mock/mock")
    assert state.status == "completed"

    # Restore
    agent.memory.get_capsule = original  # type: ignore[method-assign]
    await agent.close()


def test_get_session_messages_owner_filter(tmp_store: EnhancedMemoryStore) -> None:
    """Messages are strictly isolated by owner; no cross-owner fallback."""
    tmp_store.store_messages(
        "s1",
        [{"role": "user", "content": "legacy message"}],
        owner_key_hash=None,
    )
    tmp_store.store_messages(
        "s1",
        [{"role": "user", "content": "owner-a message"}],
        owner_key_hash="owner-a",
    )
    tmp_store.store_messages(
        "s1",
        [{"role": "user", "content": "owner-b message"}],
        owner_key_hash="owner-b",
    )

    # No-auth / local anonymous request sees only the sentinel-owner legacy rows.
    messages = tmp_store.get_session_messages("s1", owner_key_hash=None)
    contents = {m["content"] for m in messages}
    assert contents == {"legacy message"}

    # Authenticated owners see only their own rows.
    messages_a = tmp_store.get_session_messages("s1", owner_key_hash="owner-a")
    assert {m["content"] for m in messages_a} == {"owner-a message"}

    messages_b = tmp_store.get_session_messages("s1", owner_key_hash="owner-b")
    assert {m["content"] for m in messages_b} == {"owner-b message"}


def test_delete_session_is_owner_scoped(tmp_store: EnhancedMemoryStore) -> None:
    """delete_session must only remove the current owner's partition."""
    tmp_store.store_messages(
        "shared-session",
        [{"role": "user", "content": "owner-a message"}],
        owner_key_hash="owner-a",
    )
    tmp_store.store_episode(
        "shared-session",
        "owner-a summary",
        ["owner-a"],
        owner_key_hash="owner-a",
    )
    tmp_store.store_working(
        "shared-session",
        "key",
        "owner-a working",
        owner_key_hash="owner-a",
    )
    tmp_store.store_capsule(
        "shared-session",
        "owner-a capsule",
        owner_key_hash="owner-a",
    )

    tmp_store.store_messages(
        "shared-session",
        [{"role": "user", "content": "owner-b message"}],
        owner_key_hash="owner-b",
    )
    tmp_store.store_episode(
        "shared-session",
        "owner-b summary",
        ["owner-b"],
        owner_key_hash="owner-b",
    )
    tmp_store.store_working(
        "shared-session",
        "key",
        "owner-b working",
        owner_key_hash="owner-b",
    )
    tmp_store.store_capsule(
        "shared-session",
        "owner-b capsule",
        owner_key_hash="owner-b",
    )

    # Delete only owner-a's partition.
    assert tmp_store.delete_session("shared-session", owner_key_hash="owner-a") is True

    assert tmp_store.get_session_messages("shared-session", owner_key_hash="owner-a") == []
    assert tmp_store.get_working("shared-session", owner_key_hash="owner-a") == []
    assert tmp_store.get_capsule("shared-session", owner_key_hash="owner-a") is None
    assert tmp_store.get_episodes(owner_key_hash="owner-a") == []

    # Owner-b's partition must remain intact.
    assert len(tmp_store.get_session_messages("shared-session", owner_key_hash="owner-b")) == 1
    assert len(tmp_store.get_working("shared-session", owner_key_hash="owner-b")) == 1
    assert tmp_store.get_capsule("shared-session", owner_key_hash="owner-b") is not None
    assert len(tmp_store.get_episodes(owner_key_hash="owner-b")) == 1

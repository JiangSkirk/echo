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
        resp = self.responses[self.index] if self.index < len(self.responses) else ChatResponse(
            content="done", tool_calls=[], model=model, usage={}, finish_reason="stop"
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

    assert tmp_store.get_capsule("s1", owner_key_hash="owner-a") is not None
    assert tmp_store.get_capsule("s1", owner_key_hash="owner-b") is None
    assert tmp_store.get_capsule("s1") is None

    assert tmp_store.delete_capsule("s1", owner_key_hash="owner-b") is False
    assert tmp_store.delete_capsule("s1", owner_key_hash="owner-a") is True


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

    # Seed session history: 10 user/assistant pairs
    store = agent.memory
    history: list[dict[str, str]] = []
    for i in range(10):
        history.append({"role": "user", "content": f"user message {i}"})
        history.append({"role": "assistant", "content": f"assistant reply {i}"})
    store.store_messages("session-x", history)

    # Store a capsule
    store.store_capsule("session-x", "This is the long capsule summary.")

    # Mock provider
    provider = MockProvider([
        ChatResponse(content="ok", tool_calls=[], model="mock", usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}, finish_reason="stop"),
    ])
    from js.config import ModelConfig
    agent.router.add_provider("mock", provider, [ModelConfig(id="mock", name="Mock", context_window=4096)])

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

    provider = MockProvider([
        ChatResponse(content="ok", tool_calls=[], model="mock", usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}, finish_reason="stop"),
    ])
    from js.config import ModelConfig
    agent.router.add_provider("mock", provider, [ModelConfig(id="mock", name="Mock", context_window=4096)])

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

    history = [{"role": "user", "content": "old user"}, {"role": "assistant", "content": "old assistant"}]
    agent.memory.store_messages("session-z", history)

    provider = MockProvider([
        ChatResponse(content="ok", tool_calls=[], model="mock", usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}, finish_reason="stop"),
    ])
    from js.config import ModelConfig
    agent.router.add_provider("mock", provider, [ModelConfig(id="mock", name="Mock", context_window=4096)])

    state = await agent.run("hello", session_id="session-z", model="mock/mock")
    assert state.status == "completed"

    # Restore
    agent.memory.get_capsule = original  # type: ignore[method-assign]
    await agent.close()

"""Provider failover and degraded mode tests.

Verifies:
- Automatic fallback when primary provider fails
- Degraded mode entry when all providers are unhealthy
- Tool schema filtering in degraded mode
- Recovery detection when providers come back online
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from js.agent import JSAgent
from js.config import JSSettings, ModelConfig
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter

# Shared model config for tests
_TEST_MODEL = ModelConfig(id="gpt-test", name="Test Model", context_window=4096)


class ToggleableMockProvider(ModelProvider):
    """Mock provider with controllable health and scripted responses."""

    def __init__(self, name: str, healthy: bool = True) -> None:
        self.name = name
        self.healthy = healthy
        self.calls: list[list[ChatMessage]] = []
        self._responses: list[ChatResponse] = []
        self._index = 0

    def set_responses(self, responses: list[ChatResponse]) -> None:
        self._responses = responses
        self._index = 0

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls.append(messages)
        if self._index < len(self._responses):
            resp = self._responses[self._index]
            self._index += 1
            return resp
        return ChatResponse(
            content=f"Response from {self.name}",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            finish_reason="stop",
        )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        async def _gen() -> AsyncIterator[str]:
            yield f"Stream from {self.name}"
        return _gen()

    async def health_check(self) -> bool:
        return self.healthy

    async def close(self) -> None:
        pass


class TestRouterFailover:
    """Test ModelRouter fallback logic between multiple providers."""

    @pytest.fixture
    def router(self) -> ModelRouter:
        settings = JSSettings()
        return ModelRouter(settings)

    @pytest.mark.asyncio
    async def test_primary_healthy_uses_preferred(self, router: ModelRouter) -> None:
        """When preferred provider is healthy, it receives the request."""
        primary = ToggleableMockProvider("primary", healthy=True)
        backup = ToggleableMockProvider("backup", healthy=True)

        router.add_provider("primary", primary, [_TEST_MODEL])
        router.add_provider("backup", backup, [_TEST_MODEL])

        primary.set_responses([
            ChatResponse(
                content="Primary OK",
                tool_calls=[],
                model="gpt",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])

        resp = await router.chat([ChatMessage(role="user", content="hi")], model="primary/gpt-test")
        assert "Primary OK" in (resp.content or "")
        assert len(primary.calls) == 1
        assert len(backup.calls) == 0

    @pytest.mark.asyncio
    async def test_primary_unhealthy_fallback_to_backup(self, router: ModelRouter) -> None:
        """Primary fails → router automatically falls back to backup provider."""
        primary = ToggleableMockProvider("primary", healthy=False)
        backup = ToggleableMockProvider("backup", healthy=True)

        router.add_provider("primary", primary, [_TEST_MODEL])
        router.add_provider("backup", backup, [_TEST_MODEL])

        backup.set_responses([
            ChatResponse(
                content="Backup OK",
                tool_calls=[],
                model="gpt",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])

        resp = await router.chat([ChatMessage(role="user", content="hi")], model=None)
        assert "Backup OK" in (resp.content or "")
        # Primary may or may not have been called depending on select_model ordering;
        # the key assertion is that backup served the request.
        assert len(backup.calls) >= 1

    @pytest.mark.asyncio
    async def test_all_unhealthy_raises_runtime_error(self, router: ModelRouter) -> None:
        """When all providers are unhealthy and all chat calls fail, router raises RuntimeError."""
        primary = ToggleableMockProvider("primary", healthy=False)
        backup = ToggleableMockProvider("backup", healthy=False)

        router.add_provider("primary", primary, [_TEST_MODEL])
        router.add_provider("backup", backup, [_TEST_MODEL])

        # Force both providers to raise on chat
        async def _fail(*args: Any, **kwargs: Any) -> ChatResponse:
            raise RuntimeError("provider down")

        primary.chat = _fail  # type: ignore[method-assign]
        backup.chat = _fail  # type: ignore[method-assign]

        with pytest.raises(RuntimeError, match="All providers failed"):
            await router.chat([ChatMessage(role="user", content="hi")], model=None)


class TestDegradedMode:
    """Test JSAgent degraded mode behavior."""

    @pytest.fixture
    def agent(self, tmp_path: Path) -> JSAgent:
        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=10,
        )
        return JSAgent(settings)

    @pytest.mark.asyncio
    async def test_healthy_providers_not_degraded(self, agent: JSAgent) -> None:
        """With healthy providers, agent should not be degraded."""
        healthy_provider = ToggleableMockProvider("lmstudio", healthy=True)
        agent.router.add_provider("lmstudio", healthy_provider, [_TEST_MODEL])
        await agent._check_degraded()
        assert not agent.degraded
        assert agent.degraded_reason == ""

    @pytest.mark.asyncio
    async def test_all_unhealthy_enters_degraded(self, agent: JSAgent) -> None:
        """All providers unhealthy → degraded mode with reason set."""
        unhealthy = ToggleableMockProvider("lmstudio", healthy=False)
        agent.router.add_provider("lmstudio", unhealthy, [_TEST_MODEL])
        await agent._check_degraded()
        assert agent.degraded
        assert "All providers unhealthy" in agent.degraded_reason

    @pytest.mark.asyncio
    async def test_recovery_exits_degraded(self, agent: JSAgent) -> None:
        """Provider recovers → agent exits degraded mode."""
        provider = ToggleableMockProvider("lmstudio", healthy=False)
        agent.router.add_provider("lmstudio", provider, [_TEST_MODEL])

        await agent._check_degraded()
        assert agent.degraded

        provider.healthy = True
        await agent._check_degraded()
        assert not agent.degraded
        assert agent.degraded_reason == ""

    def test_degraded_filters_nonessential_tools(self, agent: JSAgent) -> None:
        """Degraded mode removes web_search and browser tools from schema."""
        # Register mock tools
        from js.tools.registry import ToolParam, ToolSpec

        agent.registry.register(
            ToolSpec(name="file_read", description="Read file", parameters=[ToolParam("path", "string", "Path")]),
            lambda path: None,  # type: ignore[return-value]
        )
        agent.registry.register(
            ToolSpec(name="web_search", description="Search web", parameters=[ToolParam("query", "string", "Query")]),
            lambda query: None,  # type: ignore[return-value]
        )
        agent.registry.register(
            ToolSpec(name="browser_fetch", description="Fetch URL", parameters=[ToolParam("url", "string", "URL")]),
            lambda url: None,  # type: ignore[return-value]
        )

        # Normal mode: all tools available
        agent._degraded = False
        schemas = agent._get_tools_schema()
        names = {s["function"]["name"] for s in schemas or []}
        assert "file_read" in names
        assert "web_search" in names
        assert "browser_fetch" in names

        # Degraded mode: network tools removed
        agent._degraded = True
        schemas = agent._get_tools_schema()
        names = {s["function"]["name"] for s in schemas or []}
        assert "file_read" in names
        assert "web_search" not in names
        assert "browser_fetch" not in names

    @pytest.mark.asyncio
    async def test_degraded_mode_agent_run_graceful_error(self, agent: JSAgent) -> None:
        """Agent run gracefully errors when all providers are down."""
        unhealthy = ToggleableMockProvider("lmstudio", healthy=False)
        agent.router.add_provider("lmstudio", unhealthy, [_TEST_MODEL])

        # Force provider to raise on chat so router fails
        async def _fail(*args: Any, **kwargs: Any) -> ChatResponse:
            raise RuntimeError("provider down")

        unhealthy.chat = _fail  # type: ignore[method-assign]

        # All providers down → router.chat raises RuntimeError
        # Agent should catch it and set status=error
        state = await agent.run("hello")
        assert state.status == "error"
        assert agent.degraded

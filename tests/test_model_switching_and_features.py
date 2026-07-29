"""Comprehensive tests for model switching and full feature/plugin compatibility.

This test suite verifies:
1. Cloud and local models can be freely switched in any session
2. Multi-session scenarios with different models per session
3. Multi-agent (fleet) tasks with model switching
4. All agent features work with both model types
5. All plugins work with both model types
6. Model parameter is correctly propagated through the entire call chain
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from js.agent import JSAgent
from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.orchestration.fleet import AgentFleet, AgentRole

# ---------------------------------------------------------------------------
# Mock providers that simulate cloud and local model behavior
# ---------------------------------------------------------------------------

class MockCloudProvider(ModelProvider):
    """Simulates a cloud provider (e.g., DeepSeek, OpenAI)."""

    def __init__(self) -> None:
        self.calls: list[list[ChatMessage]] = []
        self.models_used: list[str] = []
        self.sessions_used: list[str | None] = []
        self._responses: list[ChatResponse] = []
        self._index = 0
        self._stream_index = 0

    def set_responses(self, responses: list[ChatResponse]) -> None:
        self._responses = responses
        self._index = 0

    def reset_tracking(self) -> None:
        self.calls = []
        self.models_used = []
        self.sessions_used = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls.append(messages)
        self.models_used.append(model)
        if self._index < len(self._responses):
            resp = self._responses[self._index]
            self._index += 1
            return resp
        return ChatResponse(
            content=f"Cloud response using {model}",
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
            self.calls.append(messages)
            self.models_used.append(model)
            yield f"Cloud stream: {model}"
        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class MockLocalProvider(ModelProvider):
    """Simulates a local provider (e.g., LM Studio, Ollama)."""

    def __init__(self) -> None:
        self.calls: list[list[ChatMessage]] = []
        self.models_used: list[str] = []
        self._responses: list[ChatResponse] = []
        self._index = 0

    def set_responses(self, responses: list[ChatResponse]) -> None:
        self._responses = responses
        self._index = 0

    def reset_tracking(self) -> None:
        self.calls = []
        self.models_used = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls.append(messages)
        self.models_used.append(model)
        if self._index < len(self._responses):
            resp = self._responses[self._index]
            self._index += 1
            return resp
        return ChatResponse(
            content=f"Local response using {model}",
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
            self.calls.append(messages)
            self.models_used.append(model)
            yield f"Local stream: {model}"
        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def settings(tmp_path: Path) -> JSSettings:
    return JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=10,
    )


@pytest.fixture
def cloud_provider() -> MockCloudProvider:
    return MockCloudProvider()


@pytest.fixture
def local_provider() -> MockLocalProvider:
    return MockLocalProvider()


@pytest.fixture
def agent(settings: JSSettings, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> JSAgent:
    a = JSAgent(settings)
    cloud_cfg = ModelProviderConfig(
        name="cloud",
        base_url="https://api.cloud.example/v1",
        api_key="cloud-key",
        default_model="cloud-gpt",
        models=[ModelConfig(id="cloud-gpt", name="Cloud GPT", provider="cloud")],
    )
    local_cfg = ModelProviderConfig(
        name="local",
        base_url="http://127.0.0.1:1234/v1",
        api_key="",
        default_model="local-llm",
        models=[ModelConfig(id="local-llm", name="Local LLM", provider="local")],
    )
    a.router.add_provider("cloud", cloud_provider, cloud_cfg.models)
    a.router.add_provider("local", local_provider, local_cfg.models)
    return a


# ---------------------------------------------------------------------------
# Test Model Switching in Single Session
# ---------------------------------------------------------------------------

class TestModelSwitchingSingleSession:
    """Verify model can be switched within a single session."""

    async def test_first_call_uses_cloud_model(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """First call with explicit cloud model should use cloud provider."""
        cloud_provider.set_responses([
            ChatResponse(
                content="Hello from cloud",
                tool_calls=[],
                model="cloud-gpt",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])
        state = await agent.run("Hello", session_id="sess-1", model="cloud/cloud-gpt")
        assert state.status == "completed"
        assert cloud_provider.models_used == ["cloud-gpt"]
        assert local_provider.models_used == []

    async def test_second_call_switches_to_local_model(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """Second call with local model should switch to local provider."""
        cloud_provider.set_responses([
            ChatResponse(
                content="Hello from cloud",
                tool_calls=[],
                model="cloud-gpt",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])
        local_provider.set_responses([
            ChatResponse(
                content="Hello from local",
                tool_calls=[],
                model="local-llm",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])

        state1 = await agent.run("Hello", session_id="sess-1", model="cloud/cloud-gpt")
        assert state1.status == "completed"

        state2 = await agent.run("Hello again", session_id="sess-1", model="local/local-llm")
        assert state2.status == "completed"

        assert cloud_provider.models_used == ["cloud-gpt"]
        assert local_provider.models_used == ["local-llm"]

    async def test_switch_back_to_cloud_model(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """Switch back to cloud after using local."""
        cloud_provider.set_responses([
            ChatResponse(content="Cloud 1", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
            ChatResponse(content="Cloud 2", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])
        local_provider.set_responses([
            ChatResponse(content="Local 1", tool_calls=[], model="local-llm", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        await agent.run("Msg 1", session_id="sess-1", model="cloud/cloud-gpt")
        await agent.run("Msg 2", session_id="sess-1", model="local/local-llm")
        await agent.run("Msg 3", session_id="sess-1", model="cloud/cloud-gpt")

        assert cloud_provider.models_used == ["cloud-gpt", "cloud-gpt"]
        assert local_provider.models_used == ["local-llm"]

    async def test_streaming_with_cloud_model(self, agent: JSAgent, cloud_provider: MockCloudProvider) -> None:
        """Streaming should work with cloud model."""
        tokens = []
        async for token in agent.chat_stream("Hello", session_id="sess-stream", model="cloud/cloud-gpt"):
            tokens.append(token)
        assert "Cloud stream: cloud-gpt" in "".join(tokens)
        assert cloud_provider.models_used == ["cloud-gpt"]

    async def test_streaming_switches_to_local_model(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """Streaming should switch to local model when specified."""
        cloud_tokens = []
        async for token in agent.chat_stream("Hello", session_id="sess-stream-2", model="cloud/cloud-gpt"):
            cloud_tokens.append(token)

        local_tokens = []
        async for token in agent.chat_stream("Hello", session_id="sess-stream-2", model="local/local-llm"):
            local_tokens.append(token)

        assert "Cloud stream: cloud-gpt" in "".join(cloud_tokens)
        assert "Local stream: local-llm" in "".join(local_tokens)
        assert cloud_provider.models_used == ["cloud-gpt"]
        assert local_provider.models_used == ["local-llm"]


# ---------------------------------------------------------------------------
# Test Model Switching Across Multiple Sessions
# ---------------------------------------------------------------------------

class TestModelSwitchingMultiSession:
    """Verify different sessions can use different models simultaneously."""

    async def test_session_a_cloud_session_b_local(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """Session A uses cloud, Session B uses local concurrently."""
        cloud_provider.set_responses([
            ChatResponse(content="Cloud A", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])
        local_provider.set_responses([
            ChatResponse(content="Local B", tool_calls=[], model="local-llm", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        state_a, state_b = await asyncio.gather(
            agent.run("Hello A", session_id="sess-a", model="cloud/cloud-gpt"),
            agent.run("Hello B", session_id="sess-b", model="local/local-llm"),
        )

        assert state_a.status == "completed"
        assert state_b.status == "completed"
        assert cloud_provider.models_used == ["cloud-gpt"]
        assert local_provider.models_used == ["local-llm"]

    async def test_three_sessions_three_models(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """Three sessions with mixed model usage."""
        cloud_provider.set_responses([
            ChatResponse(content="Cloud", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
            ChatResponse(content="Cloud", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])
        local_provider.set_responses([
            ChatResponse(content="Local", tool_calls=[], model="local-llm", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        states = await asyncio.gather(
            agent.run("Hello", session_id="sess-1", model="cloud/cloud-gpt"),
            agent.run("Hello", session_id="sess-2", model="local/local-llm"),
            agent.run("Hello", session_id="sess-3", model="cloud/cloud-gpt"),
        )

        for s in states:
            assert s.status == "completed"

        assert cloud_provider.models_used == ["cloud-gpt", "cloud-gpt"]
        assert local_provider.models_used == ["local-llm"]


# ---------------------------------------------------------------------------
# Test Model Switching in Multi-Agent (Fleet) Tasks
# ---------------------------------------------------------------------------

class TestModelSwitchingFleet:
    """Verify fleet tasks can specify different models for different agents."""

    async def test_fleet_spawn_with_cloud_model(self, agent: JSAgent, cloud_provider: MockCloudProvider) -> None:
        """Fleet agent can be spawned with cloud model."""
        fleet = AgentFleet(settings=agent.settings)
        agent.set_fleet_getter(lambda: fleet)
        agent.register_fleet_tool(lambda: fleet)

        cloud_provider.set_responses([
            ChatResponse(content="Fleet cloud response", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        worker = fleet._spawn("coder-1", AgentRole.WORKER)
        worker.model = "cloud/cloud-gpt"
        # Copy providers from main agent to fleet worker so routing works
        for name, prov in agent.router._providers.items():
            models = [m for mid, (p, m) in agent.router._model_map.items() if p == name and "/" not in mid]
            worker.agent.router.add_provider(name, prov, models)

        state = await worker.agent.run("Write a hello world function", model=worker.model)

        assert state.status == "completed"
        assert cloud_provider.models_used == ["cloud-gpt"]

    async def test_fleet_spawn_with_local_model(self, agent: JSAgent, local_provider: MockLocalProvider) -> None:
        """Fleet agent can be spawned with local model."""
        fleet = AgentFleet(settings=agent.settings)
        agent.set_fleet_getter(lambda: fleet)
        agent.register_fleet_tool(lambda: fleet)

        local_provider.set_responses([
            ChatResponse(content="Fleet local response", tool_calls=[], model="local-llm", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        worker = fleet._spawn("researcher-1", AgentRole.WORKER)
        worker.model = "local/local-llm"
        for name, prov in agent.router._providers.items():
            models = [m for mid, (p, m) in agent.router._model_map.items() if p == name and "/" not in mid]
            worker.agent.router.add_provider(name, prov, models)

        state = await worker.agent.run("Research local models", model=worker.model)

        assert state.status == "completed"
        assert local_provider.models_used == ["local-llm"]

    async def test_fleet_mixed_models(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """Fleet with one cloud agent and one local agent."""
        fleet = AgentFleet(settings=agent.settings)
        agent.set_fleet_getter(lambda: fleet)
        agent.register_fleet_tool(lambda: fleet)

        cloud_provider.set_responses([
            ChatResponse(content="Cloud task done", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])
        local_provider.set_responses([
            ChatResponse(content="Local task done", tool_calls=[], model="local-llm", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        cloud_worker = fleet._spawn("cloud-coder", AgentRole.WORKER)
        cloud_worker.model = "cloud/cloud-gpt"
        local_worker = fleet._spawn("local-researcher", AgentRole.WORKER)
        local_worker.model = "local/local-llm"

        for name, prov in agent.router._providers.items():
            models = [m for mid, (p, m) in agent.router._model_map.items() if p == name and "/" not in mid]
            cloud_worker.agent.router.add_provider(name, prov, models)
            local_worker.agent.router.add_provider(name, prov, models)

        states = await asyncio.gather(
            cloud_worker.agent.run("Cloud task", model=cloud_worker.model),
            local_worker.agent.run("Local task", model=local_worker.model),
        )

        assert states[0].status == "completed"
        assert states[1].status == "completed"
        assert cloud_provider.models_used == ["cloud-gpt"]
        assert local_provider.models_used == ["local-llm"]


# ---------------------------------------------------------------------------
# Test All Features Work With Both Model Types
# ---------------------------------------------------------------------------

class TestFeaturesWithBothModels:
    """Verify all core features work correctly regardless of which model is selected."""

    async def test_tool_calling_with_cloud_model(self, agent: JSAgent, cloud_provider: MockCloudProvider) -> None:
        """Tool calling should work with cloud model."""
        cloud_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": '{"path": "."}'},
                }],
                model="cloud-gpt",
                usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                finish_reason="tool_calls",
            ),
            ChatResponse(
                content="I found some files.",
                tool_calls=[],
                model="cloud-gpt",
                usage={"prompt_tokens": 15, "completion_tokens": 5, "total_tokens": 20},
                finish_reason="stop",
            ),
        ])

        state = await agent.run("List files", session_id="sess-tools-cloud", model="cloud/cloud-gpt")
        assert state.status == "completed"
        assert state.turn_count == 2
        assert any(m.role == "tool" for m in state.messages)

    async def test_tool_calling_with_local_model(self, agent: JSAgent, local_provider: MockLocalProvider) -> None:
        """Tool calling should work with local model."""
        local_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": '{"path": "."}'},
                }],
                model="local-llm",
                usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                finish_reason="tool_calls",
            ),
            ChatResponse(
                content="I found some files locally.",
                tool_calls=[],
                model="local-llm",
                usage={"prompt_tokens": 15, "completion_tokens": 5, "total_tokens": 20},
                finish_reason="stop",
            ),
        ])

        state = await agent.run("List files", session_id="sess-tools-local", model="local/local-llm")
        assert state.status == "completed"
        assert state.turn_count == 2
        assert any(m.role == "tool" for m in state.messages)

    async def test_checkpoint_save_load_with_cloud_model(self, agent: JSAgent, cloud_provider: MockCloudProvider) -> None:
        """Checkpoint save/load should preserve model info with cloud model."""
        cloud_provider.set_responses([
            ChatResponse(content="Hello", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        state = await agent.run("Hello", session_id="sess-checkpoint", model="cloud/cloud-gpt")
        assert state.status == "completed"

        # Save checkpoint
        await agent.save_checkpoint(state)

        # Load checkpoint
        loaded = await agent.load_checkpoint("sess-checkpoint")
        assert loaded is not None
        assert loaded.model == "cloud-gpt"

    async def test_checkpoint_save_load_with_local_model(self, agent: JSAgent, local_provider: MockLocalProvider) -> None:
        """Checkpoint save/load should preserve model info with local model."""
        local_provider.set_responses([
            ChatResponse(content="Hello local", tool_calls=[], model="local-llm", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        state = await agent.run("Hello", session_id="sess-checkpoint-local", model="local/local-llm")
        assert state.status == "completed"

        await agent.save_checkpoint(state)
        loaded = await agent.load_checkpoint("sess-checkpoint-local")
        assert loaded is not None
        assert loaded.model == "local-llm"

    async def test_cancel_with_cloud_model(self, agent: JSAgent, cloud_provider: MockCloudProvider) -> None:
        """Cancellation should work with cloud model."""
        # Use finish_reason="tool_calls" so the loop continues to a second
        # turn where the cancel flag is checked.
        # Add a small delay to the first response so cancel can be requested
        # before the second turn starts.
        async def _slow_first(*args: Any, **kwargs: Any) -> ChatResponse:
            await asyncio.sleep(0.03)
            return ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": '{"path": "."}'},
                }],
                model="cloud-gpt",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="tool_calls",
            )

        cloud_provider.chat = _slow_first  # type: ignore[method-assign]

        task = asyncio.create_task(agent.run("List files", session_id="sess-cancel-cloud", model="cloud/cloud-gpt"))
        await asyncio.sleep(0.01)
        ok = agent.request_cancel("sess-cancel-cloud")
        assert ok is True

        state = await task
        assert state.status == "cancelled"

    async def test_cancel_with_local_model(self, agent: JSAgent, local_provider: MockLocalProvider) -> None:
        """Cancellation should work with local model."""
        async def _slow_first(*args: Any, **kwargs: Any) -> ChatResponse:
            await asyncio.sleep(0.03)
            return ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": '{"path": "."}'},
                }],
                model="local-llm",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="tool_calls",
            )

        local_provider.chat = _slow_first  # type: ignore[method-assign]

        task = asyncio.create_task(agent.run("List files", session_id="sess-cancel-local", model="local/local-llm"))
        await asyncio.sleep(0.01)
        ok = agent.request_cancel("sess-cancel-local")
        assert ok is True

        state = await task
        assert state.status == "cancelled"

    async def test_memory_persists_across_model_switches(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """Memory should persist when switching models within the same session."""
        cloud_provider.set_responses([
            ChatResponse(content="Cloud memory", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])
        local_provider.set_responses([
            ChatResponse(content="Local memory", tool_calls=[], model="local-llm", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        await agent.run("My name is Alice", session_id="sess-memory", model="cloud/cloud-gpt")
        await agent.run("What is my name?", session_id="sess-memory", model="local/local-llm")

        # Local provider should receive the context including the cloud turn
        local_messages = local_provider.calls[-1]
        assert any("Alice" in str(m.content) for m in local_messages)


# ---------------------------------------------------------------------------
# Test Plugin Compatibility With Both Models
# ---------------------------------------------------------------------------

class TestPluginsWithBothModels:
    """Verify all plugins work correctly with both cloud and local models."""

    async def test_health_monitor_plugin_cloud(self, agent: JSAgent, cloud_provider: MockCloudProvider) -> None:
        """Health monitor plugin should track cloud model health."""
        cloud_provider.set_responses([
            ChatResponse(content="OK", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        health = await agent.router.health_check()
        assert health.get("cloud") is True

    async def test_health_monitor_plugin_local(self, agent: JSAgent, local_provider: MockLocalProvider) -> None:
        """Health monitor plugin should track local model health."""
        health = await agent.router.health_check()
        assert health.get("local") is True

    async def test_dashboard_plugin_is_metadata_only(self, agent: JSAgent) -> None:
        """Release plugins are discoverable without importing executable code."""
        records = {record.manifest.id: record for record in agent.plugins.list_plugins()}

        assert "example-dashboard" in records
        assert records["example-dashboard"].instance is None
        assert agent.plugins.get_all_tools() == []
        assert agent.registry.get("system_dashboard") is None

    async def test_skill_tools_available_with_cloud_model(self, agent: JSAgent, cloud_provider: MockCloudProvider) -> None:
        """Skill tools should be callable with cloud model."""
        cloud_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "skill_shell-safety", "arguments": '{"command": "ls"}'},
                }],
                model="cloud-gpt",
                usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                finish_reason="tool_calls",
            ),
            ChatResponse(content="Skill executed", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 15, "completion_tokens": 5, "total_tokens": 20}, finish_reason="stop"),
        ])

        state = await agent.run("Check shell safety for ls", session_id="sess-skill-cloud", model="cloud/cloud-gpt")
        assert state.status == "completed"

    async def test_skill_tools_available_with_local_model(self, agent: JSAgent, local_provider: MockLocalProvider) -> None:
        """Skill tools should be callable with local model."""
        local_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "skill_shell-safety", "arguments": '{"command": "ls"}'},
                }],
                model="local-llm",
                usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                finish_reason="tool_calls",
            ),
            ChatResponse(content="Skill executed locally", tool_calls=[], model="local-llm", usage={"prompt_tokens": 15, "completion_tokens": 5, "total_tokens": 20}, finish_reason="stop"),
        ])

        state = await agent.run("Check shell safety for ls", session_id="sess-skill-local", model="local/local-llm")
        assert state.status == "completed"


# ---------------------------------------------------------------------------
# Test Model Parameter Propagation
# ---------------------------------------------------------------------------

class TestModelParameterPropagation:
    """Verify the 'model' parameter is correctly passed through the entire stack."""

    async def test_router_select_model_receives_preferred(self, agent: JSAgent, cloud_provider: MockCloudProvider) -> None:
        """router.select_model should receive the preferred model ID."""
        cloud_provider.set_responses([
            ChatResponse(content="Test", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        decision = await agent.router.select_model(preferred="cloud/cloud-gpt")
        assert decision.provider_name == "cloud"
        assert decision.model == "cloud-gpt"

    async def test_router_select_model_receives_local_preferred(self, agent: JSAgent, local_provider: MockLocalProvider) -> None:
        """router.select_model should receive local model ID."""
        local_provider.set_responses([
            ChatResponse(content="Test", tool_calls=[], model="local-llm", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        decision = await agent.router.select_model(preferred="local/local-llm")
        assert decision.provider_name == "local"
        assert decision.model == "local-llm"

    async def test_provider_receives_correct_model_id(self, agent: JSAgent, cloud_provider: MockCloudProvider) -> None:
        """The provider.chat() should receive the correct (unprefixed) model ID."""
        cloud_provider.set_responses([
            ChatResponse(content="Test", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        await agent.run("Hello", session_id="sess-prop", model="cloud/cloud-gpt")
        assert cloud_provider.models_used == ["cloud-gpt"]

    async def test_stream_provider_receives_correct_model_id(self, agent: JSAgent, local_provider: MockLocalProvider) -> None:
        """The provider.chat_stream() should receive the correct model ID."""
        tokens = []
        async for token in agent.chat_stream("Hello", session_id="sess-prop-stream", model="local/local-llm"):
            tokens.append(token)
        assert local_provider.models_used == ["local-llm"]

    async def test_state_records_model_used(self, agent: JSAgent, cloud_provider: MockCloudProvider) -> None:
        """AgentState.model should record the actual model used."""
        cloud_provider.set_responses([
            ChatResponse(content="Test", tool_calls=[], model="cloud-gpt", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        state = await agent.run("Hello", session_id="sess-state-model", model="cloud/cloud-gpt")
        assert state.model == "cloud-gpt"

    async def test_state_records_local_model_used(self, agent: JSAgent, local_provider: MockLocalProvider) -> None:
        """AgentState.model should record local model used."""
        local_provider.set_responses([
            ChatResponse(content="Test", tool_calls=[], model="local-llm", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        state = await agent.run("Hello", session_id="sess-state-model-local", model="local/local-llm")
        assert state.model == "local-llm"


# ---------------------------------------------------------------------------
# Test Router Fallback Behavior With Explicit Model
# ---------------------------------------------------------------------------

class TestRouterFallbackBehavior:
    """Verify that when a model is explicitly specified, fallback does NOT occur."""

    async def test_cloud_failure_no_fallback_to_local(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """If cloud model fails and user explicitly chose it, should NOT fallback to local."""

        async def _fail(*args: Any, **kwargs: Any) -> ChatResponse:
            raise RuntimeError("Cloud provider down")

        cloud_provider.chat = _fail  # type: ignore[method-assign]

        state = await agent.run("Hello", session_id="sess-fallback", model="cloud/cloud-gpt")
        assert state.status == "error"
        assert "Requested model 'cloud/cloud-gpt' failed" in state.error_message
        assert local_provider.calls == []

    async def test_local_failure_no_fallback_to_cloud(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """If local model fails and user explicitly chose it, should NOT fallback to cloud."""

        async def _fail(*args: Any, **kwargs: Any) -> ChatResponse:
            raise RuntimeError("Local provider down")

        local_provider.chat = _fail  # type: ignore[method-assign]

        state = await agent.run("Hello", session_id="sess-fallback-local", model="local/local-llm")
        assert state.status == "error"
        assert "Requested model 'local/local-llm' failed" in state.error_message
        # Cloud should not have been called as fallback
        assert len(cloud_provider.calls) == 0 or cloud_provider.calls == []

    async def test_auto_select_allows_fallback(self, agent: JSAgent, cloud_provider: MockCloudProvider, local_provider: MockLocalProvider) -> None:
        """When model is None (auto-select), fallback should be allowed."""
        cloud_provider.healthy = False  # type: ignore[attr-defined]

        async def _cloud_fail(*args: Any, **kwargs: Any) -> ChatResponse:
            raise RuntimeError("Cloud down")

        cloud_provider.chat = _cloud_fail  # type: ignore[method-assign]
        local_provider.set_responses([
            ChatResponse(content="Fallback to local", tool_calls=[], model="local-llm", usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}, finish_reason="stop"),
        ])

        # Auto-select (model=None) should fall back to local
        state = await agent.run("Hello", session_id="sess-auto-fallback", model=None)
        assert state.status == "completed"
        assert local_provider.models_used == ["local-llm"]

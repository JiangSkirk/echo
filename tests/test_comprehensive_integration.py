"""Comprehensive integration tests covering all JS Agent subsystems.

These tests verify that every major subsystem can be instantiated, configured,
and invoked in realistic workflows — using mocks to avoid external API deps.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.agent import JSAgent
from js.compression.compressor import CompressionConfig, ContextCompressor
from js.compression.feedback import CompressionFeedback
from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.cron.engine import CronEngine
from js.cron.nlp import parse_natural_language
from js.evolution.learner import SelfLearner
from js.evolution.metacognition import MetacognitionLoop
from js.evolution.optimizer import PromptOptimizer
from js.memory.embeddings import KeywordEmbedder
from js.memory.enhanced_store import EnhancedMemoryStore
from js.memory.store import MemoryStore
from js.models.circuit_breaker import CircuitBreaker, CircuitState
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter
from js.security.audit import AuditEventType, AuditLogger
from js.security.guard import BehaviorGuard
from js.security.sandbox import SandboxExecutor
from js.security.secrets import SecretManager
from js.security.strategies import DefenseContext, build_default_strategies
from js.skills.manager import SkillManager

# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


class MockModelProvider(ModelProvider):
    """A mock provider that returns scripted responses for testing."""

    def __init__(self, responses: list[ChatResponse] | None = None) -> None:
        self._responses = responses or []
        self._index = 0
        self.calls: list[list[ChatMessage]] = []

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
            content="Mock response",
            tool_calls=[],
            model="mock",
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
            yield "Mock"
            yield " stream"

        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


@pytest.fixture
def mock_provider() -> MockModelProvider:
    return MockModelProvider()


@pytest.fixture
def settings(tmp_path: Path) -> JSSettings:
    return JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=10,
    )


@pytest.fixture
def agent(settings: JSSettings, mock_provider: MockModelProvider) -> JSAgent:
    a = JSAgent(settings)
    # Inject mock provider into router
    a.router._providers["mock"] = mock_provider
    a.router._model_map["mock"] = ("mock", ModelConfig(id="gpt", name="GPT"))
    a.router._model_map["mock/gpt"] = ("mock", ModelConfig(id="gpt", name="GPT"))
    return a


# =============================================================================
# 1. Agent Core
# =============================================================================


class TestAgentCore:
    @pytest.mark.asyncio
    async def test_simple_conversation(
        self, agent: JSAgent, mock_provider: MockModelProvider
    ) -> None:
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="Hello!",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                    finish_reason="stop",
                ),
            ]
        )
        state = await agent.run("Say hello")
        assert state.status == "completed"
        assert state.turn_count == 1
        assert any(m.role == "assistant" and "Hello!" in str(m.content) for m in state.messages)

    @pytest.mark.asyncio
    async def test_tool_call_and_continue(
        self, agent: JSAgent, mock_provider: MockModelProvider
    ) -> None:
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="",
                    tool_calls=[
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "file_list", "arguments": '{"path": "."}'},
                        }
                    ],
                    model="mock",
                    usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                    finish_reason="tool_calls",
                ),
                ChatResponse(
                    content="Done.",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 15, "completion_tokens": 5, "total_tokens": 20},
                    finish_reason="stop",
                ),
            ]
        )
        state = await agent.run("List files")
        assert state.status == "completed"
        assert state.turn_count == 2
        assert any(m.role == "tool" for m in state.messages)

    @pytest.mark.asyncio
    async def test_chat_stream(self, agent: JSAgent, mock_provider: MockModelProvider) -> None:
        tokens: list[str] = []
        async for token in agent.chat_stream("Stream test"):
            tokens.append(token)
        assert tokens == ["Mock", " stream"]

    @pytest.mark.asyncio
    async def test_cancel_token(self, agent: JSAgent, mock_provider: MockModelProvider) -> None:
        async def _slow_chat(*args: Any, **kwargs: Any) -> ChatResponse:
            # Give time for cancel signal to be detected before returning
            await asyncio.sleep(0.05)
            return ChatResponse(
                content="",
                tool_calls=[
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "file_list", "arguments": "{}"},
                    }
                ],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="tool_calls",
            )

        mock_provider.chat = _slow_chat  # type: ignore[method-assign]
        task = asyncio.create_task(agent.run("test", session_id="test-session"))
        await asyncio.sleep(0.01)  # Let run() start and create cancel token
        ok = agent.request_cancel("test-session")
        assert ok is True
        state = await task
        assert state.status == "cancelled"

    @pytest.mark.asyncio
    async def test_max_turns_enforced(
        self, agent: JSAgent, mock_provider: MockModelProvider
    ) -> None:
        agent.settings.max_turns = 3
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="",
                    tool_calls=[
                        {
                            "id": f"call_{i}",
                            "type": "function",
                            "function": {"name": "file_list", "arguments": "{}"},
                        }
                    ],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                    finish_reason="tool_calls",
                )
                for i in range(5)
            ]
        )
        state = await agent.run("Loop")
        assert state.turn_count == 3
        assert state.status == "error"
        assert "maximum turn limit" in state.error_message.lower()


# =============================================================================
# 2. Memory System
# =============================================================================


class TestMemorySystem:
    def test_working_memory_roundtrip(self, settings: JSSettings) -> None:
        store = MemoryStore(settings.state_dir, settings.memory, KeywordEmbedder())
        session = "sess-1"
        store.store_working(session, "key1", "value1", "test", 5)
        results = store.get_working(session, limit=50)
        assert any(r.get("key") == "key1" and r.get("value") == "value1" for r in results)

    def test_episodic_memory(self, settings: JSSettings) -> None:
        store = MemoryStore(settings.state_dir, settings.memory, KeywordEmbedder())
        store.store_episode("sess-1", "summary", ["topic"], 100, 2, 7)
        episodes = store.get_episodes(limit=20)
        assert len(episodes) > 0
        assert episodes[0].summary == "summary"

    def test_session_messages(self, settings: JSSettings) -> None:
        store = MemoryStore(settings.state_dir, settings.memory, KeywordEmbedder())
        store.store_messages(
            "sess-1",
            [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi"},
            ],
        )
        msgs = store.get_session_messages("sess-1")
        assert len(msgs) == 2
        assert msgs[0]["role"] == "user"

    def test_enhanced_memory_semantic(self, settings: JSSettings) -> None:
        embedder = KeywordEmbedder()
        enhanced = EnhancedMemoryStore(settings.state_dir, settings.memory, embedder)
        enhanced.store_semantic("key1", "JS Agent is an AI assistant", "fact", 0.9)
        results = enhanced.search_semantic("AI assistant")
        assert len(results) > 0
        assert any("JS Agent" in r.value for r in results)

    def test_memory_cleanup(self, settings: JSSettings) -> None:
        store = MemoryStore(settings.state_dir, settings.memory, KeywordEmbedder())
        store.store_messages("empty-sess", [{"role": "user", "content": "x"}])
        store.delete_session("empty-sess")
        assert store.get_session_messages("empty-sess") == []


# =============================================================================
# 3. Security
# =============================================================================


class TestSecurity:
    def test_guard_command_block(self, settings: JSSettings) -> None:
        guard = BehaviorGuard(settings.security, settings.workspace)
        decision = guard.check_command("rm -rf /")
        assert decision.decision.value in ("block", "warn")

    def test_guard_allows_safe_command(self, settings: JSSettings) -> None:
        guard = BehaviorGuard(settings.security, settings.workspace)
        decision = guard.check_command("ls -la")
        assert decision.decision.value == "allow"

    def test_secret_redaction(self, settings: JSSettings) -> None:
        secrets = SecretManager(settings.state_dir)
        fake_key = "sk-" + "abcdefghijklmnopqrstuvwxyz12345"
        text = f"My key is {fake_key}"
        redacted = secrets.detect_and_redact(text, "test")
        assert "sk-" not in redacted
        assert "[REDACTED" in redacted

    def test_sandbox_executor(self, settings: JSSettings) -> None:
        sandbox = SandboxExecutor(settings.workspace)
        result = asyncio.run(sandbox.execute("echo hello", fs_restricted=False))
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_defense_strategies(self, settings: JSSettings) -> None:
        strategies = build_default_strategies()
        ctx = DefenseContext(
            tool_name="shell",
            arguments={"command": "rm -rf /"},
            session_id="s1",
            run_id="r1",
            user_input="test",
            config=settings.security,
        )
        result = strategies.evaluate(ctx)
        assert isinstance(result.blocked, bool)

    def test_audit_log(self, settings: JSSettings) -> None:
        audit = AuditLogger(settings.state_dir, retention_days=30)
        audit.log(AuditEventType.USER_MESSAGE, "s1", "r1", "user", "msg", {"x": 1})
        events = audit.query(limit=10)
        assert len(events) > 0
        assert events[0].event_type == AuditEventType.USER_MESSAGE


# =============================================================================
# 4. Router / Provider / Circuit Breaker
# =============================================================================


class TestRouterAndProvider:
    @pytest.mark.asyncio
    async def test_router_health_check(self, settings: JSSettings) -> None:
        router = ModelRouter(settings)
        health = await router.health_check()
        assert isinstance(health, dict)

    @pytest.mark.asyncio
    async def test_router_select_model_with_mock(self, mock_provider: MockModelProvider) -> None:
        settings = JSSettings()
        router = ModelRouter(settings)
        router.add_provider("mock", mock_provider, [ModelConfig(id="gpt", name="GPT")])
        decision = await router.select_model(preferred="gpt")
        assert decision.provider_name == "mock"
        assert decision.model == "gpt"

    @pytest.mark.asyncio
    async def test_router_cache_invalidation(self, mock_provider: MockModelProvider) -> None:
        settings = JSSettings()
        router = ModelRouter(settings)
        router.add_provider("mock", mock_provider, [ModelConfig(id="gpt", name="GPT")])
        # First call populates cache
        await router.select_model(preferred="gpt")
        # Remove provider should clear cache
        router.remove_provider("mock")
        assert len(router._routing_cache) == 0

    @pytest.mark.asyncio
    async def test_circuit_breaker_lifecycle(self) -> None:
        cb = CircuitBreaker(
            name="test", failure_threshold=2, recovery_timeout=0.1, half_open_max_calls=3
        )
        assert await cb.state() == CircuitState.CLOSED

        await cb.record_failure()
        assert await cb.state() == CircuitState.CLOSED

        await cb.record_failure()
        assert await cb.state() == CircuitState.OPEN

        await asyncio.sleep(0.15)
        assert await cb.state() == CircuitState.HALF_OPEN

        # Need 3 successful half-open calls to fully close
        for _ in range(3):
            assert await cb.can_execute() is True
            await cb.record_success()
        assert await cb.state() == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_circuit_breaker_execute(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=10.0)

        async def _ok() -> str:
            return "ok"

        result = await cb.execute(_ok())
        assert result == "ok"

        async def _fail() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await cb.execute(_fail())

        assert await cb.state() == CircuitState.OPEN


# =============================================================================
# 5. Skills
# =============================================================================


class TestSkills:
    def test_skill_manager_loads_builtin(self, settings: JSSettings) -> None:
        mgr = SkillManager(settings.state_dir, settings.workspace)
        all_skills = mgr.get_all()
        assert len(all_skills) > 0
        # At least one builtin skill should exist
        assert any(not k.startswith("hermes:") for k in all_skills)

    @pytest.mark.asyncio
    async def test_hermes_async_load(self, settings: JSSettings) -> None:
        mgr = SkillManager(settings.state_dir, settings.workspace)
        before = len(mgr.get_all())
        await mgr.load_hermes_async()
        after = len(mgr.get_all())
        # Hermes load should not reduce skill count (may increase if Hermes present)
        assert after >= before

    def test_skill_list_and_search(self, settings: JSSettings) -> None:
        mgr = SkillManager(settings.state_dir, settings.workspace)
        listed = mgr.list_skills()
        assert isinstance(listed, list)
        # Search should return a list
        results = mgr.search_skills("file")
        assert isinstance(results, list)

    def test_skill_stats(self, settings: JSSettings) -> None:
        mgr = SkillManager(settings.state_dir, settings.workspace)
        stats = mgr.get_global_stats()
        assert "skills_loaded" in stats


# =============================================================================
# 6. Compression
# =============================================================================


class TestCompression:
    def test_compressor_under_budget(self, settings: JSSettings) -> None:
        config = CompressionConfig(max_tokens=100_000)
        comp = ContextCompressor(config)
        messages = [
            ChatMessage(role="user", content="Hello"),
            ChatMessage(role="assistant", content="Hi there"),
        ]
        result = asyncio.run(comp.compress(messages))
        assert result.level.value == "none"
        assert len(result.messages) == 2

    def test_compressor_gentle_prunes_tools(self, settings: JSSettings) -> None:
        config = CompressionConfig(max_tokens=100, critical_threshold=0.3)
        comp = ContextCompressor(config)
        long_output = "x" * 5000
        messages = [
            ChatMessage(role="user", content="Run cmd"),
            ChatMessage(role="tool", content=long_output),
            ChatMessage(role="assistant", content="Done"),
        ]
        result = asyncio.run(comp.compress(messages))
        # Tool output should be pruned
        tool_msgs = [m for m in result.messages if m.role == "tool"]
        assert all(len(str(m.content)) < 5000 for m in tool_msgs)

    def test_compression_feedback(self, settings: JSSettings) -> None:
        feedback = CompressionFeedback(settings.state_dir)
        feedback.record_compression("s1", 1000, 800, "medium", 10, 8, 2)
        recs = feedback.get_adjustment_recommendations()
        assert isinstance(recs, dict)


# =============================================================================
# 7. Evolution
# =============================================================================


class TestEvolution:
    def test_learner_record_and_insights(self, settings: JSSettings) -> None:
        learner = SelfLearner(settings.state_dir)
        learner.record_interaction(
            session_id="s1",
            user_input="How do I use Python?",
            agent_output="You can use print()",
            tool_calls=[],
            success=True,
            latency_ms=500.0,
            tokens_used=100,
        )
        insights = learner.get_insights()
        assert isinstance(insights, list)
        hints = learner.generate_context_hint("Python")
        assert isinstance(hints, str)

    def test_optimizer_variant_registration(self, settings: JSSettings) -> None:
        opt = PromptOptimizer(settings.state_dir)
        vid = opt.register_variant("test", "Hello {{name}}", "template")
        assert isinstance(vid, str)
        variant = opt.select_variant("test")
        assert variant is not None
        opt.record_result(vid, True, 1.0, "test")

    def test_metacognition_tick(self, settings: JSSettings) -> None:
        meta = MetacognitionLoop(settings.state_dir)
        report = meta.reflect()
        assert hasattr(report, "overall_health_score")
        assert 0.0 <= report.overall_health_score <= 1.0


# =============================================================================
# 8. Cron
# =============================================================================


class TestCron:
    def test_cron_nlp_parsing(self) -> None:
        result = parse_natural_language("每天早上8点")
        assert result is not None
        assert result["cron_expr"] == "0 8 * * *"

    def test_cron_engine_job_lifecycle(self, settings: JSSettings) -> None:
        from js.cron.engine import ScheduledJob

        engine = CronEngine(settings.state_dir)
        job = ScheduledJob(
            name="test-job",
            cron_expr="*/5 * * * *",
            task_type="custom",
            payload={"msg": "hello"},
        )
        engine.add_job(job)
        assert job.id is not None
        listed = engine.list_jobs()
        assert any(j.id == job.id for j in listed)
        engine.remove_job(job.id)
        listed = engine.list_jobs()
        assert not any(j.id == job.id for j in listed)

    def test_cron_templates(self) -> None:
        from js.cron.templates import TEMPLATE_REGISTRY, get_template

        assert "health_check" in TEMPLATE_REGISTRY
        tmpl = get_template("health_check")
        assert tmpl is not None
        assert tmpl.default_cron != ""


# =============================================================================
# 9. Web API (via TestClient)
# =============================================================================


class TestWebAPI:
    def test_api_models_endpoint(self, agent: JSAgent) -> None:
        from js.web.auth import require_auth_dep
        from js.web.routers.system import router as system_router

        app = FastAPI()
        app.include_router(system_router)
        app.dependency_overrides[require_auth_dep] = lambda: {"role": "admin"}

        # Patch the module-level get_agent used inside handlers
        with patch("js.web.routers.system.get_agent", return_value=agent):
            client = TestClient(app)
            # Note: /api/models is in server.py, not system router
            # We test /api/status instead which is in system router
            resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "workspace" in data
        assert data["degraded"] is False

    def test_api_diag_endpoint(self, agent: JSAgent) -> None:
        from js.web.auth import require_auth_dep, require_user_write
        from js.web.routers.system import router as system_router

        app = FastAPI()
        app.include_router(system_router)
        app.dependency_overrides[require_auth_dep] = lambda: {"role": "admin"}
        app.dependency_overrides[require_user_write] = lambda: {"role": "admin"}

        with patch("js.web.routers.system.get_agent", return_value=agent):
            client = TestClient(app)
            resp = client.get("/api/diag")
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert "subsystems" in data
        assert "embedder" in data


# =============================================================================
# 10. Config
# =============================================================================


class TestConfig:
    def test_config_save_and_load(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=20,
        )
        settings.save(config_path)
        assert config_path.exists()

        loaded = JSSettings.from_file(config_path)
        assert loaded.max_turns == 20
        assert loaded.workspace == settings.workspace

    def test_provider_config_roundtrip(self) -> None:
        cfg = ModelProviderConfig(
            name="test",
            base_url="http://localhost:1234/v1",
            api_key="secret",
            default_model="gpt-4",
            models=[ModelConfig(id="gpt-4", name="GPT-4")],
        )
        assert cfg.name == "test"
        assert cfg.models[0].id == "gpt-4"
        # embedding_model should default to None
        assert cfg.embedding_model is None


# =============================================================================
# 11. End-to-end Workflow
# =============================================================================


class TestEndToEndWorkflow:
    @pytest.mark.asyncio
    async def test_full_session_with_memory_and_tools(
        self, agent: JSAgent, mock_provider: MockModelProvider
    ) -> None:
        """A realistic session: user asks → agent uses tool → memory persists →
        second run recalls context."""
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="",
                    tool_calls=[
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "file_list", "arguments": '{"path": "."}'},
                        }
                    ],
                    model="mock",
                    usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                    finish_reason="tool_calls",
                ),
                ChatResponse(
                    content="I found your files.",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 15, "completion_tokens": 5, "total_tokens": 20},
                    finish_reason="stop",
                ),
            ]
        )

        session_id = "e2e-session"
        state1 = await agent.run("List my files", session_id=session_id)
        assert state1.status == "completed"

        # Second turn in same session
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="Based on what I found earlier...",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
                    finish_reason="stop",
                ),
            ]
        )
        state2 = await agent.run("What did you find?", session_id=session_id)
        assert state2.status == "completed"
        assert state2.turn_count == 1  # New run, fresh turn count

        # Audit should have both runs
        events = agent.audit.query(limit=50)
        assert len(events) >= 2

        # Memory should have session history
        msgs = await asyncio.to_thread(
            agent.memory.get_session_messages,
            session_id,
            "local-user",
        )
        assert len(msgs) >= 4  # user, assistant, user, assistant

    @pytest.mark.asyncio
    async def test_agent_with_compression_and_security(
        self, agent: JSAgent, mock_provider: MockModelProvider
    ) -> None:
        """Agent handles secret redaction and context compression."""
        # Built-in password pattern will catch "password=secret123"

        mock_provider.set_responses(
            [
                ChatResponse(
                    content="I processed your request.",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                    finish_reason="stop",
                ),
            ]
        )

        # Input with a secret
        state = await agent.run("My password is secret123")
        assert state.status == "completed"

        # Secret should be redacted in audit
        events = agent.audit.query(limit=10)
        user_events = [e for e in events if e.event_type == AuditEventType.USER_MESSAGE]
        assert len(user_events) > 0
        assert "secret123" not in str(user_events[0])

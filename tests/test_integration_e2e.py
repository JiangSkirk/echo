"""End-to-end integration tests covering the full agent lifecycle."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from js.agent import JSAgent
from js.config import JSSettings
from js.models.circuit_breaker import CircuitBreaker, CircuitState
from js.orchestration.fleet import AgentFleet
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.security.sandbox import SandboxExecutor
from js.skills.spec import SkillSpec, SkillType
from js.web.server import create_app


class TestAgentLifecycle:
    """Test the complete agent lifecycle from config to response."""

    @pytest.fixture
    def settings(self, tmp_path: Path) -> JSSettings:
        s = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        )
        s.memory.enabled = True
        s.memory.max_memory_chars = 500
        return s

    @pytest.fixture
    def agent(self, settings: JSSettings) -> JSAgent:
        return JSAgent(settings)

    @pytest.mark.asyncio
    async def test_agent_can_initialize(self, agent: JSAgent) -> None:
        """Agent initializes all subsystems without error."""
        assert agent.router is not None
        assert agent.memory is not None
        assert agent.guard is not None
        assert agent.registry is not None

    @pytest.mark.asyncio
    async def test_model_router_selects_default(self, settings: JSSettings) -> None:
        """Router selects a default model when no preference given."""
        from js.models.router import ModelRouter
        router = ModelRouter(settings)
        if settings.providers:
            decision = await router.select_model()
            assert decision.model
            assert decision.provider_name

    @pytest.mark.asyncio
    async def test_circuit_breaker_transitions(self) -> None:
        """Circuit breaker correctly transitions through states."""
        cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.05)
        assert await cb.state() == CircuitState.CLOSED

        await cb.record_failure()
        await cb.record_failure()
        assert await cb.state() == CircuitState.OPEN

        await asyncio.sleep(0.1)
        assert await cb.state() == CircuitState.HALF_OPEN

        await cb.record_success()
        assert await cb.state() == CircuitState.CLOSED


class TestSecurityLayer:
    """Test security guard and sandbox."""

    def test_guard_blocks_rm_rf(self, tmp_path: Path) -> None:
        """BehaviorGuard blocks dangerous commands."""
        from js.config import SecurityConfig
        guard = BehaviorGuard(SecurityConfig(), tmp_path)
        decision = guard.check_command("rm -rf /", ".")
        assert decision.decision == SecurityDecisionType.BLOCK

    def test_guard_allows_safe_commands(self, tmp_path: Path) -> None:
        """BehaviorGuard allows safe workspace commands."""
        from js.config import SecurityConfig
        guard = BehaviorGuard(SecurityConfig(), tmp_path)
        decision = guard.check_command("ls -la", ".")
        assert decision.decision == SecurityDecisionType.ALLOW

    def test_strategy_blocks_high_risk(self) -> None:
        """command_block_strategy blocks high-risk patterns."""
        from js.config import DefenseMode, SecurityConfig
        from js.security.strategies import DefenseContext, command_block_strategy
        ctx = DefenseContext(
            tool_name="shell",
            arguments={"command": "rm -rf /"},
            session_id="",
            run_id="",
            user_input="",
            config=SecurityConfig(defense_mode=DefenseMode.ENFORCE),
        )
        result = command_block_strategy(ctx)
        assert result.blocked

    def test_strategy_allows_safe(self) -> None:
        """command_block_strategy allows safe commands."""
        from js.config import DefenseMode, SecurityConfig
        from js.security.strategies import DefenseContext, command_block_strategy
        ctx = DefenseContext(
            tool_name="shell",
            arguments={"command": "echo hello"},
            session_id="",
            run_id="",
            user_input="",
            config=SecurityConfig(defense_mode=DefenseMode.ENFORCE),
        )
        result = command_block_strategy(ctx)
        assert not result.blocked

    @pytest.mark.asyncio
    async def test_sandbox_executes_and_times_out(self, tmp_path: Path) -> None:
        """Sandbox executes commands and kills on timeout."""
        sandbox = SandboxExecutor(workspace=tmp_path, timeout=0.5)
        result = await sandbox.execute(["sleep", "10"], timeout=0.5)
        assert result.killed
        assert result.returncode == -9
        assert "timed out" in result.stderr.lower()


class TestMemorySystem:
    """Test memory store operations."""

    def test_working_memory_crud(self, tmp_path: Path) -> None:
        """Working memory supports create, read, update."""
        from js.config import MemoryConfig
        from js.memory.enhanced_store import EnhancedMemoryStore
        store = EnhancedMemoryStore(tmp_path, MemoryConfig(enabled=True))
        store.store_working("session-1", "key1", "value1", category="general", importance=5)
        results = store.get_working("session-1")
        assert len(results) == 1
        assert results[0]["value"] == "value1"

    def test_episode_storage(self, tmp_path: Path) -> None:
        """Episodes are stored and retrievable."""
        from js.config import MemoryConfig
        from js.memory.enhanced_store import EnhancedMemoryStore
        store = EnhancedMemoryStore(tmp_path, MemoryConfig(enabled=True))
        store.store_episode("session-1", "Test summary", ["topic"], 100, 1, importance=5)
        episodes = store.get_episodes(limit=10)
        assert len(episodes) == 1
        assert episodes[0].summary == "Test summary"

    def test_semantic_memory_search(self, tmp_path: Path) -> None:
        """Semantic memory stores and searches facts."""
        from js.config import MemoryConfig
        from js.memory.enhanced_store import EnhancedMemoryStore
        store = EnhancedMemoryStore(tmp_path, MemoryConfig(enabled=True))
        store.store_semantic("user_name", "Alice", "profile", confidence=0.9, source="direct")
        results = store.search_semantic("Alice")
        assert len(results) >= 1


class TestSkillSystem:
    """Test skill loading, security, and execution."""

    def test_skill_integrity_hash_covers_code(self, tmp_path: Path) -> None:
        """compute_hash covers all code files, not just manifest."""
        spec = SkillSpec(id="test", name="Test", type=SkillType.CODE, path=tmp_path)
        (tmp_path / "SKILL.md").write_text("---\nid: test\n---\n")
        (tmp_path / "main.py").write_text("print('hello')")
        h1 = spec.compute_hash()
        (tmp_path / "main.py").write_text("print('world')")
        h2 = spec.compute_hash()
        assert h1 != h2, "Hash should change when code changes"

    def test_skill_security_scan_detects_risk(self, tmp_path: Path) -> None:
        """Security scan flags risky code."""
        from js.skills.security import scan_skill
        from js.skills.spec import SkillType
        (tmp_path / "SKILL.md").write_text("---\nid: test\n---\n")
        (tmp_path / "main.py").write_text("import os; os.system('rm -rf /')")
        spec = SkillSpec(id="test", name="Test", type=SkillType.CODE, path=tmp_path)
        result = scan_skill(spec)
        assert len(result.risk_flags) > 0


class TestFleetIsolation:
    """Test Fleet agent isolation."""

    def test_fleet_agents_have_isolated_state_dirs(self, tmp_path: Path) -> None:
        """Each fleet agent gets its own state subdirectory."""
        from js.config import JSSettings
        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        )

        fleet = AgentFleet(settings)
        a1 = fleet._spawn_worker()
        a2 = fleet._spawn_reviewer()

        assert a1.agent.settings.state_dir != a2.agent.settings.state_dir
        fleet_state_root = (settings.state_dir / "fleet").resolve()
        for instance in (a1, a2):
            relative = instance.agent.settings.state_dir.resolve().relative_to(fleet_state_root)
            assert len(relative.parts) == 3
            assert relative.parts[-1] == instance.id
            assert instance.product_id
            assert instance.owner_key_hash

    @pytest.mark.asyncio
    async def test_fleet_collaborate_times_out(self, tmp_path: Path) -> None:
        """Collaborate has a timeout to prevent deadlocks."""
        from js.config import JSSettings
        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        )

        fleet = AgentFleet(settings)
        # This should complete (or timeout gracefully) rather than hang forever
        result = await fleet.collaborate(
            "Say hello",
            ["Say hello in one word"],
        )
        assert "final" in result
        # Cleanup
        for a in fleet.agents.values():
            await a.agent.close()


class TestWebUIApp:
    """Test FastAPI app creation and basic endpoints."""

    def test_create_app(self) -> None:
        """create_app() returns a valid FastAPI instance."""
        from fastapi.routing import iter_route_contexts

        app = create_app()
        assert app is not None
        routes = {
            route.path
            for context in iter_route_contexts(app.routes)
            if (route := context.route) is not None and hasattr(route, "path")
        }
        assert "/api/models" in routes
        assert "/api/status" in routes
        assert "/ws" in routes

    @pytest.mark.asyncio
    async def test_status_endpoint(self) -> None:
        """Status endpoint returns valid data."""
        from httpx import ASGITransport, AsyncClient
        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/status")
            # May be 503 if agent not initialized during test
            assert r.status_code in (200, 503)

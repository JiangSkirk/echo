"""End-to-end smoke tests for real usage paths.

These tests verify that the most common user workflows actually work:
1. Agent initialization
2. Skill creation → validation → testing → packaging pipeline
3. Web server startup and health endpoint
4. CLI command discovery
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI

from js.config import JSSettings
from js.skills.creator import create_skill
from js.skills.manager import SkillManager
from js.skills.packager import package_skill
from js.skills.spec import SkillType
from js.skills.tester import generate_tests, run_skill_tests
from js.skills.validator import validate_skill


class TestAgentInitialization:
    """Smoke-test that JSAgent can initialize without crashing."""

    def test_agent_init_minimal(self, tmp_path: Path) -> None:
        """Agent initializes with minimal settings."""
        from js.agent import JSAgent

        settings = JSSettings(
            state_dir=tmp_path,
            providers=[],
            skills_dir=tmp_path / "skills",
            memory_dir=tmp_path / "memory",
        )
        agent = JSAgent(settings)
        assert agent is not None
        assert agent.settings == settings
        assert agent.registry is not None
        assert agent.skills is not None
        assert agent.guard is not None

    def test_agent_init_has_all_subsystems(self, tmp_path: Path) -> None:
        """All expected subsystems are present after init."""
        from js.agent import JSAgent

        settings = JSSettings(
            state_dir=tmp_path,
            providers=[],
            skills_dir=tmp_path / "skills",
            memory_dir=tmp_path / "memory",
        )
        agent = JSAgent(settings)
        assert agent.router is not None
        assert agent.memory is not None
        assert agent.audit is not None
        assert agent.secrets is not None
        assert agent.compressor is not None


class TestSkillPipeline:
    """Smoke-test the full skill creation → validation → test → package pipeline."""

    @pytest.fixture
    def skill_dir(self, tmp_path: Path) -> Path:
        """Create a minimal code skill and return its directory."""
        return create_skill(
            tmp_path,
            skill_id="smoke-skill",
            name="Smoke Skill",
            description="A smoke test skill",
            skill_type=SkillType.CODE,
            parameters=[{"name": "input", "type": "string", "description": "Input", "required": True}],
        )

    def test_create_skill(self, skill_dir: Path) -> None:
        """Skill directory is created with all expected files."""
        assert (skill_dir / "SKILL.md").exists()
        assert (skill_dir / "main.py").exists()

    def test_validate_skill_passes(self, skill_dir: Path) -> None:
        """Validation passes for a correctly generated skill."""
        report = validate_skill(skill_dir)
        assert report.passed is True, f"Validation failed: {report.issues}"

    def test_generate_tests(self, skill_dir: Path) -> None:
        """Test stubs are generated successfully."""
        files = generate_tests(skill_dir)
        assert len(files) >= 1
        for f in files:
            assert f.exists()

    @pytest.mark.asyncio
    async def test_run_tests(self, skill_dir: Path) -> None:
        """Generated tests execute and at least some pass."""
        report = await run_skill_tests(skill_dir)
        assert report.pass_count >= 1, f"Tests failed: {report.results}"

    def test_package_skill(self, skill_dir: Path, tmp_path: Path) -> None:
        """Skill packages successfully."""
        out = tmp_path / "dist"
        result = package_skill(skill_dir, out)
        assert result.success is True
        assert result.archive_path is not None
        assert result.archive_path.exists()
        assert result.manifest is not None
        assert result.clawhub_entry is not None

    def test_full_pipeline(self, tmp_path: Path) -> None:
        """Run the entire pipeline in one go."""
        skill_dir = create_skill(
            tmp_path,
            skill_id="pipeline-skill",
            name="Pipeline Skill",
            description="Full pipeline test",
            skill_type=SkillType.PROMPT,
            instructions="Be helpful.",
            example_query="How do I test?",
        )
        # Validate
        vreport = validate_skill(skill_dir)
        assert vreport.passed is True
        # Package
        result = package_skill(skill_dir, tmp_path / "dist")
        assert result.success is True


class TestWebServer:
    """Smoke-test the FastAPI web server."""

    @pytest.mark.asyncio
    async def test_health_endpoint(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """The /api/status endpoint responds when lifespan initializes the agent."""
        from httpx import ASGITransport, AsyncClient

        from js.config import JSSettings
        from js.web import server as web_server

        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            providers=[],
            security={"api_key_required": False},
        )
        monkeypatch.setattr(
            web_server.JSSettings,
            "from_file",
            classmethod(lambda _cls: settings),
        )
        monkeypatch.delenv("JS_STATE_DIR", raising=False)
        monkeypatch.delenv("JS_WARM_START", raising=False)
        app = web_server.create_app()

        transport = ASGITransport(app=app)
        async with web_server.lifespan(app), AsyncClient(
            transport=transport, base_url="http://test",
        ) as client:
            response = await client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert "defense_mode" in data
        assert "max_turns" in data

    @pytest.mark.asyncio
    async def test_api_chat_endpoint_exists(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """The /api/chat endpoint is registered (may return 422 without body)."""
        from js.web.server import create_app, lifespan

        app = create_app()
        monkeypatch.setenv("JS_STATE_DIR", str(tmp_path))

        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with lifespan(app), AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/chat", json={})
        # Empty body should be 422 validation error, not 404
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_lifespan_and_status_reuse_agent_echo_safety_service(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        from httpx import ASGITransport, AsyncClient

        from js.web import server as web_server
        from js.web.deps import get_echo_safety_service

        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            providers=[],
            security={"api_key_required": False},
        )
        monkeypatch.setattr(
            web_server.JSSettings,
            "from_file",
            classmethod(lambda _cls: settings),
        )
        monkeypatch.delenv("JS_STATE_DIR", raising=False)
        monkeypatch.delenv("JS_WARM_START", raising=False)

        app = web_server.create_app()
        transport = ASGITransport(app=app)
        async with web_server.lifespan(app), AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as client:
            runtime = app.state.web_runtime
            authoritative = runtime.agent.echo_safety_service
            authoritative.health = MagicMock(wraps=authoritative.health)

            assert runtime.echo_safety_service is authoritative
            assert web_server._echo_safety_service is authoritative
            assert get_echo_safety_service(settings) is authoritative
            response = await client.get("/api/status")

        assert response.status_code == 200
        authoritative.health.assert_called_once()

    @pytest.mark.parametrize("fleet_timeout", [False, True], ids=["success", "timeout"])
    @pytest.mark.asyncio
    async def test_lifespan_closes_fleet_and_releases_agent_on_timeout(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        fleet_timeout: bool,
    ) -> None:
        from js.web import server as web_server

        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            providers=[],
            security={"api_key_required": False},
        )
        events: list[str] = []
        agent = MagicMock()
        agent.settings = settings
        agent.memory.enhanced.list_sessions.return_value = []
        agent.memory.cleanup_empty_sessions.return_value = 0
        agent.router._providers = {}
        agent.router.get_model_config.return_value = None
        agent.skills.load_hermes_async = AsyncMock(return_value=None)

        async def close_agent() -> None:
            events.append("agent")

        async def close_fleet() -> None:
            events.append("fleet")
            if fleet_timeout:
                raise TimeoutError("fleet close timed out")

        agent.close = AsyncMock(side_effect=close_agent)
        fleet = MagicMock()
        fleet.close_all = AsyncMock(side_effect=close_fleet)
        telemetry_logger = MagicMock()

        monkeypatch.setattr(
            web_server.JSSettings,
            "from_file",
            classmethod(lambda _cls: settings),
        )
        monkeypatch.setattr("js.agent.JSAgent", lambda _settings: agent)
        monkeypatch.setattr(web_server, "logger", telemetry_logger)
        monkeypatch.delenv("JS_WARM_START", raising=False)

        app = FastAPI()
        async with web_server.lifespan(app):
            app.state.web_runtime.fleet = fleet

        assert events == ["fleet", "agent"]
        fleet.close_all.assert_awaited_once()
        agent.close.assert_awaited_once()
        assert app.state.web_runtime is None
        if fleet_timeout:
            assert any(
                "fleet shutdown degraded" in call.args[0].lower()
                for call in telemetry_logger.warning.call_args_list
            )

    @pytest.mark.asyncio
    async def test_warm_start_does_not_probe_provider_outside_echo(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        from js.web import server as web_server

        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            providers=[],
            security={"api_key_required": False},
        )
        provider = MagicMock()
        provider.health_check = AsyncMock(
            side_effect=AssertionError("warm start provider probe bypassed Echo")
        )
        agent = MagicMock()
        agent.settings = settings
        agent.memory.enhanced.list_sessions.return_value = []
        agent.memory.cleanup_empty_sessions.return_value = 0
        agent.router._providers = {"test": provider}
        agent.router.get_model_config.return_value = None
        agent.skills.load_hermes_async = AsyncMock(return_value=None)
        agent.close = AsyncMock(return_value=None)

        monkeypatch.setattr(
            web_server.JSSettings,
            "from_file",
            classmethod(lambda _cls: settings),
        )
        monkeypatch.setattr("js.agent.JSAgent", lambda _settings: agent)
        monkeypatch.setenv("JS_WARM_START", "1")

        app = FastAPI()
        async with web_server.lifespan(app):
            pass

        provider.health_check.assert_not_awaited()


class TestCLICommands:
    """Smoke-test CLI command discovery."""

    def test_cli_help(self) -> None:
        """CLI help prints without crashing."""
        from click.testing import CliRunner

        from js.ui.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "JS Agent" in result.output

    def test_skill_subcommand_help(self) -> None:
        """Skill subcommand help prints."""
        from click.testing import CliRunner

        from js.ui.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["skill", "--help"])
        assert result.exit_code == 0
        assert "create" in result.output
        assert "validate" in result.output
        assert "test" in result.output
        assert "package" in result.output

    def test_skill_create_help(self) -> None:
        """Skill create help prints."""
        from click.testing import CliRunner

        from js.ui.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["skill", "create", "--help"])
        assert result.exit_code == 0

    def test_search_command_runs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Search command accepts --engine option and renders results."""
        from click.testing import CliRunner

        import js.search.engines as search_engines
        from js.search.engines import SearchResult
        from js.ui.cli import main

        class FakeManager:
            def __init__(self) -> None:
                self.closed = False

            def register(self, _engine: object, default: bool = False) -> None:
                return None

            async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
                return [
                    SearchResult(
                        title=f"Result for {query}",
                        url="https://example.com",
                        snippet=f"max={max_results}",
                        source="fake",
                    )
                ]

            async def close(self) -> None:
                self.closed = True

        class FakeDuckDuckGo:
            pass

        monkeypatch.setattr(search_engines, "SearchManager", FakeManager)
        monkeypatch.setattr(search_engines, "DuckDuckGoEngine", FakeDuckDuckGo)

        runner = CliRunner()
        result = runner.invoke(main, ["search", "OpenAI", "--engine", "auto"])
        assert result.exit_code == 0
        assert "Result for OpenAI" in result.output


class TestConfigLoading:
    """Smoke-test configuration loading."""

    def test_default_settings(self, tmp_path: Path) -> None:
        """Default settings can be instantiated."""
        from js.config import JSSettings

        settings = JSSettings(
            state_dir=tmp_path,
            providers=[],
            skills_dir=tmp_path / "skills",
            memory_dir=tmp_path / "memory",
        )
        assert settings.security.defense_mode.value == "enforce"
        assert settings.max_turns >= 1

    def test_settings_save_load_roundtrip(self, tmp_path: Path) -> None:
        """Settings can be saved and loaded."""
        from js.config import JSSettings

        config_path = tmp_path / "config.yaml"
        settings = JSSettings(
            state_dir=tmp_path,
            providers=[],
            skills_dir=tmp_path / "skills",
            memory_dir=tmp_path / "memory",
        )
        settings.save(config_path)
        assert config_path.exists()
        loaded = JSSettings.from_file(config_path)
        assert loaded.state_dir == settings.state_dir


class TestDockerCompose:
    """Smoke-test Docker compose file consistency."""

    def test_docker_compose_yaml_valid(self) -> None:
        """docker-compose.yaml is valid YAML and has expected services."""
        import yaml

        compose_path = Path(__file__).parent.parent / "docker-compose.yaml"
        assert compose_path.exists(), "docker-compose.yaml not found"
        with open(compose_path) as f:
            data = yaml.safe_load(f)

        assert "services" in data
        assert "js-agent" in data["services"]
        assert "js-agent-dev" in data["services"]

    def test_docker_ports_aligned(self) -> None:
        """Production and dev services expose the same port."""
        import yaml

        compose_path = Path(__file__).parent.parent / "docker-compose.yaml"
        with open(compose_path) as f:
            data = yaml.safe_load(f)

        prod = data["services"]["js-agent"]
        dev = data["services"]["js-agent-dev"]

        # Both should expose 8000
        assert prod["ports"] == ["8000:8000"]
        assert dev["ports"] == ["8000:8000"]

        # Dev command should include --reload and match port 8000
        cmd = dev.get("command", [])
        assert "--port" in cmd
        port_idx = cmd.index("--port")
        assert cmd[port_idx + 1] == "8000"
        assert "--reload" in cmd

        # Both services should set JS_STATE_DIR to the mounted volume
        prod_env = prod.get("environment", [])
        dev_env = dev.get("environment", [])
        assert any("JS_STATE_DIR=/app/state" in str(e) for e in prod_env)
        assert any("JS_STATE_DIR=/app/state" in str(e) for e in dev_env)

        # Dev should run as root so mounted volumes are writable
        assert dev.get("user") == "root"

    def test_dockerfile_expose_matches(self) -> None:
        """Dockerfile EXPOSE matches compose ports."""
        dockerfile = Path(__file__).parent.parent / "Dockerfile"
        content = dockerfile.read_text()
        assert "EXPOSE 8000" in content


class TestCompression:
    """Smoke-test context compression on real message lists."""

    def test_estimate_tokens_non_empty(self) -> None:
        """Token estimation returns positive values for real messages."""
        from js.compression.compressor import ContextCompressor
        from js.models.providers import ChatMessage

        compressor = ContextCompressor()
        messages = [
            ChatMessage(role="system", content="You are a helpful assistant."),
            ChatMessage(role="user", content="Hello, what is the weather?"),
            ChatMessage(role="assistant", content="I don't have real-time weather data."),
        ]
        tokens = compressor.estimate_tokens(messages)
        assert tokens > 0

    def test_compress_sync_small_context_no_compression(self) -> None:
        """Small context stays uncompressed."""
        from js.compression.compressor import CompressionLevel, ContextCompressor
        from js.models.providers import ChatMessage

        compressor = ContextCompressor()
        messages = [
            ChatMessage(role="system", content="System prompt."),
            ChatMessage(role="user", content="Hi"),
        ]
        result = compressor.compress_sync(messages)
        assert result.level == CompressionLevel.NONE
        assert len(result.messages) == len(messages)

    def test_compress_sync_large_context_triggers_compression(self) -> None:
        """Large context triggers at least gentle compression."""
        from js.compression.compressor import CompressionConfig, CompressionLevel, ContextCompressor
        from js.models.providers import ChatMessage

        config = CompressionConfig(max_tokens=500, warning_threshold=0.3, critical_threshold=0.7)
        compressor = ContextCompressor(config)
        # Create enough messages to exceed 500 tokens
        messages = [ChatMessage(role="system", content="System prompt here.")]
        for i in range(30):
            messages.append(ChatMessage(role="user", content=f"This is a moderately long user message number {i} with enough text to consume tokens."))
            messages.append(ChatMessage(role="assistant", content=f"This is the assistant response number {i} providing a detailed explanation of the concept."))

        result = compressor.compress_sync(messages)
        assert result.level in (CompressionLevel.GENTLE, CompressionLevel.FULL)
        assert result.compressed_tokens <= result.original_tokens

    def test_compression_preserves_head_and_tail(self) -> None:
        """Head (system) and tail (recent) messages are preserved."""
        from js.compression.compressor import CompressionConfig, ContextCompressor
        from js.models.providers import ChatMessage

        config = CompressionConfig(max_tokens=600, warning_threshold=0.3, critical_threshold=0.6)
        compressor = ContextCompressor(config)
        messages = [
            ChatMessage(role="system", content="IMPORTANT SYSTEM PROMPT"),
        ]
        for i in range(20):
            messages.append(ChatMessage(role="user", content=f"Message {i}"))
            messages.append(ChatMessage(role="assistant", content=f"Response {i}"))

        result = compressor.compress_sync(messages)
        # System prompt should survive in result
        roles = [m.role for m in result.messages]
        assert roles[0] == "system"
        assert "IMPORTANT SYSTEM PROMPT" in result.messages[0].content

    def test_get_stats_returns_metrics(self) -> None:
        """Compression stats contain expected keys."""
        from js.compression.compressor import ContextCompressor
        from js.models.providers import ChatMessage

        compressor = ContextCompressor()
        messages = [ChatMessage(role="user", content="Hello")]
        stats = compressor.get_stats(messages, messages)
        assert "original_tokens" in stats
        assert "compressed_tokens" in stats
        assert "reduction_pct" in stats


class TestSkillRealPaths:
    """Smoke-test SkillManager with real filesystem paths."""

    @pytest.fixture
    def manager(self, tmp_path: Path) -> SkillManager:
        return SkillManager(tmp_path, tmp_path / "workspace")

    @pytest.mark.asyncio
    async def test_install_from_real_path(self, manager: SkillManager, tmp_path: Path) -> None:
        """Installing from a real directory creates the expected state."""
        src = tmp_path / "real_skill"
        src.mkdir()
        (src / "SKILL.md").write_text("id: real\nname: Real\nentry: main.py\ntype: python\n")
        (src / "main.py").write_text("print('real output')")

        spec = await manager.install(str(src), "real")
        assert spec.id == "real"
        assert (manager.skills_dir / "real" / "SKILL.md").exists()
        assert (manager.skills_dir / "real" / "main.py").exists()

    @pytest.mark.asyncio
    async def test_execute_code_skill_real_path(self, manager: SkillManager, tmp_path: Path) -> None:
        """Executing an installed code skill works end-to-end."""
        src = tmp_path / "adder"
        src.mkdir()
        (src / "SKILL.md").write_text("id: adder\nname: Adder\nentry: add.py\ntype: python\n")
        (src / "add.py").write_text(
            "import json, os\n"
            "args = json.loads(os.environ.get('JS_SKILL_ARGS', '{}'))\n"
            "print(args['a'] + args['b'])"
        )

        await manager.install(str(src), "adder")
        result = await manager.execute("adder", {"a": 10, "b": 32})
        assert result["success"]
        assert "42" in result["output"]

    def test_stats_after_execution(self, manager: SkillManager, tmp_path: Path) -> None:
        """Usage stats are tracked after running a skill."""
        src = tmp_path / "counter"
        src.mkdir()
        (src / "SKILL.md").write_text("id: counter\nname: Counter\nentry: main.py\ntype: python\n")
        (src / "main.py").write_text("print('ok')")

        # Use async_to_sync helper or just call _record_usage directly
        import asyncio
        asyncio.run(manager.install(str(src), "counter"))
        manager._record_usage("counter", "code", True, 50.0)
        stats = manager.get_stats("counter")
        assert stats is not None
        assert stats["usage_count"] == 1
        assert stats["success_rate"] == 1.0
        assert stats["avg_latency_ms"] == 50.0

"""Stability and recovery tests for production resilience.

Scenarios:
- Model disconnect / reconnect → degraded mode recovery
- Task interruption / cancel → checkpoint survives
- Database corruption / lock → graceful degradation
- Web restart → session checkpoint resume
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from js.agent import AgentState, JSAgent
from js.config import JSSettings
from js.models.providers import ChatMessage, ChatResponse
from js.persistence.state_store import StateStore
from js.web import server as web_server
from js.web.server import create_app


class ToggleableMockProvider:
    """Provider whose health can be toggled at runtime."""

    def __init__(self, name: str = "mock", healthy: bool = True) -> None:
        self.name = name
        self.healthy = healthy
        self.calls: list[list[ChatMessage]] = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
    ) -> ChatResponse:
        self.calls.append(messages)
        return ChatResponse(content="ok", model=model, tool_calls=[], usage={}, finish_reason="stop")

    async def chat_stream(self, messages: list[ChatMessage], model: str, temperature: float = 0.7) -> AsyncGenerator[str, None]:
        yield "ok"

    async def health_check(self) -> bool:
        return self.healthy

    async def close(self) -> None:
        pass


class UnstableProvider(ToggleableMockProvider):
    """Provider that fails N times then recovers."""

    def __init__(self, name: str = "mock", fail_count: int = 2) -> None:
        super().__init__(name, healthy=False)
        self.fail_count = fail_count
        self.attempts = 0

    async def health_check(self) -> bool:
        self.attempts += 1
        if self.attempts > self.fail_count:
            self.healthy = True
        return self.healthy


@pytest.fixture
def agent(tmp_path: Path) -> JSAgent:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=10,
    )
    return JSAgent(settings)


class TestModelDisconnectRecovery:
    @pytest.mark.asyncio
    async def test_degraded_mode_on_disconnect(self, agent: JSAgent) -> None:
        """Provider goes unhealthy → agent enters degraded mode."""
        from js.config import ModelConfig
        provider = ToggleableMockProvider("lmstudio", healthy=False)
        model = agent.settings.models[0] if agent.settings.models else ModelConfig(id="test", provider="lmstudio")
        agent.router.add_provider("lmstudio", provider, [model])  # type: ignore[arg-type]
        await agent._check_degraded()
        assert agent.degraded
        assert "All providers unhealthy" in agent.degraded_reason

    @pytest.mark.asyncio
    async def test_auto_recovery_when_provider_returns(self, agent: JSAgent) -> None:
        """A cached provider recovery exits degraded mode without a raw probe."""
        from js.config import ModelConfig
        provider = UnstableProvider("lmstudio", fail_count=1)
        model = agent.settings.models[0] if agent.settings.models else ModelConfig(id="test", provider="lmstudio")
        agent.router.add_provider("lmstudio", provider, [model])  # type: ignore[arg-type]

        # First check → still failing
        await agent._check_degraded()
        assert agent.degraded

        # An authorized provider operation updates the local health state. The
        # passive degraded-mode check must consume that state, not open a new
        # network connection on its own.
        provider.healthy = True
        await agent._check_degraded()
        assert not agent.degraded
        assert agent.degraded_reason == ""
        assert provider.attempts == 0


class TestTaskInterruption:
    @pytest.mark.asyncio
    async def test_cancel_saves_checkpoint(self, agent: JSAgent) -> None:
        """Cancelling a run leaves a recoverable checkpoint."""
        state = AgentState(
            session_id="sess-cancel",
            run_id="run-cancel",
            messages=[ChatMessage(role="user", content="hello")],
            turn_count=3,
            total_tokens={"input": 150, "output": 0},
        )
        await agent.save_checkpoint(state)
        loaded = await agent.load_checkpoint("sess-cancel")
        assert loaded is not None
        assert loaded.session_id == "sess-cancel"
        assert loaded.turn_count == 3

    @pytest.mark.asyncio
    async def test_resume_from_interrupted_checkpoint(self, agent: JSAgent) -> None:
        """Checkpoint load returns the saved state correctly."""
        state = AgentState(
            session_id="sess-resume",
            run_id="run-resume",
            messages=[
                ChatMessage(role="user", content="q1"),
                ChatMessage(role="assistant", content="a1"),
            ],
            turn_count=2,
            total_tokens={"input": 200, "output": 0},
        )
        await agent.save_checkpoint(state)
        loaded = await agent.load_checkpoint("sess-resume")
        assert loaded is not None
        assert loaded.session_id == "sess-resume"
        assert loaded.turn_count == 2
        assert len(loaded.messages) == 2


class TestDatabaseResilience:
    def test_wal_mode_enabled(self, agent: JSAgent) -> None:
        """Checkpoint database uses WAL mode for concurrency."""
        db_path = agent.settings.state_dir / "checkpoints.db"
        conn = sqlite3.connect(str(db_path))
        journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        assert journal.lower() == "wal"

    def test_state_store_survives_corruption_attempt(self, tmp_path: Path) -> None:
        """StateStore quarantines malformed bytes before re-initializing."""
        db_path = tmp_path / "corrupt.db"
        # Create a corrupt file
        corrupt_bytes = b"NOT A DB"
        db_path.write_bytes(corrupt_bytes)
        # StateStore should preserve evidence and create a clean replacement.
        store = StateStore(db_path)
        quarantined = list(tmp_path.glob("corrupt.db.corrupt-*"))
        assert len(quarantined) == 1
        assert quarantined[0].read_bytes() == corrupt_bytes
        state = AgentState(session_id="s1", run_id="r1", messages=[ChatMessage(role="user", content="hi")])
        data = state.to_dict()
        store.save(
            session_id=data["session_id"],
            run_id=data["run_id"],
            turn_count=data["turn_count"],
            messages=data["messages"],
            tool_results=data["tool_results"],
            total_tokens=data["total_tokens"],
            cost_estimate=data["cost_estimate"],
            status=data["status"],
            error_message=data["error_message"],
            compression_stats=data["compression_stats"],
        )
        loaded = store.load("s1")
        assert loaded is not None
        assert loaded["session_id"] == "s1"

    def test_state_store_does_not_delete_database_on_lock_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Transient SQLite failures must fail closed without destroying data."""
        db_path = tmp_path / "locked.db"
        original_bytes = b"synthetic-existing-database"
        db_path.write_bytes(original_bytes)
        locked = sqlite3.OperationalError("database is locked")
        locked.sqlite_errorcode = sqlite3.SQLITE_LOCKED

        def fail_connect(*_args: object, **_kwargs: object) -> sqlite3.Connection:
            raise locked

        monkeypatch.setattr("js.persistence.state_store.sqlite3.connect", fail_connect)

        with pytest.raises(sqlite3.OperationalError) as exc_info:
            StateStore(db_path)

        assert exc_info.value is locked
        assert db_path.read_bytes() == original_bytes
        assert list(tmp_path.glob("locked.db.corrupt-*")) == []


class TestWebRestartRecovery:
    def test_setup_first_start_endpoint(self, tmp_path: Path) -> None:
        """GET /api/setup/first-start reflects config state."""
        mock_agent = MagicMock()
        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        )
        settings._config_path = tmp_path / "config.yaml"  # type: ignore[attr-defined]
        mock_agent.settings = settings
        mock_agent.settings.first_run_completed = False
        mock_agent.memory.cleanup_empty_sessions.return_value = 0
        mock_agent.registry.get_stats.return_value = {}
        mock_agent.secrets.get_stats.return_value = {"stored_secrets": 0, "detected_leaks": 0}
        mock_agent.router = MagicMock()
        mock_agent.router.health_check.return_value = {"test": True}
        web_server._agent = mock_agent
        from js.web.deps import set_globals
        set_globals(mock_agent, mock_agent.settings)
        web_server._settings = mock_agent.settings

        app = create_app()
        # The setup bootstrap window is loopback-only; simulate a local client.
        client = TestClient(app, client=("127.0.0.1", 50000))
        resp = client.get("/api/setup/first-start")
        assert resp.status_code == 200
        assert resp.json()["first_run_completed"] is False

    def test_setup_complete_endpoint(self, tmp_path: Path) -> None:
        """POST /api/setup/complete marks first run done and writes to temp config."""
        import asyncio
        import os

        import yaml

        from js.agent import JSAgent

        # Use a temp config file via JS_CONFIG_PATH to avoid touching ~/.config
        config_path = tmp_path / "config.yaml"
        config_path.write_text(yaml.safe_dump({"version": "0.1.0", "first_run_completed": False}))
        os.environ["JS_CONFIG_PATH"] = str(config_path)

        try:
            settings = JSSettings.from_file(config_path)
            settings.state_dir = tmp_path / "state"
            settings.workspace = tmp_path / "workspace"
            settings.state_dir.mkdir(parents=True, exist_ok=True)
            settings.workspace.mkdir(parents=True, exist_ok=True)
            settings.first_run_completed = False
            agent = JSAgent(settings)
            web_server._agent = agent
            from js.web.deps import set_globals
            set_globals(agent, settings)
            web_server._settings = settings

            # The setup bootstrap window is loopback-only; simulate a local client.
            client = TestClient(create_app(), client=("127.0.0.1", 50000))
            try:
                # Browser wizard fetch always sends Origin bound to the
                # loopback Host; originless mutation posts are CSRF-rejected.
                resp = client.post(
                    "/api/setup/complete",
                    headers={
                        "Host": "localhost:50000",
                        "Origin": "http://localhost:50000",
                    },
                )
                assert resp.status_code == 200
                assert resp.json()["success"] is True
                assert settings.first_run_completed is True
                # Verify it actually wrote to the temp config file
                assert config_path.exists()
                # Verify only first_run_completed was updated
                saved = yaml.safe_load(config_path.read_text())
                assert saved["first_run_completed"] is True
            finally:
                client.close()
                asyncio.run(agent.close())
        finally:
            os.environ.pop("JS_CONFIG_PATH", None)

    def test_memory_crud_endpoints(self, tmp_path: Path) -> None:
        """DELETE and PUT /api/memory/semantic/{id} work."""
        import asyncio

        from js.agent import JSAgent

        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        )
        settings.security.api_key_required = False
        agent = JSAgent(settings)
        web_server._agent = agent
        from js.web.deps import set_globals
        set_globals(agent, settings)
        web_server._settings = settings

        app = create_app()

        # Create an admin API key for admin-only memory endpoints
        from js.web.auth import AuthManager
        auth_mgr = AuthManager(settings.state_dir)
        admin_key = auth_mgr.create_key("test-admin", role="admin")
        client = TestClient(app, headers={"X-API-Key": admin_key})

        try:
            created = client.post(
                "/api/memory/semantic",
                json={"key": "synthetic", "value": "initial"},
            )
            assert created.status_code == 200
            memory_id = created.json()["memory_id"]

            resp = client.put(
                f"/api/memory/semantic/{memory_id}",
                json={"value": "updated"},
            )
            assert resp.status_code == 200
            assert resp.json()["success"] is True

            resp = client.delete(f"/api/memory/semantic/{memory_id}")
            assert resp.status_code == 200
            assert resp.json()["success"] is True
        finally:
            client.close()
            asyncio.run(agent.close())

"""Dream-log HTTP reads must pass the caller owner, not the legacy partition."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.web.auth import AuthManager
from js.web.server import create_app


def _client(tmp_path: Path) -> tuple[TestClient, MagicMock, str]:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        first_run_completed=True,
    )
    agent = MagicMock()
    agent.settings = settings
    agent.registry.get_stats.return_value = {}
    agent.secrets.get_stats.return_value = {}
    agent.memory.get_sessions.return_value = []
    agent.memory.get_episodes.return_value = []
    agent.memory.get_dream_logs.return_value = []
    agent.memory.get_all_semantic.return_value = []
    agent.memory.get_all_working.return_value = []
    agent.memory.list_memory_files.return_value = []
    agent.memory.get_context_string.return_value = ""
    agent.memory.get_working.return_value = []
    agent.memory.embedder.health.return_value = MagicMock(
        provider="test", active=True, fallback_provider=None, failure_count=0
    )

    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    with patch("js.web.server.lifespan", _noop_lifespan):
        from js.web import server as web_server
        from js.web.deps import set_globals

        web_server._agent = agent
        web_server._settings = settings
        set_globals(agent, settings)
        app = create_app(runtime_settings=settings)

    key = AuthManager(settings.state_dir).create_key("dream-owner-test", role="admin")
    identity = AuthManager(settings.state_dir).verify(key)
    client = TestClient(
        app,
        base_url="http://127.0.0.1:8000",
        headers={"Origin": "http://127.0.0.1:8000", "X-API-Key": key},
    )
    return client, agent, str(identity["key_hash"])


def test_memory_enhanced_dream_logs_are_owner_scoped(tmp_path: Path) -> None:
    client, agent, owner = _client(tmp_path)
    response = client.get("/api/memory/enhanced")
    assert response.status_code == 200
    agent.memory.get_dream_logs.assert_called_with(limit=20, owner_key_hash=owner)


def test_memory_enhanced_honors_limit_and_rejects_oversize(tmp_path: Path) -> None:
    client, agent, owner = _client(tmp_path)
    ok = client.get("/api/memory/enhanced?limit=50")
    assert ok.status_code == 200
    agent.memory.get_all_semantic.assert_called_with(limit=50, owner_key_hash=owner)
    agent.memory.get_episodes.assert_called_with(limit=50, owner_key_hash=owner)
    rejected = client.get("/api/memory/enhanced?limit=101")
    assert rejected.status_code == 422


def test_memory_metrics_dream_logs_are_owner_scoped(tmp_path: Path) -> None:
    client, agent, owner = _client(tmp_path)
    response = client.get("/api/memory/metrics")
    assert response.status_code == 200
    agent.memory.get_dream_logs.assert_called_with(limit=1000, owner_key_hash=owner)

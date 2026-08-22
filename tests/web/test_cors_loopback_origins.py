"""CORS must not treat port-less loopback as the same origin as the bind port."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from js.web.server import create_app


def _client(tmp_path: Path) -> TestClient:
    from js.web import server as web_server
    from js.web.deps import set_globals

    mock_agent = MagicMock()
    mock_agent.settings.workspace = tmp_path / "workspace"
    mock_agent.settings.state_dir = tmp_path / "state"
    mock_agent.settings.security.api_key_required = False
    mock_agent.settings.bind_host = "127.0.0.1"
    mock_agent.settings.bind_port = 8000
    mock_agent.registry.get_stats.return_value = {}
    mock_agent.secrets.get_stats.return_value = {"stored_secrets": 0, "detected_leaks": 0}
    web_server._agent = mock_agent
    web_server._settings = mock_agent.settings
    set_globals(mock_agent, mock_agent.settings)
    return TestClient(create_app(runtime_settings=mock_agent.settings))


def test_cors_allows_same_port_loopback_origin(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/health", headers={"Origin": "http://127.0.0.1:8000"})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://127.0.0.1:8000"


def test_cors_rejects_portless_loopback_origin(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/health", headers={"Origin": "http://127.0.0.1"})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") != "http://127.0.0.1"


def test_cors_rejects_portless_localhost_origin(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/health", headers={"Origin": "http://localhost"})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") != "http://localhost"

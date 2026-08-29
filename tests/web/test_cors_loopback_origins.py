"""CORS must not treat port-less loopback as the same origin as the bind port."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
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


def test_cors_does_not_list_bind_host_literal(tmp_path: Path) -> None:
    from js.web.auth import cors_allow_origins

    origins = cors_allow_origins("0.0.0.0", 8000)
    assert "http://0.0.0.0:8000" not in origins
    assert "http://127.0.0.1:8000" in origins
    assert "http://localhost:8000" in origins


def test_cors_non_loopback_bind_requires_allowed_origins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.web.auth import cors_allow_origins

    monkeypatch.delenv("JS_ALLOWED_ORIGINS", raising=False)
    import js.web.auth as auth_mod

    auth_mod._ALLOWED_ORIGINS = None
    auth_mod._ALLOWED_ORIGINS_ENV = None
    with pytest.raises(RuntimeError, match="JS_ALLOWED_ORIGINS"):
        cors_allow_origins("192.168.1.10", 8000)


def test_cors_non_loopback_bind_accepts_explicit_origins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.web.auth import cors_allow_origins

    monkeypatch.setenv("JS_ALLOWED_ORIGINS", "https://app.example")
    import js.web.auth as auth_mod

    auth_mod._ALLOWED_ORIGINS = None
    auth_mod._ALLOWED_ORIGINS_ENV = None
    origins = cors_allow_origins("192.168.1.10", 8000)
    assert "https://app.example" in origins
    assert "http://192.168.1.10:8000" not in origins

"""Tests for the chat web router."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.web.routers.chat import router as chat_router


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(chat_router)
    patch("js.web.server._settings", None).start()
    return app


def test_chat_success() -> None:
    """POST /api/chat returns assistant response."""
    mock_state = MagicMock()
    mock_state.session_id = "sess-1"
    mock_state.turn_count = 1
    mock_state.total_tokens = {"input": 10, "output": 5}
    mock_state.status = "completed"
    mock_state.messages = [
        MagicMock(role="user", content="hello"),
        MagicMock(role="assistant", content="Hi there"),
    ]

    agent = MagicMock()
    agent.run = AsyncMock(return_value=mock_state)

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json={"message": "hello", "session_id": "sess-1"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["response"] == "Hi there"
    assert data["session_id"] == "sess-1"
    assert data["status"] == "completed"
    agent.run.assert_awaited_once()


def test_chat_error() -> None:
    """Agent run failure returns 500."""
    agent = MagicMock()
    agent.run = AsyncMock(side_effect=RuntimeError("boom"))

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json={"message": "hello"})

    assert resp.status_code == 500
    assert "boom" in resp.json()["detail"]


def test_chat_empty_message() -> None:
    """Empty message still produces a valid response."""
    mock_state = MagicMock()
    mock_state.session_id = "sess-2"
    mock_state.turn_count = 1
    mock_state.total_tokens = {"input": 0, "output": 0}
    mock_state.status = "completed"
    mock_state.messages = []

    agent = MagicMock()
    agent.run = AsyncMock(return_value=mock_state)

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json={"message": ""})

    assert resp.status_code == 200
    data = resp.json()
    assert data["response"] == ""
    assert data["session_id"] == "sess-2"

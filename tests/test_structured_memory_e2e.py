"""End-to-end tests for Chinese structured memory (full API lifecycle)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from js.agent import JSAgent
from js.config import JSSettings
from js.web import server as web_server
from js.web.server import create_app


@pytest.fixture
def agent(tmp_path: Path) -> JSAgent:
    """Create a real JSAgent with memory enabled."""
    s = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
    )
    s.memory.enabled = True
    s.memory.max_memory_chars = 500
    s.security.api_key_required = False
    return JSAgent(s)


@pytest.fixture
def client(agent: JSAgent) -> TestClient:
    """Build a TestClient backed by a real agent."""
    web_server._agent = agent
    from js.web.deps import set_globals
    set_globals(agent, agent.settings)
    web_server._settings = agent.settings
    web_server._active_model = ""
    app = create_app()

    # Create an admin API key so admin-only endpoints work in tests
    from js.web.auth import AuthManager
    auth_mgr = AuthManager(agent.settings.state_dir)
    admin_key = auth_mgr.create_key("test-admin", role="admin")

    return TestClient(app, headers={"X-API-Key": admin_key})


class TestChineseStructuredMemoryE2E:
    """Full-stack tests: Chinese keywords → auto-block → search → verify."""

    def test_chinese_family_memory_auto_block(self, client: TestClient) -> None:
        """'老婆' should auto-route to /people/family via POST /api/memory/semantic."""
        resp = client.post("/api/memory/semantic", json={
            "key": "老婆姓名",
            "value": "小红",
            "source": "user",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["memory_path"] == "/people/family"
        assert data["entity_type"] == "family"

    def test_chinese_preference_memory_auto_block(self, client: TestClient) -> None:
        """'喜欢' should auto-route to /user/preferences."""
        resp = client.post("/api/memory/semantic", json={
            "key": "喜欢的颜色",
            "value": "蓝色",
            "source": "user",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["memory_path"] == "/user/preferences"
        assert data["entity_type"] == "preference"

    def test_backend_search_chinese(self, client: TestClient) -> None:
        """GET /api/memory/search?q=老婆 should return family memory."""
        client.post("/api/memory/semantic", json={
            "key": "老婆姓名",
            "value": "小红",
            "source": "user",
        })
        resp = client.get("/api/memory/search?q=老婆&limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["results"]) >= 1
        assert any("老婆" in r["key"] for r in data["results"])

    def test_backend_search_with_path_prefix(self, client: TestClient) -> None:
        """path_prefix should filter results to specific block."""
        client.post("/api/memory/semantic", json={
            "key": "喜欢的颜色",
            "value": "蓝色",
            "source": "user",
        })
        client.post("/api/memory/semantic", json={
            "key": "老婆姓名",
            "value": "小红",
            "source": "user",
        })
        resp = client.get("/api/memory/search?q=小&path_prefix=/user/family")
        assert resp.status_code == 200
        data = resp.json()
        for r in data["results"]:
            assert r["memory_path"].startswith("/user/family")

    def test_blocks_api_returns_tree(self, client: TestClient) -> None:
        """GET /api/memory/blocks should return hierarchical stats."""
        client.post("/api/memory/semantic", json={
            "key": "老婆姓名",
            "value": "小红",
            "source": "user",
        })
        resp = client.get("/api/memory/blocks")
        assert resp.status_code == 200
        data = resp.json()
        assert "blocks" in data
        paths = [b["block_path"] for b in data["blocks"]]
        assert "/people" in paths or "/people/family" in paths

    def test_block_content_api(self, client: TestClient) -> None:
        """GET /api/memory/block/{path} should list memories in that block."""
        client.post("/api/memory/semantic", json={
            "key": "老婆姓名",
            "value": "小红",
            "source": "user",
        })
        resp = client.get("/api/memory/block/%2Fpeople%2Ffamily")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["memories"]) >= 1
        assert data["memories"][0]["key"] == "老婆姓名"

    def test_verify_memory_updates_timestamp(self, client: TestClient) -> None:
        """POST /api/memory/semantic/{id}/verify should set last_verified_at."""
        resp = client.post("/api/memory/semantic", json={
            "key": "test_verify",
            "value": "v",
            "source": "user",
        })
        mem_id = resp.json()["memory_id"]
        resp2 = client.post(f"/api/memory/semantic/{mem_id}/verify")
        assert resp2.status_code == 200
        data = resp2.json()
        assert data["success"] is True
        assert data["verified"] is True

    def test_full_lifecycle_chinese(self, client: TestClient) -> None:
        """Store → Search → Verify → Blocks (Chinese end-to-end)."""
        # Store
        r1 = client.post("/api/memory/semantic", json={
            "key": "项目名称",
            "value": "TitanAgent",
            "source": "user",
        })
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["memory_path"] == "/work/projects"
        mem_id = d1["memory_id"]

        # Search
        r2 = client.get("/api/memory/search?q=项目")
        assert r2.status_code == 200
        assert any(m["key"] == "项目名称" for m in r2.json()["results"])

        # Verify
        r3 = client.post(f"/api/memory/semantic/{mem_id}/verify")
        assert r3.status_code == 200
        assert r3.json()["verified"] is True

        # Blocks
        r4 = client.get("/api/memory/blocks")
        assert r4.status_code == 200
        paths = [b["block_path"] for b in r4.json()["blocks"]]
        assert "/work" in paths or "/work/projects" in paths

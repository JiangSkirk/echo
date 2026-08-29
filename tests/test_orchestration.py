"""Tests for simplified multi-agent orchestration."""

from pathlib import Path

import pytest

from js.config import JSSettings
from js.orchestration.fleet import AgentFleet, AgentRole


class TestAgentFleet:
    @pytest.fixture
    def fleet(self, tmp_path: Path) -> AgentFleet:
        settings = JSSettings(
            state_dir=tmp_path / "state",
            workspace=tmp_path / "workspace",
        )
        return AgentFleet(settings)

    def test_spawn_worker(self, fleet: AgentFleet) -> None:
        agent = fleet._spawn_worker()
        assert agent.id in fleet.agents
        assert agent.role == AgentRole.WORKER

    def test_get_status(self, fleet: AgentFleet) -> None:
        fleet._spawn_worker()
        status = fleet.get_status()
        assert len(status["agents"]) == 1
        assert status["agents"][0]["role"] == "worker"

    def test_auto_decompose_numbered(self) -> None:
        task = "1. Research the API thoroughly\n2. Write the code implementation\n3. Test everything carefully"
        descs = AgentFleet._auto_decompose(task)
        assert len(descs) == 3

    def test_auto_decompose_splitters(self) -> None:
        task = "Write the frontend, then write the backend, then test everything"
        descs = AgentFleet._auto_decompose(task)
        assert len(descs) >= 2

    def test_auto_decompose_single(self) -> None:
        task = "Just write a hello world script"
        descs = AgentFleet._auto_decompose(task)
        assert len(descs) == 1

    def test_needs_review(self) -> None:
        assert AgentFleet._needs_review("Write a Python function")
        assert AgentFleet._needs_review("实现一个排序算法")
        assert not AgentFleet._needs_review("Search for news")

    @pytest.mark.anyio
    async def test_collaborate_simple(self, fleet: AgentFleet) -> None:
        # This test doesn't call a real LLM; we verify the orchestration logic
        # by checking that the fleet can decompose and dispatch.
        # Since we can't run real agents without LLM setup, just verify the
        # structure is correct.
        descs = fleet._auto_decompose("Step 1: do A. Step 2: do B.")
        assert len(descs) == 2

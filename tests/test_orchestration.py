"""Tests for multi-agent orchestration."""

from pathlib import Path

import pytest

from js.config import JSSettings
from js.orchestration.fleet import AgentFleet, AgentRole
from js.orchestration.router import TaskRouter


class TestTaskRouter:
    def test_route_coder(self) -> None:
        router = TaskRouter()
        score = router.route("Write a Python function to sort a list")
        assert score.role == AgentRole.CODER

    def test_route_researcher(self) -> None:
        router = TaskRouter()
        score = router.route("Research the latest AI trends")
        assert score.role == AgentRole.RESEARCHER

    def test_route_generalist(self) -> None:
        router = TaskRouter()
        score = router.route("Hello there")
        assert score.role == AgentRole.GENERALIST

    def test_decompose(self) -> None:
        router = TaskRouter()
        subtasks = router.decompose("First write code, then test it, finally review")
        assert len(subtasks) >= 1


class TestAgentFleet:
    @pytest.fixture
    def fleet(self, tmp_path: Path) -> AgentFleet:
        settings = JSSettings(
            state_dir=tmp_path / "state",
            workspace=tmp_path / "workspace",
        )
        return AgentFleet(settings)

    def test_spawn(self, fleet: AgentFleet) -> None:
        agent = fleet.spawn("test-agent", AgentRole.GENERALIST)
        assert agent.id in fleet.agents
        assert agent.role == AgentRole.GENERALIST

    def test_get_status(self, fleet: AgentFleet) -> None:
        fleet.spawn("a1", AgentRole.CODER)
        status = fleet.get_status()
        assert len(status["agents"]) == 1
        assert status["agents"][0]["name"] == "a1"

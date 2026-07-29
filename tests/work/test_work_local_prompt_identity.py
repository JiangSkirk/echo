"""Regression coverage for local-model prompts in JS Agent Work."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from js.agent import JSAgent
from js.config import JSSettings
from js_work.agent_factory import create_work_agent
from js_work.config import load_work_settings
from js_work.tools import WorkToolProfile

_ADVERTISED_TOOL = re.compile(r"^- `([^`]+)`$", re.MULTILINE)


def _advertised_tools(prompt: str) -> set[str]:
    return set(_ADVERTISED_TOOL.findall(prompt))


def _schema_tools(agent: JSAgent, model: str) -> set[str]:
    return {
        schema["function"]["name"]
        for schema in agent._get_tools_schema(model) or []
    }


@pytest.mark.parametrize("profile", list(WorkToolProfile))
def test_local_work_prompt_preserves_boundary_and_advertises_profile_schema(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile: WorkToolProfile,
) -> None:
    agent = create_work_agent(
        settings=load_work_settings(home=tmp_path / profile.value),
        profile=profile,
    )
    model = "local-work-model"
    monkeypatch.setattr(agent.router, "is_local_model", lambda _: True)

    prompt = agent._build_system_message(model=model)

    assert "## JS Agent Work Boundary" in prompt
    assert "work-focused Echo space" in prompt
    assert _advertised_tools(prompt) == _schema_tools(agent, model)


def test_local_main_js_agent_prompt_keeps_its_own_identity_and_schema(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(
            state_dir=tmp_path / "state",
            workspace=tmp_path / "workspace",
        )
    )
    model = "local-main-model"
    monkeypatch.setattr(agent.router, "is_local_model", lambda _: True)

    prompt = agent._build_system_message(model=model)

    assert prompt.startswith("You are JS, a helpful AI assistant with access to a small set of tools.")
    assert "## JS Agent Work Boundary" not in prompt
    assert _advertised_tools(prompt) == _schema_tools(agent, model)

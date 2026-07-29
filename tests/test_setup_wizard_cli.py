from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from js.config import JSSettings
from js.models.providers import ChatMessage
from js.setup_wizard import SetupWizard
from js.tools.registry import ToolResult


@pytest.mark.asyncio
async def test_cli_local_model_detection_uses_exact_echo_control_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from js import agent as agent_module
    from js.models import discovery as discovery_module

    wizard = SetupWizard()
    wizard.settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[],
        models=[],
    )
    raw_discovery = MagicMock(side_effect=AssertionError("raw local discovery bypass"))
    monkeypatch.setattr(discovery_module, "LocalModelDiscovery", raw_discovery)

    runtime = MagicMock()
    runtime.build_context.side_effect = [SimpleNamespace(), SimpleNamespace()]
    runtime.execute_tool_effect = AsyncMock(
        side_effect=[
            (
                ChatMessage(role="tool", content="discovered", name="control_provider_discover"),
                ToolResult(
                    success=True,
                    output="discovered",
                    metadata={"models": [{"id": "local-model", "name": "Local Model"}]},
                ),
            ),
            (
                ChatMessage(role="tool", content="unavailable", name="control_provider_discover"),
                ToolResult(success=False, error="not running"),
            ),
        ]
    )
    fake_agent = MagicMock()
    fake_agent.echo_runtime = runtime
    fake_agent.stage_provider_discovery_key.side_effect = ["lm-key-ref", "ollama-key-ref"]
    fake_agent.close = AsyncMock(return_value=None)
    monkeypatch.setattr(agent_module, "JSAgent", lambda _settings: fake_agent)

    await wizard._detect_models(non_interactive=True)

    raw_discovery.assert_not_called()
    assert runtime.execute_tool_effect.await_count == 2
    for call in runtime.execute_tool_effect.await_args_list:
        effect = call.args[0]
        assert effect.tool_name == "control_provider_discover"
        assert effect.allowed_tools == ("control_provider_discover",)
    assert [provider.name for provider in wizard.settings.providers] == ["lmstudio"]
    assert wizard.settings.providers[0].default_model == "local-model"
    fake_agent.close.assert_awaited_once()
    assert fake_agent.discard_provider_discovery_key.call_count == 2

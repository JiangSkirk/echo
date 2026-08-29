from __future__ import annotations

import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

from click.testing import CliRunner

from js.agent import JSAgent
from js.config import JSSettings
from js.echo.attachment_gate import owner_slug, session_slug
from js.orchestration.fleet import AgentFleet
from js_work.agent_factory import WORK_SYSTEM_APPENDIX, create_work_agent
from js_work.cli import main as work_main
from js_work.config import default_work_config_path, load_work_settings
from js_work.routines.tools import ROUTINE_TOOL_NAMES
from js_work.tools import WorkToolProfile
from js_work.workflows import WorkIntent, WorkIntentRouter

if TYPE_CHECKING:
    import pytest


def test_pyproject_exposes_js_work_script_and_package() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert data["project"]["scripts"]["js-work"] == "js_work.cli:compat_main"
    assert "js_work" in data["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    dependencies = {item.split(">=", 1)[0] for item in data["project"]["dependencies"]}
    assert {"openpyxl", "pypdf", "python-docx", "reportlab"} <= dependencies


def test_work_settings_use_independent_echo_defaults(tmp_path: Path) -> None:
    settings = load_work_settings(home=tmp_path)

    assert settings.state_dir == tmp_path / ".js-work" / "state"
    assert settings.workspace == tmp_path / ".js-work" / "workspace"
    assert default_work_config_path(tmp_path) == tmp_path / ".config" / "js-work" / "config.yaml"
    assert settings.echo_engine == "on"
    assert settings.features.plugins_enabled is False
    assert settings.features.skills_enabled is False
    assert settings.features.skill_tools_enabled is False
    assert settings.features.evolution_enabled is False
    assert settings.features.pipeline_enabled is False
    assert settings.features.daemon_enabled is False
    assert settings.pipeline.enabled is False


def test_existing_work_config_without_paths_still_uses_work_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("providers: []\n", encoding="utf-8")

    settings = load_work_settings(config_path=config_path, home=tmp_path)

    assert settings.state_dir == tmp_path / ".js-work" / "state"
    assert settings.workspace == tmp_path / ".js-work" / "workspace"
    assert settings.echo_engine == "on"
    assert settings.features.skills_enabled is False


def test_create_work_agent_is_echo_owned_and_skill_free(tmp_path: Path) -> None:
    settings = load_work_settings(home=tmp_path)
    agent = create_work_agent(settings=settings)

    tool_names = {tool.name for tool in agent.registry.list_tools()}
    assert agent.settings.echo_engine == "on"
    assert agent.echo_safety_service.mode == "on"
    assert agent.skills is None
    assert agent.promotion_store is None
    assert not any(name.startswith("skill_") for name in tool_names)
    assert not (settings.state_dir / "skills.db").exists()
    assert not (settings.state_dir / "skill_promotions.db").exists()


def test_work_system_prompt_is_never_compacted_or_tail_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = load_work_settings(home=tmp_path)
    agent = create_work_agent(settings=settings)

    cloud_prompt = agent._build_system_message(model="cloud/model")
    monkeypatch.setattr(agent.router, "is_local_model", lambda _model: True)
    local_prompt = agent._build_system_message(model="local/model")

    for prompt in (cloud_prompt, local_prompt):
        assert prompt.startswith(agent.SYSTEM_PROMPT)
        assert WORK_SYSTEM_APPENDIX.strip() in prompt
        assert "...[truncated]" not in prompt


def test_work_echo_runtime_scopes_lease_roots_to_owner(tmp_path: Path) -> None:
    settings = load_work_settings(home=tmp_path)
    agent = create_work_agent(settings=settings, profile=WorkToolProfile.OFFICE)

    context = agent.echo_runtime.build_context(
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
    )

    assert context.fs_roots == (
        (
            settings.workspace / "owners" / owner_slug("owner-a") / session_slug("session-a")
        ).resolve(),
        (
            settings.workspace / "uploads" / owner_slug("owner-a") / session_slug("session-a")
        ).resolve(),
    )


def test_work_echo_runtime_scopes_local_owner_to_local_root(tmp_path: Path) -> None:
    settings = load_work_settings(home=tmp_path)
    agent = create_work_agent(settings=settings, profile=WorkToolProfile.OFFICE)

    context = agent.echo_runtime.build_context(
        channel="test",
        owner_key_hash="js-work-local",
        session_id="session-a",
    )

    from js.echo.attachment_gate import session_slug

    assert context.fs_roots == (
        (settings.workspace / "local" / session_slug("session-a")).resolve(),
        (
            settings.workspace / "uploads" / owner_slug("js-work-local") / session_slug("session-a")
        ).resolve(),
    )


def test_create_work_agent_denies_host_code_tools_unless_explicitly_local(
    tmp_path: Path,
) -> None:
    safe_default = create_work_agent(settings=load_work_settings(home=tmp_path / "safe"))
    local_cli = create_work_agent(
        settings=load_work_settings(home=tmp_path / "local"),
        allow_host_code_tools=True,
    )

    assert not {"shell", "python"} & {tool.name for tool in safe_default.registry.list_tools()}
    assert {"shell", "python"} <= {tool.name for tool in local_cli.registry.list_tools()}


def test_work_tool_profiles_filter_visible_tools(tmp_path: Path) -> None:
    execute_agent = create_work_agent(
        settings=load_work_settings(home=tmp_path / "execute"),
        allow_host_code_tools=True,
    )
    execute_names = {tool.name for tool in execute_agent.registry.list_tools()}
    assert {
        "web_search",
        "browser_fetch",
        "file_read",
        "file_write",
        "file_edit",
        "code_search",
        "shell",
        "python",
        "fleet_collaborate",
    } <= execute_names
    assert "csv_write" not in execute_names
    assert "file_delete" not in execute_names

    safe_agent = create_work_agent(
        settings=load_work_settings(home=tmp_path / "safe"),
        profile=WorkToolProfile.SAFE,
    )
    safe_names = {tool.name for tool in safe_agent.registry.list_tools()}
    assert {
        "web_search",
        "browser_fetch",
        "file_read",
        "file_view",
        "file_list",
        "file_search",
        "code_search",
    } <= safe_names
    assert not {"file_write", "file_edit", "file_delete", "shell", "python"} & safe_names
    assert "fleet_collaborate" not in safe_names
    assert "control_fleet_configure" in safe_names

    office_agent = create_work_agent(
        settings=load_work_settings(home=tmp_path / "office"),
        profile=WorkToolProfile.OFFICE,
    )
    office_names = {tool.name for tool in office_agent.registry.list_tools()}
    assert {
        "web_search",
        "browser_fetch",
        "file_read",
        "file_write",
        "csv_read",
        "csv_write",
        "excel_read",
        "excel_write",
        "excel_merge",
        "excel_create",
        "pdf_generate",
    } <= office_names
    assert not {"shell", "python", "fleet_collaborate", "file_delete"} & office_names
    assert "control_fleet_configure" in office_names

    for agent, tool_names in (
        (execute_agent, execute_names),
        (safe_agent, safe_names),
        (office_agent, office_names),
    ):
        assert agent._current_allowed_tools == tool_names


def test_personal_registry_and_work_profiles_keep_routine_tools_isolated(tmp_path: Path) -> None:
    personal = JSAgent(
        JSSettings(
            workspace=tmp_path / "personal-workspace",
            state_dir=tmp_path / "personal-state",
            providers=[],
        )
    )
    personal_names = {tool.name for tool in personal.registry.list_tools()}
    assert personal_names.isdisjoint(ROUTINE_TOOL_NAMES)

    profile_names = {
        profile: {
            tool.name
            for tool in create_work_agent(
                settings=load_work_settings(home=tmp_path / profile.value),
                profile=profile,
            ).registry.list_tools()
        }
        for profile in WorkToolProfile
    }
    assert profile_names[WorkToolProfile.OFFICE] >= ROUTINE_TOOL_NAMES
    for profile in (WorkToolProfile.SAFE, WorkToolProfile.EXECUTE):
        assert "work_routine_run" not in profile_names[profile]
        assert "work_routine_preview" not in profile_names[profile]
        assert "excel_write" not in profile_names[profile]


def test_fleet_can_disable_skill_inheritance(monkeypatch, tmp_path: Path) -> None:
    registered: list[str] = []

    class FakeChildSkills:
        def register_auto_skill(self, spec: object) -> None:
            registered.append(str(spec))

    class FakeAgent:
        SYSTEM_PROMPT = "base"

        def __init__(self, settings: JSSettings) -> None:
            self.settings = settings
            self.skills = FakeChildSkills()
            self._role: str | None = None

    class FakeSkillSource:
        def get_all(self) -> dict[str, object]:
            return {"demo": "demo-spec"}

    monkeypatch.setattr("js.orchestration.fleet.agent_fleet.JSAgent", FakeAgent)
    settings = JSSettings(state_dir=tmp_path / "state", workspace=tmp_path / "workspace")

    fleet = AgentFleet(settings, skills=FakeSkillSource(), inherit_skills=False)
    child = fleet._spawn_worker()

    assert registered == []
    assert "已注册的技能工具" not in child.agent.SYSTEM_PROMPT


def test_work_intent_router_classifies_core_workflows() -> None:
    router = WorkIntentRouter()

    assert router.classify("搜索并整理一个行业报告") == WorkIntent.RESEARCH
    assert router.classify("把这个项目拆成可执行任务") == WorkIntent.PROJECT_BREAKDOWN
    assert (
        router.classify("从表格1提取面料信息，按表格2模板生成表格3")
        == WorkIntent.SPREADSHEET_ROUTINE
    )
    assert router.classify("帮我写一段说明") == WorkIntent.GENERAL

    research_prompt = router.prepare_message("搜索并整理一个行业报告")
    assert "优先使用搜索" in research_prompt
    assert "不要调用 skill" in research_prompt
    routine_prompt = router.prepare_message("从表格1提取面料信息，按表格2模板生成表格3")
    assert "表格 Routine" in routine_prompt
    assert "规则校验" in routine_prompt
    assert "reviewer" in routine_prompt


def test_js_work_cli_supports_init_and_no_provider_message(tmp_path: Path) -> None:
    runner = CliRunner()
    config_path = tmp_path / "config.yaml"

    init_result = runner.invoke(
        work_main, ["--home", str(tmp_path), "init", "--path", str(config_path)]
    )
    assert init_result.exit_code == 0
    assert config_path.exists()

    no_provider_result = runner.invoke(
        work_main,
        ["--home", str(tmp_path), "--profile", "safe", "run", "hello"],
    )
    assert no_provider_result.exit_code == 0
    assert "js work init" in no_provider_result.output


def test_js_work_run_uses_echo_turn_runtime(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, str] = {}

    class FakeMessage:
        role = "assistant"
        content = "整理完成"

    class FakeState:
        session_id = "session-1"
        status = "completed"
        error_message = ""
        messages = [FakeMessage()]

    class FakeAgent:
        def start_background_tasks(self) -> None:
            return None

        async def close(self) -> None:
            return None

    fake_agent = FakeAgent()

    def fake_create_work_agent(
        *,
        settings: JSSettings,
        profile: WorkToolProfile,
        allow_host_code_tools: bool,
    ) -> FakeAgent:
        assert allow_host_code_tools is True
        captured["profile"] = profile.value
        captured["state_dir"] = str(settings.state_dir)
        return fake_agent

    async def fake_run_echo_turn(
        agent: FakeAgent,
        message: str,
        *,
        channel: str,
        owner_key_hash: str | None = None,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[str] | None = None,
    ) -> FakeState:
        assert agent is fake_agent
        captured["message"] = message
        captured["channel"] = channel
        captured["owner_key_hash"] = owner_key_hash or ""
        captured["session_id"] = session_id or ""
        captured["model"] = model or ""
        captured["attachments"] = ",".join(attachments or [])
        return FakeState()

    monkeypatch.setattr("js_work.cli.create_work_agent", fake_create_work_agent)
    monkeypatch.setattr("js_work.cli.run_echo_turn", fake_run_echo_turn)
    monkeypatch.setattr(
        "js_work.cli.load_work_settings",
        lambda config=None, *, home=None, personal_roots=None: JSSettings(
            state_dir=tmp_path / ".js-work" / "state",
            workspace=tmp_path / ".js-work" / "workspace",
            providers=[
                {
                    "name": "mock",
                    "base_url": "http://127.0.0.1:1/v1",
                    "default_model": "mock-model",
                    "models": [{"id": "mock-model", "provider": "mock"}],
                }
            ],
        ),
    )

    runner = CliRunner()
    result = runner.invoke(
        work_main,
        [
            "--home",
            str(tmp_path),
            "--profile",
            "execute",
            "run",
            "搜索并整理资料",
            "--model",
            "mock-model",
        ],
    )

    assert result.exit_code == 0
    assert "整理完成" in result.output
    assert captured["profile"] == "execute"
    assert captured["channel"] == "js_work_cli"
    assert captured["owner_key_hash"] == "js-work-local"
    assert captured["model"] == "mock-model"
    assert ".js-work" in captured["state_dir"]
    assert "优先使用搜索" in captured["message"]
    assert "不要调用 skill" in captured["message"]

    captured.clear()
    routine_result = runner.invoke(
        work_main,
        ["--home", str(tmp_path), "--profile", "execute", "run", "按表格2模板生成面料统计表格3"],
    )

    assert routine_result.exit_code == 0
    # Message classification may prepare a spreadsheet workflow, but it must
    # never widen the caller-selected capability profile.
    assert captured["profile"] == "execute"
    assert "表格 Routine" in captured["message"]
    assert "规则校验" in captured["message"]

    FakeState.status = "error"
    FakeState.error_message = "provider failed"
    failed_result = runner.invoke(
        work_main,
        ["--home", str(tmp_path), "--profile", "execute", "run", "hello"],
    )

    assert failed_result.exit_code == 1
    terminal_output = failed_result.output + failed_result.stderr
    assert "处理你的请求" in terminal_output
    assert "provider failed" not in terminal_output
    assert "整理完成" not in failed_result.output

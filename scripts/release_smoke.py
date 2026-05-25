#!/usr/bin/env python3
"""Release smoke checks for JS Agent.

These checks are intentionally small and end-to-end. They verify that a fresh
install can start the CLI/Web UI, add and switch an OpenAI-compatible provider,
load OpenClaw/Hermes-style skills, run dream memory, run the autonomous
evolution entrypoint, and execute a multi-agent workflow.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

CHECKS = ("package", "web", "model", "skills", "dream", "evolution", "fleet")
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class SmokeError(RuntimeError):
    """A user-facing smoke test failure."""


def _short(text: str, limit: int = 4000) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[-limit:]


def _write_config(base: Path) -> Path:
    config_path = base / "config.yaml"
    config = {
        "version": "0.1.1",
        "workspace": str(base / "workspace"),
        "state_dir": str(base / "state"),
        "log_level": "INFO",
        "max_turns": 3,
        "auto_delegate": False,
        "providers": [],
        "models": [],
        "security": {
            "defense_mode": "enforce",
            "api_key_required": False,
        },
    }
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return config_path


def _env(base: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["JS_CONFIG_PATH"] = str(_write_config(base))
    env["JS_STATE_DIR"] = str(base / "state")
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = "127.0.0.1,localhost"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _run(cmd: list[str], *, env: dict[str, str], timeout: int = 120) -> str:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=timeout,
        check=False,
    )
    output = proc.stdout or ""
    if proc.returncode != 0:
        raise SmokeError(
            f"命令执行失败: {' '.join(cmd)}\n"
            f"退出码: {proc.returncode}\n"
            f"输出:\n{_short(output)}"
        )
    return output


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request_json(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _LOCAL_OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SmokeError(f"HTTP {exc.code} 请求失败: {url}\n{_short(detail)}") from exc
    return json.loads(raw)


def _request_text(url: str, *, timeout: float = 8.0) -> str:
    try:
        with _LOCAL_OPENER.open(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SmokeError(f"HTTP {exc.code} 请求失败: {url}\n{_short(detail)}") from exc


def _wait_for_server(base_url: str, proc: subprocess.Popen[str], log_path: Path) -> None:
    deadline = time.monotonic() + 45
    last_error = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            raise SmokeError(f"Web 服务启动后立刻退出。\n日志:\n{_short(log)}")
        try:
            html = _request_text(base_url, timeout=2.0)
            if "<html" in html.lower() or "JS" in html:
                return
        except Exception as exc:  # noqa: BLE001 - keep retrying until deadline
            last_error = str(exc)
        time.sleep(0.5)
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise SmokeError(
        "Web 服务没有在 45 秒内启动。\n"
        f"最后错误: {last_error}\n"
        f"日志:\n{_short(log)}"
    )


def _stop_process(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def check_package(base: Path) -> None:
    env = _env(base)
    _run([sys.executable, "-m", "pip", "check"], env=env, timeout=120)
    help_text = _run([sys.executable, "-m", "js", "--help"], env=env, timeout=60)
    if "web" not in help_text:
        raise SmokeError("CLI 能启动，但帮助信息里没有 web 命令。")
    _run(
        [
            sys.executable,
            "-c",
            "import js; import js.web.server; from cachetools import TTLCache; import aiosqlite; print('ok')",
        ],
        env=env,
        timeout=60,
    )


def check_web_and_model(base: Path) -> None:
    env = _env(base)
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    log_path = base / "web-smoke.log"
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(
            [sys.executable, "-m", "js", "web", "--host", "127.0.0.1", "--port", str(port)],
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        try:
            _wait_for_server(base_url, proc, log_path)
            status = _request_json(f"{base_url}/api/status")
            if "state_dir" not in status:
                raise SmokeError(f"/api/status 返回异常: {status}")

            skills = _request_json(f"{base_url}/api/skills")
            if not isinstance(skills.get("skills"), list):
                raise SmokeError(f"/api/skills 返回异常: {skills}")
            skill_ids = {item.get("id") for item in skills["skills"] if isinstance(item, dict)}
            missing_skills = {"excel-helper", "pdf-helper", "file-search"} - skill_ids
            if missing_skills:
                raise SmokeError(f"内置技能未正确加载: {sorted(missing_skills)}")

            presets = _request_json(f"{base_url}/api/providers/cloud-presets")
            if not presets.get("presets"):
                raise SmokeError("云模型预设为空，普通用户无法一键选择常见 Provider。")

            provider_name = "smoke_local"
            model_id = "smoke-model"
            connect = _request_json(
                f"{base_url}/api/providers/connect",
                method="POST",
                body={
                    "name": provider_name,
                    "base_url": f"http://127.0.0.1:{_free_port()}/v1",
                    "models": [{"id": model_id, "name": "Smoke Model"}],
                },
            )
            if connect.get("provider") != provider_name or connect.get("models_added") != 1:
                raise SmokeError(f"Provider 添加返回异常: {connect}")

            switch = _request_json(
                f"{base_url}/api/models/switch",
                method="POST",
                body={"model_id": f"{provider_name}/{model_id}"},
            )
            if not switch.get("success"):
                raise SmokeError(f"模型切换失败: {switch}")

            models = _request_json(f"{base_url}/api/models")
            if models.get("active_model") != f"{provider_name}/{model_id}":
                raise SmokeError(f"模型切换未生效: {models}")
        finally:
            _stop_process(proc)


async def check_skills(base: Path) -> None:
    from js.config import JSSettings
    from js.skills.hermes_bridge import load_all_hermes_skills
    from js.skills.manager import SkillManager
    from js.skills.spec import SkillType

    settings = JSSettings(workspace=base / "workspace", state_dir=base / "state", providers=[], models=[])
    manager = SkillManager(settings.state_dir, settings.workspace)

    prompt_skill = base / "openclaw_prompt"
    prompt_skill.mkdir()
    (prompt_skill / "SKILL.md").write_text(
        "---\n"
        "name: OpenClaw Prompt Smoke\n"
        "description: Prompt-only OpenClaw style skill\n"
        "---\n"
        "Return a concise answer.\n",
        encoding="utf-8",
    )
    installed_prompt = await manager.install(str(prompt_skill))
    if installed_prompt.type != SkillType.PROMPT:
        raise SmokeError(f"OpenClaw prompt 技能类型识别错误: {installed_prompt.type}")

    code_skill = base / "openclaw_code"
    (code_skill / "scripts").mkdir(parents=True)
    (code_skill / "SKILL.md").write_text(
        "---\n"
        "name: OpenClaw Code Smoke\n"
        "description: Code OpenClaw style skill\n"
        "---\n"
        "Run the script.\n",
        encoding="utf-8",
    )
    (code_skill / "scripts" / "process.py").write_text("print('ok')\n", encoding="utf-8")
    installed_code = await manager.install(str(code_skill))
    if installed_code.type != SkillType.CODE:
        raise SmokeError(f"OpenClaw code 技能类型识别错误: {installed_code.type}")

    hermes_root = base / "fake-hermes" / "skills"
    hermes_prompt = hermes_root / "writing" / "brief"
    hermes_prompt.mkdir(parents=True)
    (hermes_prompt / "SKILL.md").write_text(
        "---\n"
        "name: Hermes Brief Smoke\n"
        "description: Hermes prompt skill smoke\n"
        "metadata:\n"
        "  hermes:\n"
        "    category: writing\n"
        "    tags: [brief]\n"
        "---\n"
        "Write a brief answer.\n",
        encoding="utf-8",
    )
    hermes_code = hermes_root / "dev" / "scripted"
    (hermes_code / "scripts").mkdir(parents=True)
    (hermes_code / "SKILL.md").write_text(
        "---\n"
        "name: Hermes Code Smoke\n"
        "description: Hermes code skill smoke\n"
        "metadata:\n"
        "  hermes:\n"
        "    category: dev\n"
        "    tags: [script]\n"
        "---\n"
        "Run code.\n",
        encoding="utf-8",
    )
    (hermes_code / "scripts" / "run.py").write_text(
        "import argparse\n"
        "parser = argparse.ArgumentParser()\n"
        "parser.add_argument('--input', help='input text')\n"
        "print(parser.parse_args().input or 'ok')\n",
        encoding="utf-8",
    )
    hermes_skills = load_all_hermes_skills(hermes_root)
    if len(hermes_skills) != 2:
        raise SmokeError(f"Hermes 技能桥加载数量错误: {len(hermes_skills)}")
    if not all(skill_id.startswith("hermes:") for skill_id in hermes_skills):
        raise SmokeError(f"Hermes 技能没有正确加命名空间: {list(hermes_skills)}")
    if not any(spec.type == SkillType.CODE for spec in hermes_skills.values()):
        raise SmokeError("Hermes code 技能没有识别为 CODE。")


async def check_dream(base: Path) -> None:
    from js.config import JSSettings, MemoryConfig
    from js.memory.store import MemoryStore

    settings = JSSettings(workspace=base / "workspace", state_dir=base / "state", providers=[], models=[])
    memory = MemoryStore(settings.state_dir, MemoryConfig())
    memory.store(
        "release-smoke",
        "用户正在验证梦境记忆是否能整理长期记忆。",
        category="conversation",
        importance=9,
    )
    report = await memory.dream(llm_summarizer=lambda _text: "梦境摘要：长期记忆整理正常。")
    logs = memory.get_dream_logs(limit=10)
    dreams_path = settings.state_dir / "memory" / "dreams.md"
    memory.close()
    phases = [phase["phase"] for phase in report.get("phases", [])]
    if phases != ["light", "rem", "deep"]:
        raise SmokeError(f"梦境阶段异常: {phases}")
    if len(logs) < 3 or not dreams_path.exists():
        raise SmokeError("梦境记忆没有写入日志或 dreams.md。")


class _StaticRouter:
    def get_model_config(self, model: str = "") -> Any:
        from js.config import ModelConfig

        return ModelConfig(id=model or "mock", name="Mock", provider="mock")

    async def health_check(self) -> dict[str, bool]:
        return {"mock": True}

    async def chat(
        self,
        messages: list[Any],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> Any:
        from js.models.providers import ChatResponse

        prompt = messages[-1].content if messages else ""
        if isinstance(prompt, list):
            prompt = str(prompt)
        if "===USER===" in str(prompt) or "USER.md" in str(prompt):
            content = (
                "===USER===\n"
                "# USER\n"
                "- 测试用户正在验证发布烟测\n"
                "===IDENTITY===\n"
                "# IDENTITY\n"
                "- 测试助手运行正常"
            )
        else:
            content = f"release smoke completed: {str(prompt)[:120]}"
        return ChatResponse(content=content, model=model or "mock", tool_calls=[], usage={}, finish_reason="stop")

    async def chat_stream(
        self,
        messages: list[Any],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> Any:
        yield "ok"

    async def close(self) -> None:
        return None


async def check_evolution(base: Path) -> None:
    from js.agent import JSAgent
    from js.config import JSSettings

    settings = JSSettings(
        workspace=base / "workspace",
        state_dir=base / "state",
        providers=[],
        models=[],
        max_turns=3,
    )
    agent = JSAgent(settings)
    agent.router = _StaticRouter()  # type: ignore[assignment]
    agent.memory.store("install-test", "用户想测试自主进化、梦境记忆和安装稳定性", category="conversation", importance=8)
    report = await agent._run_evolution_cycle(
        [{"user": "请测试安装、梦境记忆和自主进化", "assistant": "我会做端到端验证"}]
    )
    logs = agent.memory.get_dream_logs(limit=10)
    await agent.close()
    if not report["profile_update"]["ok"]:
        raise SmokeError(f"自主进化档案更新失败: {report}")
    if not report["dreaming"]["ok"]:
        raise SmokeError(f"自主进化梦境记忆失败: {report}")
    if not report["skill_evolution"]["ok"]:
        raise SmokeError(f"自主进化技能入口失败: {report}")
    if len(logs) < 3:
        raise SmokeError("自主进化没有触发梦境记忆日志。")


async def check_fleet(base: Path) -> None:
    from js.config import JSSettings
    from js.orchestration.fleet import AgentFleet, AgentRole, Task

    class SmokeFleet(AgentFleet):
        def spawn(
            self,
            name: str,
            role: AgentRole,
            model: str | None = None,
            capabilities: list[str] | None = None,
        ) -> Any:
            inst = super().spawn(name, role, model=model or "mock", capabilities=capabilities)
            inst.agent.router = _StaticRouter()  # type: ignore[assignment]
            return inst

    settings = JSSettings(
        workspace=base / "workspace",
        state_dir=base / "state",
        providers=[],
        models=[],
        auto_delegate=False,
        max_turns=3,
    )
    fleet = SmokeFleet(settings, max_agents=4)
    fleet.spawn("coder", AgentRole.CODER)
    task_id = await fleet.dispatch(Task(id="release-smoke-task", description="检查功能是否能运行", role_hint=AgentRole.CODER))
    task = fleet.tasks[task_id]
    deadline = time.monotonic() + 20
    while task.status not in {"done", "failed"} and time.monotonic() < deadline:
        await asyncio.sleep(0.1)
    if task.status != "done":
        raise SmokeError(f"多 agent 单任务失败: status={task.status}, result={task.result}")

    result = await fleet.collaborate("验证多 agent 协作", [("写实现建议", AgentRole.CODER), ("做测试建议", AgentRole.TESTER)])
    for inst in fleet.agents.values():
        await inst.agent.close()
    if not result.get("final") or len(result.get("subtasks", {})) != 2:
        raise SmokeError(f"多 agent 协作汇总失败: {result}")


async def _run_async_check(name: str, func: Callable[[Path], Any], root: Path) -> None:
    base = root / name
    base.mkdir(parents=True, exist_ok=True)
    result = func(base)
    if asyncio.iscoroutine(result):
        await result


async def run_checks(selected: list[str], keep_temp: bool) -> int:
    if "all" in selected:
        selected = list(CHECKS)

    checks: dict[str, Callable[[Path], Any]] = {
        "package": check_package,
        "web": check_web_and_model,
        "model": check_web_and_model,
        "skills": check_skills,
        "dream": check_dream,
        "evolution": check_evolution,
        "fleet": check_fleet,
    }

    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    if keep_temp:
        root = Path(tempfile.mkdtemp(prefix="titan-release-smoke-"))
    else:
        temp_dir = tempfile.TemporaryDirectory(prefix="titan-release-smoke-")
        root = Path(temp_dir.name)
    try:
        print(f"临时测试目录: {root}")
        completed_web = False
        for name in selected:
            if name == "model" and completed_web:
                print("  [OK] model 已包含在 web/provider 烟测中")
                continue
            step_name = "web/model" if name == "web" else name
            print(f"\n[检查] {step_name}")
            try:
                await _run_async_check(name, checks[name], root)
            except SmokeError as exc:
                print(f"  [失败] {step_name}")
                print(str(exc))
                print("\n排查建议：先在本机运行同一条命令；如果失败，把上面的输出和临时测试目录里的日志发给开发者。")
                if keep_temp:
                    print(f"临时目录保留: {root}")
                    return 1
                return 1
            except Exception as exc:  # noqa: BLE001 - final guard for user-friendly output
                print(f"  [失败] {step_name}")
                print(f"出现未预期错误: {type(exc).__name__}: {exc}")
                print("\n排查建议：这是程序级异常，优先把堆栈和当前 Python 版本发给开发者。")
                if keep_temp:
                    print(f"临时目录保留: {root}")
                    return 1
                return 1
            else:
                print(f"  [OK] {step_name}")
                if name == "web":
                    completed_web = True

        if keep_temp:
            print(f"\n临时目录保留: {root}")
        print("\n发布烟测通过。")
        return 0
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run JS Agent release smoke checks.")
    parser.add_argument("--all", action="store_true", help="Run all release smoke checks.")
    parser.add_argument("--keep-temp", action="store_true", help="Keep temporary test files after failure.")
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=("all", *CHECKS),
        default=["all"],
        help="Checks to run. Defaults to all.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    selected = ["all"] if args.all else args.checks
    return asyncio.run(run_checks(selected, keep_temp=args.keep_temp))


if __name__ == "__main__":
    raise SystemExit(main())

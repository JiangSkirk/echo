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
from typing import Any, cast

import yaml

from js.echo.ledger.release_gates import (
    ReleaseSourceIntegrityError,
    validate_release_source_integrity,
)
from js.echo.slo_contract import SLO_CONTRACT

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKS = (
    "package",
    "web",
    "model",
    "skills",
    "dream",
    "evolution",
    "fleet",
    "work",
    "echo",
    "echo_ledger",
)
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
        "version": "0.1.5",
        "workspace": str(base / "workspace"),
        "state_dir": str(base / "state"),
        "log_level": "INFO",
        "max_turns": 3,
        "auto_delegate": False,
        "providers": [],
        "models": [],
        "security": {
            "defense_mode": "enforce",
            # F-01 semantics: auth-off now means anonymous=guest (read-only).
            # Require API keys so bootstrap hands out the one-time admin key.
            "api_key_required": True,
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
    env.pop("JS_ECHO_ENGINE", None)
    # Host-derived loopback Origin checks must not inherit a stale allowlist
    # left in the parent process by parallel pytest fixtures.
    env.pop("JS_ALLOWED_ORIGINS", None)
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
            f"命令执行失败: {' '.join(cmd)}\n退出码: {proc.returncode}\n输出:\n{_short(output)}"
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
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    data = None
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _LOCAL_OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SmokeError(f"HTTP {exc.code} 请求失败: {url}\n{_short(detail)}") from exc
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise SmokeError(f"HTTP 响应不是 JSON object: {url}")
    return {str(key): value for key, value in payload.items()}


def _request_text(url: str, *, timeout: float = 8.0) -> str:
    try:
        with _LOCAL_OPENER.open(url, timeout=timeout) as resp:
            raw = resp.read()
            if not isinstance(raw, bytes):
                raise SmokeError(f"HTTP 响应不是 bytes: {url}")
            return raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SmokeError(f"HTTP {exc.code} 请求失败: {url}\n{_short(detail)}") from exc


def _wait_for_server(base_url: str, proc: subprocess.Popen[str], log_path: Path) -> None:
    deadline = time.monotonic() + 45
    last_error = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log = (
                log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            )
            raise SmokeError(f"Web 服务启动后立刻退出。\n日志:\n{_short(log)}")
        try:
            html = _request_text(base_url, timeout=2.0)
            if "<html" in html.lower() or "JS" in html:
                return
        except Exception as exc:  # noqa: BLE001 - keep retrying until deadline
            last_error = str(exc)
        time.sleep(0.5)
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise SmokeError(f"Web 服务没有在 45 秒内启动。\n最后错误: {last_error}\n日志:\n{_short(log)}")


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
            # F-01 semantics: anonymous requests are read-only guests.  When
            # api_key_required=true the server mints a one-time bootstrap admin
            # key for the local operator (0600, state dir); use it for all
            # subsequent admin calls instead of unauthenticated bootstrap.
            key_file = base / "state" / "bootstrap_admin_key.txt"
            admin_key = ""
            for _ in range(20):
                if key_file.is_file():
                    admin_key = key_file.read_text(encoding="utf-8").strip()
                    if admin_key:
                        break
                time.sleep(0.25)
            if not admin_key:
                raise SmokeError("服务器未生成 bootstrap 管理员密钥 (bootstrap_admin_key.txt)")
            admin_headers = {"Origin": base_url, "x-api-key": admin_key}
            status = _request_json(f"{base_url}/api/status", extra_headers=admin_headers)
            if "state_dir" not in status:
                raise SmokeError(f"/api/status 返回异常: {status}")
            echo_status = status.get("echo") or {}
            if (
                echo_status.get("mode") != "on"
                or echo_status.get("default_architecture") is not True
                or echo_status.get("ledger_mode") != "on"
                or echo_status.get("architecture_state") != "primary_healthy"
            ):
                raise SmokeError(f"Echo primary 状态异常: {echo_status}")

            skills = _request_json(f"{base_url}/api/skills", extra_headers=admin_headers)
            if not isinstance(skills.get("skills"), list):
                raise SmokeError(f"/api/skills 返回异常: {skills}")
            skill_ids = {item.get("id") for item in skills["skills"] if isinstance(item, dict)}
            missing_skills = {"excel-helper", "pdf-helper", "file-search"} - skill_ids
            if missing_skills:
                raise SmokeError(f"内置技能未正确加载: {sorted(missing_skills)}")

            presets = _request_json(
                f"{base_url}/api/providers/cloud-presets", extra_headers=admin_headers
            )
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
                extra_headers=admin_headers,
            )
            if connect.get("provider") != provider_name or connect.get("models_added") != 1:
                raise SmokeError(f"Provider 添加返回异常: {connect}")

            switch = _request_json(
                f"{base_url}/api/models/switch",
                method="POST",
                body={"model_id": f"{provider_name}/{model_id}"},
                extra_headers=admin_headers,
            )
            if not switch.get("success"):
                raise SmokeError(f"模型切换失败: {switch}")

            models = _request_json(f"{base_url}/api/models", extra_headers=admin_headers)
            if models.get("active_model") != f"{provider_name}/{model_id}":
                raise SmokeError(f"模型切换未生效: {models}")
        finally:
            _stop_process(proc)


async def check_skills(base: Path) -> None:
    from js.config import JSSettings
    from js.skills.hermes_bridge import load_all_hermes_skills
    from js.skills.manager import SkillManager
    from js.skills.spec import SkillType

    settings = JSSettings(
        workspace=base / "workspace", state_dir=base / "state", providers=[], models=[]
    )
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

    settings = JSSettings(
        workspace=base / "workspace", state_dir=base / "state", providers=[], models=[]
    )
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

    # Verify structured block fields on promoted memories
    semantic_mems = memory.get_all_semantic(limit=100)
    for mem in semantic_mems:
        if not mem.get("memory_path"):
            raise SmokeError(f"梦境提升的记忆缺少 memory_path: {mem.get('key')}")
        if not mem.get("entity_type"):
            raise SmokeError(f"梦境提升的记忆缺少 entity_type: {mem.get('key')}")

    # Verify block API works
    blocks = memory.get_blocks()
    if not isinstance(blocks, list):
        raise SmokeError("get_blocks() 未返回列表。")

    memory.close()
    phases = [phase["phase"] for phase in report.get("phases", [])]
    if phases != ["light", "rem", "deep"]:
        raise SmokeError(f"梦境阶段异常: {phases}")
    if len(logs) < 3 or not dreams_path.exists():
        raise SmokeError("梦境记忆没有写入日志或 dreams.md。")


class _StaticRouter:
    def __init__(self) -> None:
        from js.config import JSSettings, ModelConfig
        from js.models.providers import ModelProvider

        model = ModelConfig(id="mock", name="Mock", provider="mock")
        self.settings = JSSettings(providers=[], models=[])
        self._providers: dict[str, ModelProvider] = {"mock": cast("ModelProvider", self)}
        self._model_map = {
            "mock": ("mock", model),
            "mock/mock": ("mock", model),
        }
        self._permit_verifier: Any = None

    async def select_model(
        self, _task_complexity: str = "medium", preferred: str | None = None
    ) -> Any:
        from js.models.providers import ModelProvider
        from js.models.router import RoutingDecision

        return RoutingDecision(
            provider=cast("ModelProvider", self),
            model=preferred or "mock",
            provider_name="mock",
            reason="release smoke",
        )

    def get_model_config(self, model: str = "") -> Any:
        binding = self.get_model_binding(model or "mock")
        return binding[1] if binding is not None else None

    def get_model_binding(self, model: str) -> tuple[str, Any] | None:
        return self._model_map.get(model)

    def is_local_model(self, model: str | None = None) -> bool:
        return False

    async def health_check(self) -> dict[str, bool]:
        return {"mock": True}

    async def chat(
        self,
        messages: list[Any],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        before_model_call: Callable[..., Any] | None = None,
        after_model_call: Callable[..., Any] | None = None,
        permit_grant: Callable[..., Any] | None = None,
    ) -> Any:
        from js.models.providers import ChatResponse

        del temperature, max_tokens
        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError("release smoke router requires model callbacks and permit grant")
        decision = await self.select_model(preferred=model)
        self._permit_verifier.verify_and_consume(
            permit_grant(decision, messages, tools),
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
        )
        context = await before_model_call(decision, messages, tools)
        response: ChatResponse | None = None
        error: BaseException | None = None
        try:
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
            response = ChatResponse(
                content=content,
                model=decision.model,
                tool_calls=[],
                usage={},
                finish_reason="stop",
            )
            return response
        except BaseException as exc:  # noqa: BLE001 - finalize exact failure
            error = exc
            response = None
            raise
        finally:
            await after_model_call(context, response, error)

    async def chat_stream(
        self,
        messages: list[Any],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> Any:
        yield "ok"

    async def chat_stream_events(
        self,
        messages: list[Any],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        before_model_call: Callable[..., Any] | None = None,
        after_model_call: Callable[..., Any] | None = None,
        permit_grant: Callable[..., Any] | None = None,
    ) -> Any:
        del max_tokens
        from js.models.providers import ChatResponse
        from js.models.stream_events import StreamEvent

        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError(
                "release smoke stream requires Echo model callbacks and permit grant"
            )
        decision = await self.select_model(preferred=model)
        # Consume the runtime permit exactly like the production router gate.
        self._permit_verifier.verify_and_consume(
            permit_grant(decision, messages, tools),
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
        )
        context = await before_model_call(decision, messages, tools)
        response: ChatResponse | None = None
        error: BaseException | None = None
        try:
            usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            response = ChatResponse(
                content="ok",
                model=decision.model,
                tool_calls=[],
                usage=usage,
                finish_reason="stop",
            )
            yield StreamEvent(kind="text_delta", text="ok", model=decision.model)
            yield StreamEvent(kind="usage", usage=usage, model=decision.model)
            yield StreamEvent(kind="done", finish_reason="stop", model=decision.model)
        except BaseException as exc:  # noqa: BLE001 - finalize exact failure
            error = exc
            response = None
            raise
        finally:
            await after_model_call(context, response, error)

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
    _static = _StaticRouter()
    _static._permit_verifier = agent._model_permit_issuer
    agent.router = _static  # type: ignore[assignment]
    agent.memory.store(
        "install-test",
        "用户想测试自主进化、梦境记忆和安装稳定性",
        category="conversation",
        importance=8,
    )
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
    from js.orchestration.fleet import AgentFleet, AgentInstance, AgentRole

    class SmokeFleet(AgentFleet):
        def _spawn_agent(
            self,
            name: str,
            role: AgentRole,
            *,
            product_id: str | None = None,
            owner_key_hash: str | None = None,
        ) -> AgentInstance:
            inst = super()._spawn_agent(
                name,
                role,
                product_id=product_id,
                owner_key_hash=owner_key_hash,
            )
            inst.model = "mock"
            _static = _StaticRouter()
            _static._permit_verifier = inst.agent._model_permit_issuer
            inst.agent.router = _static  # type: ignore[assignment]
            return inst

    settings = JSSettings(
        workspace=base / "workspace",
        state_dir=base / "state",
        providers=[],
        models=[],
        max_turns=3,
    )
    fleet = SmokeFleet(settings, max_workers=4)
    result = await fleet.collaborate(
        "实现并测试一个多 agent 发布烟测流程",
        ["写实现建议", "做测试建议"],
        role_mapping={0: "coder", 1: "tester"},
    )
    for inst in list(fleet.agents.values()):
        await inst.agent.close()
    subtasks = result.get("subtasks", {})
    failed_subtasks = {
        name: output
        for name, output in subtasks.items()
        if not output or "error:" in str(output).lower() or "failed:" in str(output).lower()
    }
    if not result.get("final") or len(subtasks) != 2 or failed_subtasks:
        raise SmokeError(f"多 agent 协作汇总失败: {result}")


def check_echo_ledger(base: Path) -> None:
    from js.config import JSSettings
    from js.echo.ledger.release_gates import verify_release_readiness
    from js.echo.ledger.sandbox_backend import EchoSandboxBackend
    from js.echo.ledger.security_matrix import run_security_matrix
    from js.echo.ledger.service import EchoSafetyService

    matrix = run_security_matrix()
    if not matrix.ok or matrix.total != 25:
        raise SmokeError(
            f"Echo internal safety ledger 25 项安全矩阵失败: total={matrix.total} failed={matrix.failed}"
        )

    probe = EchoSandboxBackend(workspace=base / "workspace").probe()
    if not probe.real_process_backend:
        raise SmokeError(f"Echo internal safety ledger sandbox backend 不是真实进程后端: {probe}")

    readiness = verify_release_readiness(
        Path.cwd(),
        require_audit_reports=False,
        require_live_acceptance=False,
    )
    if not readiness.internal_ready:
        raise SmokeError(f"Echo 内部门禁未通过: {readiness.internal_blockers}")
    if "security_matrix_25" not in readiness.passed:
        raise SmokeError("Echo release gate 没有记录 security_matrix_25。")
    if "real_sandbox_backend" not in readiness.passed:
        raise SmokeError("Echo release gate 没有记录 real_sandbox_backend。")
    if "echo_ip_boundary" not in readiness.passed:
        raise SmokeError("Echo 自研/IP 边界门禁未通过。")

    service = EchoSafetyService.from_settings(JSSettings(state_dir=base / "state"))
    for index in range(8):
        service.record_chat_turn(
            tenant_id="smoke-owner",
            run_id=f"smoke-run-{index}",
            user_text=f"hello {index}",
            assistant_text="ok",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )
    journal_p95 = service.health().journal_append_p95_ms
    if journal_p95 is None or journal_p95 > SLO_CONTRACT.journal_append_p95_ms:
        raise SmokeError(f"Echo internal safety ledger journal append SLO 失败: p95={journal_p95}")


def check_echo(base: Path) -> None:
    env = _env(base)
    baseline = (
        Path(__file__).resolve().parents[1] / "docs" / "security" / "ECHO_BASELINE_65CC545.json"
    )
    if not baseline.is_file():
        raise SmokeError(f"Echo detached baseline evidence missing: {baseline}")
    _run([sys.executable, "scripts/echo_smoke.py"], env=env, timeout=120)
    _run(
        [
            sys.executable,
            "scripts/echo_architecture_benchmark.py",
            "--iterations",
            "50",
            "--warmup",
            "10",
            "--enforce-slo",
            "--baseline",
            str(baseline),
            "--output",
            str(base / "echo-slo-benchmark.json"),
        ],
        env=env,
        timeout=180,
    )


def check_work(base: Path) -> None:
    env = _env(base)
    _run(
        [
            sys.executable,
            "scripts/js_work_echo_smoke.py",
            "--turns",
            "3",
            "--state-dir",
            str(base / "home"),
        ],
        env=env,
        timeout=180,
    )


def check_stable_release_gate(root: Path) -> None:
    from js.echo.ledger.release_gates import verify_release_readiness

    readiness = verify_release_readiness(root)
    if readiness.stable_ready:
        return
    blockers = (*readiness.internal_blockers, *readiness.external_blockers)
    raise SmokeError("stable release blockers: " + ", ".join(blockers or ("stable_ready_false",)))


async def _run_async_check(name: str, func: Callable[[Path], Any], root: Path) -> None:
    base = root / name
    base.mkdir(parents=True, exist_ok=True)
    result = func(base)
    if asyncio.iscoroutine(result):
        await result


async def run_checks(selected: list[str], keep_temp: bool, *, stable: bool = False) -> int:
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
        "work": check_work,
        "echo": check_echo,
        "echo_ledger": check_echo_ledger,
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
                print(
                    "\n排查建议：先在本机运行同一条命令；如果失败，把上面的输出和临时测试目录里的日志发给开发者。"
                )
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

        if stable:
            print("\n[检查] stable-release-gate")
            try:
                check_stable_release_gate(Path.cwd())
            except SmokeError as exc:
                print("  [失败] stable-release-gate")
                print(str(exc))
                return 1
            else:
                print("  [OK] stable-release-gate")

        if keep_temp:
            print(f"\n临时目录保留: {root}")
        print("\n发布烟测通过。")
        from js.echo.ledger.release_gates import format_release_result_line

        print(format_release_result_line(gate="release_smoke", ok=True))
        return 0
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run JS Agent release smoke checks.")
    parser.add_argument("--all", action="store_true", help="Run all release smoke checks.")
    parser.add_argument(
        "--keep-temp", action="store_true", help="Keep temporary test files after failure."
    )
    parser.add_argument(
        "--stable",
        action="store_true",
        help="Also require external stable-release evidence, SBOM, and license scan.",
    )
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
    try:
        validate_release_source_integrity(REPO_ROOT)
    except ReleaseSourceIntegrityError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    selected = ["all"] if args.all else args.checks
    return asyncio.run(run_checks(selected, keep_temp=args.keep_temp, stable=args.stable))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Deterministic JS Agent Work smoke on the Echo runtime."""

from __future__ import annotations

import argparse
import asyncio
import shutil
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

from js.config import ModelConfig
from js.echo.turn_runtime import run_echo_turn
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter, RoutingDecision
from js_work.agent_factory import create_work_agent
from js_work.cli import WORK_CHANNEL, WORK_OWNER_KEY_HASH
from js_work.config import load_work_settings
from js_work.tools import WorkToolProfile


class WorkSmokeError(RuntimeError):
    """Human-readable Work smoke failure."""


class _Provider(ModelProvider):
    def __init__(self) -> None:
        self.calls: list[tuple[list[ChatMessage], list[dict[str, Any]] | None]] = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls.append((messages, tools))
        return ChatResponse(
            content="js work echo smoke ok",
            tool_calls=[],
            model="mock-work",
            usage={"prompt_tokens": 13, "completion_tokens": 5, "total_tokens": 18},
            finish_reason="stop",
        )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        async def _gen() -> AsyncIterator[str]:
            yield "js work echo smoke ok"

        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class _Router(ModelRouter):
    def __init__(self, provider: _Provider, *, permit_verifier: Any) -> None:
        model = ModelConfig(id="mock-work", name="Mock Work", provider="mock-work")
        self._provider = provider
        self._providers: dict[str, ModelProvider] = {"mock-work": provider}
        self._model_map: dict[str, tuple[str, ModelConfig]] = {
            "mock-work": ("mock-work", model),
            "mock-work/mock-work": ("mock-work", model),
        }
        self._permit_verifier = permit_verifier

    async def select_model(
        self,
        task_complexity: str = "medium",
        preferred: str | None = None,
    ) -> RoutingDecision:
        return RoutingDecision(
            provider=self._provider,
            model=preferred or "mock-work",
            provider_name="mock-work",
            reason="js-work-smoke",
        )

    def is_local_model(self, model: str | None) -> bool:
        return False

    async def health_check(self) -> dict[str, bool]:
        return {"mock-work": True}

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        before_model_call: Callable[..., Any] | None = None,
        after_model_call: Callable[..., Any] | None = None,
        permit_grant: Callable[..., Any] | None = None,
    ) -> ChatResponse:
        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError("Work smoke router requires model callbacks and permit grant")
        decision = await self.select_model(preferred=model)
        self._consume_model_permit(permit_grant, decision, messages, tools)
        context = await before_model_call(decision, messages, tools)
        response: ChatResponse | None = None
        error: BaseException | None = None
        try:
            response = await self._provider.chat(
                messages=messages,
                model=decision.model,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response
        except BaseException as exc:  # noqa: BLE001 - finalize exact failure
            error = exc
            response = None
            raise
        finally:
            await after_model_call(context, response, error)


async def _run_echo_turns(root: Path, turns: int) -> tuple[Path, int]:
    settings = load_work_settings(home=root)
    settings.max_turns = 3
    provider = _Provider()
    agent = create_work_agent(settings=settings, profile=WorkToolProfile.EXECUTE)
    agent.router = _Router(provider, permit_verifier=agent._model_permit_issuer)

    for index in range(turns):
        state = await run_echo_turn(
            agent,
            f"work smoke turn {index}",
            channel=WORK_CHANNEL,
            owner_key_hash=WORK_OWNER_KEY_HASH,
            session_id="js-work-echo-smoke",
            model="mock-work",
            attachments=[],
        )
        if state.status != "completed":
            raise WorkSmokeError(f"turn {index} did not complete: {state.status}")

    if len(provider.calls) != turns:
        raise WorkSmokeError(f"provider call count mismatch: {len(provider.calls)} != {turns}")

    health = agent.echo_safety_service.health(max_verify_age_seconds=0.0)
    if not health.ok:
        raise WorkSmokeError(f"Echo health is not ok: {health}")
    journal = Path(agent.echo_safety_service.journal_path_for(WORK_OWNER_KEY_HASH))
    if not journal.exists():
        raise WorkSmokeError(f"Work Echo journal was not created: {journal}")
    if ".js-work" not in str(journal):
        raise WorkSmokeError(f"Work Echo journal escaped Work home: {journal}")
    return journal, health.record_count


def _check_profile(
    root: Path,
    profile: WorkToolProfile,
    *,
    allow_host_code_tools: bool = False,
) -> set[str]:
    mode = "local" if allow_host_code_tools else "isolated"
    settings = load_work_settings(home=root / f"profile-{profile.value}-{mode}")
    agent = create_work_agent(
        settings=settings,
        profile=profile,
        allow_host_code_tools=allow_host_code_tools,
    )
    names = {tool.name for tool in agent.registry.list_tools()}
    if any(name.startswith("skill_") for name in names):
        raise WorkSmokeError(f"{profile.value} exposed skill tools: {sorted(names)}")
    if agent.skills is not None or agent.promotion_store is not None:
        raise WorkSmokeError(f"{profile.value} initialized skills or promotion store")
    if (settings.state_dir / "skills.db").exists():
        raise WorkSmokeError(f"{profile.value} created skills.db")
    if (settings.state_dir / "skill_promotions.db").exists():
        raise WorkSmokeError(f"{profile.value} created skill_promotions.db")
    return names


def _check_profiles(root: Path) -> None:
    execute = _check_profile(
        root,
        WorkToolProfile.EXECUTE,
        allow_host_code_tools=True,
    )
    isolated_execute = _check_profile(root, WorkToolProfile.EXECUTE)
    safe = _check_profile(root, WorkToolProfile.SAFE)
    office = _check_profile(root, WorkToolProfile.OFFICE)

    if not {"file_write", "shell", "python", "fleet_collaborate"} <= execute:
        raise WorkSmokeError(f"execute profile missing work tools: {sorted(execute)}")
    if {"shell", "python"} & isolated_execute:
        raise WorkSmokeError(
            "isolated execute profile exposed host code tools: "
            f"{sorted(isolated_execute)}"
        )
    if {"file_write", "file_edit", "shell", "python", "fleet_collaborate"} & safe:
        raise WorkSmokeError(f"safe profile exposed write/execute tools: {sorted(safe)}")
    if {"shell", "python", "fleet_collaborate"} & office:
        raise WorkSmokeError(f"office profile exposed execute tools: {sorted(office)}")
    required_office_tools = {
        "csv_read",
        "excel_read",
        "excel_precise_edit",
        "pdf_generate",
    }
    if not required_office_tools <= office:
        raise WorkSmokeError(f"office profile missing office tools: {sorted(office)}")


async def run_smoke(root: Path, turns: int) -> None:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    _check_profiles(root)
    journal, records = await _run_echo_turns(root, turns)
    print(f"js_work_echo_smoke ok turns={turns} records={records} journal={journal}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run JS Agent Work through Echo smoke checks.")
    parser.add_argument("--turns", type=int, default=5)
    parser.add_argument("--state-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.turns < 1:
        raise WorkSmokeError("--turns must be >= 1")
    asyncio.run(run_smoke(args.state_dir, args.turns))


if __name__ == "__main__":
    main()

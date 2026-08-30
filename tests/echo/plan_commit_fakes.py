"""Shared fakes for plan-commit / mid-turn loop tests."""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from js.compression.compressor import CompressionLevel, CompressionResult
from js.config import EchoPlanCommitConfig, GatewayConfig, JSSettings
from js.echo.effect_interpreter import ToolEffect
from js.echo.state import AgentState
from js.echo.turn_context import RuntimeContext
from js.echo.turn_loop import EchoTurnLoop
from js.models.providers import ChatMessage, ChatResponse
from js.tools.registry import ToolResult


class _EventStore:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


class _Audit:
    def log(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class RecordingRuntime:
    def __init__(self) -> None:
        self.executed: list[str] = []

    def derive_context(self, context: RuntimeContext, **_kwargs: Any) -> RuntimeContext:
        return context

    async def execute_tool_effect(
        self,
        effect: ToolEffect,
        *_args: Any,
        **_kwargs: Any,
    ) -> tuple[ChatMessage, ToolResult]:
        self.executed.append(effect.tool_name)
        return (
            ChatMessage(
                role="tool",
                content=f"ok:{effect.tool_name}",
                tool_call_id=effect.tool_call_id,
                name=effect.tool_name,
            ),
            ToolResult(success=True, output=f"ok:{effect.tool_name}"),
        )


class LoopAgent:
    def __init__(
        self,
        tmp_path: Path,
        *,
        plan_commit: EchoPlanCommitConfig | None = None,
        gateway: GatewayConfig | None = None,
        max_turns: int = 8,
        echo_exec_tools: bool = True,
    ) -> None:
        kwargs: dict[str, Any] = {
            "workspace": tmp_path / "workspace",
            "state_dir": tmp_path / "state",
            "echo_engine": "on",
            "max_turns": max_turns,
        }
        if plan_commit is not None:
            kwargs["echo_plan_commit"] = plan_commit
        if gateway is not None:
            kwargs["gateway"] = gateway
        self.settings = JSSettings(**kwargs)
        self.settings.security.echo_exec_tools = echo_exec_tools
        self.logger = logging.getLogger("tests.echo.plan_commit")
        self.echo_runtime = RecordingRuntime()
        self.registry = SimpleNamespace(
            get=lambda name: SimpleNamespace(read_only=name in {"file_read", "list_dir", "grep"})
        )
        self.event_store = _EventStore()
        self.audit = _Audit()
        self._quality_scorer = None
        self._cancel_tokens: dict[str, Any] = {}
        self._shutdown_requested = False
        self.router = SimpleNamespace(get_model_config=lambda _model: None)
        self.secrets = SimpleNamespace(detect_and_redact=lambda value, _source: value)
        self.compressor = SimpleNamespace(
            config=SimpleNamespace(max_tokens=100_000),
            compress=self._passthrough_compress,
        )

    async def _passthrough_compress(
        self,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        token_counter: Any = None,
    ) -> CompressionResult:
        unit = getattr(token_counter, "token_unit_id", "heuristic:v1")
        return CompressionResult(
            messages=list(messages),
            level=CompressionLevel.NONE,
            original_tokens=8,
            compressed_tokens=8,
            token_unit_id=unit,
            trigger_ratio=0.0,
        )

    def _get_tools_schema(self, _model: str | None) -> list[dict[str, Any]]:
        names = (
            "file_read",
            "file_write",
            "shell",
            "browser_fetch",
            "list_dir",
            "glob",
            "grep",
            "memory_search",
        )
        return [
            {"type": "function", "function": {"name": name, "description": name}} for name in names
        ]

    def _token_counter_for_model(self, _model: str | None) -> Any:
        class _Counter:
            token_unit_id = "heuristic:v1"

            def __call__(self, payload: bytes) -> int:
                return max(1, len(payload) // 8)

        return _Counter()

    async def save_checkpoint(self, _state: AgentState) -> None:
        return None

    def _build_untrusted_context(self, **_kwargs: Any) -> str:
        return ""


def runtime_context(
    tmp_path: Path, *, channel: str, session_id: str = "session-1"
) -> RuntimeContext:
    return RuntimeContext(
        product_id="js-agent",
        channel=channel,
        owner_key_hash="owner-a",
        session_id=session_id,
        run_id="run-1",
        role="owner",
        profile="default",
        capabilities=(),
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
    )


def new_loop(agent: LoopAgent, *, user_input: str = "hello") -> EchoTurnLoop:
    loop = EchoTurnLoop(agent, user_input, "session-1", None, None, None, None, None)
    loop.run_id = "run-1"
    loop.owner_key_hash = "owner-a"
    loop.state = AgentState(session_id="session-1", run_id="run-1")
    loop.state.messages = [
        ChatMessage(role="system", content="sys"),
        ChatMessage(role="user", content=user_input),
    ]
    return loop


def tool_response(name: str, *, call_id: str, arguments: str = "{}") -> ChatResponse:
    return ChatResponse(
        content="",
        tool_calls=[
            {
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": arguments},
            }
        ],
        model="test-model",
        usage={"prompt_tokens": 1, "completion_tokens": 1},
        finish_reason="tool_calls",
    )


def text_response(content: str) -> ChatResponse:
    return ChatResponse(
        content=content,
        tool_calls=[],
        model="test-model",
        usage={"prompt_tokens": 1, "completion_tokens": 1},
        finish_reason="stop",
    )

"""API facade: RunnerMixin delegates every turn to EchoRuntime."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import suppress
from typing import TYPE_CHECKING, Any

from js.agent.base import AgentBase
from js.echo.state import AgentState
from js.tools.registry import ToolResult

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class RunnerMixin(AgentBase):
    """Public agent run/stream API; every turn is owned by EchoRuntime."""

    async def run(
        self,
        user_input: str,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[str] | None = None,
        _resume_state: AgentState | None = None,
        stream_callback: Callable[[str], Awaitable[None]] | None = None,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
        event_callback: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        disable_tools: bool = False,
    ) -> AgentState:
        from js.echo.turn_runtime import EchoRuntime, authoritative_runtime

        runtime = authoritative_runtime(self)
        result = await EchoRuntime.run_agent_turn(
            runtime,
            user_input,
            channel="agent_api",
            session_id=session_id,
            model=model,
            attachments=attachments,
            _resume_state=_resume_state,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            event_callback=event_callback,
            disable_tools=disable_tools,
        )
        if not isinstance(result, AgentState):
            raise TypeError("Echo runtime returned an invalid agent state")
        return result

    async def _do_run(
        self,
        user_input: str,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[str] | None = None,
        _resume_state: AgentState | None = None,
        stream_callback: Callable[[str], Awaitable[None]] | None = None,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
        event_callback: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        disable_tools: bool = False,
    ) -> AgentState:
        return await self.run(
            user_input,
            session_id=session_id,
            model=model,
            attachments=attachments,
            _resume_state=_resume_state,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            event_callback=event_callback,
            disable_tools=disable_tools,
        )

    async def chat_stream(
        self,
        user_input: str,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[str] | None = None,
        *,
        enable_tools: bool = True,
    ) -> AsyncIterator[str]:
        queue: asyncio.Queue[str | BaseException | None] = asyncio.Queue()

        async def _emit(token: str) -> None:
            await queue.put(token)

        async def _run() -> None:
            try:
                state = await self.run(
                    user_input,
                    session_id=session_id,
                    model=model,
                    attachments=attachments or [],
                    stream_callback=_emit,
                    disable_tools=not enable_tools,
                )
                if state.status == "cancelled":
                    raise asyncio.CancelledError(state.error_message or "Echo turn cancelled")
                if state.status != "completed":
                    from js.echo.ledger.service import EchoUnavailableError

                    raise EchoUnavailableError(
                        state.error_message or f"Echo turn ended with status {state.status}"
                    )
            except BaseException as exc:  # noqa: BLE001
                await queue.put(exc)
            finally:
                await queue.put(None)

        task = asyncio.create_task(_run())
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                if isinstance(item, BaseException):
                    raise item
                yield item
        finally:
            if not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task


__all__ = ["RunnerMixin"]

"""AppShell Personal ↔ Work switch state machine (v1 thin slice)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class WorkspaceProduct(StrEnum):
    PERSONAL = "js-agent"
    WORK = "js-work"


class SwitchStep(StrEnum):
    CANCEL_STREAMS = "cancel_streams"
    INVALIDATE_LEASES = "invalidate_leases"
    CLEAR_UI_CACHE = "clear_ui_cache"
    REBIND_CONTEXT = "rebind_context"


SWITCH_ORDER: tuple[SwitchStep, ...] = (
    SwitchStep.CANCEL_STREAMS,
    SwitchStep.INVALIDATE_LEASES,
    SwitchStep.CLEAR_UI_CACHE,
    SwitchStep.REBIND_CONTEXT,
)

DEFAULT_UI_CACHE_KEYS: tuple[str, ...] = (
    "messages",
    "leases",
    "stream_buffers",
    "tab_transient",
    "sessionId",
    "ws",
    "fleetWS",
    "pendingAttachments",
)


CancelFn = Callable[[], Awaitable[None] | None]
InvalidateFn = Callable[[], Awaitable[Mapping[str, Any] | None] | Mapping[str, Any] | None]
RebindFn = Callable[[], Awaitable[Mapping[str, Any] | None] | Mapping[str, Any] | None]


@dataclass
class SwitchResult:
    ok: bool
    from_product: str
    to_product: str
    completed_steps: list[str] = field(default_factory=list)
    failed_step: str | None = None
    error: str | None = None
    clear_ui_cache_keys: tuple[str, ...] = ()
    target_capability_product: str | None = None
    revoked_lease_ids: tuple[str, ...] = ()
    rebind: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "from_product": self.from_product,
            "to_product": self.to_product,
            "completed_steps": list(self.completed_steps),
            "failed_step": self.failed_step,
            "error": self.error,
            "clear_ui_cache_keys": list(self.clear_ui_cache_keys),
            "target_capability_product": self.target_capability_product,
            "revoked_lease_ids": list(self.revoked_lease_ids),
            "rebind": dict(self.rebind),
        }


async def _maybe_await(result: Awaitable[Any] | Any) -> Any:
    if isinstance(result, Awaitable):
        return await result
    return result


async def run_workspace_switch(
    *,
    from_product: str,
    to_product: str,
    cancel_streams: CancelFn,
    invalidate_leases: InvalidateFn,
    rebind_context: RebindFn | None = None,
) -> SwitchResult:
    """Execute the fail-closed Personal/Work switch protocol."""
    if from_product == to_product:
        return SwitchResult(
            ok=False,
            from_product=from_product,
            to_product=to_product,
            error="from_product and to_product must differ",
            failed_step=SwitchStep.CANCEL_STREAMS,
        )
    if to_product not in {WorkspaceProduct.PERSONAL, WorkspaceProduct.WORK}:
        return SwitchResult(
            ok=False,
            from_product=from_product,
            to_product=to_product,
            error=f"unsupported target product: {to_product}",
            failed_step=SwitchStep.CANCEL_STREAMS,
        )

    completed: list[str] = []
    revoked: tuple[str, ...] = ()
    rebind: dict[str, Any] = {}
    try:
        await _maybe_await(cancel_streams())
        completed.append(SwitchStep.CANCEL_STREAMS)

        invalidate_result = await _maybe_await(invalidate_leases())
        if isinstance(invalidate_result, Mapping):
            raw_ids = invalidate_result.get("revoked_lease_ids", ())
            if isinstance(raw_ids, (list, tuple)):
                revoked = tuple(str(item) for item in raw_ids)
        completed.append(SwitchStep.INVALIDATE_LEASES)

        completed.append(SwitchStep.CLEAR_UI_CACHE)

        if rebind_context is not None:
            rebind_result = await _maybe_await(rebind_context())
            if isinstance(rebind_result, Mapping):
                rebind = dict(rebind_result)
        else:
            rebind = {"target_product": to_product}
        completed.append(SwitchStep.REBIND_CONTEXT)
    except Exception as exc:
        failed = SWITCH_ORDER[len(completed)] if len(completed) < len(SWITCH_ORDER) else None
        return SwitchResult(
            ok=False,
            from_product=from_product,
            to_product=to_product,
            completed_steps=completed,
            failed_step=str(failed) if failed else None,
            error=f"{type(exc).__name__}: {exc}",
            revoked_lease_ids=revoked,
            rebind=rebind,
        )

    return SwitchResult(
        ok=True,
        from_product=from_product,
        to_product=to_product,
        completed_steps=completed,
        clear_ui_cache_keys=DEFAULT_UI_CACHE_KEYS + (f"product:{from_product}",),
        target_capability_product=to_product,
        revoked_lease_ids=revoked,
        rebind=rebind,
    )

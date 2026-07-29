"""AppShell switch state machine tests."""

from __future__ import annotations

import pytest

from js.appshell.switch import SWITCH_ORDER, SwitchStep, run_workspace_switch


@pytest.mark.asyncio
async def test_switch_runs_ordered_steps_and_returns_cache_keys() -> None:
    calls: list[str] = []

    async def cancel() -> None:
        calls.append("cancel")

    async def invalidate() -> None:
        calls.append("invalidate")

    result = await run_workspace_switch(
        from_product="js-agent",
        to_product="js-work",
        cancel_streams=cancel,
        invalidate_leases=invalidate,
    )
    assert result.ok is True
    assert result.completed_steps == [step.value for step in SWITCH_ORDER]
    assert calls == ["cancel", "invalidate"]
    assert "product:js-agent" in result.clear_ui_cache_keys
    assert result.target_capability_product == "js-work"


@pytest.mark.asyncio
async def test_switch_fail_closed_on_cancel_error() -> None:
    async def cancel() -> None:
        raise RuntimeError("stream busy")

    async def invalidate() -> None:
        raise AssertionError("must not run")

    result = await run_workspace_switch(
        from_product="js-work",
        to_product="js-agent",
        cancel_streams=cancel,
        invalidate_leases=invalidate,
    )
    assert result.ok is False
    assert result.failed_step == SwitchStep.CANCEL_STREAMS
    assert result.completed_steps == []
    assert "stream busy" in (result.error or "")


@pytest.mark.asyncio
async def test_switch_rejects_same_product() -> None:
    result = await run_workspace_switch(
        from_product="js-agent",
        to_product="js-agent",
        cancel_streams=lambda: None,
        invalidate_leases=lambda: None,
    )
    assert result.ok is False

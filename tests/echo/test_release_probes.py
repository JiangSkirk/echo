from __future__ import annotations

import pytest

from js.echo.release_probes import run_echo_release_probes


@pytest.mark.asyncio
async def test_release_probes_are_safe_inside_an_active_event_loop() -> None:
    report = run_echo_release_probes()

    assert report.ok, report.failed
    assert "echo_local_sandbox_adapter" in report.passed

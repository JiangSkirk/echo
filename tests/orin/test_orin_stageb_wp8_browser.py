"""WP8 BrowserTool routing into the resident Network Cell."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from js.agent.tool_executor import ToolExecutorMixin


def _executor(
    *,
    enabled: bool,
    stage_b: bool,
    cell_net: bool,
    authority: object | None = None,
) -> ToolExecutorMixin:
    executor = object.__new__(ToolExecutorMixin)
    executor.settings = SimpleNamespace(  # type: ignore[attr-defined]
        orin=SimpleNamespace(enabled=enabled, stage_b=stage_b, cell_net=cell_net)
    )
    if authority is not None:
        executor._get_echo_tool_lease_authority = lambda: authority  # type: ignore[method-assign]
    return executor


class TestNetworkCellBackendConfig:
    @pytest.mark.parametrize(
        ("enabled", "stage_b", "cell_net"),
        (
            (False, True, True),
            (True, False, True),
            (True, True, False),
            (False, False, False),
        ),
    )
    def test_backend_absent_unless_all_three_switches_are_enabled(
        self, enabled: bool, stage_b: bool, cell_net: bool
    ) -> None:
        executor = _executor(enabled=enabled, stage_b=stage_b, cell_net=cell_net)
        assert executor._network_cell_backend() is None  # type: ignore[attr-defined]

    def test_enabled_backend_dispatches_only_to_network_cell(self) -> None:
        calls: list[tuple[str, dict[str, Any]]] = []

        class Authority:
            def run_in_cell(self, cap: str, payload: dict[str, Any]) -> dict[str, Any]:
                calls.append((cap, payload))
                return {"status": "COMMITTED", "output": "cell-output"}

        executor = _executor(
            enabled=True,
            stage_b=True,
            cell_net=True,
            authority=Authority(),
        )
        backend = executor._network_cell_backend()  # type: ignore[attr-defined]
        assert backend is not None
        payload = {
            "tool": "net.fetch",
            "url": "https://example.com/",
            "max_chars": 123,
        }
        assert backend(payload) == {"status": "COMMITTED", "output": "cell-output"}
        assert calls == [("cell.net", payload)]

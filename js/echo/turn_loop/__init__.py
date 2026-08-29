"""Echo-owned multi-turn reasoning loop.

The public ``JSAgent`` methods are compatibility facades.  This module owns the
actual turn state machine and never imports the legacy agent runner.
"""

from __future__ import annotations

from js.echo.model_budget import EchoBudgetExceededError
from js.echo.turn_loop.loop import EchoTurnLoop
from js.echo.turn_loop.model_gate import (
    _authorize_echo_model_call,
    _finish_echo_model_call,
    _model_terminal_status,
    _router_supports_model_gate_callbacks,
)
from js.echo.turn_loop.schema import _echo_tool_schema_subset
from js.echo.turn_loop.telemetry import _tool_quality_score, _tool_result_event

__all__ = [
    "EchoBudgetExceededError",
    "EchoTurnLoop",
    "_authorize_echo_model_call",
    "_echo_tool_schema_subset",
    "_finish_echo_model_call",
    "_model_terminal_status",
    "_router_supports_model_gate_callbacks",
    "_tool_quality_score",
    "_tool_result_event",
]

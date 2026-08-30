"""Echo ↔ AgentDojo adapter (P1-1).

Maps js-agent tools onto the AgentDojo pipeline. Evaluation stays
deterministic and offline unless a live runner is invoked with keys.
Held-out cases are never used to tune policy (R3).
"""

from __future__ import annotations

from js.echo.agentdojo.cases import (
    AdapterCase,
    CaseSplit,
    load_cases,
    parse_taint_names,
)
from js.echo.agentdojo.gate import (
    BASELINE_NAME,
    GateDecision,
    evaluate_gate,
    load_baseline,
)
from js.echo.agentdojo.mapping import (
    MappingError,
    map_agentdojo_tool,
    mapped_js_tools,
)

__all__ = [
    "BASELINE_NAME",
    "AdapterCase",
    "CaseSplit",
    "GateDecision",
    "MappingError",
    "evaluate_gate",
    "load_baseline",
    "load_cases",
    "map_agentdojo_tool",
    "mapped_js_tools",
    "parse_taint_names",
]

"""Plan-then-execute mode for untrusted Echo turns.

PLAN/BIND/EXECUTE lives inside ``EchoTurnLoop._run_loop``. It is not a
second runtime. Default off; gateway may opt the surface in.
"""

from __future__ import annotations

from js.echo.plan_commit.activation import (
    READONLY_GATEWAY_TOOLS,
    gateway_tool_allowlist,
    midturn_narrowing_active,
    plan_commit_explicitly_disabled,
    plan_commit_surface_enabled,
    plan_commit_turn_active,
    remaining_rebind_active,
)
from js.echo.plan_commit.assembler import (
    AssemblyError,
    apply_assembled_arguments,
    assemble_step,
    assembled_args_schema,
    plan_commit_argument_error,
)
from js.echo.plan_commit.labels import remaining_step_allowed
from js.echo.plan_commit.plan import (
    Plan,
    PlanError,
    PlanStep,
    SlotBinding,
    parse_plan,
)

__all__ = [
    "READONLY_GATEWAY_TOOLS",
    "AssemblyError",
    "Plan",
    "PlanError",
    "PlanStep",
    "SlotBinding",
    "apply_assembled_arguments",
    "assemble_step",
    "assembled_args_schema",
    "gateway_tool_allowlist",
    "midturn_narrowing_active",
    "parse_plan",
    "plan_commit_argument_error",
    "plan_commit_explicitly_disabled",
    "plan_commit_surface_enabled",
    "plan_commit_turn_active",
    "remaining_rebind_active",
    "remaining_step_allowed",
]

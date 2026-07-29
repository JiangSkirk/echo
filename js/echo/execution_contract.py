"""Echo unified execution bridge contract.

This module owns the join between Echo's turn boundary, the model/tool
executors, and the internal compatibility ledger. It deliberately avoids
importing Echo types so Echo remains the public architecture surface while
Echo can validate and persist this contract from its side.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from js.echo.primitives import ECHO_2_ARCHITECTURE, stable_payload_hash

ExecutorKind = Literal["model", "tool"]
ReplayClass = Literal["idempotent", "probe_required", "non_idempotent"]
SideEffectCommitment = Literal[
    "idempotent_retry",
    "probe_before_merge",
    "manual_confirmation_required",
]

_MODEL_EXECUTOR = "JSAgent.authorized_model_chat"
_TOOL_EXECUTOR = "ToolExecutor.execute_tool"
_LEDGER_OWNER = "EchoSafetyService"
_MEMORY_OWNER = "js.memory via Echo ContextVault"
_CONTRACT_VERSION = "echo-unified-turn-v1"


@dataclass(frozen=True)
class EchoExecutionContract:
    architecture: str = ECHO_2_ARCHITECTURE
    version: str = _CONTRACT_VERSION
    model_executor: str = _MODEL_EXECUTOR
    tool_executor: str = _TOOL_EXECUTOR
    ledger_owner: str = _LEDGER_OWNER
    memory_owner: str = _MEMORY_OWNER
    begin_records: tuple[str, ...] = (
        "intake",
        "decision",
        "policy_decision",
        "permit",
        "model_privacy_envelope",
        "outbox",
    )
    finish_records: tuple[str, ...] = ("receipt", "merge")


@dataclass(frozen=True)
class EffectBridge:
    architecture: str
    contract_version: str
    tenant_id: str
    session_id: str
    run_id: str
    channel: str
    executor_kind: ExecutorKind
    executor_route: str
    effect_id: str
    outbox_id: str
    action_kind: str
    resource: str
    scopes: tuple[str, ...]
    input_hash: str
    replay_class: ReplayClass
    side_effect_commitment: SideEffectCommitment
    state_refs: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "contract_version": self.contract_version,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "channel": self.channel,
            "executor_kind": self.executor_kind,
            "executor_route": self.executor_route,
            "effect": {
                "effect_id": self.effect_id,
                "action_kind": self.action_kind,
                "resource": self.resource,
                "scopes": list(self.scopes),
                "input_hash": self.input_hash,
                "replay_class": self.replay_class,
            },
            "outbox": {
                "outbox_id": self.outbox_id,
                "effect_id": self.effect_id,
                "bridge_hash": stable_payload_hash(self._hash_payload()),
            },
            "state_mapping": dict(self.state_refs),
            "side_effect": {
                "replay_class": self.replay_class,
                "commitment": self.side_effect_commitment,
            },
        }

    def _hash_payload(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "contract_version": self.contract_version,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "channel": self.channel,
            "executor_kind": self.executor_kind,
            "effect_id": self.effect_id,
            "outbox_id": self.outbox_id,
            "action_kind": self.action_kind,
            "resource": self.resource,
            "scopes": self.scopes,
            "input_hash": self.input_hash,
            "replay_class": self.replay_class,
            "side_effect_commitment": self.side_effect_commitment,
            "state_refs": self.state_refs,
        }


def current_execution_contract() -> EchoExecutionContract:
    return EchoExecutionContract()


def build_effect_bridge(
    *,
    tenant_id: str,
    session_id: str,
    run_id: str,
    channel: str,
    executor_kind: ExecutorKind,
    effect_id: str,
    outbox_id: str,
    action_kind: str,
    resource: str,
    scopes: tuple[str, ...],
    input_hash: str,
    replay_class: ReplayClass,
    state_refs: dict[str, Any] | None = None,
) -> EffectBridge:
    _validate_non_empty(
        tenant_id=tenant_id,
        run_id=run_id,
        effect_id=effect_id,
        outbox_id=outbox_id,
        action_kind=action_kind,
        input_hash=input_hash,
    )
    _validate_executor_scope(executor_kind, action_kind=action_kind, scopes=scopes)
    return EffectBridge(
        architecture=ECHO_2_ARCHITECTURE,
        contract_version=_CONTRACT_VERSION,
        tenant_id=tenant_id,
        session_id=session_id,
        run_id=run_id,
        channel=channel,
        executor_kind=executor_kind,
        executor_route=_executor_route(executor_kind),
        effect_id=effect_id,
        outbox_id=outbox_id,
        action_kind=action_kind,
        resource=resource,
        scopes=tuple(scopes),
        input_hash=input_hash,
        replay_class=replay_class,
        side_effect_commitment=_side_effect_commitment(replay_class),
        state_refs=dict(state_refs or {}),
    )


def _executor_route(executor_kind: ExecutorKind) -> str:
    if executor_kind == "model":
        return _MODEL_EXECUTOR
    if executor_kind == "tool":
        return _TOOL_EXECUTOR
    raise ValueError(f"unknown executor kind: {executor_kind}")


def _side_effect_commitment(replay_class: ReplayClass) -> SideEffectCommitment:
    if replay_class == "idempotent":
        return "idempotent_retry"
    if replay_class == "probe_required":
        return "probe_before_merge"
    if replay_class == "non_idempotent":
        return "manual_confirmation_required"
    raise ValueError(f"unknown replay class: {replay_class}")


def _validate_executor_scope(
    executor_kind: ExecutorKind,
    *,
    action_kind: str,
    scopes: tuple[str, ...],
) -> None:
    if executor_kind == "model":
        if not action_kind.startswith("model."):
            raise ValueError("model execution bridge requires model.* action_kind")
        if "model:invoke" not in scopes:
            raise ValueError("model execution bridge requires model:invoke scope")
        return
    if executor_kind == "tool":
        if not action_kind.startswith("tool."):
            raise ValueError("tool execution bridge requires tool.* action_kind")
        if not any(scope.startswith("tool:") for scope in scopes):
            raise ValueError("tool execution bridge requires tool:* scope")
        return
    raise ValueError(f"unknown executor kind: {executor_kind}")


def _validate_non_empty(**values: str) -> None:
    for name, value in values.items():
        if not value:
            raise ValueError(f"{name} must not be empty")


__all__ = [
    "EchoExecutionContract",
    "EffectBridge",
    "ExecutorKind",
    "ReplayClass",
    "SideEffectCommitment",
    "build_effect_bridge",
    "current_execution_contract",
]

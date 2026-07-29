from __future__ import annotations

import importlib.util
import inspect
import pathlib

from js.echo import FrameLedger, ScopeGate, primitives, stable_payload_hash
from js.echo.ledger.journal import FileEchoLedger

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_echo_public_entrypoint_describes_current_primary_architecture() -> None:
    init_text = (REPO_ROOT / "js" / "echo" / "__init__.py").read_text(encoding="utf-8")

    assert "T1A" not in init_text
    assert "minimal pass-through stubs" not in init_text
    assert "Echo 2.0" in init_text


def test_echo_source_no_longer_uses_obsolete_stage_labels() -> None:
    offenders: list[str] = []
    for py_file in sorted((REPO_ROOT / "js" / "echo").glob("*.py")):
        text = py_file.read_text(encoding="utf-8")
        for marker in ("T1A", "minimal pass-through"):
            if marker in text:
                offenders.append(f"{py_file}: {marker}")

    assert offenders == []


def test_no_stale_rivetline_gates_note_package_exists() -> None:
    gates_init = REPO_ROOT / "js" / "rivetline" / "gates" / "__init__.py"

    assert not gates_init.exists()


def test_daemon_has_no_executable_legacy_scheduled_task_runtime() -> None:
    from js.daemon import core

    assert not hasattr(core, "ScheduledTask")
    source = (REPO_ROOT / "js" / "daemon" / "core.py").read_text(encoding="utf-8")
    assert "self._tasks" not in source
    assert "def _tick(" not in source


def test_echo2_compatibility_shells_are_removed_and_primitives_are_in_package() -> None:
    assert not (REPO_ROOT / "js" / "echo2_primitives.py").exists()
    assert not (REPO_ROOT / "js" / "echo" / "echo2.py").exists()
    assert importlib.util.find_spec("js.echo2_primitives") is None
    assert importlib.util.find_spec("js.echo.echo2") is None

    assert (REPO_ROOT / "js" / "echo" / "primitives.py").is_file()
    assert ScopeGate is primitives.ScopeGate
    assert FrameLedger is FileEchoLedger
    assert stable_payload_hash is primitives.stable_payload_hash


def test_echo_ledger_hash_identity_uses_echo_canonical_primitive() -> None:
    hashing_file = REPO_ROOT / "js" / "echo" / "ledger" / "_hashing.py"
    source = hashing_file.read_text(encoding="utf-8")

    assert "from js.echo.primitives import stable_payload_hash" in source
    assert "hashlib.sha256" not in source


def test_file_echo_ledger_is_the_only_persistent_echo_ledger() -> None:
    from js.echo.runtime import EchoPulseRuntime

    assert FrameLedger is FileEchoLedger
    assert not hasattr(primitives, "FrameLedger")
    assert "ledger" not in inspect.signature(EchoPulseRuntime).parameters
    assert not (REPO_ROOT / "js" / "echo" / "pulse_ledger.py").exists()
    assert not (REPO_ROOT / "js" / "echo" / "recovery.py").exists()


def test_echo_ledger_adr_marks_ledger_as_only_persistent_safety_boundary() -> None:
    adr_text = (
        REPO_ROOT / "docs" / "adr" / "0001-echo-ledger-boundary.md"
    ).read_text(encoding="utf-8")

    assert "js/echo/ledger/" in adr_text
    assert "only persistent safety ledger" in adr_text
    assert "There is no alternate" in adr_text
    assert "runtime mode" in adr_text


def test_unified_execution_contract_document_exists() -> None:
    doc_text = (
        REPO_ROOT / "docs" / "echo" / "ECHO_UNIFIED_EXECUTION_CONTRACT.md"
    ).read_text(encoding="utf-8")

    assert "JSAgent.authorized_model_chat" in doc_text
    assert "ToolExecutor.execute_tool" in doc_text
    assert "EffectBridge" in doc_text
    assert "probe_before_merge" in doc_text
    assert "manual_confirmation_required" in doc_text


def test_unified_execution_contract_names_model_and_tool_executors() -> None:
    from js.echo.execution_contract import current_execution_contract

    contract = current_execution_contract()

    assert contract.architecture == "echo-2.0"
    assert contract.model_executor == "JSAgent.authorized_model_chat"
    assert contract.tool_executor == "ToolExecutor.execute_tool"
    assert contract.ledger_owner == "EchoSafetyService"
    assert contract.memory_owner == "js.memory via Echo ContextVault"


def test_effect_bridge_maps_model_effect_to_outbox_without_rollback_claim() -> None:
    from js.echo.execution_contract import build_effect_bridge

    bridge = build_effect_bridge(
        tenant_id="owner-a",
        session_id="session-a",
        run_id="run-a",
        channel="api_chat",
        executor_kind="model",
        effect_id="eff_123",
        outbox_id="out_123",
        action_kind="model.js_agent_chat",
        resource="model:mock",
        scopes=("model:invoke",),
        input_hash="sha256:input",
        replay_class="probe_required",
        state_refs={"amber_root_hash": "sha256:amber", "journal_seq": 4},
    )

    payload = bridge.to_payload()

    assert payload["executor_route"] == "JSAgent.authorized_model_chat"
    assert payload["state_mapping"]["amber_root_hash"] == "sha256:amber"
    assert payload["state_mapping"]["journal_seq"] == 4
    assert payload["outbox"]["outbox_id"] == "out_123"
    assert payload["outbox"]["effect_id"] == "eff_123"
    assert payload["side_effect"]["commitment"] == "probe_before_merge"
    assert "rollback" not in str(payload).lower()


def test_non_idempotent_bridge_requires_confirmation_not_rollback() -> None:
    from js.echo.execution_contract import build_effect_bridge

    bridge = build_effect_bridge(
        tenant_id="owner-a",
        session_id="session-a",
        run_id="run-a",
        channel="tool",
        executor_kind="tool",
        effect_id="eff_tool",
        outbox_id="out_tool",
        action_kind="tool.email_send",
        resource="tool:email_send",
        scopes=("tool:email_send",),
        input_hash="sha256:input",
        replay_class="non_idempotent",
        state_refs={},
    )

    payload = bridge.to_payload()

    assert payload["executor_route"] == "ToolExecutor.execute_tool"
    assert payload["side_effect"]["commitment"] == "manual_confirmation_required"
    assert "rollback" not in str(payload).lower()

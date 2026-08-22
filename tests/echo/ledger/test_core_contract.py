from __future__ import annotations

import ast
import inspect
import pathlib

import pytest

from js.echo.ledger.kernel import decide
from js.echo.ledger.types import EffectIntent, IntakeEvent, KernelSnapshot

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
LEDGER_DIR = REPO_ROOT / "js" / "echo" / "ledger"
MODE_CONTRACT_PATH = REPO_ROOT / "js" / "echo" / "mode_contract.py"


def test_decide_is_deterministic_and_does_not_sample_time() -> None:
    snapshot = KernelSnapshot(
        tenant_id="tenant-a",
        run_id="run-1",
        run_seq=7,
        facts=(("mode", "mock-chat"),),
    )
    events = (
        IntakeEvent(
            event_id="evt-1",
            tenant_id="tenant-a",
            run_id="run-1",
            payload_ref="blob:hello",
            trust_level="user",
            monotonic_ms=123,
            wall_time="2026-06-28T00:00:00Z",
        ),
    )

    assert decide(snapshot, events) == decide(snapshot, events)

    src = inspect.getsource(decide)
    forbidden_tokens = ("time.", "datetime.", "random", "uuid", "open(", "httpx", "requests")
    for token in forbidden_tokens:
        assert token not in src


def test_decide_rejects_cross_tenant_input_before_intent_creation() -> None:
    snapshot = KernelSnapshot(
        tenant_id="tenant-a",
        run_id="run-1",
        run_seq=1,
        facts=(),
    )
    events = (
        IntakeEvent(
            event_id="evt-cross",
            tenant_id="tenant-b",
            run_id="run-1",
            payload_ref="blob:bad",
            trust_level="user",
            monotonic_ms=10,
            wall_time="2026-06-28T00:00:00Z",
        ),
    )

    bundle = decide(snapshot, events)

    assert bundle.intents == ()
    assert bundle.denials == ("tenant_mismatch:evt-cross",)


def test_effect_id_is_stable_from_runtime_fields() -> None:
    intent_a = EffectIntent.build(
        tenant_id="tenant-a",
        run_id="run-1",
        task_path=("root", "tool"),
        action_kind="tool.echo",
        resource="tool:echo",
        scopes=("tool:echo",),
        input_hash="sha256:abc",
        replay_class="idempotent",
        risk="low",
    )
    intent_b = EffectIntent.build(
        tenant_id="tenant-a",
        run_id="run-1",
        task_path=("root", "tool"),
        action_kind="tool.echo",
        resource="tool:echo",
        scopes=("tool:echo",),
        input_hash="sha256:abc",
        replay_class="idempotent",
        risk="low",
    )

    assert intent_a.effect_id == intent_b.effect_id


def test_echo_ledger_package_avoids_legacy_runtime_imports_except_echo_primitives() -> None:
    assert LEDGER_DIR.is_dir(), f"Echo ledger package missing: {LEDGER_DIR}"
    forbidden_import_prefixes = (
        "js.agent",
        "js.web",
        "js.tools",
        "js.memory",
        "js.models",
    )
    allowed_echo_imports = {
        (LEDGER_DIR / "_hashing.py", "js.echo.primitives"),
        (LEDGER_DIR / "release_gates.py", "js.echo.release_probes"),
        (LEDGER_DIR / "sandbox_backend.py", "js.echo.os_sandbox"),
        (LEDGER_DIR / "service.py", "js.echo.execution_contract"),
        # Task 4 intentionally binds durable receipt replay to the frozen R1
        # projection DTO.  mode_contract is a pure leaf, not a legacy runtime.
        (LEDGER_DIR / "effects.py", "js.echo.mode_contract"),
        (LEDGER_DIR / "partition_retention.py", "js.echo.mode_contract"),
        (LEDGER_DIR / "service.py", "js.echo.mode_contract"),
        (LEDGER_DIR / "service.py", "js.echo.primitives"),
    }
    offenders: list[str] = []
    scanned = 0

    for py_file in sorted(LEDGER_DIR.rglob("*.py")):
        if "__pycache__" in py_file.parts:
            continue
        scanned += 1
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(
                        alias.name == prefix or alias.name.startswith(prefix + ".")
                        for prefix in forbidden_import_prefixes
                    ):
                        offenders.append(f"{py_file}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "js.echo.ledger" or module.startswith("js.echo.ledger."):
                    continue
                if (py_file, module) in allowed_echo_imports:
                    continue
                if module == "js.echo" or module.startswith("js.echo."):
                    offenders.append(f"{py_file}: from {module} import ...")
                    continue
                if any(
                    module == prefix or module.startswith(prefix + ".")
                    for prefix in forbidden_import_prefixes
                ):
                    offenders.append(f"{py_file}: from {module} import ...")

    assert scanned > 0, f"No Python files scanned under {LEDGER_DIR}"
    assert not offenders


def test_task4_projection_contract_edges_are_exact_and_leaf_remains_runtime_free() -> None:
    expected_edges = {
        (LEDGER_DIR / "effects.py", ("ArtifactRefV1",)),
        (
            LEDGER_DIR / "partition_retention.py",
            ("AppMode", "ArtifactRefV1"),
        ),
        (LEDGER_DIR / "service.py", ("AppMode", "ArtifactRefV1")),
    }
    actual_edges: set[tuple[pathlib.Path, tuple[str, ...]]] = set()
    for source_path in (
        LEDGER_DIR / "effects.py",
        LEDGER_DIR / "partition_retention.py",
        LEDGER_DIR / "service.py",
    ):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "js.echo.mode_contract":
                assert node.level == 0
                assert all(alias.asname is None and alias.name != "*" for alias in node.names)
                actual_edges.add((source_path, tuple(alias.name for alias in node.names)))
            assert not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "__import__"
            )
    assert actual_edges == expected_edges

    runtime_prefixes = (
        "js.agent",
        "js.appshell",
        "js.config",
        "js.echo.ledger",
        "js.echo.turn_context",
        "js.echo.turn_runtime",
        "js.memory",
        "js.models",
        "js.security",
        "js.tools",
        "js.web",
        "js_work",
    )
    tree = ast.parse(
        MODE_CONTRACT_PATH.read_text(encoding="utf-8"),
        filename=str(MODE_CONTRACT_PATH),
    )
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported_modules.append(node.module or "")
    assert not [
        module
        for module in imported_modules
        if any(
            module == prefix or module.startswith(prefix + ".")
            for prefix in runtime_prefixes
        )
    ]


def test_decide_requires_non_empty_input_for_user_request() -> None:
    snapshot = KernelSnapshot(
        tenant_id="tenant-a",
        run_id="run-1",
        run_seq=1,
        facts=(),
    )
    events = (
        IntakeEvent(
            event_id="evt-empty",
            tenant_id="tenant-a",
            run_id="run-1",
            payload_ref="",
            trust_level="user",
            monotonic_ms=10,
            wall_time="2026-06-28T00:00:00Z",
        ),
    )

    with pytest.raises(ValueError, match="payload_ref"):
        decide(snapshot, events)

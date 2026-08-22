"""R1-B: TaskRef integration into RuntimeContext/EchoRuntime."""
from __future__ import annotations

import importlib
import re
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.config import JSSettings
from js.echo.turn_runtime import EchoRuntime

ROOT = Path(__file__).resolve().parents[2]


def echo() -> Any:
    return importlib.import_module("js.echo.turn_runtime")


def context_mod() -> Any:
    return importlib.import_module("js.echo.turn_context")


def contract() -> Any:
    return importlib.import_module("js.echo.mode_contract")


class _AdmitPulse:
    def observe(self, **_kwargs: Any) -> Any:
        return SimpleNamespace(admitted=True)


def _make_personal_agent(tmp_path: Path) -> Any:
    agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        ),
        registry=SimpleNamespace(list_tools=lambda: []),
        _current_allowed_tools=set(),
    )
    object.__setattr__(agent.settings, "product_id", "js-agent")
    agent.settings.workspace.mkdir(parents=True, exist_ok=True)
    agent.echo_runtime = EchoRuntime(agent, pulse_runtime=_AdmitPulse())
    return agent


def _make_work_agent(tmp_path: Path) -> Any:
    agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "work_ws",
            state_dir=tmp_path / "state",
        ),
        registry=SimpleNamespace(list_tools=lambda: []),
        _current_allowed_tools=set(),
    )
    object.__setattr__(agent.settings, "product_id", "js-work")
    agent.settings.workspace.mkdir(parents=True, exist_ok=True)
    agent.echo_runtime = EchoRuntime(agent, pulse_runtime=_AdmitPulse())
    return agent


# ---- R1-F01 RED: real build_context tests ----

def test_personal_build_context_produces_non_null_task_ref(tmp_path: Path) -> None:
    """Personal build_context() must produce a non-null TaskRef with workspace=None."""
    agent = _make_personal_agent(tmp_path)
    runtime = agent.echo_runtime
    context = runtime.build_context(channel="test", owner_key_hash="owner-a")
    assert context.task_ref is not None, "Personal build_context() must produce a non-null TaskRef"


def test_work_build_context_produces_non_null_task_ref(tmp_path: Path) -> None:
    """Work build_context() must produce a non-null TaskRef with a valid workspace handle."""
    agent = _make_work_agent(tmp_path)
    runtime = agent.echo_runtime
    context = runtime.build_context(channel="test", owner_key_hash="owner-a")
    assert context.task_ref is not None, "Work build_context() must produce a non-null TaskRef"


def test_personal_task_ref_workspace_is_none(tmp_path: Path) -> None:
    agent = _make_personal_agent(tmp_path)
    context = agent.echo_runtime.build_context(channel="test", owner_key_hash="owner-a")
    assert context.task_ref is not None
    assert context.task_ref.workspace is None


def test_work_task_ref_workspace_is_opaque_handle(tmp_path: Path) -> None:
    """Work TaskRef.workspace must be ws-<64hex>, not an absolute path."""
    agent = _make_work_agent(tmp_path)
    context = agent.echo_runtime.build_context(channel="test", owner_key_hash="owner-a")
    assert context.task_ref is not None
    ws = context.task_ref.workspace
    assert ws is not None
    assert re.fullmatch(r"ws-[0-9a-f]{64}", ws), f"workspace must be ws-<64hex>, got {ws!r}"
    assert "/" not in ws, "workspace handle must not contain path separators"
    assert str(tmp_path) not in ws, "workspace handle must not contain the raw path"


def test_task_ref_mode_owner_session_run_consistency(tmp_path: Path) -> None:
    """TaskRef fields must be consistent with context."""
    agent = _make_work_agent(tmp_path)
    context = agent.echo_runtime.build_context(
        channel="test",
        owner_key_hash="owner-x",
        session_id="session-y",
        run_id="run-z",
    )
    tr = context.task_ref
    assert tr is not None
    assert tr.mode is contract().AppMode.WORK
    assert tr.owner == "owner-x"
    assert tr.session == "session-y"
    assert tr.run == "run-z"
    assert tr.legacy_product_id == context.product_id


def test_task_ref_hash_enters_context_fingerprint(tmp_path: Path) -> None:
    """Changing task_ref must change the fingerprint."""
    agent = _make_personal_agent(tmp_path)
    runtime = agent.echo_runtime
    context = runtime.build_context(channel="test", owner_key_hash="owner-a")
    fp1 = runtime._context_fingerprint(context)
    c = contract()
    different_ref = c.TaskRef(
        mode=c.AppMode.PERSONAL,
        owner="owner-a",
        session=context.session_id,
        run="different-run",
    )
    context2 = replace(context, task_ref=different_ref)
    fp2 = runtime._context_fingerprint(context2)
    assert fp1 != fp2, "Changing task_ref must change the fingerprint"


def test_sign_context_rejects_mismatched_task_ref_product(tmp_path: Path) -> None:
    """_sign_context must reject a TaskRef whose legacy_product_id doesn't match context.product_id."""
    agent = _make_personal_agent(tmp_path)
    runtime = agent.echo_runtime
    context = runtime.build_context(channel="test", owner_key_hash="owner-a")
    c = contract()
    work_ref = c.TaskRef(
        mode=c.AppMode.WORK,
        owner="owner-a",
        session=context.session_id,
        run=context.run_id,
        workspace="ws-test",
    )
    mismatched = replace(context, task_ref=work_ref, authority_mac="")
    with pytest.raises(PermissionError):
        runtime._sign_context(mismatched)


def test_sign_context_rejects_mismatched_task_ref_owner(tmp_path: Path) -> None:
    agent = _make_personal_agent(tmp_path)
    runtime = agent.echo_runtime
    context = runtime.build_context(channel="test", owner_key_hash="owner-a")
    c = contract()
    wrong_owner_ref = c.TaskRef(
        mode=c.AppMode.PERSONAL,
        owner="wrong-owner",
        session=context.session_id,
        run=context.run_id,
    )
    mismatched = replace(context, task_ref=wrong_owner_ref, authority_mac="")
    with pytest.raises(PermissionError):
        runtime._sign_context(mismatched)


def test_sign_context_rejects_personal_task_ref_with_workspace(tmp_path: Path) -> None:
    agent = _make_personal_agent(tmp_path)
    runtime = agent.echo_runtime
    context = runtime.build_context(channel="test", owner_key_hash="owner-a")
    c = contract()
    # Bypass __init__ validation to simulate a tampered TaskRef
    bad_ref = object.__new__(c.TaskRef)
    object.__setattr__(bad_ref, "mode", c.AppMode.PERSONAL)
    object.__setattr__(bad_ref, "owner", "owner-a")
    object.__setattr__(bad_ref, "session", context.session_id)
    object.__setattr__(bad_ref, "run", context.run_id)
    object.__setattr__(bad_ref, "workspace", "ws-leaked")
    mismatched = replace(context, task_ref=bad_ref, authority_mac="")
    with pytest.raises(PermissionError):
        runtime._sign_context(mismatched)


def test_sign_context_rejects_work_task_ref_without_workspace(tmp_path: Path) -> None:
    agent = _make_work_agent(tmp_path)
    runtime = agent.echo_runtime
    context = runtime.build_context(channel="test", owner_key_hash="owner-a")
    c = contract()
    # Bypass __init__ validation to simulate a tampered TaskRef
    bad_ref = object.__new__(c.TaskRef)
    object.__setattr__(bad_ref, "mode", c.AppMode.WORK)
    object.__setattr__(bad_ref, "owner", "owner-a")
    object.__setattr__(bad_ref, "session", context.session_id)
    object.__setattr__(bad_ref, "run", context.run_id)
    object.__setattr__(bad_ref, "workspace", None)
    mismatched = replace(context, task_ref=bad_ref, authority_mac="")
    with pytest.raises(PermissionError):
        runtime._sign_context(mismatched)


def test_work_workspace_handle_is_stable_and_deterministic(tmp_path: Path) -> None:
    """Same workspace path must produce the same handle."""
    agent1 = _make_work_agent(tmp_path)
    agent2 = _make_work_agent(tmp_path)
    ctx1 = agent1.echo_runtime.build_context(channel="test", owner_key_hash="owner-a")
    ctx2 = agent2.echo_runtime.build_context(channel="test", owner_key_hash="owner-a")
    assert ctx1.task_ref is not None
    assert ctx2.task_ref is not None
    assert ctx1.task_ref.workspace == ctx2.task_ref.workspace


def test_different_workspaces_produce_different_handles(tmp_path: Path) -> None:
    """Different workspace paths must produce different handles."""
    agent1 = _make_work_agent(tmp_path)
    agent2 = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "different_ws",
            state_dir=tmp_path / "state2",
        ),
        registry=SimpleNamespace(list_tools=lambda: []),
        _current_allowed_tools=set(),
    )
    object.__setattr__(agent2.settings, "product_id", "js-work")
    agent2.settings.workspace.mkdir(parents=True, exist_ok=True)
    agent2.echo_runtime = EchoRuntime(agent2, pulse_runtime=_AdmitPulse())
    ctx1 = agent1.echo_runtime.build_context(channel="test", owner_key_hash="owner-a")
    ctx2 = agent2.echo_runtime.build_context(channel="test", owner_key_hash="owner-a")
    assert ctx1.task_ref is not None
    assert ctx2.task_ref is not None
    assert ctx1.task_ref.workspace != ctx2.task_ref.workspace

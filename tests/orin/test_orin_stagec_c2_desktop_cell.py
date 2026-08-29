"""WP-C2 Desktop Cell target, state, and observe-act-observe contracts.

The scripted backend is deterministic protocol evidence.  It does not stand
in for a native-pixel or real-model desktop end-to-end run.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from js.orin.desktop import (
    DesktopTargetBindingV1,
    derive_desktop_target_handle_id,
    desktop_target_binding_from_dict,
    normalize_desktop_action,
    normalize_desktop_observe_arguments,
    normalize_desktop_target,
)
from js.orin.draft import CellPackage, CommitPermit, EffectDraft, StateWitness
from js.orin.handles import OriginHandle
from js.orin.protocol import ProtocolError
from js.orind.broker import HandleBroker
from js.orind.cells.desktop import MacOSDesktopBackend
from js.orind.kernel import canonical_effect_hash_of
from js.orind.store import OrinStore


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _script(path: Path, *, revision: int = 1) -> dict[str, Any]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data: dict[str, Any] = {
        "schema": "DesktopScriptV1",
        "revision": revision,
        "target": {
            "kind": "screen",
            "display_id": 1,
            "window_id": 0,
            "owner_pid": 0,
            "control_id": "screen",
            "bounds": [0, 0, 80, 60],
        },
        "pixel_hash": "sha256:" + "a" * 64,
        "width": 80,
        "height": 60,
        "actions": [],
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)
    return data


def _draft(
    task_id: str,
    effect_type: str,
    arguments: dict[str, Any],
) -> EffectDraft:
    return EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=task_id,
        effect_type=effect_type,
        arguments=arguments,
        declared_expectation={
            "external_visibility": "private",
            "reversibility": "reversible_until_stage",
        },
    )


def _package(
    draft: EffectDraft,
    *,
    handles: tuple[OriginHandle, ...] = (),
) -> CellPackage:
    return CellPackage(
        draft=draft,
        executor_id="cell.desktop",
        canonical_effect_hash=canonical_effect_hash_of(draft),
        resolved_handles=handles,
        clearance=1,
    )


def _observe_arguments() -> dict[str, Any]:
    return {
        "target": {"kind": "screen"},
        "request": {
            "tool": "desktop_screenshot",
            "arguments": {
                "x": 0,
                "y": 0,
                "width": 80,
                "height": 60,
                "show_cursor": False,
            },
        },
    }


def _permit(package: CellPackage, witness: StateWitness) -> CommitPermit:
    now = _now_ms()
    return CommitPermit(
        permit_id=f"permit:{uuid4().hex}",
        intent_id=f"intent:{uuid4().hex}",
        draft_id=package.draft.draft_id,
        state_witness_id=witness.witness_id,
        executor_id="cell.desktop",
        canonical_effect_hash=package.canonical_effect_hash,
        idempotency_key=f"idem:{uuid4().hex}",
        sequence=1,
        not_before_ms=now - 100,
        expires_at_ms=now + 60_000,
    )


def _broker_handle(cell_handle: OriginHandle, mac_key: bytes) -> OriginHandle:
    base = replace(cell_handle, issuer="cell:desktop", signature="")
    return base.sealed_by(mac_key, "cell:desktop", cell_handle.created_at_ms)


def _desktop_cell(
    tmp_path: Path,
    mac_key: bytes,
    script_path: Path,
    *,
    backend: Any | None = None,
) -> Any:
    from js.orind.cells.desktop import DesktopCell, ScriptedDesktopBackend

    cell = DesktopCell(
        socket_path=tmp_path / "unused.sock",
        state_dir=tmp_path / "state",
        mac_key=mac_key,
        backend=backend or ScriptedDesktopBackend(script_path),
    )
    cell._session_key = b"s" * 32  # noqa: SLF001 - direct Cell seal contract
    return cell


def _preflighted_action(
    tmp_path: Path,
    *,
    backend: Any | None = None,
    action: dict[str, Any] | None = None,
) -> tuple[Any, CellPackage, StateWitness, CommitPermit, CellPackage]:
    script_path = tmp_path / "desktop-script.json"
    if not script_path.exists():
        _script(script_path)
    mac_key = b"b" * 32
    cell = _desktop_cell(
        tmp_path,
        mac_key,
        script_path,
        backend=backend,
    )
    task_id = f"task:{uuid4().hex}"
    observed = cell._preflight_package(  # noqa: SLF001 - direct Cell seam
        _package(_draft(task_id, "desktop.observe", _observe_arguments()))
    )
    binding = {
        "schema": "DesktopTargetBindingV1",
        "task_id": task_id,
        "draft_id": observed.witness.draft_id,
        "witness_id": observed.witness.witness_id,
        "canonical_effect_hash": observed.witness.canonical_effect_hash,
        "owner_key_hash": "sha256:" + "1" * 64,
        "tenant": "work",
        "expires_at_ms": min(observed.witness.expires_at_ms, _now_ms() + 30_000),
    }
    handle = _broker_handle(
        cell._resolve_handle(observed.witness.target_version, binding),  # noqa: SLF001
        mac_key,
    )
    exact_action = action or {
        "kind": "click",
        "x": 10,
        "y": 12,
        "button": "left",
        "clicks": 1,
    }
    package = _package(
        _draft(
            task_id,
            "desktop.action",
            {
                "desktop_target_handle": handle.handle_id,
                "action": exact_action,
            },
        ),
        handles=(handle,),
    )
    preflight = cell._preflight_package(package)  # noqa: SLF001
    witness = preflight.witness
    permit = _permit(package, witness)
    committed = replace(package, state_witness=witness)
    return cell, package, witness, permit, committed


def test_desktop_nested_schemas_are_closed_world_and_reject_fake_integers() -> None:
    assert normalize_desktop_target({"kind": "screen"}) == {"kind": "screen"}
    assert normalize_desktop_observe_arguments(_observe_arguments()) == _observe_arguments()
    assert normalize_desktop_action(
        {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1}
    ) == {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1}

    for invalid_target in (
        {"kind": []},
        {"kind": "screen", "display_id": True},
        {"kind": "screen", "window_id": 1},
        {"kind": "window", "window_id": 0},
        {"kind": "control", "window_id": 1, "control_id": "x", "root": "/"},
    ):
        with pytest.raises(ProtocolError):
            normalize_desktop_target(invalid_target)
    for invalid_observe in (
        {
            "target": {"kind": "screen"},
            "request": {"tool": [], "arguments": {}},
        },
        {
            "target": {"kind": "screen"},
            "request": {"tool": "desktop_screenshot", "arguments": {}},
        },
        {
            "target": {"kind": "screen"},
            "request": {
                "tool": "desktop_screenshot",
                "arguments": {
                    "x": 0,
                    "y": 0,
                    "width": 80,
                    "height": 60,
                    "show_cursor": 1,
                },
            },
        },
        {
            "target": {"kind": "screen"},
            "request": {"tool": "desktop_get_state", "arguments": {"root": "/"}},
        },
    ):
        with pytest.raises(ProtocolError):
            normalize_desktop_observe_arguments(invalid_observe)
    for invalid_action in (
        {"kind": "click", "x": 10, "y": 12, "button": [], "clicks": 1},
        {"kind": "key", "key": "a", "modifiers": [[]]},
        {"kind": "click", "x": True, "y": 12, "button": "left", "clicks": 1},
        {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 3},
        {
            "kind": "click",
            "x": 10,
            "y": 12,
            "button": "left",
            "clicks": 1,
            "window_id": 7,
        },
    ):
        with pytest.raises(ProtocolError):
            normalize_desktop_action(invalid_action)


def test_desktop_target_binding_and_handle_id_are_exact() -> None:
    binding = DesktopTargetBindingV1(
        task_id="task:exact",
        draft_id="draft:exact",
        witness_id="state:exact",
        canonical_effect_hash="sha256:" + "1" * 64,
        owner_key_hash="sha256:" + "2" * 64,
        tenant="work",
        expires_at_ms=4_000_000_000_000,
    )
    assert desktop_target_binding_from_dict(binding.to_dict()) == binding
    with pytest.raises(ProtocolError):
        desktop_target_binding_from_dict({**binding.to_dict(), "handle": "desktop:fake"})
    with pytest.raises(ProtocolError):
        desktop_target_binding_from_dict({**binding.to_dict(), "expires_at_ms": True})

    exact = derive_desktop_target_handle_id(
        task_id=binding.task_id,
        draft_id=binding.draft_id,
        canonical_effect_hash=binding.canonical_effect_hash,
        target_digest="sha256:" + "3" * 64,
    )
    changed = derive_desktop_target_handle_id(
        task_id="task:changed",
        draft_id=binding.draft_id,
        canonical_effect_hash=binding.canonical_effect_hash,
        target_digest="sha256:" + "3" * 64,
    )
    assert exact.startswith("desktop:")
    assert exact != changed


def test_only_authenticated_desktop_cell_seals_can_enter_broker(
    tmp_path: Path,
) -> None:
    store = OrinStore(tmp_path / "orin.db")
    broker_key = b"b" * 32
    cell_key = b"c" * 32
    broker = HandleBroker(store=store, mac_key=broker_key)
    now = _now_ms()
    handle_id = "desktop:cell-observed-target"
    raw = OriginHandle(
        handle_id=handle_id,
        kind="DesktopTargetHandle",
        owner_key_hash="sha256:" + "1" * 64,
        tenant="work",
        source_class="TRUSTED_LOCAL",
        integrity="trusted_local_object",
        confidentiality="CONFIDENTIAL",
        object_digest="sha256:" + "2" * 64,
        capabilities=("read", "use"),
        issuer="cell:desktop",
        created_at_ms=now,
        expires_at_ms=now + 60_000,
    ).sealed_by(cell_key, "cell:desktop", now)
    try:
        accepted = broker.register_desktop_cell_handle(
            raw.to_dict(),
            cell_session_key=cell_key,
            expected_handle_id=handle_id,
            owner_key_hash=raw.owner_key_hash,
            tenant="work",
            expires_at_ms=raw.expires_at_ms,
            now_ms=now,
        )
        assert accepted["ok"] is True
        assert accepted["status"] == "stored"
        resolved = broker.resolve(handle_id, now_ms=now)
        assert resolved["ok"] is True
        assert resolved["handle"]["kind"] == "DesktopTargetHandle"
        assert resolved["handle"]["signature"] != raw.signature

        replay = broker.register_desktop_cell_handle(
            raw.to_dict(),
            cell_session_key=cell_key,
            expected_handle_id=handle_id,
            owner_key_hash=raw.owner_key_hash,
            tenant="work",
            expires_at_ms=raw.expires_at_ms,
            now_ms=now,
        )
        assert replay == {**accepted, "status": "idempotent"}

        conflicting = replace(
            raw,
            object_digest="sha256:" + "4" * 64,
            signature="",
        ).sealed_by(cell_key, "cell:desktop", now)
        conflict = broker.register_desktop_cell_handle(
            conflicting.to_dict(),
            cell_session_key=cell_key,
            expected_handle_id=handle_id,
            owner_key_hash=raw.owner_key_hash,
            tenant="work",
            expires_at_ms=raw.expires_at_ms,
            now_ms=now,
        )
        assert conflict["ok"] is False

        for mutation in (
            {"cell_session_key": b"x" * 32},
            {"expected_handle_id": "desktop:wrong"},
            {"owner_key_hash": "sha256:" + "9" * 64},
            {"tenant": "personal"},
        ):
            fields: dict[str, Any] = {
                "cell_session_key": cell_key,
                "expected_handle_id": handle_id,
                "owner_key_hash": raw.owner_key_hash,
                "tenant": "work",
                "expires_at_ms": raw.expires_at_ms,
                "now_ms": now,
            }
            fields.update(mutation)
            denied = broker.register_desktop_cell_handle(raw.to_dict(), **fields)
            assert denied["ok"] is False

        ordinary_issue = broker.issue(
            kind="DesktopTargetHandle",
            token="echo-forged",
            owner_key_hash=raw.owner_key_hash,
            tenant="work",
            approved=True,
        )
        assert ordinary_issue["ok"] is False
    finally:
        store.close()


def test_observe_preflight_is_zero_action_and_binds_target_handle(
    tmp_path: Path,
) -> None:
    script_path = tmp_path / "desktop-script.json"
    before = _script(script_path)
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)
    draft = _draft(f"task:{uuid4().hex}", "desktop.observe", _observe_arguments())
    package = _package(draft)

    result = cell._preflight_package(package)  # noqa: SLF001 - Cell contract probe

    assert result.witness.draft_id == draft.draft_id
    assert result.witness.executor_id == "cell.desktop"
    assert result.witness.canonical_effect_hash == package.canonical_effect_hash
    assert result.witness.target_version.startswith("desktop:")
    assert result.projection == {
        "desktop_target_handle_id": result.witness.target_version,
        "target_kind": "screen",
        "display_id": 1,
        "window_number": 0,
        "owner_pid": 0,
        "scale": 1.0,
        "pixel_hash": before["pixel_hash"],
        "width": 80,
        "height": 60,
    }
    after = json.loads(script_path.read_text(encoding="utf-8"))
    assert after["actions"] == []
    assert after["revision"] == before["revision"]

    binding = {
        "schema": "DesktopTargetBindingV1",
        "task_id": draft.task_id,
        "draft_id": draft.draft_id,
        "witness_id": result.witness.witness_id,
        "canonical_effect_hash": package.canonical_effect_hash,
        "owner_key_hash": "sha256:" + "1" * 64,
        "tenant": "work",
        "expires_at_ms": _now_ms() + 60_000,
    }
    handle = cell._resolve_handle(  # noqa: SLF001 - existing handle/ack path
        result.witness.target_version,
        binding,
    )
    assert handle.handle_id == result.witness.target_version
    assert handle.kind == "DesktopTargetHandle"
    assert handle.issuer == "cell:desktop"
    assert handle.capabilities == ("read", "use")
    assert handle.verify_seal(b"s" * 32)

    for field, wrong in (
        ("task_id", f"task:{uuid4().hex}"),
        ("draft_id", f"draft:{uuid4().hex}"),
        ("witness_id", "state:wrong"),
        ("canonical_effect_hash", "sha256:" + "9" * 64),
        ("tenant", "personal"),
    ):
        with pytest.raises(ProtocolError):
            cell._resolve_handle(  # noqa: SLF001
                result.witness.target_version,
                {**binding, field: wrong},
            )


@pytest.mark.parametrize(
    "action",
    [
        {
            "kind": "window",
            "action": "activate",
            "app_name": "TextEdit",
            "window_title": "C2",
        },
        {
            "kind": "window",
            "action": "move",
            "app_name": "TextEdit",
            "window_title": "C2",
            "x": 10,
            "y": 20,
        },
        {
            "kind": "window",
            "action": "resize",
            "app_name": "TextEdit",
            "window_title": "C2",
            "width": 640,
            "height": 480,
        },
    ],
)
def test_native_window_actions_fail_closed_without_exact_ax_identity(
    action: dict[str, Any],
) -> None:
    from js.orind.cells.desktop import MacOSDesktopBackend

    class FakeController:
        def window_action(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("legacy first-window authority must not run")

    backend = MacOSDesktopBackend.__new__(MacOSDesktopBackend)
    backend._action_sink = None  # noqa: SLF001 - missing sink must fail closed
    backend._lock = threading.RLock()  # noqa: SLF001 - isolated action seam
    backend._revision = 0  # noqa: SLF001
    backend._operation_count = 0  # noqa: SLF001
    backend._emergency_stop = False  # noqa: SLF001

    target = {
        "kind": "window",
        "display_id": 1,
        "window_id": 7,
        "owner_pid": 99,
        "control_id": "window",
        "bounds": [0, 0, 800, 600],
        "app_name": "TextEdit",
        "window_title": "C2",
    }
    pixel_hash = "sha256:" + "a" * 64
    backend._capture = lambda _selector, _request: (  # type: ignore[method-assign]  # noqa: SLF001,E501
        target,
        pixel_hash,
        800,
        600,
        {},
    )
    observation = {
        "schema": "DesktopObservationV1",
        "revision": 0,
        "target": target,
        "pixel_hash": pixel_hash,
        "width": 800,
        "height": 600,
        "projection": {},
    }
    with pytest.raises(ProtocolError, match="exact native desktop action"):
        backend.act(
            action,
            expected_observation=observation,
            selector={"kind": "window", "window_id": 7},
            request={
                "tool": "desktop_screenshot",
                "arguments": {
                    "x": 0,
                    "y": 0,
                    "width": 0,
                    "height": 0,
                    "show_cursor": False,
                },
            },
        )
    assert backend._revision == 0  # noqa: SLF001
    assert backend._operation_count == 0  # noqa: SLF001


@pytest.mark.parametrize(
    ("action", "target_kind"),
    [
        (
            {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1},
            "screen",
        ),
        ({"kind": "type", "text": "must-not-type"}, "screen"),
        ({"kind": "scroll", "direction": "down", "amount": 3}, "screen"),
        (
            {
                "kind": "window",
                "action": "activate",
                "app_name": "TextEdit",
                "window_title": "C2",
            },
            "window",
        ),
        ({"kind": "clear_stop"}, "screen"),
    ],
)
def test_native_backend_hard_rejects_every_os_mutation_without_controller_calls(
    action: dict[str, Any],
    target_kind: str,
) -> None:
    from js.orind.cells.desktop import MacOSDesktopBackend

    controller_calls: list[str] = []

    class FakeController:
        def __getattr__(self, name: str) -> Any:
            def called(*_args: object, **_kwargs: object) -> dict[str, str]:
                controller_calls.append(name)
                return {"status": "success"}

            return called

    focus = {
        "focused_owner_pid": 99,
        "focused_window_id": 7,
        "focused_app_name": "TextEdit",
        "focused_control_id": "control",
        "focused_window_title": "C2",
    }
    if target_kind == "window":
        target = {
            "kind": "window",
            "display_id": 1,
            "window_id": 7,
            "owner_pid": 99,
            "control_id": "window",
            "bounds": [0, 0, 80, 60],
            "app_name": "TextEdit",
            "window_title": "C2",
            **focus,
        }
        selector = {"kind": "window", "window_id": 7}
    else:
        target = {
            "kind": "screen",
            "display_id": 1,
            "window_id": 0,
            "owner_pid": 0,
            "control_id": "screen",
            "bounds": [0, 0, 80, 60],
            **focus,
        }
        selector = {"kind": "screen"}
    pixel_hash = "sha256:" + "a" * 64
    observation = {
        "schema": "DesktopObservationV1",
        "revision": 0,
        "target": target,
        "pixel_hash": pixel_hash,
        "width": 80,
        "height": 60,
        "projection": {},
    }
    backend = MacOSDesktopBackend.__new__(MacOSDesktopBackend)
    backend._action_sink = None  # noqa: SLF001 - missing sink must fail closed
    backend._lock = threading.RLock()  # noqa: SLF001
    backend._revision = 0  # noqa: SLF001
    backend._operation_count = 0  # noqa: SLF001
    backend._emergency_stop = False  # noqa: SLF001
    backend._capture = lambda _selector, _request: (  # type: ignore[method-assign]  # noqa: SLF001,E501
        target,
        pixel_hash,
        80,
        60,
        {},
    )
    backend._frontmost_focus = lambda: dict(focus)  # type: ignore[method-assign]  # noqa: SLF001,E501

    with pytest.raises(ProtocolError):
        backend.act(
            action,
            expected_observation=observation,
            selector=selector,
            request={
                "tool": "desktop_screenshot",
                "arguments": {
                    "x": 0,
                    "y": 0,
                    "width": 0,
                    "height": 0,
                    "show_cursor": False,
                },
            },
        )

    assert controller_calls == []
    assert backend._revision == 0  # noqa: SLF001
    assert backend._operation_count == 0  # noqa: SLF001


def test_action_preflight_has_no_side_effect_and_state_drift_rejects_commit(
    tmp_path: Path,
) -> None:
    script_path = tmp_path / "desktop-script.json"
    _script(script_path)
    mac_key = b"b" * 32
    cell = _desktop_cell(tmp_path, mac_key, script_path)
    task_id = f"task:{uuid4().hex}"
    observed = cell._preflight_package(  # noqa: SLF001
        _package(_draft(task_id, "desktop.observe", _observe_arguments()))
    )
    binding = {
        "schema": "DesktopTargetBindingV1",
        "task_id": task_id,
        "draft_id": observed.witness.draft_id,
        "witness_id": observed.witness.witness_id,
        "canonical_effect_hash": observed.witness.canonical_effect_hash,
        "owner_key_hash": "sha256:" + "1" * 64,
        "tenant": "work",
        "expires_at_ms": _now_ms() + 60_000,
    }
    cell_handle = cell._resolve_handle(  # noqa: SLF001 - existing handle/ack payload
        observed.witness.target_version,
        binding,
    )
    handle = _broker_handle(cell_handle, mac_key)
    forged = replace(
        handle,
        handle_id="desktop:echo-forged-target",
        signature="",
    ).sealed_by(mac_key, "cell:desktop", handle.created_at_ms)
    forged_package = _package(
        _draft(
            task_id,
            "desktop.action",
            {
                "desktop_target_handle": forged.handle_id,
                "action": {
                    "kind": "click",
                    "x": 10,
                    "y": 12,
                    "button": "left",
                    "clicks": 1,
                },
            },
        ),
        handles=(forged,),
    )
    with pytest.raises(ProtocolError, match="(?i)handle|target"):
        cell._preflight_package(forged_package)  # noqa: SLF001

    outside = _package(
        _draft(
            task_id,
            "desktop.action",
            {
                "desktop_target_handle": handle.handle_id,
                "action": {
                    "kind": "click",
                    "x": 81,
                    "y": 12,
                    "button": "left",
                    "clicks": 1,
                },
            },
        ),
        handles=(handle,),
    )
    with pytest.raises(ProtocolError, match="bound|coordinate|target"):
        cell._preflight_package(outside)  # noqa: SLF001
    assert json.loads(script_path.read_text(encoding="utf-8"))["actions"] == []

    action = {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1}
    action_package = _package(
        _draft(
            task_id,
            "desktop.action",
            {"desktop_target_handle": handle.handle_id, "action": action},
        ),
        handles=(handle,),
    )

    preflight = cell._preflight_package(action_package)  # noqa: SLF001
    witness = preflight.witness
    before_drift = json.loads(script_path.read_text(encoding="utf-8"))
    assert before_drift["actions"] == []

    cell._backend.mutate(  # noqa: SLF001 - simulate a trusted state change
        target={
            "kind": "screen",
            "display_id": 2,
            "window_id": 0,
            "owner_pid": 0,
            "control_id": "screen",
            "bounds": [0, 0, 80, 60],
        },
    )
    committed_package = replace(action_package, state_witness=witness)
    with pytest.raises(ProtocolError, match="state|stale|changed"):
        cell._commit_package(  # noqa: SLF001
            _permit(action_package, witness),
            committed_package,
        )
    after = json.loads(script_path.read_text(encoding="utf-8"))
    assert after["actions"] == []


def test_scripted_success_is_exact_observe_act_observe_and_replay_safe(
    tmp_path: Path,
) -> None:
    script_path = tmp_path / "desktop-script.json"
    _script(script_path)
    mac_key = b"b" * 32
    cell = _desktop_cell(tmp_path, mac_key, script_path)
    task_id = f"task:{uuid4().hex}"
    observed = cell._preflight_package(  # noqa: SLF001
        _package(_draft(task_id, "desktop.observe", _observe_arguments()))
    )
    binding = {
        "schema": "DesktopTargetBindingV1",
        "task_id": task_id,
        "draft_id": observed.witness.draft_id,
        "witness_id": observed.witness.witness_id,
        "canonical_effect_hash": observed.witness.canonical_effect_hash,
        "owner_key_hash": "sha256:" + "1" * 64,
        "tenant": "work",
        "expires_at_ms": _now_ms() + 60_000,
    }
    handle = _broker_handle(
        cell._resolve_handle(observed.witness.target_version, binding),  # noqa: SLF001
        mac_key,
    )
    action = {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1}
    package = _package(
        _draft(
            task_id,
            "desktop.action",
            {"desktop_target_handle": handle.handle_id, "action": action},
        ),
        handles=(handle,),
    )
    preflight = cell._preflight_package(package)  # noqa: SLF001
    witness = preflight.witness
    permit = _permit(package, witness)
    committed = replace(package, state_witness=witness)

    result = cell._commit_package(permit, committed)  # noqa: SLF001

    assert result["status"] == "COMMITTED"
    assert result["action"] == "click"
    assert result["before_digest"].startswith("sha256:")
    assert result["after_digest"].startswith("sha256:")
    assert result["before_digest"] != result["after_digest"]
    assert result["receipt_id"].startswith("receipt:")
    assert set(result) == {
        "status",
        "action",
        "before_digest",
        "after_digest",
        "receipt_id",
        "target_digest",
        "signed_receipt",
    }
    after = json.loads(script_path.read_text(encoding="utf-8"))
    assert after["revision"] == 2
    assert after["actions"] == [action]

    with pytest.raises(ProtocolError, match="replay|already|state|stale"):
        cell._commit_package(permit, committed)  # noqa: SLF001
    replayed = json.loads(script_path.read_text(encoding="utf-8"))
    assert replayed["actions"] == [action]


def test_commit_rejects_every_post_preflight_binding_change(tmp_path: Path) -> None:
    cell, package, witness, permit, committed = _preflighted_action(tmp_path)
    changed_draft = replace(
        package.draft,
        arguments={
            **package.draft.arguments,
            "action": {
                "kind": "click",
                "x": 11,
                "y": 12,
                "button": "left",
                "clicks": 1,
            },
        },
    )
    changed_hash = canonical_effect_hash_of(changed_draft)
    changed_witness = replace(
        witness,
        target_version="desktop-action:" + "9" * 64,
    )
    cases = (
        (
            replace(permit, canonical_effect_hash=changed_hash),
            replace(
                committed,
                draft=changed_draft,
                canonical_effect_hash=changed_hash,
            ),
        ),
        (permit, replace(committed, state_witness=changed_witness)),
        (
            replace(permit, canonical_effect_hash="sha256:" + "9" * 64),
            replace(committed, canonical_effect_hash="sha256:" + "9" * 64),
        ),
        (
            permit,
            replace(
                committed,
                draft=replace(package.draft, task_id=f"task:{uuid4().hex}"),
            ),
        ),
    )

    for changed_permit, changed_package in cases:
        with pytest.raises(ProtocolError):
            cell._commit_package(changed_permit, changed_package)  # noqa: SLF001

    state = json.loads((tmp_path / "desktop-script.json").read_text(encoding="utf-8"))
    assert state["actions"] == []
    assert cell._action_reports[package.draft.draft_id].attempted is False  # noqa: SLF001


def test_private_report_capacity_and_ttl_cleanup_are_bounded(tmp_path: Path) -> None:
    ttl_cell, _package_, _witness, _permit_, _committed = _preflighted_action(tmp_path / "ttl")
    assert len(ttl_cell._reports) == 1  # noqa: SLF001
    assert len(ttl_cell._action_reports) == 1  # noqa: SLF001
    expiry = max(  # noqa: SLF001 - Cell-private lifecycle contract
        [report.witness.expires_at_ms for report in ttl_cell._reports.values()]
        + [report.witness.expires_at_ms for report in ttl_cell._action_reports.values()]
    )
    ttl_cell._prune_private_reports(now_ms=expiry)  # noqa: SLF001
    assert ttl_cell._reports == {}  # noqa: SLF001
    assert ttl_cell._observation_drafts == {}  # noqa: SLF001
    assert ttl_cell._action_reports == {}  # noqa: SLF001

    observe_root = tmp_path / "observe-cap"
    observe_path = observe_root / "desktop-script.json"
    _script(observe_path)
    observe_cell = _desktop_cell(observe_root, b"b" * 32, observe_path)
    first_observe = observe_cell._preflight_package(  # noqa: SLF001
        _package(_draft(f"task:{uuid4().hex}", "desktop.observe", _observe_arguments()))
    )
    sample_observation = observe_cell._reports[first_observe.witness.target_version]  # noqa: SLF001
    observe_cell._reports = {  # noqa: SLF001
        f"desktop:capacity-{index}": sample_observation for index in range(1_024)
    }
    with pytest.raises(ProtocolError, match="observation capacity"):
        observe_cell._preflight_package(  # noqa: SLF001
            _package(
                _draft(
                    f"task:{uuid4().hex}",
                    "desktop.observe",
                    _observe_arguments(),
                )
            )
        )

    action_cell, original, _witness, _permit_, _committed = _preflighted_action(
        tmp_path / "action-cap"
    )
    sample_action = next(iter(action_cell._action_reports.values()))  # noqa: SLF001
    action_cell._action_reports = {  # noqa: SLF001
        f"draft:capacity-{index}": sample_action for index in range(1_024)
    }
    next_action = _package(
        _draft(
            original.draft.task_id,
            "desktop.action",
            dict(original.draft.arguments),
        ),
        handles=original.resolved_handles,
    )
    with pytest.raises(ProtocolError, match="action capacity"):
        action_cell._preflight_package(next_action)  # noqa: SLF001


class _IdentityTrackingNativeBackend(MacOSDesktopBackend):
    """Minimal native-backend double for Cell-private identity lifecycle tests."""

    def __init__(
        self,
        *,
        fail_action: bool = False,
        observed_display_id: int = 1,
    ) -> None:
        self.revision = 0
        self.fail_action = fail_action
        self.observed_display_id = observed_display_id
        self.released_scopes: list[str] = []

    def observe(
        self,
        _target: dict[str, Any],
        _request: dict[str, Any],
        *,
        identity_scope: str | None = None,
    ) -> dict[str, Any]:
        del identity_scope
        return {
            "schema": "DesktopObservationV1",
            "revision": self.revision,
            "target": {
                "kind": "screen",
                "display_id": self.observed_display_id,
                "window_id": 0,
                "owner_pid": 0,
                "control_id": "screen",
                "bounds": [0, 0, 80, 60],
            },
            "pixel_hash": "sha256:" + str(self.revision) * 64,
            "width": 80,
            "height": 60,
            "projection": {},
        }

    def act(
        self,
        _action: dict[str, Any],
        *,
        expected_observation: dict[str, Any],
        selector: dict[str, Any],
        request: dict[str, Any],
        identity_scope: str | None = None,
    ) -> None:
        del expected_observation, selector, request, identity_scope
        self.revision += 1
        if self.fail_action:
            raise ProtocolError("native action became ambiguous")

    def release_identity(self, identity_scope: str) -> None:
        self.released_scopes.append(identity_scope)


@pytest.mark.parametrize("fail_action", [False, True])
def test_native_identity_scope_is_released_after_action_attempt(
    tmp_path: Path,
    fail_action: bool,
) -> None:
    backend = _IdentityTrackingNativeBackend(fail_action=fail_action)
    cell, _package_, _witness, permit, committed = _preflighted_action(
        tmp_path,
        backend=backend,
    )
    observation_scope = next(iter(cell._reports.values())).draft_id  # noqa: SLF001

    if fail_action:
        with pytest.raises(ProtocolError, match="ambiguous"):
            cell._commit_package(permit, committed)  # noqa: SLF001
    else:
        assert cell._commit_package(permit, committed)["status"] == "COMMITTED"  # noqa: SLF001

    assert backend.released_scopes == [observation_scope]
    assert cell._action_reports[committed.draft.draft_id].attempted is True  # noqa: SLF001


def test_new_native_scope_is_released_when_observation_validation_fails(
    tmp_path: Path,
) -> None:
    backend = _IdentityTrackingNativeBackend(observed_display_id=2)
    cell = _desktop_cell(tmp_path, b"b" * 32, tmp_path / "unused.json", backend=backend)
    arguments = _observe_arguments()
    arguments["target"] = {"kind": "screen", "display_id": 1}
    draft = _draft(f"task:{uuid4().hex}", "desktop.observe", arguments)

    with pytest.raises(ProtocolError, match="selector|display"):
        cell._preflight_package(_package(draft))  # noqa: SLF001

    assert backend.released_scopes == [draft.draft_id]


@pytest.mark.parametrize("unsafe", ["symlink", "wrong-mode"])
def test_script_backend_rejects_symlink_and_non_private_mode(
    tmp_path: Path,
    unsafe: str,
) -> None:
    from js.orind.cells.desktop import ScriptedDesktopBackend

    real = tmp_path / "real-script.json"
    _script(real)
    candidate = real
    if unsafe == "symlink":
        candidate = tmp_path / "linked-script.json"
        candidate.symlink_to(real)
    else:
        real.chmod(0o644)
    backend = ScriptedDesktopBackend(candidate)

    with pytest.raises(ProtocolError, match="0600|unavailable"):
        backend.observe(
            {"kind": "screen"},
            _observe_arguments()["request"],
        )


def test_post_action_failure_is_claimed_before_side_effect_and_never_replayed(
    tmp_path: Path,
) -> None:
    from js.orind.cells.desktop import ScriptedDesktopBackend

    script_path = tmp_path / "desktop-script.json"
    _script(script_path)
    inner = ScriptedDesktopBackend(script_path)

    class FailAfterActBackend:
        def __init__(self) -> None:
            self.action_calls = 0

        def observe(
            self,
            target: dict[str, Any],
            request: dict[str, Any],
        ) -> dict[str, Any]:
            return inner.observe(target, request)

        def act(
            self,
            action: dict[str, Any],
            *,
            expected_observation: dict[str, Any],
            selector: dict[str, Any],
            request: dict[str, Any],
        ) -> None:
            self.action_calls += 1
            inner.act(
                action,
                expected_observation=expected_observation,
                selector=selector,
                request=request,
            )
            raise RuntimeError("synthetic failure after desktop side effect")

    backend = FailAfterActBackend()
    cell, _package_, _witness, permit, committed = _preflighted_action(
        tmp_path,
        backend=backend,
    )

    with pytest.raises(RuntimeError, match="after desktop side effect"):
        cell._commit_package(permit, committed)  # noqa: SLF001
    after_first = json.loads(script_path.read_text(encoding="utf-8"))
    assert len(after_first["actions"]) == 1

    with pytest.raises(ProtocolError, match="replay|already"):
        cell._commit_package(permit, committed)  # noqa: SLF001
    after_second = json.loads(script_path.read_text(encoding="utf-8"))
    assert len(after_second["actions"]) == 1
    assert backend.action_calls == 1


def test_non_screenshot_native_observe_never_returns_image_projection() -> None:
    from js.orind.cells.desktop import MacOSDesktopBackend

    backend = MacOSDesktopBackend.__new__(MacOSDesktopBackend)
    backend._lock = threading.RLock()  # noqa: SLF001 - isolated projection seam
    backend._revision = 3  # noqa: SLF001
    backend._operation_count = 2  # noqa: SLF001
    backend._emergency_stop = False  # noqa: SLF001
    target = {
        "kind": "screen",
        "display_id": 1,
        "window_id": 0,
        "owner_pid": 0,
        "control_id": "screen",
        "bounds": [0, 0, 80, 60],
    }
    backend._capture = lambda _selector, _request: (  # type: ignore[method-assign]  # noqa: SLF001,E501
        target,
        "sha256:" + "a" * 64,
        80,
        60,
        {
            "image_base64": "must-not-return",
            "image_mime_type": "image/png",
            "target_kind": "screen",
        },
    )

    observed = backend.observe(
        {"kind": "screen"},
        {"tool": "desktop_operation_log", "arguments": {"limit": 10}},
    )

    assert "image_base64" not in observed["projection"]
    assert "image_mime_type" not in observed["projection"]
    assert observed["projection"]["target_kind"] == "screen"

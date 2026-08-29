"""WP-C2 Desktop Cell integration and Echo-visible projection contracts.

Scripted desktop state proves the authenticated protocol and authority
boundary only.  It is deliberately not evidence for real-pixel or real-model
desktop closure.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.echo.capability import LeaseDenied
from js.orin.client import OrinDesktopCellBackend, OrinLeaseClientAdapter, OrinUnavailable
from js.orin.desktop import normalize_desktop_action
from js.orin.draft import EffectDraft
from js.orin.intent import Budgets, IntentEnvelope, request_hash_of
from js.orin.testing import C2TestOrind
from js.tools.desktop import DesktopMode
from js.tools.desktop_tools import DesktopTools


def _assert_no_authority_material(value: Any) -> None:
    forbidden = {
        "canonical_effect_hash",
        "draft_id",
        "mac",
        "nonce",
        "object_digest",
        "package",
        "permit",
        "root",
        "seal",
        "secret",
        "session_key",
        "stage_path",
        "task_id",
        "token",
        "witness",
    }
    if isinstance(value, dict):
        assert forbidden.isdisjoint(value)
        for item in value.values():
            _assert_no_authority_material(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_authority_material(item)


def _public_key(private_key: ed25519.Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _desktop_intent(
    private_key: ed25519.Ed25519PrivateKey,
    *,
    task_id: str,
    profile: str = "work",
    effect_classes: tuple[str, ...] = ("desktop.observe", "desktop.action"),
    handles: tuple[str, ...] = (),
) -> IntentEnvelope:
    now = time.time_ns() // 1_000_000
    return IntentEnvelope(
        intent_id=f"intent:{uuid4().hex}",
        owner_key_hash="sha256:" + "1" * 64,
        product_id="js-work" if profile == "work" else "js-personal",
        profile=profile,
        task_id=task_id,
        raw_request_hash=request_hash_of("observe and click the C2 harness window"),
        allowed_effect_classes=effect_classes,
        allowed_resource_handles=handles,
        allowed_sink_handles=(),
        budgets=Budgets(
            max_invocations=20,
            max_bytes_read=1 << 20,
            max_bytes_out=0,
            max_cost_minor_units=0,
        ),
        approval_policy=(
            "preauthorized_exact_template" if profile == "work" else "exact_commit_required"
        ),
        issued_by="appshell:owner-witness",
        issued_at_ms=now - 1_000,
        expires_at_ms=now + 60_000,
    ).sign_with(private_key)


def _adapter(orind: C2TestOrind) -> OrinLeaseClientAdapter:
    return OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=Path(orind.daemon._state_dir),  # noqa: SLF001 - harness boundary
        stage_b=True,
    )


def _write_desktop_script(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "DesktopScriptV1",
                "revision": 1,
                "target": {
                    "kind": "screen",
                    "display_id": 1,
                    "window_id": 0,
                    "owner_pid": 0,
                    "control_id": "screen",
                    "bundle_id": "com.apple.calculator",
                    "bounds": [0, 0, 80, 60],
                },
                "pixel_hash": "sha256:" + "a" * 64,
                "width": 80,
                "height": 60,
                "actions": [],
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


@pytest.mark.parametrize(
    ("tool", "arguments", "kind"),
    [
        ("desktop_click", {"x": 1, "y": 2, "button": "left", "clicks": 1}, "click"),
        ("desktop_move", {"x": 1, "y": 2}, "move"),
        ("desktop_scroll", {"direction": "down", "amount": 3}, "scroll"),
        (
            "desktop_drag",
            {
                "start_x": 1,
                "start_y": 2,
                "end_x": 3,
                "end_y": 4,
                "button": "left",
            },
            "drag",
        ),
        ("desktop_type", {"text": "exact"}, "type"),
        ("desktop_key", {"key": "return", "modifiers": ["cmd"]}, "key"),
        ("desktop_app", {"action": "open", "app_name": "TextEdit"}, "app"),
        (
            "desktop_window",
            {"action": "activate", "app_name": "TextEdit", "window_title": "C2"},
            "window",
        ),
        (
            "desktop_window",
            {
                "action": "move",
                "app_name": "TextEdit",
                "window_title": "C2",
                "x": 10,
                "y": 20,
            },
            "window",
        ),
        (
            "desktop_window",
            {
                "action": "resize",
                "app_name": "TextEdit",
                "window_title": "C2",
                "width": 640,
                "height": 480,
            },
            "window",
        ),
        ("desktop_set_mode", {"mode": "confirm"}, "set_mode"),
        ("desktop_emergency_stop", {"reason": "owner stop"}, "emergency_stop"),
        ("desktop_clear_stop", {}, "clear_stop"),
    ],
)
def test_existing_desktop_mutations_map_to_one_strict_action_union(
    tool: str,
    arguments: dict[str, Any],
    kind: str,
) -> None:
    action = OrinDesktopCellBackend._action_from_tool(tool, arguments)  # noqa: SLF001

    assert normalize_desktop_action(action)["kind"] == kind


def test_work_desktop_action_preflights_but_k4_blocks_commit_without_export_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script_path = tmp_path / "desktop-script.json"
    _write_desktop_script(script_path)
    private_key = ed25519.Ed25519PrivateKey.generate()
    task_id = f"task:{uuid4().hex}"
    owner = "sha256:" + "1" * 64
    appshell_session = "session:c2-work"
    handle_id = C2TestOrind.appshell_application_handle(
        owner_key_hash=owner,
        task_id=task_id,
        principal_owner="owner:c2",
        principal_session=appshell_session,
        principal_epoch=1,
        bundle_id="com.apple.calculator",
    )
    intent = _desktop_intent(private_key, task_id=task_id, handles=(handle_id,))

    with C2TestOrind(
        state_dir=tmp_path / "state",
        desktop_script_path=script_path,
        witness_public_keys=(_public_key(private_key),),
    ) as orind:
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if orind.daemon._cell_by_cap("cell.desktop") is not None:  # noqa: SLF001
                break
            time.sleep(0.05)
        else:
            pytest.fail("authenticated Desktop Cell did not become ready")

        intents = orind.daemon._intents  # noqa: SLF001 - no-export C2 probe
        assert intents is not None

        def forbidden_export(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("desktop effects must not inspect or claim ExportPass")

        for method_name in (
            "export_passes_for_task",
            "active_exact_export_passes",
            "claim_personal_export_pass",
        ):
            monkeypatch.setattr(intents, method_name, forbidden_export)

        adapter = _adapter(orind)
        bound = adapter.register_desktop_app_binding(
            intent.to_dict(),
            appshell_owner="owner:c2",
            appshell_session=appshell_session,
            appshell_epoch=1,
            bundle_id="com.apple.calculator",
        )
        assert bound["application_handle_id"] == handle_id
        observed = adapter.observe_desktop(task_id, {"kind": "screen"})
        handle_id = observed["desktop_target_handle_id"]
        assert observed["status"] == "OBSERVED"
        assert handle_id.startswith("desktop:")
        assert observed["width"] == 80
        assert observed["height"] == 60
        internal = orind.daemon._broker.resolve(handle_id)  # noqa: SLF001
        assert internal["ok"] is True
        with pytest.raises(LeaseDenied):
            adapter._call(  # noqa: SLF001 - public UDS rejection contract
                lambda: adapter._request(  # noqa: SLF001
                    "handle",
                    op="issue",
                    kind="DesktopTargetHandle",
                    spec={"token": "echo-forged", "approved": True},
                )
            )
        with pytest.raises(LeaseDenied):
            adapter._call(  # noqa: SLF001 - full sealed objects stay Cell-private
                lambda: adapter._request(  # noqa: SLF001
                    "handle",
                    op="resolve",
                    handle=internal["handle"],
                )
            )

        def forbidden_raw(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("harness DesktopTools must not touch a raw controller")

        monkeypatch.setattr(
            "js.tools.desktop_tools.PermissionChecker.is_macos",
            forbidden_raw,
        )
        monkeypatch.setattr("js.tools.desktop_tools.DesktopGuard", forbidden_raw)
        submitted: dict[str, str] = {}
        preflighted: list[str] = []
        submit_draft = adapter.submit_draft
        preflight_draft = adapter.preflight_draft

        def recording_submit(
            draft_data: dict[str, Any],
            **kwargs: Any,
        ) -> dict[str, Any]:
            submitted[str(draft_data["draft_id"])] = str(draft_data["effect_type"])
            return submit_draft(draft_data, **kwargs)

        def recording_preflight(
            draft_id: str,
            executor_id: str | None = None,
            **kwargs: Any,
        ) -> dict[str, Any]:
            result = preflight_draft(draft_id, executor_id, **kwargs)
            preflighted.append(submitted[draft_id])
            return result

        monkeypatch.setattr(adapter, "submit_draft", recording_submit)
        monkeypatch.setattr(adapter, "preflight_draft", recording_preflight)
        tools = DesktopTools(cell_backend=adapter.desktop_cell_backend(task_id))
        committed = asyncio.run(tools._click(x=10, y=12))  # noqa: SLF001

        assert committed.success is False
        assert "Desktop Cell" in committed.to_text()
        assert "desktop.action" in preflighted
        _assert_no_authority_material(committed.metadata)
        state = json.loads(script_path.read_text(encoding="utf-8"))
        assert state["revision"] == 1
        assert state["actions"] == []

        with pytest.raises((LeaseDenied, OrinUnavailable)):
            adapter.run_desktop_action(
                f"task:{uuid4().hex}",
                handle_id,
                {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1},
            )
        after_denial = json.loads(script_path.read_text(encoding="utf-8"))
        assert after_denial["actions"] == []


def test_denied_desktop_observe_cannot_be_forced_into_cell_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script_path = tmp_path / "desktop-script.json"
    _write_desktop_script(script_path)
    private_key = ed25519.Ed25519PrivateKey.generate()
    task_id = f"task:{uuid4().hex}"
    intent = _desktop_intent(
        private_key,
        task_id=task_id,
        effect_classes=("file.commit",),
    )
    draft = EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=task_id,
        effect_type="desktop.observe",
        arguments={
            "target": {"kind": "screen"},
            "request": {
                "tool": "desktop_screenshot",
                "arguments": {
                    "x": 0,
                    "y": 0,
                    "width": 0,
                    "height": 0,
                    "show_cursor": False,
                },
            },
        },
        declared_expectation={
            "external_visibility": "private",
            "reversibility": "reversible_until_stage",
        },
    )

    with C2TestOrind(
        state_dir=tmp_path / "state",
        desktop_script_path=script_path,
        witness_public_keys=(_public_key(private_key),),
    ) as orind:
        adapter = _adapter(orind)
        assert adapter.register_intent(intent.to_dict())["ok"] is True
        cell_dispatches: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

        async def forbidden_cell_dispatch(
            *args: Any,
            **kwargs: Any,
        ) -> dict[str, Any]:
            cell_dispatches.append((args, kwargs))
            raise AssertionError("denied draft reached the scripted Desktop Cell")

        monkeypatch.setattr(orind.daemon, "_request_cell", forbidden_cell_dispatch)
        proposed = adapter.submit_draft(draft.to_dict())
        assert proposed["verdict"] == "deny_policy"
        assert proposed["missing"] == []

        with pytest.raises(LeaseDenied):
            adapter.preflight_draft(draft.draft_id, "cell.desktop")

        assert cell_dispatches == []
        assert orind.daemon._store.current_state_witness(draft.draft_id) is None  # noqa: SLF001
        state = json.loads(script_path.read_text(encoding="utf-8"))
        assert state["revision"] == 1
        assert state["actions"] == []


def test_personal_desktop_action_preflights_but_consume_fails_without_export_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script_path = tmp_path / "desktop-script.json"
    _write_desktop_script(script_path)
    private_key = ed25519.Ed25519PrivateKey.generate()
    task_id = f"task:{uuid4().hex}"
    intent = _desktop_intent(private_key, task_id=task_id, profile="personal")

    with C2TestOrind(
        state_dir=tmp_path / "state",
        desktop_script_path=script_path,
        witness_public_keys=(_public_key(private_key),),
    ) as orind:
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if orind.daemon._cell_by_cap("cell.desktop") is not None:  # noqa: SLF001
                break
            time.sleep(0.05)
        else:
            pytest.fail("authenticated Desktop Cell did not become ready")

        intents = orind.daemon._intents  # noqa: SLF001 - no-export C2 probe
        assert intents is not None

        def forbidden_export(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("Personal desktop.action must not inspect ExportPass")

        for method_name in (
            "export_passes_for_task",
            "active_exact_export_passes",
            "claim_personal_export_pass",
        ):
            monkeypatch.setattr(intents, method_name, forbidden_export)

        adapter = _adapter(orind)
        assert adapter.register_intent(intent.to_dict())["ok"] is True
        observed = adapter.observe_desktop(task_id, {"kind": "screen"})
        handle_id = observed["desktop_target_handle_id"]
        preflight_calls: list[tuple[str, str]] = []
        preflight = adapter.preflight_draft

        def recording_preflight(
            draft_id: str,
            executor_id: str | None = None,
            **kwargs: Any,
        ) -> dict[str, Any]:
            preflight_calls.append((draft_id, str(executor_id or "")))
            return preflight(draft_id, executor_id, **kwargs)

        monkeypatch.setattr(adapter, "preflight_draft", recording_preflight)
        with pytest.raises(LeaseDenied):
            adapter.run_desktop_action(
                task_id,
                handle_id,
                {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1},
            )

        assert len(preflight_calls) == 1
        assert preflight_calls[0][1] == "cell.desktop"
        state = json.loads(script_path.read_text(encoding="utf-8"))
        assert state["revision"] == 1
        assert state["actions"] == []


@pytest.mark.asyncio
async def test_desktop_tools_cell_path_never_constructs_or_falls_back_to_raw_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_calls: list[str] = []

    def forbidden_permission_probe(*_args: object, **_kwargs: object) -> object:
        raw_calls.append("permission")
        raise AssertionError("C2 harness must not probe desktop authority in Echo")

    class ForbiddenGuard:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raw_calls.append("guard")
            raise AssertionError("C2 harness must not construct DesktopGuard in Echo")

    monkeypatch.setattr(
        "js.tools.desktop_tools.PermissionChecker.is_macos",
        forbidden_permission_probe,
    )
    monkeypatch.setattr("js.tools.desktop_tools.DesktopGuard", ForbiddenGuard)
    payloads: list[dict[str, Any]] = []

    def backend(payload: dict[str, Any]) -> dict[str, Any]:
        payloads.append(payload)
        if payload["tool"] == "desktop_screenshot":
            return {
                "status": "OBSERVED",
                "output": "safe pixel projection",
                "projection": {
                    "desktop_target_handle_id": "desktop:opaque-target",
                    "width": 80,
                    "height": 60,
                    "pixel_hash": "sha256:" + "a" * 64,
                    "target_kind": "screen",
                },
            }
        return {
            "status": "COMMITTED",
            "output": "exact click committed",
            "projection": {
                "action": "click",
                "receipt_id": "receipt:opaque",
                "before_digest": "sha256:" + "1" * 64,
                "after_digest": "sha256:" + "2" * 64,
            },
        }

    tools = DesktopTools(cell_backend=backend)
    assert tools.available is True
    assert tools._guard is None  # noqa: SLF001 - raw authority must not exist

    observed = await tools._screenshot(width=80, height=60)  # noqa: SLF001
    acted = await tools._click(x=10, y=12)  # noqa: SLF001

    assert observed.success is True
    assert acted.success is True
    assert raw_calls == []
    assert payloads == [
        {
            "tool": "desktop_screenshot",
            "arguments": {
                "x": 0,
                "y": 0,
                "width": 80,
                "height": 60,
                "show_cursor": False,
            },
        },
        {
            "tool": "desktop_click",
            "arguments": {"x": 10, "y": 12, "button": "left", "clicks": 1},
        },
    ]
    _assert_no_authority_material(observed.metadata)
    _assert_no_authority_material(acted.metadata)

    def dead_cell(_payload: dict[str, Any]) -> dict[str, Any]:
        raise ConnectionError("synthetic dead Desktop Cell")

    failed = DesktopTools(cell_backend=dead_cell)
    denied = await failed._click(x=10, y=12)  # noqa: SLF001
    assert denied.success is False
    assert raw_calls == []


@pytest.mark.asyncio
async def test_desktop_tools_rejects_authority_shaped_cell_projection() -> None:
    for leaked in (
        {"permit": "permit:must-not-return"},
        {"draft_id": "draft:must-not-return"},
        {"witness_id": "state:must-not-return"},
        {"root": "/private/must-not-return"},
        {"nested": {"token": "must-not-return"}},
        {"apps": ["permit:must-not-return"]},
        {
            "windows": [
                {
                    "app_name": "TextEdit",
                    "title": "package:must-not-return",
                    "bounds": [0, 0, 80, 60],
                }
            ]
        },
    ):
        tools = DesktopTools(
            cell_backend=lambda _payload, leaked=leaked: {
                "status": "OBSERVED",
                "projection": leaked,
            }
        )
        result = await tools._get_state()  # noqa: SLF001
        assert result.success is False
        assert "must-not-return" not in result.to_text()


def test_desktop_backend_rejects_unknown_tool_arguments_before_authority_call() -> None:
    from js.orin.client import OrinDesktopCellBackend

    class ForbiddenAuthority:
        def observe_desktop(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("unknown arguments must fail before authority dispatch")

        def run_desktop_action(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("unknown arguments must fail before authority dispatch")

    backend = OrinDesktopCellBackend(ForbiddenAuthority(), task_id="task:strict")  # type: ignore[arg-type]
    with pytest.raises(LeaseDenied, match="arguments"):
        backend(
            {
                "tool": "desktop_click",
                "arguments": {
                    "x": 10,
                    "y": 12,
                    "button": "left",
                    "clicks": 1,
                    "root": "/private/must-not-enter",
                },
            }
        )


def test_cell_observations_are_never_marked_cacheable_but_default_specs_are_unchanged() -> None:
    backend_tools = DesktopTools(
        cell_backend=lambda _payload: {"status": "OBSERVED", "projection": {}}
    )
    default_read_flags = {
        spec.name: spec.read_only for spec in DesktopTools().get_read_only_specs()
    }
    backend_read_flags = {spec.name: spec.read_only for spec in backend_tools.get_read_only_specs()}

    observable = {
        "desktop_get_permissions",
        "desktop_get_state",
        "desktop_screenshot",
        "desktop_list",
        "desktop_operation_log",
    }
    assert all(default_read_flags[name] is True for name in observable)
    assert all(backend_read_flags[name] is False for name in observable)


@pytest.mark.asyncio
async def test_default_desktop_tools_keep_the_legacy_in_process_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class FakeGuard:
        def __init__(self, *, mode: DesktopMode, approval_queue: Any) -> None:
            calls.append(("init", mode, approval_queue))

        async def mouse_click(self, *, point: Any, button: Any, clicks: int) -> dict[str, Any]:
            calls.append(("click", point.x, point.y, button.value, clicks))
            return {"status": "success"}

    monkeypatch.setattr("js.tools.desktop_tools.PermissionChecker.is_macos", lambda: True)
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/present")
    monkeypatch.setattr("js.tools.desktop_tools.DesktopGuard", FakeGuard)
    tools = DesktopTools(mode=DesktopMode.CONFIRM)
    result = await tools._click(x=4, y=9)  # noqa: SLF001

    assert result.success is True
    assert calls == [
        ("init", DesktopMode.CONFIRM, None),
        ("click", 4, 9, "left", 1),
    ]
    assert tools._cell_backend is None  # noqa: SLF001 - legacy product path


def test_scripted_evidence_file_does_not_claim_native_or_model_execution(
    tmp_path: Path,
) -> None:
    """The C2 harness fixture is explicit protocol evidence, not K§15.6 #8."""

    script = {
        "schema": "DesktopScriptV1",
        "revision": 1,
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
    path = tmp_path / "desktop-script.json"
    path.write_text(json.dumps(script), encoding="utf-8")
    path.chmod(0o600)

    restored = json.loads(path.read_text(encoding="utf-8"))
    assert restored["schema"] == "DesktopScriptV1"
    assert "provider" not in restored
    assert "model" not in restored
    assert "native_capture" not in restored

"""WP-C2 residual: owner ApplicationHandle, durable reconcile, Echo sanitize.

These tests prove the closable C2 leftovers.  They do not complete C2:
desktop.action stays non-idempotent, consume stays dual-control, real-model
E2E and official TCC remain blocked.
"""

from __future__ import annotations

import base64
import inspect
import json
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.echo.capability import LeaseDenied
from js.orin.client import OrinLeaseClientAdapter
from js.orin.desktop import normalize_desktop_safe_projection
from js.orin.draft import signed_receipt_from_dict
from js.orin.handles import OriginHandle
from js.orin.intent import Budgets, IntentEnvelope, request_hash_of
from js.orin.protocol import ProtocolError
from js.orin.testing import C2TestOrind
from js.orind.cells.desktop import MacOSDesktopBackend
from js.orind.manifest import builtin_manifest
from js.orind.store import OrinStore
from tests.orin.test_orin_stagec_c2_desktop_cell import (
    _desktop_cell,
    _draft,
    _observe_arguments,
    _package,
    _preflighted_action,
    _script,
)


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _public_key(private_key: ed25519.Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _application_handle(bundle_id: str) -> OriginHandle:
    now = _now_ms()
    return OriginHandle(
        handle_id="app:" + "a" * 32,
        kind="ApplicationHandle",
        owner_key_hash="sha256:" + "1" * 64,
        tenant="work",
        source_class="TRUSTED_LOCAL",
        integrity="trusted_local_object",
        confidentiality="CONFIDENTIAL",
        object_digest=bundle_id,
        capabilities=("read", "use"),
        issuer="orind",
        created_at_ms=now,
        expires_at_ms=now + 60_000,
    )


def _app_script(
    path: Path,
    *,
    bundle_id: str = "com.apple.calculator",
    app_name: str = "Calculator",
    kind: str = "application",
    window_title: str = "Untitled",
) -> dict[str, Any]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target: dict[str, Any] = {
        "kind": kind,
        "display_id": 1,
        "window_id": 0 if kind == "application" else 7,
        "owner_pid": 4242,
        "control_id": "ax:app" if kind == "application" else "window",
        "bounds": [0, 0, 80, 60],
        "app_name": app_name,
        "bundle_id": bundle_id,
    }
    if kind == "window":
        target["window_title"] = window_title
    data: dict[str, Any] = {
        "schema": "DesktopScriptV1",
        "revision": 1,
        "target": target,
        "pixel_hash": "sha256:" + "a" * 64,
        "width": 80,
        "height": 60,
        "actions": [],
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)
    return data


def _observe_window_id(window_id: int = 7) -> dict[str, Any]:
    arguments = _observe_arguments()
    arguments["target"] = {"kind": "window", "window_id": window_id}
    return arguments


def _observe_application(app_name: str = "Calculator") -> dict[str, Any]:
    arguments = _observe_arguments()
    arguments["target"] = {"kind": "application", "app_name": app_name}
    return arguments


def _observe_window(app_name: str = "Calculator", title: str = "Untitled") -> dict[str, Any]:
    arguments = _observe_arguments()
    arguments["target"] = {
        "kind": "window_query",
        "app_name": app_name,
        "window_title": title,
    }
    return arguments


def _adapter(orind: C2TestOrind) -> OrinLeaseClientAdapter:
    return OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=Path(orind.daemon._state_dir),  # noqa: SLF001
        stage_b=True,
    )


def _desktop_intent(
    private_key: ed25519.Ed25519PrivateKey,
    *,
    task_id: str,
    handles: tuple[str, ...] = (),
) -> IntentEnvelope:
    now = _now_ms()
    return IntentEnvelope(
        intent_id=f"intent:{uuid4().hex}",
        owner_key_hash="sha256:" + "1" * 64,
        product_id="js-work",
        profile="work",
        task_id=task_id,
        raw_request_hash=request_hash_of("observe the granted calculator"),
        allowed_effect_classes=("desktop.observe", "desktop.action"),
        allowed_resource_handles=handles,
        allowed_sink_handles=(),
        budgets=Budgets(
            max_invocations=20,
            max_bytes_read=1 << 20,
            max_bytes_out=0,
            max_cost_minor_units=0,
        ),
        approval_policy="preauthorized_exact_template",
        issued_by="appshell:owner-witness",
        issued_at_ms=now - 1_000,
        expires_at_ms=now + 60_000,
    ).sign_with(private_key)


def test_macos_backend_never_imports_or_constructs_desktop_controller() -> None:
    source = inspect.getsource(MacOSDesktopBackend)
    module_source = Path(inspect.getfile(MacOSDesktopBackend)).read_text(encoding="utf-8")
    assert "DesktopController" not in source
    assert "js.tools.desktop.controller" not in module_source
    assert "js.tools.desktop.controller" not in source


def test_named_observe_without_application_handle_is_rejected(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    _app_script(script_path)
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)
    package = _package(_draft(f"task:{uuid4().hex}", "desktop.observe", _observe_application()))

    with pytest.raises(ProtocolError, match="ApplicationHandle"):
        cell._preflight_package(package)  # noqa: SLF001


def test_named_observe_rejects_a_different_granted_bundle(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    _app_script(script_path, bundle_id="com.apple.calculator", app_name="Calculator")
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)
    package = _package(
        _draft(f"task:{uuid4().hex}", "desktop.observe", _observe_application()),
        handles=(_application_handle("com.other.impostor"),),
    )

    with pytest.raises(ProtocolError, match="outside the granted application"):
        cell._preflight_package(package)  # noqa: SLF001


def test_same_name_other_bundle_is_rejected(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    _app_script(script_path, bundle_id="com.evil.calculator", app_name="Calculator")
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)
    package = _package(
        _draft(f"task:{uuid4().hex}", "desktop.observe", _observe_application()),
        handles=(_application_handle("com.apple.calculator"),),
    )

    with pytest.raises(ProtocolError, match="outside the granted application"):
        cell._preflight_package(package)  # noqa: SLF001


def test_window_query_requires_the_granted_bundle(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    _app_script(script_path, kind="window", bundle_id="com.apple.calculator")
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)
    granted = _package(
        _draft(f"task:{uuid4().hex}", "desktop.observe", _observe_window()),
        handles=(_application_handle("com.apple.calculator"),),
    )
    denied = _package(
        _draft(f"task:{uuid4().hex}", "desktop.observe", _observe_window()),
        handles=(_application_handle("com.other.impostor"),),
    )

    accepted = cell._preflight_package(granted)  # noqa: SLF001
    assert accepted.witness.target_version.startswith("desktop:")
    with pytest.raises(ProtocolError, match="outside the granted application"):
        cell._preflight_package(denied)  # noqa: SLF001


def test_granted_bundle_observe_does_not_mutate(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    before = _app_script(script_path)
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)
    package = _package(
        _draft(f"task:{uuid4().hex}", "desktop.observe", _observe_application()),
        handles=(_application_handle("com.apple.calculator"),),
    )

    result = cell._preflight_package(package)  # noqa: SLF001

    assert result.projection["target_kind"] == "application"
    after = json.loads(script_path.read_text(encoding="utf-8"))
    assert after["actions"] == []
    assert after["revision"] == before["revision"]


def test_screen_observe_still_works_without_an_application_handle(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    _script(script_path)
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)
    result = cell._preflight_package(  # noqa: SLF001
        _package(_draft(f"task:{uuid4().hex}", "desktop.observe", _observe_arguments()))
    )
    assert result.projection["target_kind"] == "screen"


def test_reconcile_is_absent_before_any_attempt(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    _script(script_path)
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)

    assert cell._reconcile_effect("draft:missing", {"draft_id": "draft:missing"}) == {
        "state": "PREPARED"
    }


def test_reconcile_is_unknown_after_attempt_without_commit(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    _script(script_path)
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)
    draft_id = f"draft:{uuid4().hex}"
    permit_id = f"permit:{uuid4().hex}"
    cell._receipts.record(  # noqa: SLF001
        {
            "permit_id": permit_id,
            "draft_id": draft_id,
            "before_digest": "sha256:" + "b" * 64,
            "after_digest": "",
            "target_digest": "sha256:" + "c" * 64,
            "state": "unknown",
            "created_at_ms": _now_ms(),
        }
    )

    assert cell._reconcile_effect(draft_id, {"permit_id": permit_id, "draft_id": draft_id}) == {
        "state": "UNKNOWN_COMMIT",
        "before_digest": "sha256:" + "b" * 64,
        "target_digest": "sha256:" + "c" * 64,
    }


def test_commit_persists_and_reconciles_committed(tmp_path: Path) -> None:
    cell, _package_in, _witness, permit, committed = _preflighted_action(tmp_path)

    result = cell._commit_package(permit, committed)  # noqa: SLF001

    assert result["status"] == "COMMITTED"
    assert "signed_receipt" in result
    sealed = signed_receipt_from_dict(json.loads(str(result["signed_receipt"])), mac_key=b"b" * 32)
    assert sealed.receipt.permit_id == permit.permit_id
    assert sealed.receipt.executor_id == "cell.desktop"
    reconciled = cell._reconcile_effect(
        committed.draft.draft_id,
        {"permit_id": permit.permit_id, "draft_id": committed.draft.draft_id},
    )
    assert reconciled["state"] == "COMMITTED"
    assert reconciled["before_digest"] == result["before_digest"]
    assert reconciled["after_digest"] == result["after_digest"]
    assert reconciled["target_digest"] == result["target_digest"]
    store = OrinStore(tmp_path / "orind.db")
    try:
        store.record_desktop_action_receipt(
            permit_id=permit.permit_id,
            draft_id=committed.draft.draft_id,
            before_digest=str(result["before_digest"]),
            after_digest="",
            target_digest="",
            state="unknown",
            created_at_ms=_now_ms(),
        )
        store.record_desktop_action_receipt(
            permit_id=permit.permit_id,
            draft_id=committed.draft.draft_id,
            before_digest=str(result["before_digest"]),
            after_digest=str(result["after_digest"]),
            target_digest=str(result["target_digest"]),
            state="committed",
            created_at_ms=_now_ms(),
        )
        stored = store.desktop_action_receipt(permit_id=permit.permit_id)
        assert stored is not None
        assert stored["state"] == "committed"
        assert stored["before_digest"] == result["before_digest"]
        assert stored["after_digest"] == result["after_digest"]
        assert stored["target_digest"] == result["target_digest"]
    finally:
        store.close()


def test_desktop_action_opens_reconcile_but_stays_non_idempotent() -> None:
    manifest = builtin_manifest(b"k" * 32, include_desktop=True)
    entry = manifest.get("desktop.action")
    assert entry is not None
    assert entry.idempotent is False
    assert entry.reconcile_query is True
    assert entry.capability_grid_complete is False


def test_window_id_observe_requires_the_granted_bundle(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    _app_script(script_path, kind="window", bundle_id="com.apple.calculator")
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)
    missing = _package(_draft(f"task:{uuid4().hex}", "desktop.observe", _observe_window_id()))
    denied = _package(
        _draft(f"task:{uuid4().hex}", "desktop.observe", _observe_window_id()),
        handles=(_application_handle("com.other.impostor"),),
    )
    granted = _package(
        _draft(f"task:{uuid4().hex}", "desktop.observe", _observe_window_id()),
        handles=(_application_handle("com.apple.calculator"),),
    )

    with pytest.raises(ProtocolError, match="ApplicationHandle"):
        cell._preflight_package(missing)  # noqa: SLF001
    with pytest.raises(ProtocolError, match="outside the granted application"):
        cell._preflight_package(denied)  # noqa: SLF001
    accepted = cell._preflight_package(granted)  # noqa: SLF001
    assert accepted.projection["target_kind"] == "window"


def test_window_without_bundle_id_is_rejected(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    data = _app_script(script_path, kind="window", bundle_id="com.apple.calculator")
    del data["target"]["bundle_id"]
    script_path.write_text(json.dumps(data), encoding="utf-8")
    script_path.chmod(0o600)
    cell = _desktop_cell(tmp_path, b"b" * 32, script_path)
    package = _package(
        _draft(f"task:{uuid4().hex}", "desktop.observe", _observe_window_id()),
        handles=(_application_handle("com.apple.calculator"),),
    )

    with pytest.raises(ProtocolError, match="outside the granted application"):
        cell._preflight_package(package)  # noqa: SLF001


def test_echo_sanitize_drops_pid_and_ax_material() -> None:
    sanitized = normalize_desktop_safe_projection(
        {
            "desktop_target_handle_id": "desktop:" + "a" * 32,
            "target_kind": "window",
            "display_id": 1,
            "window_number": 7,
            "owner_pid": 4242,
            "width": 80,
            "height": 60,
            "scale": 1.0,
            "pixel_hash": "sha256:" + "a" * 64,
        },
        effect_type="desktop.observe",
    )
    assert "owner_pid" not in sanitized
    assert "window_number" not in sanitized
    assert "ax:" not in json.dumps(sanitized)


def test_appshell_binding_and_echo_cannot_resolve_or_issue_app_handles(
    tmp_path: Path,
) -> None:
    script_path = tmp_path / "desktop-script.json"
    _app_script(script_path)
    private_key = ed25519.Ed25519PrivateKey.generate()
    task_id = f"task:{uuid4().hex}"
    owner = "sha256:" + "1" * 64
    appshell_session = "session:appshell-c2"
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

        adapter = _adapter(orind)
        bound = adapter.register_desktop_app_binding(
            intent.to_dict(),
            appshell_owner="owner:c2",
            appshell_session=appshell_session,
            appshell_epoch=1,
            bundle_id="com.apple.calculator",
        )
        assert bound["application_handle_id"] == handle_id
        observed = adapter.observe_desktop(
            task_id,
            {"kind": "application", "app_name": "Calculator"},
        )
        assert observed["target_kind"] == "application"
        assert "owner_pid" not in observed
        assert "window_number" not in observed
        assert "ax:" not in json.dumps(observed)

        with pytest.raises(LeaseDenied):
            adapter._call(  # noqa: SLF001
                lambda: adapter._request(  # noqa: SLF001
                    "handle",
                    op="issue",
                    kind="ApplicationHandle",
                    spec={"token": "echo-forged", "approved": True},
                )
            )
        with pytest.raises(LeaseDenied):
            adapter._call(  # noqa: SLF001
                lambda: adapter._request(  # noqa: SLF001
                    "handle",
                    op="resolve",
                    handle=handle_id,
                )
            )


def test_observe_application_without_binding_is_denied(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    _app_script(script_path)
    private_key = ed25519.Ed25519PrivateKey.generate()
    task_id = f"task:{uuid4().hex}"
    intent = _desktop_intent(private_key, task_id=task_id)

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
        adapter = _adapter(orind)
        assert adapter.register_intent(intent.to_dict())["ok"] is True
        with pytest.raises((LeaseDenied, ProtocolError)):
            adapter.observe_desktop(
                task_id,
                {"kind": "application", "app_name": "Calculator"},
            )


def test_c2_orind_upsert_keeps_digests_after_unknown_then_commit(tmp_path: Path) -> None:
    script_path = tmp_path / "desktop-script.json"
    _script(script_path)
    private_key = ed25519.Ed25519PrivateKey.generate()
    permit_id = f"permit:{uuid4().hex}"
    draft_id = f"draft:{uuid4().hex}"
    before = "sha256:" + "1" * 64
    after = "sha256:" + "2" * 64
    target = "sha256:" + "3" * 64

    with C2TestOrind(
        state_dir=tmp_path / "state",
        desktop_script_path=script_path,
        witness_public_keys=(_public_key(private_key),),
    ) as orind:
        daemon = orind.daemon
        daemon._persist_desktop_action_receipt(  # noqa: SLF001
            permit_id=permit_id,
            draft_id=draft_id,
            before_digest=before,
            after_digest="",
            target_digest=target,
            state="unknown",
            created_at_ms=_now_ms(),
        )
        daemon._persist_desktop_action_receipt(  # noqa: SLF001
            permit_id=permit_id,
            draft_id=draft_id,
            before_digest=before,
            after_digest=after,
            target_digest=target,
            state="committed",
            created_at_ms=_now_ms(),
        )
        stored = daemon._store.desktop_action_receipt(permit_id=permit_id)  # noqa: SLF001
        assert stored is not None
        assert stored["before_digest"] == before
        assert stored["after_digest"] == after
        assert stored["target_digest"] == target
        import asyncio

        outcome = asyncio.run(
            daemon._reconcile_desktop_action(permit_id=permit_id, draft_id=draft_id)  # noqa: SLF001
        )
        assert outcome["state"] == "committed"
        stored_again = daemon._store.desktop_action_receipt(permit_id=permit_id)  # noqa: SLF001
        assert stored_again is not None
        assert stored_again["before_digest"] == before
        assert stored_again["after_digest"] == after
        assert stored_again["target_digest"] == target

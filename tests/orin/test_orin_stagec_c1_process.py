"""WP-C1 explicit AppShell-host / restricted-Echo process harness tests.

The harness is intentionally not wired into the default AppShell launch path.
It exists only to collect C1 construction evidence with a real, deny-default OS
process boundary while production ``orin.enforce`` remains off.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

import pytest

import js.appshell.c1_harness as c1_harness
from js.appshell.c1_harness import (
    C1HarnessDeniedError,
    C1HarnessUnavailableError,
    C1WorkerProjection,
    c1_harness_backend_available,
    make_c1_worker_request_for_test,
    run_c1_process_harness,
    run_c1_worker_frames_for_test,
    sign_c1_worker_request_for_test,
)
from js.echo.os_sandbox import SandboxExecutor


def _projection(**overrides: object) -> C1WorkerProjection:
    values: dict[str, object] = {
        "task_id": "task:c1-process-boundary",
        "handle_ids": ("dirh:c1-workspace", "artifact:c1-input"),
        "model_context": {"messages": ["only bounded model context"]},
        "safe_projection": {"file_count": 1, "bytes": 17},
    }
    values.update(overrides)
    return C1WorkerProjection.from_values(**values)


def _host_state(root: Path) -> Path:
    state = root / "host-state"
    state.mkdir(parents=True)
    witness = state / "orin" / "appshell_witness"
    witness.mkdir(parents=True)
    (witness / ".signing_key").write_text("test-owner-private-key", encoding="utf-8")
    (state / "provider-token").write_text("test-provider-token", encoding="utf-8")
    (state / "appshell-state.json").write_text('{"trusted":true}', encoding="utf-8")
    return state


@pytest.mark.skipif(
    not c1_harness_backend_available(),
    reason="C1 evidence requires a deny-default filesystem isolation backend",
)
@pytest.mark.asyncio
async def test_worker_is_real_sandboxed_process_without_host_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "c1-boundary"
    _host_state(root)
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-enter-worker")
    monkeypatch.setenv("HTTPS_PROXY", "http://must-not-enter-worker.invalid")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/must/not/enter/worker")
    monkeypatch.setenv("ORIN_OWNER_WITNESS_PRIVATE", "must-not-enter-worker")

    evidence = await run_c1_process_harness(root=root, projection=_projection())

    assert evidence.worker_pid > 1
    assert evidence.worker_pid != os.getpid()
    assert evidence.parent_pid == os.getpid()
    assert evidence.received == _projection()
    assert not evidence.host_state_readable
    assert not evidence.owner_key_readable
    assert not evidence.provider_token_readable
    assert not evidence.control_plane_importable
    assert evidence.privileged_surface == ()
    assert {
        "OPENAI_API_KEY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "SSH_AUTH_SOCK",
        "ORIN_OWNER_WITNESS_PRIVATE",
    }.isdisjoint(evidence.environment_keys)


@pytest.mark.skipif(
    not c1_harness_backend_available(),
    reason="C1 evidence requires a deny-default filesystem isolation backend",
)
@pytest.mark.asyncio
async def test_worker_ipc_rejects_privilege_mac_nonce_sequence_and_replay(
    tmp_path: Path,
) -> None:
    root = tmp_path / "c1-protocol"
    _host_state(root)
    session_key = secrets.token_bytes(32)
    nonce = secrets.token_hex(16)
    valid = make_c1_worker_request_for_test(
        projection=_projection(),
        session_key=session_key,
        nonce=nonce,
        seq=1,
    )

    unknown_operation = dict(valid)
    unknown_operation["op"] = "handle.issue"
    unknown_operation = sign_c1_worker_request_for_test(unknown_operation, session_key)

    privileged_projection = dict(valid)
    privileged_payload = dict(valid["payload"])
    privileged_payload["safe_projection"] = {"approved": True}
    privileged_projection["payload"] = privileged_payload
    privileged_projection = sign_c1_worker_request_for_test(
        privileged_projection,
        session_key,
    )

    wrong_mac = dict(valid)
    wrong_mac["mac"] = "c1-hmac-sha256:" + "0" * 64

    wrong_nonce = dict(valid)
    wrong_nonce["nonce"] = "f" * 32
    wrong_nonce = sign_c1_worker_request_for_test(wrong_nonce, session_key)

    wrong_seq = dict(valid)
    wrong_seq["seq"] = 2
    wrong_seq = sign_c1_worker_request_for_test(wrong_seq, session_key)

    responses = await run_c1_worker_frames_for_test(
        root=root,
        session_key=session_key,
        nonce=nonce,
        frames=(
            unknown_operation,
            privileged_projection,
            wrong_mac,
            wrong_nonce,
            wrong_seq,
            valid,
            valid,
        ),
    )

    assert [(response.ok, response.code) for response in responses] == [
        (False, "bad_message"),
        (False, "authority_denied"),
        (False, "mac_invalid"),
        (False, "nonce_mismatch"),
        (False, "seq_invalid"),
        (True, ""),
        (False, "replay"),
    ]


@pytest.mark.asyncio
async def test_harness_fails_closed_without_isolation_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "c1-no-backend"
    _host_state(root)
    monkeypatch.setattr(SandboxExecutor, "filesystem_isolation_available", lambda _self: False)

    with pytest.raises(C1HarnessUnavailableError, match="filesystem isolation"):
        await run_c1_process_harness(root=root, projection=_projection())


@pytest.mark.parametrize(
    "field,value",
    [
        ("model_context", {"owner_private_key": "forged"}),
        ("model_context", {"owner_signing_key": "forged"}),
        ("safe_projection", {"state_dir": "/forged"}),
        ("safe_projection", {"approved": True}),
        ("safe_projection", {"provider_token": "forged"}),
        ("safe_projection", {"x_api_key": "forged"}),
        ("safe_projection", {"bearer": "forged"}),
        ("safe_projection", {"private_key": "forged"}),
        ("safe_projection", {"signing_secret": "forged"}),
    ],
)
def test_projection_rejects_authority_bearing_fields(field: str, value: object) -> None:
    with pytest.raises(C1HarnessDeniedError, match="allowlist|authority-bearing"):
        _projection(**{field: value})


def test_host_rejects_worker_response_with_wrong_request_sequence() -> None:
    session_key = secrets.token_bytes(32)
    nonce = secrets.token_hex(16)
    response: dict[str, object] = {
        "schema": "C1WorkerResponseV1",
        "seq": 0,
        "nonce": nonce,
        "ok": False,
        "code": "bad_message",
        "evidence": None,
    }
    response["mac"] = c1_harness._compute_mac(session_key, response)  # noqa: SLF001

    with pytest.raises(C1HarnessDeniedError, match="sequence"):
        c1_harness._parse_worker_response(  # noqa: SLF001
            json.dumps(response),
            session_key=session_key,
            nonce=nonce,
            expected_seq=1,
        )


def test_default_appshell_and_sidecar_paths_do_not_wire_c1_harness() -> None:
    root = Path(__file__).resolve().parents[2]
    default_paths = (
        root / "js" / "appshell" / "launcher.py",
        root / "js" / "appshell" / "server.py",
        root / "js" / "appshell" / "routers.py",
        root / "desktop" / "sidecar" / "host.py",
    )

    for path in default_paths:
        assert "c1_harness" not in path.read_text(encoding="utf-8"), path

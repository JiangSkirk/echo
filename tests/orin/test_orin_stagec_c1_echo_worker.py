"""WP-C1 evidence for the real, test-only Echo worker process boundary.

The older ``python -c`` probe remains a negative control.  These tests require
the explicit C1 harness to execute the authoritative JSAgent/Echo turn path
from a read-only runtime image that contains no AppShell signing surface.
"""

from __future__ import annotations

import ast
import os
import secrets
import stat
from pathlib import Path

import pytest

from js.appshell.c1_harness import (
    C1WorkerProjection,
    c1_real_echo_harness_backend_available,
    make_c1_worker_request_for_test,
    run_c1_real_echo_frame_for_test,
    run_c1_real_echo_process_harness,
    sign_c1_worker_request_for_test,
)


def _projection() -> C1WorkerProjection:
    return C1WorkerProjection.from_values(
        task_id="task:c1-real-echo-worker",
        handle_ids=("dirh:c1-workspace", "artifact:c1-context"),
        model_context={"messages": ["execute one deterministic Echo turn"]},
        safe_projection={"status": "PREFLIGHTED", "file_count": 1, "bytes": 23},
    )


@pytest.mark.skipif(
    not c1_real_echo_harness_backend_available(),
    reason="real Echo C1 PID evidence currently requires macOS sandbox-exec",
)
@pytest.mark.asyncio
async def test_real_echo_worker_runs_authoritative_turn_in_distinct_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-enter-real-worker")
    monkeypatch.setenv("HTTPS_PROXY", "http://must-not-enter-real-worker.invalid")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/must/not/enter/real-worker")
    monkeypatch.setenv("ORIN_OWNER_WITNESS_PRIVATE", "must-not-enter-real-worker")

    evidence = await run_c1_real_echo_process_harness(
        root=tmp_path / "c1-real-boundary",
        projection=_projection(),
    )

    # ``worker_pid`` is captured by the parent at create_subprocess_exec(), not
    # accepted from the untrusted response.  The reported value is only a
    # cross-check that the fixed worker entry ran in that child.
    assert evidence.host_pid == os.getpid()
    assert evidence.worker_pid > 1
    assert evidence.worker_pid != evidence.host_pid
    assert evidence.worker_reported_pid == evidence.worker_pid
    assert evidence.worker_parent_pid == evidence.host_pid

    assert evidence.entrypoint == "js.echo.c1_worker"
    assert evidence.agent_type == "js.agent.JSAgent"
    assert evidence.runtime_type == "js.echo.turn_runtime.EchoRuntime"
    assert evidence.turn_entry == "js.echo.turn_runtime.run_echo_turn"
    assert evidence.turn_status == "completed"
    assert evidence.turn_count == 1
    assert evidence.provider_calls == 1
    assert evidence.projection_digest.startswith("sha256:")
    assert evidence.response_digest.startswith("sha256:")

    assert {
        "OPENAI_API_KEY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "SSH_AUTH_SOCK",
        "ORIN_OWNER_WITNESS_PRIVATE",
    }.isdisjoint(evidence.environment_keys)


@pytest.mark.skipif(
    not c1_real_echo_harness_backend_available(),
    reason="real Echo C1 PID evidence currently requires macOS sandbox-exec",
)
@pytest.mark.asyncio
async def test_owner_key_and_signing_authority_remain_host_only(tmp_path: Path) -> None:
    root = tmp_path / "c1-real-authority"
    evidence = await run_c1_real_echo_process_harness(
        root=root,
        projection=_projection(),
    )

    assert evidence.host_authority.host_pid == os.getpid()
    assert evidence.host_authority.intent_signature_valid
    assert evidence.host_authority.exact_approval_signature_valid
    assert evidence.host_authority.export_pass_signature_valid
    assert evidence.host_authority.unfreeze_signature_valid
    assert evidence.host_authority.worker_forgery_trusted is False

    owner_key = root / "host-state" / "orin" / "appshell_witness" / ".signing_key"
    assert owner_key.is_file()
    assert stat.S_IMODE(owner_key.stat().st_mode) == 0o600
    assert not evidence.isolation.host_state_readable
    assert not evidence.isolation.owner_key_readable
    assert not evidence.isolation.repo_authority_source_readable
    assert not evidence.isolation.orind_socket_connectable
    assert not evidence.isolation.worker_client_has_signing_surface

    assert evidence.isolation.missing_authority_modules == (
        "js.appshell.c1_harness",
        "js.appshell.launcher",
        "js.appshell.routers",
        "js.appshell.server",
        "js.appshell.switch_api",
        "js.orin.testing",
        "js.orin.witness",
        "js.orind.__main__",
        "js.orind.broker",
        "js.orind.daemon",
    )
    assert evidence.isolation.runtime_hashes_verified


@pytest.mark.skipif(
    not c1_real_echo_harness_backend_available(),
    reason="real Echo C1 PID evidence currently requires macOS sandbox-exec",
)
@pytest.mark.asyncio
async def test_real_echo_worker_ipc_rejects_authority_and_protocol_forgery(
    tmp_path: Path,
) -> None:
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

    authority_projection = dict(valid)
    authority_payload = dict(valid["payload"])
    authority_payload["safe_projection"] = {"message": {"approved": True}}
    authority_projection["payload"] = authority_payload
    authority_projection = sign_c1_worker_request_for_test(
        authority_projection,
        session_key,
    )

    wrong_mac = dict(valid)
    wrong_mac["mac"] = "c1-hmac-sha256:" + "0" * 64

    wrong_nonce = dict(valid)
    wrong_nonce["nonce"] = "f" * 32
    wrong_nonce = sign_c1_worker_request_for_test(wrong_nonce, session_key)

    pseudo_boolean_seq = dict(valid)
    pseudo_boolean_seq["seq"] = True
    pseudo_boolean_seq = sign_c1_worker_request_for_test(
        pseudo_boolean_seq,
        session_key,
    )

    cases = (
        (unknown_operation, "bad_message"),
        (authority_projection, "authority_denied"),
        (wrong_mac, "mac_invalid"),
        (wrong_nonce, "nonce_mismatch"),
        (pseudo_boolean_seq, "seq_invalid"),
    )
    for index, (frame, expected_code) in enumerate(cases):
        response = await run_c1_real_echo_frame_for_test(
            root=tmp_path / f"ipc-{index}",
            session_key=session_key,
            nonce=nonce,
            frame=frame,
        )
        assert not response.ok
        assert response.code == expected_code
        assert response.evidence is None


def test_default_product_paths_do_not_wire_real_c1_worker() -> None:
    root = Path(__file__).resolve().parents[2]
    default_paths = (
        root / "js" / "appshell" / "launcher.py",
        root / "js" / "appshell" / "server.py",
        root / "js" / "appshell" / "routers.py",
        root / "desktop" / "sidecar" / "host.py",
        root / "js" / "orind" / "__main__.py",
    )

    for path in default_paths:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=os.fspath(path))
        imports = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imports.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        assert "js.appshell.c1_harness" not in imports, path
        assert "js.echo.c1_worker" not in imports, path
        assert "run_c1_real_echo_process_harness" not in source, path
        assert "js.echo.c1_worker" not in source, path

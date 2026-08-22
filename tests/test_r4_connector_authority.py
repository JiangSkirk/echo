"""R4-A approval and lease authority regressions."""

from __future__ import annotations

import concurrent.futures
import dataclasses
import multiprocessing
import time
from pathlib import Path

import pytest

from js.echo.capability import LeaseAuthority, LeaseDenied
from js.security.approvals import (
    ApprovalDecisionType,
    ApprovalMode,
    ApprovalQueue,
)


def _resolved_approval(tmp_path: Path) -> tuple[ApprovalQueue, str, str]:
    queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    arguments = {
        "authority_binding_hash": "sha256:" + "1" * 64,
        "scope": "publish",
    }
    pending = queue.request_decision(
        "connector.local_publish.write",
        arguments,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    assert pending.action is ApprovalDecisionType.PENDING
    decision = queue.decide(
        pending.request_id,
        ApprovalDecisionType.APPROVE,
        owner_key_hash="owner-a",
    )
    assert decision.action is ApprovalDecisionType.APPROVE
    return queue, pending.request_id, queue.arguments_hash(arguments)


def _claim_approval_worker(
    ledger_path: str,
    request_id: str,
    arguments_hash: str,
    start_event: object,
    result_queue: object,
) -> None:
    start_event.wait()  # type: ignore[attr-defined]
    queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=Path(ledger_path),
    )
    try:
        queue.consume_approved_binding(
            request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="connector.local_publish.write",
            arguments_hash=arguments_hash,
            require_manual=True,
        )
    except PermissionError:
        result_queue.put("denied")  # type: ignore[attr-defined]
    else:
        result_queue.put("consumed")  # type: ignore[attr-defined]


def test_manual_approval_exact_binding_is_consumed_once(tmp_path: Path) -> None:
    queue, request_id, arguments_hash = _resolved_approval(tmp_path)
    kwargs = {
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "connector.local_publish.write",
        "arguments_hash": arguments_hash,
        "require_manual": True,
    }

    decision = queue.consume_approved_binding(request_id, **kwargs)

    assert decision.action is ApprovalDecisionType.APPROVE
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(request_id, **kwargs)


def test_manual_approval_survives_restart_and_is_claimed_once(tmp_path: Path) -> None:
    queue, request_id, arguments_hash = _resolved_approval(tmp_path)
    del queue
    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )

    decision = restarted.consume_approved_binding(
        request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_publish.write",
        arguments_hash=arguments_hash,
        require_manual=True,
    )

    assert decision.action is ApprovalDecisionType.APPROVE
    after_claim_restart = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    with pytest.raises(PermissionError):
        after_claim_restart.consume_approved_binding(
            request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="connector.local_publish.write",
            arguments_hash=arguments_hash,
            require_manual=True,
        )


def test_two_processes_claim_one_manual_approval_exactly_once(tmp_path: Path) -> None:
    queue, request_id, arguments_hash = _resolved_approval(tmp_path)
    del queue
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_claim_approval_worker,
            args=(
                str(tmp_path / "approvals.jsonl"),
                request_id,
                arguments_hash,
                start_event,
                result_queue,
            ),
        )
        for _index in range(2)
    ]
    for process in processes:
        process.start()
    start_event.set()
    results = [result_queue.get(timeout=10), result_queue.get(timeout=10)]
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    assert sorted(results) == ["consumed", "denied"]


def test_approval_sink_failure_does_not_remove_pending_request(tmp_path: Path) -> None:
    queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    pending = queue.request_decision(
        "connector.local_publish.write",
        {"authority_binding_hash": "sha256:" + "1" * 64, "scope": "publish"},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )

    def fail_sink(_event: dict[str, object]) -> None:
        raise RuntimeError("simulated authoritative sink failure")

    queue.set_echo_event_sink(fail_sink)
    with pytest.raises(RuntimeError, match="sink failure"):
        queue.decide(
            pending.request_id,
            ApprovalDecisionType.APPROVE,
            owner_key_hash="owner-a",
        )

    assert queue.get_pending_request(
        pending.request_id,
        owner_key_hash="owner-a",
    ) is not None


@pytest.mark.parametrize(
    "decision_type",
    [ApprovalDecisionType.EDIT, ApprovalDecisionType.REJECT, ApprovalDecisionType.RESPOND],
)
def test_non_approve_decision_cannot_satisfy_publish_claim(
    tmp_path: Path,
    decision_type: ApprovalDecisionType,
) -> None:
    queue = ApprovalQueue(default_mode=ApprovalMode.MANUAL)
    arguments = {"authority_binding_hash": "sha256:" + "1" * 64, "scope": "publish"}
    pending = queue.request_decision(
        "connector.local_publish.write",
        arguments,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    decision_kwargs: dict[str, object] = {}
    if decision_type is ApprovalDecisionType.EDIT:
        decision_kwargs["edited_arguments"] = {"scope": "narrowed"}
    if decision_type is ApprovalDecisionType.RESPOND:
        decision_kwargs["response"] = "needs clarification"
    queue.decide(pending.request_id, decision_type, **decision_kwargs)  # type: ignore[arg-type]

    with pytest.raises(PermissionError):
        queue.consume_approved_binding(
            pending.request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="connector.local_publish.write",
            arguments_hash=queue.arguments_hash(arguments),
            require_manual=True,
        )


def test_auto_approve_cannot_satisfy_manual_publish_claim() -> None:
    queue = ApprovalQueue(default_mode=ApprovalMode.AUTO_APPROVE)
    arguments = {"authority_binding_hash": "sha256:" + "1" * 64, "scope": "publish"}
    decision = queue.request_decision(
        "connector.local_publish.write",
        arguments,
        context="web",
        mode=ApprovalMode.AUTO_APPROVE,
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
    )

    with pytest.raises(PermissionError):
        queue.consume_approved_binding(
            decision.request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="connector.local_publish.write",
            arguments_hash=queue.arguments_hash(arguments),
            require_manual=True,
        )


def test_exact_manual_callback_approval_enters_one_shot_claim_store() -> None:
    queue = ApprovalQueue(default_mode=ApprovalMode.MANUAL)
    arguments = {"authority_binding_hash": "sha256:" + "1" * 64, "scope": "publish"}
    queue.set_callback(
        "session-a",
        lambda _request: True,
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="connector.local_publish.write",
        arguments=arguments,
    )

    decision = queue.request_decision(
        "connector.local_publish.write",
        arguments,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
    )

    assert decision.action is ApprovalDecisionType.APPROVE
    assert queue.consume_approved_binding(
        decision.request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_publish.write",
        arguments_hash=queue.arguments_hash(arguments),
        require_manual=True,
    ).action is ApprovalDecisionType.APPROVE


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("owner_key_hash", "owner-b"),
        ("session_id", "session-b"),
        ("run_id", "run-b"),
        ("tool_name", "connector.local_import.read"),
        ("arguments_hash", "sha256:" + "2" * 64),
    ],
)
def test_wrong_approval_binding_does_not_consume_exact_record(
    tmp_path: Path,
    field: str,
    wrong: str,
) -> None:
    queue, request_id, arguments_hash = _resolved_approval(tmp_path)
    kwargs = {
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "connector.local_publish.write",
        "arguments_hash": arguments_hash,
        "require_manual": True,
    }
    wrong_kwargs = {**kwargs, field: wrong}

    with pytest.raises(PermissionError):
        queue.consume_approved_binding(request_id, **wrong_kwargs)

    assert queue.consume_approved_binding(request_id, **kwargs).action is (
        ApprovalDecisionType.APPROVE
    )


def _lease_authority(tmp_path: Path) -> tuple[LeaseAuthority, object]:
    authority = LeaseAuthority(
        mac_key=b"r4-lease-test-key-is-32-bytes!!",
        now_fn=lambda: 1_000,
        ledger_path=tmp_path / "leases.jsonl",
    )
    lease = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_publish.write",
        args_schema="sha256:" + "1" * 64,
        resource_scope="connection:publish-a:publish",
        fs_roots=("/tmp/r4-publish",),
        network_policy="deny",
        network_hosts=(),
        max_bytes=1024,
        max_duration_ms=1_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    return authority, lease


def _consume_kwargs() -> dict[str, object]:
    return {
        "expected_product_id": "js-agent",
        "expected_owner": "owner-a",
        "expected_session": "session-a",
        "expected_run": "run-a",
        "expected_tool": "connector.local_publish.write",
        "expected_args_schema": "sha256:" + "1" * 64,
        "expected_resource_scope": "connection:publish-a:publish",
        "expected_fs_roots": ("/tmp/r4-publish",),
        "expected_network_policy": "deny",
        "expected_network_hosts": (),
        "expected_max_bytes": 1024,
        "expected_max_duration_ms": 1_000,
        "now": 1_000,
        "require_single_use": True,
    }


@pytest.mark.parametrize(
    ("issue_override", "expected_override"),
    [
        ({"network_policy": "allow"}, {}),
        ({"network_hosts": ("example.com",)}, {}),
        ({"max_bytes": 2048}, {}),
        ({"max_duration_ms": 2_000}, {}),
        ({"max_invocations": 2}, {}),
    ],
)
def test_consume_bound_rejects_valid_signed_lease_with_wrong_exact_ceiling(
    tmp_path: Path,
    issue_override: dict[str, object],
    expected_override: dict[str, object],
) -> None:
    authority = LeaseAuthority(
        mac_key=b"r4-lease-test-key-is-32-bytes!!",
        now_fn=lambda: 1_000,
        ledger_path=tmp_path / "leases.jsonl",
    )
    issue_kwargs: dict[str, object] = {
        "product_id": "js-agent",
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "connector.local_publish.write",
        "args_schema": "sha256:" + "1" * 64,
        "resource_scope": "connection:publish-a:publish",
        "fs_roots": ("/tmp/r4-publish",),
        "network_policy": "deny",
        "network_hosts": (),
        "max_bytes": 1024,
        "max_duration_ms": 1_000,
        "max_invocations": 1,
        "ttl_ms": 60_000,
    }
    issue_kwargs.update(issue_override)
    lease = authority.issue(**issue_kwargs)  # type: ignore[arg-type]
    consume_kwargs = {**_consume_kwargs(), **expected_override}

    with pytest.raises(LeaseDenied):
        authority.consume_bound(lease, **consume_kwargs)  # type: ignore[arg-type]


def test_consume_bound_is_atomic_and_persistent_single_use(tmp_path: Path) -> None:
    authority, lease = _lease_authority(tmp_path)
    kwargs = _consume_kwargs()

    def consume() -> str:
        try:
            authority.consume_bound(lease, **kwargs)  # type: ignore[arg-type]
        except LeaseDenied:
            return "denied"
        return "consumed"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: consume(), range(2)))

    assert sorted(results) == ["consumed", "denied"]
    restarted = LeaseAuthority(
        mac_key=b"r4-lease-test-key-is-32-bytes!!",
        now_fn=lambda: 1_000,
        ledger_path=tmp_path / "leases.jsonl",
    )
    with pytest.raises(LeaseDenied):
        restarted.consume_bound(lease, **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("product_id", "js-work"),
        ("owner_key_hash", "owner-b"),
        ("session_id", "session-b"),
        ("run_id", "run-b"),
        ("tool_name", "connector.local_import.read"),
        ("args_schema", "sha256:" + "2" * 64),
        ("resource_scope", "connection:other:publish"),
        ("fs_roots", ("/tmp/other",)),
        ("network_policy", "allow"),
        ("network_hosts", ("example.com",)),
        ("max_invocations", 2),
        ("expires_at", 999_999),
        ("mac", b"0" * 32),
    ],
)
def test_consume_bound_rejects_each_tampered_lease_field_without_consuming(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    authority, lease = _lease_authority(tmp_path)
    tampered = dataclasses.replace(lease, **{field: value})

    with pytest.raises(LeaseDenied):
        authority.consume_bound(tampered, **_consume_kwargs())  # type: ignore[arg-type]

    authority.consume_bound(lease, **_consume_kwargs())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# R4A-B2: Echo authority atomic approval claim (mirror truncation recovery)
# ---------------------------------------------------------------------------
from js.echo.ledger.service import EchoSafetyService  # noqa: E402
from js.security.approvals import (  # noqa: E402
    ApprovalEchoAuthority,
    wire_echo_approval_authority,
)


def _echo_approval_queue(
    tmp_path: Path,
) -> tuple[ApprovalQueue, EchoSafetyService, ApprovalEchoAuthority]:
    """Create an ApprovalQueue wired to a real EchoSafetyService authority."""
    service = EchoSafetyService(state_dir=tmp_path / "echo")
    authority = wire_echo_approval_authority(service, product_id="js-agent")
    queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    queue.set_echo_authority(authority)
    return queue, service, authority


def _resolved_echo_approval(
    tmp_path: Path,
) -> tuple[ApprovalQueue, str, str, EchoSafetyService, ApprovalEchoAuthority]:
    queue, service, authority = _echo_approval_queue(tmp_path)
    arguments = {
        "authority_binding_hash": "sha256:" + "1" * 64,
        "scope": "publish",
    }
    pending = queue.request_decision(
        "connector.local_publish.write",
        arguments,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    queue.decide(
        pending.request_id,
        ApprovalDecisionType.APPROVE,
        owner_key_hash="owner-a",
    )
    return queue, pending.request_id, queue.arguments_hash(arguments), service, authority


def test_echo_mirror_truncation_rebuilds_consumed(tmp_path: Path) -> None:
    """Echo has claim, mirror truncated -> approval stays consumed."""
    queue, request_id, args_hash, service, authority = _resolved_echo_approval(tmp_path)
    kwargs = {
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "connector.local_publish.write",
        "arguments_hash": args_hash,
        "require_manual": True,
    }
    queue.consume_approved_binding(request_id, **kwargs)

    # Truncate mirror: remove the last line (approval_execution_claimed)
    mirror_path = tmp_path / "approvals.jsonl"
    lines = mirror_path.read_text(encoding="utf-8").splitlines()
    del lines[-1]
    mirror_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Restart queue with same Echo authority
    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=mirror_path,
    )
    restarted.set_echo_authority(authority)

    # Must NOT be able to re-consume
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(request_id, **kwargs)


def test_echo_mirror_delete_claim_and_approved(tmp_path: Path) -> None:
    """Delete both claim and approved lines from mirror; Echo intact."""
    queue, request_id, args_hash, service, authority = _resolved_echo_approval(tmp_path)
    kwargs = {
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "connector.local_publish.write",
        "arguments_hash": args_hash,
        "require_manual": True,
    }
    queue.consume_approved_binding(request_id, **kwargs)

    mirror_path = tmp_path / "approvals.jsonl"
    lines = mirror_path.read_text(encoding="utf-8").splitlines()
    # Delete last 2 lines (claim + approved)
    del lines[-2:]
    mirror_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=mirror_path,
    )
    restarted.set_echo_authority(authority)

    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(request_id, **kwargs)


def test_echo_claimed_now_vs_already_claimed(tmp_path: Path) -> None:
    """claim_once returns claimed_now=True first, False on retry."""
    queue, request_id, args_hash, service, authority = _resolved_echo_approval(tmp_path)

    receipt1 = authority.claim_once(
        tenant_id="owner-a",
        session_id="session-a",
        run_id="run-a",
        request_id=request_id,
        tool_name="connector.local_publish.write",
        arguments_hash=args_hash,
        approval_mode="manual",
        expires_at=time.time() + 3600,
        requested_at=time.time(),
    )
    assert receipt1.claimed_now is True

    receipt2 = authority.claim_once(
        tenant_id="owner-a",
        session_id="session-a",
        run_id="run-a",
        request_id=request_id,
        tool_name="connector.local_publish.write",
        arguments_hash=args_hash,
        approval_mode="manual",
        expires_at=time.time() + 3600,
        requested_at=time.time(),
    )
    assert receipt2.claimed_now is False
    assert receipt2.request_id == receipt1.request_id


def test_echo_binding_conflict_different_binding_same_id(tmp_path: Path) -> None:
    """Same request_id but different binding -> ValueError (corruption)."""
    queue, request_id, args_hash, service, authority = _resolved_echo_approval(tmp_path)

    authority.claim_once(
        tenant_id="owner-a",
        session_id="session-a",
        run_id="run-a",
        request_id=request_id,
        tool_name="connector.local_publish.write",
        arguments_hash=args_hash,
        approval_mode="manual",
        expires_at=time.time() + 3600,
        requested_at=time.time(),
    )

    # Try to claim with different binding (different tool_name)
    with pytest.raises(ValueError, match="binding conflict"):
        authority.claim_once(
            tenant_id="owner-a",
            session_id="session-a",
            run_id="run-a",
            request_id=request_id,
            tool_name="connector.local_import.read",  # different
            arguments_hash=args_hash,
            approval_mode="manual",
            expires_at=time.time() + 3600,
            requested_at=time.time(),
        )


def test_echo_authority_set_once_sealed(tmp_path: Path) -> None:
    """set_echo_authority is set-once; second call raises."""
    service = EchoSafetyService(state_dir=tmp_path / "echo")
    authority = wire_echo_approval_authority(service, product_id="js-agent")
    queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    queue.set_echo_authority(authority)
    with pytest.raises(RuntimeError, match="already sealed"):
        queue.set_echo_authority(authority)


def _echo_claim_worker(
    state_dir: str,
    product_id: str,
    request_id: str,
    args_hash: str,
    start_event: object,
    result_queue: object,
) -> None:
    from js.echo.ledger.service import EchoSafetyService
    from js.security.approvals import wire_echo_approval_authority

    service = EchoSafetyService(state_dir=Path(state_dir))
    authority = wire_echo_approval_authority(service, product_id=product_id)
    start_event.wait()  # type: ignore[attr-defined]
    try:
        receipt = authority.claim_once(
            tenant_id="owner-a",
            session_id="session-a",
            run_id="run-a",
            request_id=request_id,
            tool_name="connector.local_publish.write",
            arguments_hash=args_hash,
            approval_mode="manual",
            expires_at=time.time() + 3600,
            requested_at=time.time(),
        )
        result_queue.put("claimed_now" if receipt.claimed_now else "already_claimed")  # type: ignore[attr-defined]
    except Exception as exc:
        result_queue.put(f"error:{type(exc).__name__}")  # type: ignore[attr-defined]


def test_two_process_echo_claim_exact_once(tmp_path: Path) -> None:
    """Two processes claim same binding; exactly one succeeds via Echo CAS."""
    queue, request_id, args_hash, service, authority = _resolved_echo_approval(tmp_path)
    del queue

    ctx = multiprocessing.get_context("spawn")
    start_event = ctx.Event()
    result_queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=_echo_claim_worker,
            args=(
                str(tmp_path / "echo"),
                "js-agent",
                request_id,
                args_hash,
                start_event,
                result_queue,
            ),
        )
        for _ in range(2)
    ]
    for p in processes:
        p.start()
    start_event.set()
    results = [result_queue.get(timeout=10), result_queue.get(timeout=10)]
    for p in processes:
        p.join(timeout=10)
        assert p.exitcode == 0

    assert sorted(results) == ["already_claimed", "claimed_now"], results

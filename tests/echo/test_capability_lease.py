"""Echo T7 — CapabilityLease policy tests.

Exercises :mod:`js.echo.capability` in isolation: MAC determinism, MAC
field-sensitivity, consume / replay / exhaustion semantics, expiry,
owner / tool / scope mismatches, tampered MACs, parent revoke
cascade, parent-missing rejection, nonce / lease_id uniqueness, and
two hermetic source-level guards (no env reads, no dangerous imports).

No real LLM / network / sandbox / filesystem / env access.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import multiprocessing
from collections.abc import Callable
from pathlib import Path

import pytest

from js.echo.capability import (
    DEFAULT_NETWORK_POLICY,
    LEASE_MAC_DOMAIN,
    LeaseAuthority,
    LeaseDenied,
    LeaseExhausted,
    LeaseExpired,
    LeaseMacInvalid,
    LeaseNonceReplay,
    LeaseOwnerMismatch,
    LeaseParentMissing,
    LeaseRevoked,
    LeaseScopeMismatch,
    LeaseToolMismatch,
    compute_lease_mac,
)
from js.echo.types import CapabilityLease

# ---------------------------------------------------------------------------
# Fixed test-only MAC key. NEVER use in production.
# ---------------------------------------------------------------------------
_TEST_KEY: bytes = b"echo-test-mac-key-do-not-use-in-prod"
_OTHER_KEY: bytes = b"echo-test-mac-key-DIFFERENT-aaaaaaaa"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_clock() -> tuple[dict[str, int], Callable[[], int]]:
    """Mutable clock dict + a now_fn that reads from it."""
    state = {"now": 0}
    return state, lambda: state["now"]


def _make_authority(*, key: bytes = _TEST_KEY) -> tuple[LeaseAuthority, dict[str, int]]:
    clock, now_fn = _make_clock()
    return LeaseAuthority(mac_key=key, now_fn=now_fn), clock


def _issue_default(
    auth: LeaseAuthority,
    *,
    owner_key_hash: str = "alice",
    run_id: str = "run-A",
    tool_name: str = "echo",
    args_schema: str = "schema-v1",
    resource_scope: str = "scope-a",
    max_bytes: int = 1024,
    max_duration_ms: int = 1_000,
    ttl_ms: int = 60_000,
    fs_roots: tuple[str, ...] = (),
    network_policy: str = DEFAULT_NETWORK_POLICY,
    max_invocations: int = 1,
    parent_lease_id: str | None = None,
) -> CapabilityLease:
    return auth.issue(
        owner_key_hash=owner_key_hash,
        run_id=run_id,
        tool_name=tool_name,
        args_schema=args_schema,
        resource_scope=resource_scope,
        max_bytes=max_bytes,
        max_duration_ms=max_duration_ms,
        ttl_ms=ttl_ms,
        fs_roots=fs_roots,
        network_policy=network_policy,
        max_invocations=max_invocations,
        parent_lease_id=parent_lease_id,
    )


def _issue_persistent_worker(
    ledger_path: str,
    start_event,
    ready_queue,
    result_queue,
    worker_id: int,
) -> None:
    try:
        authority = LeaseAuthority(
            mac_key=_TEST_KEY,
            now_fn=lambda: 0,
            ledger_path=Path(ledger_path),
        )
        ready_queue.put(worker_id)
        start_event.wait(timeout=10)
        lease = _issue_default(authority, run_id=f"run-{worker_id}")
        result_queue.put(("ok", lease.lease_id))
    except BaseException as exc:  # pragma: no cover - reported to parent
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


def _consume_persistent_worker(
    ledger_path: str,
    lease: CapabilityLease,
    start_event,
    ready_queue,
    result_queue,
    worker_id: int,
) -> None:
    auth = LeaseAuthority(
        mac_key=_TEST_KEY,
        now_fn=lambda: 0,
        ledger_path=Path(ledger_path),
    )
    ready_queue.put(worker_id)
    start_event.wait(timeout=10)
    try:
        auth.consume(lease, now=0)
    except LeaseNonceReplay:
        result_queue.put("replay")
    except BaseException as exc:  # pragma: no cover - reported to parent
        result_queue.put(f"error:{type(exc).__name__}:{exc}")
    else:
        result_queue.put("ok")


# ---------------------------------------------------------------------------
# 1. Construction validation
# ---------------------------------------------------------------------------
def test_mac_key_must_be_bytes() -> None:
    _, now_fn = _make_clock()
    with pytest.raises((ValueError, TypeError)):
        LeaseAuthority(mac_key="not-bytes-but-string", now_fn=now_fn)  # type: ignore[arg-type]


def test_mac_key_must_be_long_enough() -> None:
    _, now_fn = _make_clock()
    with pytest.raises(ValueError):
        LeaseAuthority(mac_key=b"short", now_fn=now_fn)


def test_now_fn_must_be_callable() -> None:
    with pytest.raises((TypeError, ValueError)):
        LeaseAuthority(mac_key=_TEST_KEY, now_fn=42)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 2. Issuance basics
# ---------------------------------------------------------------------------
def test_issue_returns_valid_lease() -> None:
    auth, clock = _make_authority()
    clock["now"] = 1_000
    lease = _issue_default(auth, ttl_ms=5_000)
    assert isinstance(lease.mac, bytes)
    assert len(lease.mac) == 32
    assert lease.lease_id != ""
    assert lease.nonce != ""
    assert lease.expires_at == 1_000 + 5_000


def test_issue_self_verifies() -> None:
    auth, clock = _make_authority()
    lease = _issue_default(auth)
    # Should not raise.
    auth.verify(
        lease,
        expected_owner=lease.owner_key_hash,
        expected_tool=lease.tool_name,
        expected_scope=lease.resource_scope,
        now=clock["now"],
    )


def test_mac_field_type_is_bytes() -> None:
    auth, _ = _make_authority()
    lease = _issue_default(auth)
    assert isinstance(lease.mac, bytes)


# ---------------------------------------------------------------------------
# 3. MAC determinism + key sensitivity
# ---------------------------------------------------------------------------
def test_mac_is_deterministic() -> None:
    auth, _ = _make_authority()
    lease = _issue_default(auth)
    mac1 = compute_lease_mac(_TEST_KEY, lease)
    mac2 = compute_lease_mac(_TEST_KEY, lease)
    assert mac1 == mac2
    assert mac1 == lease.mac


def test_mac_excludes_mac_field() -> None:
    """Changing only the ``mac`` field must not affect ``compute_lease_mac``."""
    auth, _ = _make_authority()
    lease = _issue_default(auth)
    tampered = dataclasses.replace(lease, mac=b"\x00" * 32)
    assert compute_lease_mac(_TEST_KEY, lease) == compute_lease_mac(_TEST_KEY, tampered)


def test_wrong_key_produces_different_mac() -> None:
    auth, _ = _make_authority()
    lease = _issue_default(auth)
    assert compute_lease_mac(_TEST_KEY, lease) != compute_lease_mac(_OTHER_KEY, lease)


# ---------------------------------------------------------------------------
# 4. MAC field sensitivity — 14 non-mac fields
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "field_name, new_value",
    [
        ("lease_id", "deadbeef" * 4),
        ("owner_key_hash", "bob"),
        ("run_id", "run-Z"),
        ("tool_name", "other-tool"),
        ("args_schema", "schema-v9"),
        ("resource_scope", "scope-z"),
        ("fs_roots", ("/tmp/extra",)),
        ("network_policy", "allow"),
        ("max_bytes", 999_999),
        ("max_duration_ms", 999_999),
        ("max_invocations", 99),
        ("nonce", "cafebabe" * 4),
        ("expires_at", 12_345_678),
        ("parent_lease_id", "deadbeef" * 4),
    ],
)
def test_mac_changes_when_each_field_changes(field_name: str, new_value: object) -> None:
    auth, _ = _make_authority()
    lease = _issue_default(auth)
    mutated = dataclasses.replace(lease, **{field_name: new_value})
    assert compute_lease_mac(_TEST_KEY, lease) != compute_lease_mac(_TEST_KEY, mutated), (
        f"MAC should change when {field_name!r} changes"
    )


# ---------------------------------------------------------------------------
# 5. Consume — single / multi / replay / exhaustion
# ---------------------------------------------------------------------------
def test_consume_single_use_replay_denied() -> None:
    auth, clock = _make_authority()
    lease = _issue_default(auth, max_invocations=1)
    auth.consume(lease, now=clock["now"])
    with pytest.raises(LeaseNonceReplay):
        auth.consume(lease, now=clock["now"])


def test_persistent_lease_ledger_replays_consumed_nonce(tmp_path: Path) -> None:
    clock, now_fn = _make_clock()
    ledger_path = tmp_path / "leases.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn, ledger_path=ledger_path)
    lease = _issue_default(auth, max_invocations=1)

    auth.consume(lease, now=clock["now"])
    restarted = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn, ledger_path=ledger_path)

    assert lease.lease_id in restarted.known_lease_ids()
    with pytest.raises(LeaseNonceReplay):
        restarted.consume(lease, now=clock["now"])


def test_persistent_lease_ledger_recovers_one_corrupt_tail(tmp_path: Path) -> None:
    clock, now_fn = _make_clock()
    ledger_path = tmp_path / "leases.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn, ledger_path=ledger_path)
    lease = _issue_default(auth)
    auth.consume(lease, now=clock["now"])
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq":')

    restarted = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn, ledger_path=ledger_path)

    assert lease.lease_id in restarted.known_lease_ids()
    with pytest.raises(LeaseNonceReplay):
        restarted.consume(lease, now=clock["now"])
    assert ledger_path.with_suffix(ledger_path.suffix + ".corrupt").is_file()


def test_persistent_lease_ledger_rejects_middle_corruption(tmp_path: Path) -> None:
    ledger_path = tmp_path / "leases.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    first = _issue_default(auth, run_id="run-1")
    _issue_default(auth, run_id="run-2")
    rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    rows[0]["payload"]["lease"]["run_id"] = "tampered"
    ledger_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows)
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="record_hash mismatch"):
        LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    assert first.lease_id


def test_persistent_lease_ledger_serializes_multi_process_issuance(
    tmp_path: Path,
) -> None:
    ctx = multiprocessing.get_context("spawn")
    ledger_path = tmp_path / "leases.jsonl"
    start_event = ctx.Event()
    ready_queue = ctx.Queue()
    result_queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=_issue_persistent_worker,
            args=(str(ledger_path), start_event, ready_queue, result_queue, worker_id),
        )
        for worker_id in range(2)
    ]
    for process in processes:
        process.start()
    assert {ready_queue.get(timeout=10), ready_queue.get(timeout=10)} == {0, 1}
    start_event.set()
    results = [result_queue.get(timeout=10), result_queue.get(timeout=10)]
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    assert all(status == "ok" for status, _value in results), results
    restarted = LeaseAuthority(
        mac_key=_TEST_KEY,
        now_fn=lambda: 0,
        ledger_path=ledger_path,
    )
    assert len(restarted.known_lease_ids()) == 2


def test_persistent_lease_ledger_allows_exactly_one_cross_process_consume(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "leases.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    lease = _issue_default(auth)
    ctx = multiprocessing.get_context("spawn")
    start_event = ctx.Event()
    ready_queue = ctx.Queue()
    result_queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=_consume_persistent_worker,
            args=(str(ledger_path), lease, start_event, ready_queue, result_queue, worker_id),
        )
        for worker_id in range(2)
    ]
    for process in processes:
        process.start()
    assert {ready_queue.get(timeout=10), ready_queue.get(timeout=10)} == {0, 1}
    start_event.set()
    results = [result_queue.get(timeout=10), result_queue.get(timeout=10)]
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    assert sorted(results) == ["ok", "replay"]


def test_consume_multi_use_exhaustion() -> None:
    """After ``max_invocations`` consumes on a multi-use lease, the
    next call raises :class:`LeaseExhausted`.

    Source behaviour: ``consume()`` keeps the nonce slot alive past
    zero *only* when ``lease.max_invocations > 1`` so the budget-gone
    case can be reported as the more informative ``LeaseExhausted``.
    Single-use leases (``max_invocations == 1``) instead burn the
    nonce immediately, so a second attempt presents as the cheaper
    ``LeaseNonceReplay`` — verified separately below.
    """
    auth, clock = _make_authority()
    lease = _issue_default(auth, max_invocations=3)
    auth.consume(lease, now=clock["now"])
    auth.consume(lease, now=clock["now"])
    auth.consume(lease, now=clock["now"])
    with pytest.raises(LeaseExhausted):
        auth.consume(lease, now=clock["now"])
    # Single-use lease: replay still presents as LeaseNonceReplay.
    auth2, _ = _make_authority()
    lease2 = _issue_default(auth2, max_invocations=1)
    auth2.consume(lease2, now=0)
    with pytest.raises(LeaseNonceReplay):
        auth2.consume(lease2, now=0)


# ---------------------------------------------------------------------------
# 6. Expiry
# ---------------------------------------------------------------------------
def test_verify_rejects_expired_lease() -> None:
    auth, clock = _make_authority()
    clock["now"] = 0
    lease = _issue_default(auth, ttl_ms=1_000)
    with pytest.raises(LeaseExpired):
        auth.verify(
            lease,
            expected_owner=lease.owner_key_hash,
            expected_tool=lease.tool_name,
            expected_scope=lease.resource_scope,
            now=lease.expires_at + 1,
        )


def test_consume_rejects_expired_lease() -> None:
    auth, clock = _make_authority()
    clock["now"] = 0
    lease = _issue_default(auth, ttl_ms=1_000)
    with pytest.raises(LeaseExpired):
        auth.consume(lease, now=lease.expires_at + 1)


# ---------------------------------------------------------------------------
# 7. Owner / tool / scope mismatch
# ---------------------------------------------------------------------------
def test_verify_owner_mismatch() -> None:
    auth, clock = _make_authority()
    lease = _issue_default(auth, owner_key_hash="alice")
    with pytest.raises(LeaseOwnerMismatch):
        auth.verify(
            lease,
            expected_owner="bob",
            expected_tool=lease.tool_name,
            expected_scope=lease.resource_scope,
            now=clock["now"],
        )


def test_verify_tool_mismatch() -> None:
    auth, clock = _make_authority()
    lease = _issue_default(auth, tool_name="echo")
    with pytest.raises(LeaseToolMismatch):
        auth.verify(
            lease,
            expected_owner=lease.owner_key_hash,
            expected_tool="other-tool",
            expected_scope=lease.resource_scope,
            now=clock["now"],
        )


def test_verify_scope_mismatch() -> None:
    auth, clock = _make_authority()
    lease = _issue_default(auth, resource_scope="scope-a")
    with pytest.raises(LeaseScopeMismatch):
        auth.verify(
            lease,
            expected_owner=lease.owner_key_hash,
            expected_tool=lease.tool_name,
            expected_scope="scope-z",
            now=clock["now"],
        )


# ---------------------------------------------------------------------------
# 8. Tampered MAC / owner
# ---------------------------------------------------------------------------
def test_tampered_mac_rejected() -> None:
    auth, clock = _make_authority()
    lease = _issue_default(auth)
    tampered = dataclasses.replace(lease, mac=b"\x00" * 32)
    with pytest.raises(LeaseMacInvalid):
        auth.verify(
            tampered,
            expected_owner=tampered.owner_key_hash,
            expected_tool=tampered.tool_name,
            expected_scope=tampered.resource_scope,
            now=clock["now"],
        )


def test_tampered_owner_rejected() -> None:
    auth, clock = _make_authority()
    lease = _issue_default(auth, owner_key_hash="alice")
    tampered = dataclasses.replace(lease, owner_key_hash="bob")
    # MAC was computed against owner=alice, so replacing owner invalidates MAC.
    with pytest.raises(LeaseMacInvalid):
        auth.verify(
            tampered,
            expected_owner="bob",
            expected_tool=tampered.tool_name,
            expected_scope=tampered.resource_scope,
            now=clock["now"],
        )


# ---------------------------------------------------------------------------
# 9. Parent chain revoke cascade
# ---------------------------------------------------------------------------
def test_parent_chain_revoke_cascades() -> None:
    auth, clock = _make_authority()
    a = _issue_default(auth, run_id="A")
    b = _issue_default(auth, run_id="B", parent_lease_id=a.lease_id)
    c = _issue_default(auth, run_id="C", parent_lease_id=b.lease_id)
    auth.revoke(a.lease_id)
    assert auth.is_revoked(a.lease_id)
    assert auth.is_revoked(b.lease_id)
    assert auth.is_revoked(c.lease_id)
    for lease in (a, b, c):
        with pytest.raises(LeaseRevoked):
            auth.verify(
                lease,
                expected_owner=lease.owner_key_hash,
                expected_tool=lease.tool_name,
                expected_scope=lease.resource_scope,
                now=clock["now"],
            )


def test_persistent_parent_revoke_cascade_survives_restart(tmp_path: Path) -> None:
    clock, now_fn = _make_clock()
    ledger_path = tmp_path / "leases.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn, ledger_path=ledger_path)
    parent = _issue_default(auth, run_id="parent")
    child = _issue_default(auth, run_id="child", parent_lease_id=parent.lease_id)
    grandchild = _issue_default(auth, run_id="grandchild", parent_lease_id=child.lease_id)

    auth.revoke(parent.lease_id)
    restarted = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn, ledger_path=ledger_path)

    assert restarted.is_revoked(parent.lease_id)
    assert restarted.is_revoked(child.lease_id)
    assert restarted.is_revoked(grandchild.lease_id)


def test_revoke_nonexistent_is_idempotent() -> None:
    auth, _ = _make_authority()
    # Should not raise.
    auth.revoke("deadbeef" * 4)
    auth.revoke("deadbeef" * 4)
    assert not auth.is_revoked("deadbeef" * 4)


def test_parent_missing_rejected_at_issue() -> None:
    auth, _ = _make_authority()
    with pytest.raises(LeaseParentMissing):
        _issue_default(auth, parent_lease_id="deadbeef" * 4)


# ---------------------------------------------------------------------------
# 10. Uniqueness — many issues
# ---------------------------------------------------------------------------
def test_nonces_are_unique_across_many_issues() -> None:
    auth, _ = _make_authority()
    nonces: set[str] = set()
    for _ in range(100):
        nonces.add(_issue_default(auth).nonce)
    assert len(nonces) == 100


def test_lease_ids_are_unique_across_many_issues() -> None:
    auth, _ = _make_authority()
    ids: set[str] = set()
    for _ in range(100):
        ids.add(_issue_default(auth).lease_id)
    assert len(ids) == 100
    assert auth.known_lease_ids() >= frozenset(ids)


# ---------------------------------------------------------------------------
# 11. Hermetic source guards
# ---------------------------------------------------------------------------
def _capability_src() -> str:
    import js.echo.capability as mod

    return Path(mod.__file__).read_text(encoding="utf-8")


def test_module_does_not_consult_env() -> None:
    """capability.py must not call os.environ.get / os.environ[ / os.getenv."""
    src = _capability_src()
    for needle in ("os.environ.get", "os.environ[", "os.getenv", "environ.get"):
        assert needle not in src, f"capability.py must not read env (found {needle!r})"


def _imported_top_levels(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    return mods


def test_module_does_not_import_dangerous_modules() -> None:
    """Capability persistence may use local OS durability APIs, never execution/network APIs."""
    import js.echo.capability as mod

    mods = _imported_top_levels(Path(mod.__file__))
    forbidden = {"subprocess", "socket", "urllib", "requests", "httpx"}
    intersect = mods & forbidden
    assert not intersect, f"capability.py imports forbidden modules: {intersect}"


# ---------------------------------------------------------------------------
# 12. Public constants
# ---------------------------------------------------------------------------
def test_lease_mac_domain_constant_value() -> None:
    assert LEASE_MAC_DOMAIN == b"echo-capability-lease-v1:"
    assert isinstance(LEASE_MAC_DOMAIN, bytes)


def test_default_network_policy_constant() -> None:
    assert DEFAULT_NETWORK_POLICY == "deny"


# ---------------------------------------------------------------------------
# 13. Exception hierarchy sanity (small belt-and-braces)
# ---------------------------------------------------------------------------
def test_exception_hierarchy() -> None:
    for sub in (
        LeaseMacInvalid,
        LeaseExpired,
        LeaseNonceReplay,
        LeaseRevoked,
        LeaseExhausted,
        LeaseOwnerMismatch,
        LeaseScopeMismatch,
        LeaseToolMismatch,
        LeaseParentMissing,
    ):
        assert issubclass(sub, LeaseDenied)


# ---------------------------------------------------------------------------
# 14. T7.1 — consume forged-input guards
# ---------------------------------------------------------------------------


def test_consume_rejects_tampered_mac() -> None:
    """consume must reject a lease with a tampered MAC and must not
    burn the underlying nonce."""
    auth, _ = _make_authority()
    real = _issue_default(auth)
    tampered = dataclasses.replace(real, mac=b"\x00" * 32)
    with pytest.raises(LeaseMacInvalid):
        auth.consume(tampered, now=0)
    # nonce 未被烧：用真 lease 仍然能 consume 一次。
    auth.consume(real, now=0)
    # 再 consume 一次应当 replay。
    with pytest.raises(LeaseNonceReplay):
        auth.consume(real, now=0)


def test_consume_rejects_tampered_expires_at_future_on_expired_lease() -> None:
    """已过期的 lease 不能通过把 expires_at 换成远未来 + 伪 MAC 绕过过期检查。"""
    auth, clock = _make_authority()
    clock["now"] = 0
    real = _issue_default(auth, ttl_ms=1_000)
    clock["now"] = real.expires_at + 1
    forged = dataclasses.replace(real, expires_at=2**62, mac=b"\x00" * 32)
    with pytest.raises(LeaseMacInvalid):
        auth.consume(forged, now=clock["now"])
    # 真 lease 在同一时钟下应当报 LeaseExpired（stored.expires_at 仍然是原值）。
    with pytest.raises(LeaseExpired):
        auth.consume(real, now=clock["now"])


def test_consume_rejects_tampered_max_invocations() -> None:
    """单次 lease consume 一次后，伪造 max_invocations=9999 不能续命。"""
    auth, _ = _make_authority()
    real = _issue_default(auth, max_invocations=1)
    auth.consume(real, now=0)
    forged = dataclasses.replace(real, max_invocations=9999, mac=b"\x00" * 32)
    # MAC fail 优先；即便实现顺序变化，也必须是 LeaseDenied 子类。
    with pytest.raises((LeaseMacInvalid, LeaseNonceReplay)):
        auth.consume(forged, now=0)


def test_consume_failed_mac_does_not_burn_nonce() -> None:
    """MAC 失败的 consume 必须不留任何副作用——再用真 lease 仍可成功。"""
    auth, _ = _make_authority()
    real = _issue_default(auth)
    tampered = dataclasses.replace(real, mac=b"\xff" * 32)
    for _ in range(5):
        with pytest.raises(LeaseMacInvalid):
            auth.consume(tampered, now=0)
    # 5 次伪造拒绝后，真 lease 仍可一次性 consume。
    auth.consume(real, now=0)


def test_consume_unknown_lease_id_rejected() -> None:
    """未在 authority 注册的 lease_id 必须被 LeaseNonceReplay 拒绝。"""
    auth, _ = _make_authority()
    real = _issue_default(auth)
    # 改 lease_id 后 MAC 会失败，但 _canonical_check 第一步就 LeaseNonceReplay
    fake = dataclasses.replace(real, lease_id="deadbeef" * 4)
    with pytest.raises(LeaseNonceReplay):
        auth.consume(fake, now=0)


def test_authority_does_not_expose_raw_mac_key() -> None:
    """LeaseAuthority 不应在公共 API 上暴露 raw HMAC key。"""
    auth, _ = _make_authority()
    # 实例层：没有公共 mac_key 属性。
    assert not hasattr(auth, "mac_key"), "LeaseAuthority must not expose mac_key on instance"
    # 类层：没有 mac_key 成员（property / 方法均不允许）。
    public_members = {
        name for name, _ in inspect.getmembers(type(auth)) if not name.startswith("_")
    }
    assert "mac_key" not in public_members, "LeaseAuthority class must not have public mac_key"
    # 私有 _mac_key 仍然保留（issue / verify / consume 内部使用）。
    assert hasattr(auth, "_mac_key"), "internal _mac_key still required"


# ---------------------------------------------------------------------------
# 15. T7.2 — stored authority record MAC self-check
# ---------------------------------------------------------------------------
def test_consume_rejects_corrupted_stored_expires_at() -> None:
    """Codex T7.1 audit PoC: tampering authority._issued[lease_id].expires_at
    must be caught by the stored-record MAC self-check; consume must NOT
    bypass expiry."""
    auth, clock = _make_authority()
    clock["now"] = 0
    real = _issue_default(auth, ttl_ms=1_000)
    clock["now"] = real.expires_at + 1
    auth._issued[real.lease_id] = dataclasses.replace(real, expires_at=2**62)
    with pytest.raises(LeaseMacInvalid):
        auth.consume(real, now=clock["now"])


def test_consume_corrupted_stored_record_does_not_burn_nonce() -> None:
    """T7.2: failure of the stored-record MAC self-check must NOT mutate
    nonce state — once the authority record is restored, the real lease
    can still consume exactly once."""
    auth, clock = _make_authority()
    clock["now"] = 0
    real = _issue_default(auth, ttl_ms=60_000)
    # 污染 stored record
    auth._issued[real.lease_id] = dataclasses.replace(real, expires_at=2**62)
    for _ in range(3):
        with pytest.raises(LeaseMacInvalid):
            auth.consume(real, now=clock["now"])
    # 恢复真 lease 后仍可 consume 一次
    auth._issued[real.lease_id] = real
    auth.consume(real, now=clock["now"])
    # 再 consume 一次必须报 replay（单次 lease，nonce 已烧）
    with pytest.raises(LeaseNonceReplay):
        auth.consume(real, now=clock["now"])


def test_consume_rejects_corrupted_stored_max_invocations() -> None:
    """T7.2: tampering stored.max_invocations must trip the MAC self-check
    before consume reads invocation budgets."""
    auth, _ = _make_authority()
    real = _issue_default(auth, max_invocations=1)
    auth._issued[real.lease_id] = dataclasses.replace(real, max_invocations=9_999)
    with pytest.raises(LeaseMacInvalid):
        auth.consume(real, now=0)


def test_consume_rejects_corrupted_stored_owner_or_scope() -> None:
    """T7.2: tampering stored.owner_key_hash or stored.resource_scope must
    trip the MAC self-check at the authority level."""
    auth, _ = _make_authority()
    real = _issue_default(auth, owner_key_hash="alice", resource_scope="scope-a")
    auth._issued[real.lease_id] = dataclasses.replace(real, owner_key_hash="evil")
    with pytest.raises(LeaseMacInvalid):
        auth.consume(real, now=0)
    # 恢复后再篡改 resource_scope
    auth._issued[real.lease_id] = dataclasses.replace(real, resource_scope="evil")
    with pytest.raises(LeaseMacInvalid):
        auth.consume(real, now=0)

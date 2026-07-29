"""Echo T7 — LeasedSandbox fail-closed tests.

Every execute() either returns a deterministic handler string or raises a
:class:`LeaseDenied` subclass — no third path. Exercises owner binding,
unknown-tool rejection, replay / exhaustion / expiry / tampering / revoke
denials, handler-exception wrapping, and source-level hermetic guards.

No real LLM / network / sandbox / filesystem / env access.
"""

from __future__ import annotations

import ast
import dataclasses
from collections.abc import Callable
from pathlib import Path

import pytest

from js.echo import spi
from js.echo.capability import (
    LeaseAuthority,
    LeaseDenied,
    LeaseExhausted,
    LeaseExpired,
    LeaseMacInvalid,
    LeaseNonceReplay,
    LeaseOwnerMismatch,
    LeaseRevoked,
    LeaseUnknownTool,
)
from js.echo.sandbox import LeasedSandbox
from js.echo.types import CapabilityLease

# ---------------------------------------------------------------------------
# Fixed test-only MAC key. NEVER use in production.
# ---------------------------------------------------------------------------
_TEST_KEY: bytes = b"echo-test-mac-key-do-not-use-in-prod"
_ALICE: str = "alice"
_BOB: str = "bob"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_clock() -> tuple[dict[str, int], Callable[[], int]]:
    state = {"now": 0}
    return state, lambda: state["now"]


def _ok_handler(_lease: CapabilityLease, arguments_hash: str) -> str:
    return f"ok:{arguments_hash}"


def _make_sb(
    *, owner: str | None = _ALICE, tool: str = "echo"
) -> tuple[LeasedSandbox, LeaseAuthority, dict[str, int]]:
    clock, now_fn = _make_clock()
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn)
    sb = LeasedSandbox(authority=auth, now_fn=now_fn)
    if owner is not None:
        sb.bind_owner(owner)
    if tool is not None:
        sb.register_handler(tool, _ok_handler)
    return sb, auth, clock


# ---------------------------------------------------------------------------
# 1. Protocol conformance
# ---------------------------------------------------------------------------
def test_sandbox_implements_protocol() -> None:
    sb, _, _ = _make_sb()
    assert isinstance(sb, spi.Sandbox)


def test_bound_owner_property() -> None:
    sb, _, _ = _make_sb(owner=None, tool="echo")
    assert sb.bound_owner is None
    sb.bind_owner(_ALICE)
    assert sb.bound_owner == _ALICE


def test_registered_tools_helper() -> None:
    sb, _, _ = _make_sb(tool="echo")
    sb.register_handler("ping", _ok_handler)
    tools = sb.registered_tools()
    assert isinstance(tools, frozenset)
    assert tools == frozenset({"echo", "ping"})


# ---------------------------------------------------------------------------
# 2. Owner binding semantics
# ---------------------------------------------------------------------------
def test_bind_owner_rejects_double_bind() -> None:
    sb, _, _ = _make_sb(owner=None, tool="echo")
    sb.bind_owner(_ALICE)
    with pytest.raises(ValueError):
        sb.bind_owner(_BOB)


def test_bind_owner_idempotent_same_owner() -> None:
    sb, _, _ = _make_sb(owner=None, tool="echo")
    sb.bind_owner(_ALICE)
    sb.bind_owner(_ALICE)  # no raise
    assert sb.bound_owner == _ALICE


def test_grant_requires_bound_owner() -> None:
    sb, _, clock = _make_sb(owner=None, tool="echo")
    with pytest.raises((ValueError, LeaseDenied)):
        sb.grant("echo", "scope-a", clock["now"])


# ---------------------------------------------------------------------------
# 3. Unknown tool / execute happy path
# ---------------------------------------------------------------------------
def test_default_sandbox_rejects_unknown_tool() -> None:
    # Sandbox bound to alice but no handler registered. Manually issue
    # a lease for `unknown-tool` via authority so we can present it.
    clock, now_fn = _make_clock()
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn)
    sb = LeasedSandbox(authority=auth, now_fn=now_fn)
    sb.bind_owner(_ALICE)
    lease = auth.issue(
        owner_key_hash=_ALICE,
        run_id="r",
        tool_name="unknown-tool",
        args_schema="s",
        resource_scope="scope-a",
        max_bytes=1024,
        max_duration_ms=1_000,
        ttl_ms=60_000,
    )
    with pytest.raises(LeaseUnknownTool):
        sb.execute(lease, "args-hash")


def test_grant_execute_happy_path() -> None:
    sb, _, clock = _make_sb()
    lease = sb.grant("echo", "scope-a", clock["now"])
    result = sb.execute(lease, "args-hash-1")
    assert isinstance(result, str)
    assert result == "ok:args-hash-1"


def test_execute_requires_bound_owner() -> None:
    # Build authority + issue a lease for alice, then construct a
    # sandbox that does not bind its owner.
    clock, now_fn = _make_clock()
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn)
    sb = LeasedSandbox(authority=auth, now_fn=now_fn)
    sb.register_handler("echo", _ok_handler)
    lease = auth.issue(
        owner_key_hash=_ALICE,
        run_id="r",
        tool_name="echo",
        args_schema="s",
        resource_scope="scope-a",
        max_bytes=1024,
        max_duration_ms=1_000,
        ttl_ms=60_000,
    )
    with pytest.raises((LeaseOwnerMismatch, LeaseDenied, ValueError)):
        sb.execute(lease, "args")


# ---------------------------------------------------------------------------
# 4. Replay / exhaustion / expiry
# ---------------------------------------------------------------------------
def test_execute_replay_denied() -> None:
    sb, _, clock = _make_sb()
    lease = sb.grant("echo", "scope-a", clock["now"])
    sb.execute(lease, "args")
    with pytest.raises(LeaseNonceReplay):
        sb.execute(lease, "args")


def test_execute_max_invocations_exhausted() -> None:
    """After ``max_invocations`` calls on a multi-use lease, the next
    ``execute`` raises :class:`LeaseExhausted`.

    Multi-use leases keep their nonce slot alive past zero so the
    budget-gone case can be reported as the more informative
    ``LeaseExhausted`` rather than the cheaper ``LeaseNonceReplay``
    used for single-use leases. See
    :func:`test_consume_multi_use_exhaustion` in
    ``test_capability_lease`` for the underlying authority contract.
    """
    clock, now_fn = _make_clock()
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn)
    sb = LeasedSandbox(authority=auth, now_fn=now_fn)
    sb.bind_owner(_ALICE)
    sb.register_handler("echo", _ok_handler)
    lease = auth.issue(
        owner_key_hash=_ALICE,
        run_id="r",
        tool_name="echo",
        args_schema="s",
        resource_scope="scope-a",
        max_bytes=1024,
        max_duration_ms=1_000,
        ttl_ms=60_000,
        max_invocations=2,
    )
    sb.execute(lease, "a")
    sb.execute(lease, "b")
    with pytest.raises(LeaseExhausted):
        sb.execute(lease, "c")


def test_execute_expired_lease_denied() -> None:
    clock, now_fn = _make_clock()
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn)
    sb = LeasedSandbox(authority=auth, now_fn=now_fn)
    sb.bind_owner(_ALICE)
    sb.register_handler("echo", _ok_handler)
    clock["now"] = 0
    lease = auth.issue(
        owner_key_hash=_ALICE,
        run_id="r",
        tool_name="echo",
        args_schema="s",
        resource_scope="scope-a",
        max_bytes=1024,
        max_duration_ms=1_000,
        ttl_ms=1_000,
    )
    clock["now"] = lease.expires_at + 1
    with pytest.raises(LeaseExpired):
        sb.execute(lease, "args")


# ---------------------------------------------------------------------------
# 5. Tampered MAC / scope / tool / revoke / owner-mismatch
# ---------------------------------------------------------------------------
def test_execute_tampered_mac_denied() -> None:
    sb, _, clock = _make_sb()
    lease = sb.grant("echo", "scope-a", clock["now"])
    tampered = dataclasses.replace(lease, mac=b"\x00" * 32)
    with pytest.raises(LeaseMacInvalid):
        sb.execute(tampered, "args")


def test_execute_scope_change_denied() -> None:
    sb, _, clock = _make_sb()
    lease = sb.grant("echo", "scope-a", clock["now"])
    tampered = dataclasses.replace(lease, resource_scope="scope-z")
    with pytest.raises(LeaseMacInvalid):
        sb.execute(tampered, "args")


def test_execute_tool_change_denied() -> None:
    sb, _, clock = _make_sb()
    # Register both tools so the tool-name lookup succeeds and we get
    # past the unknown-tool check, then trip the MAC check.
    sb.register_handler("other", _ok_handler)
    lease = sb.grant("echo", "scope-a", clock["now"])
    tampered = dataclasses.replace(lease, tool_name="other")
    with pytest.raises(LeaseMacInvalid):
        sb.execute(tampered, "args")


def test_execute_revoked_parent_denied() -> None:
    clock, now_fn = _make_clock()
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn)
    sb = LeasedSandbox(authority=auth, now_fn=now_fn)
    sb.bind_owner(_ALICE)
    sb.register_handler("echo", _ok_handler)
    parent = auth.issue(
        owner_key_hash=_ALICE,
        run_id="r",
        tool_name="echo",
        args_schema="s",
        resource_scope="scope-a",
        max_bytes=1024,
        max_duration_ms=1_000,
        ttl_ms=60_000,
    )
    child = auth.issue(
        owner_key_hash=_ALICE,
        run_id="r",
        tool_name="echo",
        args_schema="s",
        resource_scope="scope-a",
        max_bytes=1024,
        max_duration_ms=1_000,
        ttl_ms=60_000,
        parent_lease_id=parent.lease_id,
    )
    auth.revoke(parent.lease_id)
    with pytest.raises(LeaseRevoked):
        sb.execute(child, "args")


def test_execute_owner_mismatch_denied() -> None:
    clock, now_fn = _make_clock()
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn)
    sb = LeasedSandbox(authority=auth, now_fn=now_fn)
    sb.bind_owner(_ALICE)
    sb.register_handler("echo", _ok_handler)
    # Issue lease under bob; sandbox is bound to alice.
    lease = auth.issue(
        owner_key_hash=_BOB,
        run_id="r",
        tool_name="echo",
        args_schema="s",
        resource_scope="scope-a",
        max_bytes=1024,
        max_duration_ms=1_000,
        ttl_ms=60_000,
    )
    with pytest.raises(LeaseOwnerMismatch):
        sb.execute(lease, "args")


# ---------------------------------------------------------------------------
# 6. Handler-exception wrapping
# ---------------------------------------------------------------------------
def test_handler_internal_exception_wrapped() -> None:
    clock, now_fn = _make_clock()
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn)
    sb = LeasedSandbox(authority=auth, now_fn=now_fn)
    sb.bind_owner(_ALICE)

    def boom(_lease: CapabilityLease, _args: str) -> str:
        raise RuntimeError("kaboom")

    sb.register_handler("echo", boom)
    lease = sb.grant("echo", "scope-a", clock["now"])
    with pytest.raises(LeaseDenied):
        sb.execute(lease, "args")


def test_handler_non_str_return_wrapped() -> None:
    clock, now_fn = _make_clock()
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn)
    sb = LeasedSandbox(authority=auth, now_fn=now_fn)
    sb.bind_owner(_ALICE)

    def not_str(_lease: CapabilityLease, _args: str) -> str:
        return 42  # type: ignore[return-value]

    sb.register_handler("echo", not_str)
    lease = sb.grant("echo", "scope-a", clock["now"])
    with pytest.raises(LeaseDenied):
        sb.execute(lease, "args")


# ---------------------------------------------------------------------------
# 7. Source-level hermetic guards
# ---------------------------------------------------------------------------
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


def _imported_dotted(path: Path) -> set[str]:
    """Return the full dotted module names imported by ``path``."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def _echo_path(name: str) -> Path:
    import js.echo as pkg

    return Path(pkg.__file__).resolve().parent / name


def test_runtime_does_not_import_capability() -> None:
    src = _echo_path("runtime.py")
    assert src.exists(), "runtime.py missing"
    mods = _imported_dotted(src)
    assert "js.echo.capability" not in mods
    assert "js.echo.sandbox" not in mods


def test_core_does_not_import_capability() -> None:
    src = _echo_path("core.py")
    assert src.exists(), "core.py missing"
    mods = _imported_dotted(src)
    assert "js.echo.capability" not in mods
    assert "js.echo.sandbox" not in mods


def test_sandbox_module_does_not_consult_env() -> None:
    import js.echo.sandbox as mod

    src = Path(mod.__file__).read_text(encoding="utf-8")
    for needle in ("os.environ.get", "os.environ[", "os.getenv", "environ.get"):
        assert needle not in src, f"sandbox.py must not read env (found {needle!r})"


def test_sandbox_module_does_not_import_dangerous_modules() -> None:
    import js.echo.sandbox as mod

    mods = _imported_top_levels(Path(mod.__file__))
    forbidden = {"subprocess", "socket", "urllib", "requests", "httpx", "os"}
    intersect = mods & forbidden
    assert not intersect, f"sandbox.py imports forbidden modules: {intersect}"


# ---------------------------------------------------------------------------
# 8. T7.1 — execute rejects forged safety fields
# ---------------------------------------------------------------------------
def test_execute_tampered_expires_at_denied() -> None:
    """sandbox.execute 必须拒绝把 expires_at 篡改成远未来的 lease，
    并且不调用 handler。"""
    clock, now_fn = _make_clock()
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=now_fn)
    sb = LeasedSandbox(authority=auth, now_fn=now_fn)
    sb.bind_owner(_ALICE)

    calls: list[str] = []

    def _counting_handler(_lease: CapabilityLease, args_hash: str) -> str:
        calls.append(args_hash)
        return f"ok:{args_hash}"

    sb.register_handler("echo", _counting_handler)
    clock["now"] = 0
    lease = sb.grant("echo", "scope-a", clock["now"])
    # 把 lease 过期；同时伪造 expires_at 试图绕过。
    clock["now"] = lease.expires_at + 1
    forged = dataclasses.replace(lease, expires_at=2**62)
    with pytest.raises(LeaseDenied):
        sb.execute(forged, "args-hash")
    assert calls == [], "handler must not be invoked when lease is forged"

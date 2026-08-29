"""Property tests: lease consume is bound to owner/tool/args/scope."""

from __future__ import annotations

import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from js.echo.capability import DEFAULT_NETWORK_POLICY, LeaseAuthority, LeaseBindingMismatch
from js.echo.types import CapabilityLease

_TEST_KEY = b"echo-property-mac-key-16b"
_TOKEN = st.text(alphabet=string.ascii_lowercase + string.digits, min_size=3, max_size=10)


def _authority() -> LeaseAuthority:
    return LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 1_000)


def _issue(
    authority: LeaseAuthority,
    *,
    owner: str = "owner-a",
    tool: str = "shell",
    args_schema: str = "schema-a",
    scope: str = "scope-a",
    run_id: str = "run-a",
    session_id: str = "sess-a",
) -> CapabilityLease:
    return authority.issue(
        owner_key_hash=owner,
        run_id=run_id,
        tool_name=tool,
        args_schema=args_schema,
        resource_scope=scope,
        max_bytes=1024,
        max_duration_ms=1_000,
        ttl_ms=60_000,
        product_id="js-agent",
        session_id=session_id,
    )


def _consume(
    authority: LeaseAuthority,
    lease: CapabilityLease,
    **overrides: object,
) -> None:
    kwargs: dict[str, object] = {
        "expected_product_id": "js-agent",
        "expected_owner": lease.owner_key_hash,
        "expected_session": lease.session_id,
        "expected_run": lease.run_id,
        "expected_tool": lease.tool_name,
        "expected_args_schema": lease.args_schema,
        "expected_resource_scope": lease.resource_scope,
        "expected_fs_roots": tuple(lease.fs_roots),
        "expected_network_policy": DEFAULT_NETWORK_POLICY,
        "expected_network_hosts": tuple(lease.network_hosts),
        "expected_max_bytes": lease.max_bytes,
        "expected_max_duration_ms": lease.max_duration_ms,
        "now": 1_000,
    }
    kwargs.update(overrides)
    authority.consume_bound(lease, **kwargs)  # type: ignore[arg-type]


@settings(max_examples=40, deadline=None)
@given(_TOKEN, _TOKEN)
def test_wrong_tool_or_owner_fails_closed(other_tool: str, other_owner: str) -> None:
    authority = _authority()
    lease = _issue(authority)
    if other_tool != lease.tool_name:
        with pytest.raises(LeaseBindingMismatch, match="tool_name"):
            _consume(authority, lease, expected_tool=other_tool)
    if other_owner != lease.owner_key_hash:
        with pytest.raises(LeaseBindingMismatch, match="owner_key_hash"):
            _consume(authority, lease, expected_owner=other_owner)


@settings(max_examples=30, deadline=None)
@given(_TOKEN)
def test_args_schema_mismatch_fails_closed(other_schema: str) -> None:
    authority = _authority()
    lease = _issue(authority)
    if other_schema == lease.args_schema:
        return
    with pytest.raises(LeaseBindingMismatch, match="args_schema"):
        _consume(authority, lease, expected_args_schema=other_schema)


def test_matching_binding_consumes_once() -> None:
    authority = _authority()
    lease = _issue(authority)
    _consume(authority, lease)
    with pytest.raises(Exception, match="nonce|exhausted|replay"):
        _consume(authority, lease)

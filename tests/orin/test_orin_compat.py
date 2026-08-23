"""Orin Stage A compat red-line tests.

Covers A §3.3 (lease v2 encoding), A §6 checklist item 1 (old HMAC ledger
chain stays green), and the orin_enabled=false equivalence requirement.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import secrets
from pathlib import Path

import pytest

from js.echo.capability import (
    DEFAULT_CLEARANCE,
    DEFAULT_SANDBOX_PROFILE,
    DEFAULT_TAINT_FLOOR,
    DEFAULT_TAINT_SINK,
    LeaseAuthority,
    _canonical_lease_payload,
    _lease_to_payload,
    compute_lease_mac,
    lease_mac_tag,
)
from js.echo.types import CapabilityLease


@pytest.fixture()
def mac_key() -> bytes:
    return secrets.token_bytes(32)


def _legacy_lease() -> CapabilityLease:
    return CapabilityLease(
        lease_id="l1",
        owner_key_hash="owner",
        run_id="run",
        tool_name="tool",
        args_schema="args",
        resource_scope="scope",
        fs_roots=("/workspace",),
        network_policy="deny",
        max_bytes=100,
        max_duration_ms=200,
        max_invocations=1,
        nonce="nonce",
        expires_at=9_999_999,
        parent_lease_id=None,
        mac=b"",
        product_id="p",
        session_id="s",
        network_hosts=(),
    )


class TestV2Encoding:
    def test_default_fields_keep_legacy_preimage(self, mac_key: bytes) -> None:
        lease = _legacy_lease()
        mac = compute_lease_mac(mac_key, lease)
        # Recompute exactly as the pre-Orin code did.
        legacy = hmac.new(mac_key, _canonical_lease_payload(lease), hashlib.sha256).digest()
        assert mac == legacy

    def test_nondefault_field_switches_preimage(self, mac_key: bytes) -> None:
        lease = _legacy_lease()
        old_mac = compute_lease_mac(mac_key, lease)
        v2 = dataclasses.replace(lease, taint_sink=0b10)
        assert compute_lease_mac(mac_key, v2) != old_mac

    def test_mac_tag_prefixes(self, mac_key: bytes) -> None:
        lease = dataclasses.replace(_legacy_lease(), mac=compute_lease_mac(mac_key, _legacy_lease()))
        assert lease_mac_tag(lease).startswith("authority-hmac-sha256:")
        v2 = dataclasses.replace(lease, clearance=2)
        v2 = dataclasses.replace(v2, mac=compute_lease_mac(mac_key, v2))
        assert lease_mac_tag(v2).startswith("authority-hmac-sha256-v2:")

    def test_tampering_v2_field_breaks_mac(self, mac_key: bytes) -> None:
        lease = _legacy_lease()
        v2 = dataclasses.replace(lease, taint_floor=0)
        v2 = dataclasses.replace(v2, mac=compute_lease_mac(mac_key, v2))
        reset = dataclasses.replace(v2, taint_floor=DEFAULT_TAINT_FLOOR)
        assert compute_lease_mac(mac_key, reset) != v2.mac

    def test_default_v2_fields_not_serialized(self, mac_key: bytes) -> None:
        lease = _legacy_lease()
        lease = dataclasses.replace(lease, mac=compute_lease_mac(mac_key, lease))
        payload = _lease_to_payload(lease)
        assert "taint_floor" not in payload
        assert "taint_sink" not in payload
        assert "sandbox_profile" not in payload
        assert "clearance" not in payload

    def test_defaults_match_design_appendix(self) -> None:
        assert DEFAULT_TAINT_FLOOR == 0xFFFFFFFFFFFFFFFF
        assert DEFAULT_TAINT_SINK == 0
        assert DEFAULT_SANDBOX_PROFILE == 0
        assert DEFAULT_CLEARANCE == 1


class TestLegacyLedger:
    def test_old_chain_verifies_after_change(self, tmp_path: Path) -> None:
        """A ledger written before the v2 fields must replay green."""

        key = secrets.token_bytes(32)
        ledger = tmp_path / "echo_tool_lease.jsonl"
        now = 1_000_000
        writer = LeaseAuthority(mac_key=key, now_fn=lambda: now, ledger_path=ledger)
        lease = writer.issue(
            owner_key_hash="o", run_id="r", tool_name="t", args_schema="a",
            resource_scope="s", max_bytes=1, max_duration_ms=1, ttl_ms=600_000,
            product_id="p", session_id="se",
        )
        writer.consume(lease, now=now)
        writer.revoke(lease.lease_id)

        # A fresh authority (post-change code) replays the same chain.
        reader = LeaseAuthority(mac_key=key, now_fn=lambda: now, ledger_path=ledger)
        assert reader.is_revoked(lease.lease_id) is True
        stored = reader._issued[lease.lease_id]
        assert stored.mac == lease.mac

    def test_v2_leases_round_trip_through_ledger(self, tmp_path: Path) -> None:
        key = secrets.token_bytes(32)
        ledger = tmp_path / "echo_tool_lease.jsonl"
        now = 1_000_000
        auth = LeaseAuthority(mac_key=key, now_fn=lambda: now, ledger_path=ledger)
        lease = auth.issue(
            owner_key_hash="o", run_id="r", tool_name="t", args_schema="a",
            resource_scope="s", max_bytes=1, max_duration_ms=1, ttl_ms=600_000,
        )
        # WP2 will inject taint via a dedicated API; here we forge one via
        # payload round-trip to prove the ledger codec carries v2 fields.
        v2_payload = _lease_to_payload(lease)
        v2_payload["taint_sink"] = 0b100
        from js.echo.capability import _lease_from_payload

        v2_lease = _lease_from_payload(v2_payload)
        v2_lease = dataclasses.replace(
            v2_lease, mac=compute_lease_mac(key, v2_lease)
        )
        assert v2_lease.taint_sink == 0b100
        assert v2_lease.mac != lease.mac


class TestOrinDisabledEquivalence:
    def test_orin_disabled_defaults(self, tmp_path: Path) -> None:
        """orin_enabled=false must be the default with pre-Orin behavior."""

        from js.config import JSSettings

        settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "st")
        assert settings.orin.enabled is False
        assert settings.orin.fail_mode.value == "closed"
        assert settings.orin.policy_profile.value == "conservative"
        assert settings.orin.socket_path is None
        assert settings.orin.keybox_tier.value == "dev"
        assert settings.orin.shadow_mode is False

    def test_getter_returns_inprocess_authority_when_disabled(self, tmp_path: Path) -> None:
        """The tool-executor getter keeps the LeaseAuthority path when off."""

        from js.agent.tool_executor import ToolExecutorMixin

        state = tmp_path / "state"
        state.mkdir()

        class _FakeSettings:
            state_dir = str(state)
            orin = None  # type: ignore[assignment]

        class _FakeAgent(ToolExecutorMixin):  # type: ignore[misc]
            def __init__(self) -> None:
                self.settings = _FakeSettings()

        agent = _FakeAgent()
        authority = agent._get_echo_tool_lease_authority()
        assert type(authority) is LeaseAuthority
        assert (state / "echo_tool_lease.key").exists()

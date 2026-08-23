"""KeyBox adoption tests (Stage A decision 4: adopt, never rotate)."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from js.agent.tool_executor import _load_or_create_tool_lease_key
from js.echo.capability import LeaseAuthority
from js.orind.keybox import KeyBox, KeyBoxError


def _make_state(tmp_path: Path) -> Path:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    return state_dir


def test_adopts_legacy_key_without_rotation(tmp_path: Path) -> None:
    state_dir = _make_state(tmp_path)
    legacy = _load_or_create_tool_lease_key(state_dir / "echo_tool_lease.key")
    box = KeyBox(state_dir, tier="dev")
    assert box.adopted_legacy is True
    assert box.key == legacy
    assert box.active_tier == "dev"


def test_legacy_key_file_never_deleted(tmp_path: Path) -> None:
    state_dir = _make_state(tmp_path)
    _load_or_create_tool_lease_key(state_dir / "echo_tool_lease.key")
    KeyBox(state_dir, tier="dev")
    assert (state_dir / "echo_tool_lease.key").exists()


def test_fresh_key_when_no_legacy(tmp_path: Path) -> None:
    state_dir = _make_state(tmp_path)
    box = KeyBox(state_dir, tier="dev")
    assert box.adopted_legacy is False
    assert len(box.key) == 32


def test_fingerprint_idempotent(tmp_path: Path) -> None:
    state_dir = _make_state(tmp_path)
    legacy = _load_or_create_tool_lease_key(state_dir / "echo_tool_lease.key")
    first = KeyBox(state_dir, tier="dev")
    second = KeyBox(state_dir, tier="dev")
    assert first.key == second.key == legacy
    assert second.adopted_legacy is False


def test_disagreement_with_legacy_stops_start(tmp_path: Path) -> None:
    state_dir = _make_state(tmp_path)
    _load_or_create_tool_lease_key(state_dir / "echo_tool_lease.key")
    KeyBox(state_dir, tier="dev")
    # Corrupt the keybox content while keeping the fingerprint.
    keybox = state_dir / "orin" / "keybox.key"
    stored = bytes.fromhex(keybox.read_text().strip())
    tampered = bytes(stored[:16]) + bytes([stored[16] ^ 0xFF]) + stored[17:]
    keybox.write_text(tampered.hex())
    with pytest.raises(KeyBoxError):
        KeyBox(state_dir, tier="dev")


def test_fingerprint_mismatch_stops_start(tmp_path: Path) -> None:
    state_dir = _make_state(tmp_path)
    KeyBox(state_dir, tier="dev")
    fp = state_dir / "orin" / "keybox.fp"
    fp.write_text("0" * 64 + "\n")
    with pytest.raises(KeyBoxError, match="fingerprint"):
        KeyBox(state_dir, tier="dev")


def test_symlink_legacy_key_rejected(tmp_path: Path) -> None:
    state_dir = _make_state(tmp_path)
    real = state_dir / "real.key"
    real.write_text(secrets.token_bytes(32).hex())
    link = state_dir / "echo_tool_lease.key"
    link.symlink_to(real)
    with pytest.raises(KeyBoxError):
        KeyBox(state_dir, tier="dev")


def test_adopted_ledger_replays_in_place(tmp_path: Path) -> None:
    """Pre-Orin leases stay consumable after adoption (same key, same ledger)."""

    state_dir = _make_state(tmp_path)
    legacy = _load_or_create_tool_lease_key(state_dir / "echo_tool_lease.key")
    ledger = state_dir / "echo_tool_lease.jsonl"
    now = 1_000_000
    local = LeaseAuthority(mac_key=legacy, now_fn=lambda: now, ledger_path=ledger)
    lease = local.issue(
        owner_key_hash="o", run_id="r", tool_name="t", args_schema="a",
        resource_scope="s", max_bytes=1, max_duration_ms=1, ttl_ms=600_000,
        product_id="p", session_id="se",
    )
    KeyBox(state_dir, tier="dev")  # adopt
    reloaded = LeaseAuthority(mac_key=legacy, now_fn=lambda: now, ledger_path=ledger)
    stored = reloaded._issued[lease.lease_id]
    assert stored.mac == lease.mac
    reloaded.consume(stored, now=now + 1)

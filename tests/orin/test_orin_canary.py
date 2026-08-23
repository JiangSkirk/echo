"""WP3 canary matching, dual-evidence freeze, and fixed wording."""

from __future__ import annotations

import time
from pathlib import Path

from js.orin.client import OrinLeaseClientAdapter
from js.orin.testing import TestOrind
from js.orind.canary import (
    CREDENTIAL_COUNT,
    FREEZE_TEXT,
    REFUSAL_TEXT,
    SEMANTIC_COUNT,
    CanaryVault,
)
from js.orind.store import OrinStore


def test_session_mix_is_three_to_seven_tokens(tmp_path: Path) -> None:
    vault = CanaryVault(OrinStore(tmp_path / "s.db"))
    tokens = vault.ensure_session("sess", now_ms=1)
    assert len(tokens) == CREDENTIAL_COUNT + SEMANTIC_COUNT
    assert 3 <= len(tokens) <= 7
    assert sum(item.startswith("sk-orin-canary-") for item in tokens) == CREDENTIAL_COUNT


def test_literal_match_and_miss(tmp_path: Path) -> None:
    vault = CanaryVault(OrinStore(tmp_path / "s.db"))
    token = vault.ensure_session("sess", now_ms=1)[0]
    assert vault.match("sess", f"prefix {token} suffix")
    assert vault.match("sess", "harmless text") is None


def test_disabled_vault_never_matches(tmp_path: Path) -> None:
    vault = CanaryVault(OrinStore(tmp_path / "s.db"), enabled=False)
    token = vault.ensure_session("sess", now_ms=1)[0]
    assert vault.match("sess", token) is None


def test_dual_evidence_freeze_under_one_second(tmp_path: Path) -> None:
    harness = TestOrind(state_dir=tmp_path)
    harness.start()
    adapter = OrinLeaseClientAdapter(
        socket_path=harness.socket_path,
        state_dir=tmp_path,
    )
    try:
        token = harness.daemon._gatekeeper.canaries.ensure_session("sess-a", now_ms=1)[0]
        started = time.perf_counter()
        assert adapter.scan_canary(token, "read", "sess-a") is None
        result = adapter.scan_canary(f"exfil {token}", "net", "sess-a")
        elapsed = time.perf_counter() - started
        assert result == FREEZE_TEXT
        assert elapsed < 1.0
        assert "canary" not in result.lower()
        assert "honeypot" not in result.lower()
    finally:
        adapter.close()
        harness.stop()


def test_single_egress_hit_is_fixed_refusal(tmp_path: Path) -> None:
    harness = TestOrind(state_dir=tmp_path)
    harness.start()
    adapter = OrinLeaseClientAdapter(
        socket_path=harness.socket_path,
        state_dir=tmp_path,
    )
    try:
        token = harness.daemon._gatekeeper.canaries.ensure_session("sess-b", now_ms=1)[0]
        result = adapter.scan_canary(token, "shell", "sess-b")
        assert result == REFUSAL_TEXT
        assert "canary" not in result.lower()
    finally:
        adapter.close()
        harness.stop()


def test_lock_l0_and_canary_off_are_independent(tmp_path: Path) -> None:
    locked = TestOrind(state_dir=tmp_path / "lock", responder_lock_l0=True)
    locked.start()
    adapter = OrinLeaseClientAdapter(
        socket_path=locked.socket_path,
        state_dir=tmp_path / "lock",
    )
    try:
        token = locked.daemon._gatekeeper.canaries.ensure_session("sess-c", now_ms=1)[0]
        adapter.scan_canary(token, "read", "sess-c")
        assert adapter.scan_canary(token, "net", "sess-c") is None
        assert locked.daemon._gatekeeper.responder.level_of("sess-c") == 0
    finally:
        adapter.close()
        locked.stop()

    off = TestOrind(state_dir=tmp_path / "off", canary_enabled=False)
    off.start()
    adapter2 = OrinLeaseClientAdapter(
        socket_path=off.socket_path,
        state_dir=tmp_path / "off",
    )
    try:
        token = off.daemon._gatekeeper.canaries.ensure_session("sess-d", now_ms=1)[0]
        assert adapter2.scan_canary(token, "net", "sess-d") is None
    finally:
        adapter2.close()
        off.stop()


def test_closed_adapter_does_not_refuse_later_writes(tmp_path: Path) -> None:
    """OrinUnavailable is LeaseDenied — a leftover sink must not fake a hit."""

    from js.orin.hooks import inspect_canary_text, installed_canary_sink

    harness = TestOrind(state_dir=tmp_path)
    harness.start()
    adapter = OrinLeaseClientAdapter(socket_path=harness.socket_path, state_dir=tmp_path)
    try:
        assert installed_canary_sink() is not None
    finally:
        adapter.close()
        harness.stop()
    assert installed_canary_sink() is None
    assert inspect_canary_text("private", surface="write", session_id="session-a") is None

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from js.config import EchoPlanCommitConfig, GatewayConfig, JSSettings
from js.echo.plan_commit.activation import plan_commit_turn_active
from js.echo.turn_context import current_runtime_context, reset_runtime_context, set_runtime_context
from js.orin import taint as t
from js.orin.client import OrinLeaseClientAdapter
from js.orin.protocol import canonical_json, make_envelope, parse_frame
from js.orin.taint import reset_entry_source, set_entry_source
from js.orind.gatekeeper import GateKeeper
from js.orind.policy import PROFILE_COMPAT, VERDICT_ALLOW, VERDICT_DENY
from js.orind.store import OrinStore
from tests.echo.plan_commit_fakes import runtime_context


def _gate(tmp_path: Path, *, profile: str = PROFILE_COMPAT) -> GateKeeper:
    return GateKeeper(
        mac_key=b"k" * 32,
        ledger_path=tmp_path / "lease.jsonl",
        store=OrinStore(tmp_path / "orin.db"),
        key_dir=tmp_path / "keys",
        policy_profile=profile,
        now_fn=lambda: 1_000_000,
    )


def _lease_params(tool: str) -> dict[str, Any]:
    return {
        "owner_key_hash": "owner-a",
        "run_id": "run-1",
        "tool_name": tool,
        "args_schema": "args",
        "resource_scope": "scope",
        "max_bytes": 1024,
        "max_duration_ms": 1000,
        "ttl_ms": 60_000,
        "max_invocations": 1,
        "network_policy": "deny",
    }


def test_compat_cli_write_dirty_reason_is_compat(tmp_path: Path) -> None:
    gate = _gate(tmp_path)
    decision = gate._evaluate_policy(
        tool_name="file_write",
        context_taint=t.WEB_CONTENT,
        arg_taint_bits=t.WEB_CONTENT,
        args_overlap_dirty=True,
        clearance=1,
        channel="cli",
    )
    assert decision.verdict == VERDICT_ALLOW
    assert decision.reason.startswith("compat:")
    result = gate.handle_issue(
        _lease_params("file_write"),
        None,
        context_taint=t.WEB_CONTENT,
        arg_taint=t.WEB_CONTENT,
        channel="cli",
    )
    assert result["ok"] is True


def test_gateway_channel_does_not_compat_degrade(tmp_path: Path) -> None:
    gate = _gate(tmp_path)
    result = gate.handle_issue(
        _lease_params("file_write"),
        None,
        context_taint=t.WEB_CONTENT,
        arg_taint=t.WEB_CONTENT,
        channel="gateway:telegram",
    )
    assert result["ok"] is False
    assert result["code"] == "approval_required"
    assert "compat:" not in result["reason"]


def test_gateway_shell_web_is_deny_not_compat_allow(tmp_path: Path) -> None:
    gate = _gate(tmp_path)
    result = gate.handle_issue(
        _lease_params("shell"),
        None,
        context_taint=t.WEB_CONTENT,
        arg_taint=t.WEB_CONTENT,
        channel="gateway:telegram",
    )
    assert result["ok"] is False
    assert result["code"] == "policy_deny"
    assert "compat:" not in result["reason"]
    decision = gate._evaluate_policy(
        tool_name="shell",
        context_taint=t.WEB_CONTENT,
        arg_taint_bits=t.WEB_CONTENT,
        args_overlap_dirty=True,
        clearance=1,
        channel="gateway:telegram",
    )
    assert decision.verdict == VERDICT_DENY


def test_consume_remembers_gateway_lease_without_channel(tmp_path: Path) -> None:
    gate = _gate(tmp_path)
    issued = gate.handle_issue(
        _lease_params("file_write"),
        None,
        context_taint=t.USER_TURN,
        arg_taint=0,
        channel="gateway:telegram",
    )
    assert issued["ok"] is True
    consumed = gate.handle_consume(
        "consume",
        issued["lease"],
        None,
        None,
        context_taint=t.WEB_CONTENT,
        arg_taint=t.WEB_CONTENT,
        channel="",
    )
    assert consumed["ok"] is False
    assert consumed["code"] == "approval_required"
    assert "compat:" not in consumed["reason"]


def test_verify_does_not_drop_gateway_lease_stash(tmp_path: Path) -> None:
    gate = _gate(tmp_path)
    issued = gate.handle_issue(
        _lease_params("file_write"),
        None,
        context_taint=t.USER_TURN,
        arg_taint=0,
        channel="gateway:telegram",
    )
    assert issued["ok"] is True
    lease = issued["lease"]
    lease_id = str(lease["lease_id"])
    verified = gate.handle_consume(
        "verify",
        lease,
        None,
        {
            "owner": lease["owner_key_hash"],
            "tool": lease["tool_name"],
            "scope": lease["resource_scope"],
        },
        context_taint=t.USER_TURN,
        arg_taint=0,
        channel="",
    )
    assert verified["ok"] is True
    assert lease_id in gate._gateway_lease_ids
    consumed = gate.handle_consume(
        "consume",
        lease,
        None,
        None,
        context_taint=t.WEB_CONTENT,
        arg_taint=t.WEB_CONTENT,
        channel="",
    )
    assert consumed["ok"] is False
    assert consumed["code"] == "approval_required"
    assert "compat:" not in consumed["reason"]


def test_successful_consume_drops_gateway_lease_stash(tmp_path: Path) -> None:
    gate = _gate(tmp_path)
    issued = gate.handle_issue(
        _lease_params("file_write"),
        None,
        context_taint=t.USER_TURN,
        arg_taint=0,
        channel="gateway:telegram",
    )
    assert issued["ok"] is True
    lease_id = str(issued["lease"]["lease_id"])
    consumed = gate.handle_consume(
        "consume",
        issued["lease"],
        None,
        None,
        context_taint=t.USER_TURN,
        arg_taint=0,
        channel="",
    )
    assert consumed["ok"] is True
    assert lease_id not in gate._gateway_lease_ids


def test_call_propagates_runtime_channel_across_orin_thread(tmp_path: Path) -> None:
    adapter = OrinLeaseClientAdapter(
        socket_path=tmp_path / "orin.sock",
        state_dir=tmp_path / "state",
    )
    seen: dict[str, str] = {}

    async def probe() -> str:
        runtime = current_runtime_context()
        seen["channel"] = runtime.channel if runtime is not None else ""
        return "ok"

    token = set_runtime_context(runtime_context(tmp_path, channel="gateway:telegram"))
    try:
        assert adapter._call(probe) == "ok"
        captured: dict[str, Any] = {}

        class _FakeConn:
            closed = False

            async def request(self, message_type: str, **fields: Any) -> dict[str, Any]:
                captured["channel"] = fields.get("channel", "")
                captured["type"] = message_type
                return {"ok": False, "code": "denied", "reason": "probe"}

        async def _fake_connection() -> Any:
            return _FakeConn()

        adapter._connection = _fake_connection  # type: ignore[method-assign]
        try:
            adapter._call(lambda: adapter._request("issue"))
        except Exception as exc:
            assert type(exc).__name__ in {"LeaseDenied", "OrinUnavailable"}
        assert captured["type"] == "issue"
        assert captured["channel"] == "gateway:telegram"
    finally:
        reset_runtime_context(token)
        adapter.close()


def test_protocol_accepts_issue_and_consume_channel() -> None:
    key = secrets.token_bytes(32)
    nonce = secrets.token_hex(16)
    issue = make_envelope(
        "issue",
        seq=1,
        nonce=nonce,
        session_key=key,
        lease=_lease_params("file_read"),
        channel="gateway:telegram",
    )
    parsed_issue = parse_frame(canonical_json(issue).encode())
    assert parsed_issue["channel"] == "gateway:telegram"
    consume = make_envelope(
        "consume",
        seq=2,
        nonce=nonce,
        session_key=key,
        mode="consume",
        lease={
            "lease_id": "l",
            "owner_key_hash": "o",
            "run_id": "r",
            "tool_name": "t",
            "args_schema": "a",
            "resource_scope": "s",
            "nonce": "n",
            "mac": "0" * 64,
            "max_bytes": 1,
            "max_duration_ms": 1,
            "max_invocations": 1,
            "expires_at": 99,
        },
        channel="gateway:telegram",
    )
    parsed_consume = parse_frame(canonical_json(consume).encode())
    assert parsed_consume["channel"] == "gateway:telegram"


def test_gateway_enabled_defaults_plan_commit() -> None:
    settings = JSSettings(
        gateway=GatewayConfig(enabled=True),
        echo_plan_commit=EchoPlanCommitConfig(),
    )
    entry = set_entry_source("gateway:telegram")
    try:
        assert plan_commit_turn_active(settings=settings, channel="gateway:telegram")
        explicit = JSSettings(
            gateway=GatewayConfig(enabled=True),
            echo_plan_commit=EchoPlanCommitConfig(enabled=False),
        )
        assert not plan_commit_turn_active(settings=explicit, channel="gateway:telegram")
    finally:
        reset_entry_source(entry)

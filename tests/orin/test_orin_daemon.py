"""Orin daemon + adapter integration tests over a real UDS in-process."""

from __future__ import annotations

import asyncio
import os
import secrets
import time
from pathlib import Path

import pytest

from js.echo.capability import (
    LeaseAuthority,
    is_lease_authority_handle,
)
from js.orin.client import OrinLeaseClientAdapter, OrinUnavailable
from js.orin.protocol import encode_frame, make_envelope, parse_frame
from js.orin.testing import TestOrind


@pytest.fixture()
def state_dir(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir()
    return state


@pytest.fixture()
def orind(state_dir: Path) -> TestOrind:
    with TestOrind(state_dir=state_dir) as daemon:
        yield daemon


@pytest.fixture()
def adapter(orind: TestOrind, state_dir: Path) -> OrinLeaseClientAdapter:
    client = OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=state_dir,
    )
    yield client
    client.close()


def _issue_kwargs(**overrides: object) -> dict:
    kwargs: dict = {
        "owner_key_hash": "owner-1",
        "run_id": "run-1",
        "tool_name": "shell",
        "args_schema": "args-1",
        "resource_scope": "scope-1",
        "max_bytes": 1024,
        "max_duration_ms": 1000,
        "ttl_ms": 600_000,
        "product_id": "js-agent",
        "session_id": "sess-1",
        # Production turn loops always carry USER_TURN on the active window
        # (the user message is tagged at site 1); simulate that here so
        # conservative-policy shell rows allow the issue.
        "context_taint": 1,
    }
    kwargs.update(overrides)
    return kwargs


class TestAdapterSurface:
    def test_is_handle_not_authority(self, adapter: OrinLeaseClientAdapter) -> None:
        assert is_lease_authority_handle(adapter)
        assert not isinstance(adapter, LeaseAuthority)

    def test_healthy(self, adapter: OrinLeaseClientAdapter) -> None:
        assert adapter.healthy()

    def test_issue_verify_consume(self, adapter: OrinLeaseClientAdapter) -> None:
        lease = adapter.issue(**_issue_kwargs())
        now = int(time.time() * 1000)
        adapter.verify(
            lease,
            expected_owner="owner-1",
            expected_tool="shell",
            expected_scope="scope-1",
            now=now,
        )
        adapter.consume(lease, now=now)
        from js.echo.capability import LeaseDenied

        with pytest.raises(LeaseDenied):
            adapter.consume(lease, now=now)

    def test_replay_rejected(self, adapter: OrinLeaseClientAdapter) -> None:
        lease = adapter.issue(**_issue_kwargs())
        now = int(time.time() * 1000)
        from js.echo.capability import LeaseDenied

        adapter.consume(lease, now=now)
        with pytest.raises(LeaseDenied):
            adapter.consume(lease, now=now)

    def test_bound_consume_returns_ledger_receipt(
        self, adapter: OrinLeaseClientAdapter
    ) -> None:
        lease = adapter.issue(**_issue_kwargs())
        expected = {
            "expected_product_id": "js-agent",
            "expected_owner": "owner-1",
            "expected_session": "sess-1",
            "expected_run": "run-1",
            "expected_tool": "shell",
            "expected_args_schema": "args-1",
            "expected_resource_scope": "scope-1",
            "expected_fs_roots": (),
            "expected_network_policy": "deny",
            "expected_network_hosts": (),
            "expected_max_bytes": 1024,
            "expected_max_duration_ms": 1000,
        }
        adapter.verify_bound(lease, **expected)
        receipt = adapter.consume_bound(lease, **expected)
        assert receipt.lease_id == lease.lease_id
        assert receipt.ledger_record_hash.startswith("sha256:")
        assert receipt.ledger_seq >= 1

    def test_revoke_and_queries(self, adapter: OrinLeaseClientAdapter) -> None:
        lease = adapter.issue(**_issue_kwargs())
        assert adapter.is_revoked(lease.lease_id) is False
        adapter.revoke(lease.lease_id)
        assert adapter.is_revoked(lease.lease_id) is True
        sessions = adapter.active_session_ids_for_owner(owner_key_hash="owner-1")
        assert sessions == ()
        lease2 = adapter.issue(**_issue_kwargs(run_id="run-2"))
        sessions = adapter.active_session_ids_for_owner(owner_key_hash="owner-1")
        assert sessions == ("sess-1",)
        revoked = adapter.revoke_for_session(
            owner_key_hash="owner-1", session_id="sess-1"
        )
        assert lease2.lease_id in revoked


class TestContextSigning:
    def test_issue_sign_consume_round_trip(
        self, adapter: OrinLeaseClientAdapter
    ) -> None:
        from js.orin.protocol import EchoContextPayload

        lease = adapter.issue_with_context(profile="default", **_issue_kwargs())
        ctx = EchoContextPayload(
            product_id="js-agent",
            owner_key_hash="owner-1",
            session_id="sess-1",
            run_id="run-1",
            profile="default",
            tool_name="shell",
            args_hash="args-1",
            resource_scope="scope-1",
            fs_roots=(),
            network_policy="deny",
            network_hosts=(),
            max_bytes=1024,
            max_duration_ms=1000,
            lease_id=lease.lease_id,
            lease_mac=lease.mac.hex(),
        )
        import dataclasses

        now = int(time.time() * 1000)
        signature = adapter.sign_execution_context(ctx, lease, now)
        assert signature.startswith("authority-hmac-sha256:")
        signed = dataclasses.replace(ctx, signature=signature)
        from js.echo.capability import LeaseDenied

        adapter.consume_execution_context(signed, now=now)
        with pytest.raises(LeaseDenied):
            adapter.consume_execution_context(signed, now=now)

    def test_signing_lease_not_issued_here_fails_closed(
        self, adapter: OrinLeaseClientAdapter
    ) -> None:
        from js.echo.capability import LeaseContextMismatch
        from js.orin.protocol import EchoContextPayload

        issued = adapter.issue(**_issue_kwargs())
        other = adapter.issue(**_issue_kwargs(run_id="run-2"))
        ctx = EchoContextPayload(
            product_id="js-agent",
            owner_key_hash="owner-1",
            session_id="sess-1",
            run_id="run-1",
            profile="default",
            tool_name="shell",
            args_hash="args-1",
            resource_scope="scope-1",
            fs_roots=(),
            network_policy="deny",
            network_hosts=(),
            max_bytes=1024,
            max_duration_ms=1000,
        )
        with pytest.raises(LeaseContextMismatch):
            adapter.sign_execution_context(ctx, other, now=0)
        del issued


class TestFailModes:
    def test_kill_orind_closes_new_issuance(
        self, orind: TestOrind, state_dir: Path
    ) -> None:
        client = OrinLeaseClientAdapter(
            socket_path=orind.socket_path, state_dir=state_dir, fail_mode="closed"
        )
        try:
            lease = client.issue(**_issue_kwargs())
            assert lease.lease_id
            orind.stop()
            with pytest.raises(OrinUnavailable):
                client.issue(**_issue_kwargs(run_id="run-x"))
        finally:
            client.close()

    def test_readonly_fallback_for_read_only_tools(
        self, orind: TestOrind, state_dir: Path
    ) -> None:
        client = OrinLeaseClientAdapter(
            socket_path=orind.socket_path,
            state_dir=state_dir,
            fail_mode="readonly",
            readonly_tool_classifier=lambda name: name == "file_read",
        )
        try:
            orind.stop()
            lease = client.issue(**_issue_kwargs(tool_name="file_read"))
            now = int(time.time() * 1000)
            client.verify(
                lease,
                expected_owner="owner-1",
                expected_tool="file_read",
                expected_scope="scope-1",
                now=now,
            )
            client.consume(lease, now=now)
            assert client.readonly_fallback_count == 1
            with pytest.raises(OrinUnavailable):
                client.issue(**_issue_kwargs(tool_name="shell"))
        finally:
            client.close()

    def test_readonly_without_classifier_fails_closed(
        self, orind: TestOrind, state_dir: Path
    ) -> None:
        client = OrinLeaseClientAdapter(
            socket_path=orind.socket_path,
            state_dir=state_dir,
            fail_mode="readonly",
        )
        try:
            orind.stop()
            with pytest.raises(OrinUnavailable):
                client.issue(**_issue_kwargs(tool_name="file_read"))
        finally:
            client.close()


class TestSingleLedger:
    def test_rollback_sees_orin_leases(
        self, orind: TestOrind, state_dir: Path
    ) -> None:
        """orin_enabled=false rollback keeps WP1 leases (one JSONL, no fork)."""

        from js.agent.tool_executor import _load_or_create_tool_lease_key

        client = OrinLeaseClientAdapter(
            socket_path=orind.socket_path, state_dir=state_dir
        )
        try:
            lease = client.issue(**_issue_kwargs())
        finally:
            client.close()
        orind.stop()

        key = _load_or_create_tool_lease_key(state_dir / "echo_tool_lease.key")
        local = LeaseAuthority(
            mac_key=key,
            now_fn=lambda: int(time.time() * 1000),
            ledger_path=state_dir / "echo_tool_lease.jsonl",
        )
        assert lease.lease_id in local.known_lease_ids()
        local.verify(
            lease,
            expected_owner="owner-1",
            expected_tool="shell",
            expected_scope="scope-1",
            now=int(time.time() * 1000),
        )
        local.consume(lease, now=int(time.time() * 1000))

    def test_fresh_key_generation_mirrors_legacy(
        self, state_dir: Path
    ) -> None:
        """orind fresh keys mirror to echo_tool_lease.key for rollback."""

        from js.agent.tool_executor import _load_or_create_tool_lease_key

        assert not (state_dir / "echo_tool_lease.key").exists()
        with TestOrind(state_dir=state_dir) as orind:
            key = _load_or_create_tool_lease_key(state_dir / "echo_tool_lease.key")
            assert key == orind.daemon._keybox.key


class TestAttackSurface:
    async def _fresh_session(self, orind: TestOrind, state_dir: Path):
        reader, writer = await asyncio.open_unix_connection(path=str(orind.socket_path))
        hello = make_envelope(
            "hello", seq=1, nonce=secrets.token_hex(16), session_key=None,
            caps=["lease.v2"], pid=os.getpid(),
        )
        writer.write(encode_frame(hello))
        await writer.drain()
        ack = await self._read_frame(reader)
        assert ack["type"] == "hello_ack"
        key_file = state_dir / "orin" / f"session-{os.getpid()}.key"
        session_key = key_file.read_bytes()
        key_file.unlink()
        return reader, writer, hello["nonce"] + ack["server_nonce"], session_key

    async def _read_frame(self, reader: asyncio.StreamReader) -> dict:
        header = await reader.readexactly(4)
        length = int.from_bytes(header, "big")
        payload = await reader.readexactly(length)
        return parse_frame(payload)

    async def test_forged_mac_disconnects(self, orind: TestOrind, state_dir: Path) -> None:
        reader, writer, nonce, key = await self._fresh_session(orind, state_dir)
        env = make_envelope("heartbeat", seq=2, nonce=nonce, session_key=key)
        env["mac"] = "orin-hmac-sha256:" + "0" * 64
        writer.write(encode_frame(env))
        await writer.drain()
        with pytest.raises((asyncio.IncompleteReadError, asyncio.TimeoutError)):
            await asyncio.wait_for(self._read_frame(reader), timeout=2.0)
        writer.close()

    async def test_seq_replay_disconnects(self, orind: TestOrind, state_dir: Path) -> None:
        reader, writer, nonce, key = await self._fresh_session(orind, state_dir)
        env = make_envelope("heartbeat", seq=2, nonce=nonce, session_key=key)
        writer.write(encode_frame(env))
        await writer.drain()
        assert (await self._read_frame(reader)).get("ok") is True
        writer.write(encode_frame(env))  # replay
        await writer.drain()
        with pytest.raises((asyncio.IncompleteReadError, asyncio.TimeoutError)):
            await asyncio.wait_for(self._read_frame(reader), timeout=2.0)
        writer.close()

    async def test_unknown_field_disconnects(self, orind: TestOrind, state_dir: Path) -> None:
        reader, writer, nonce, key = await self._fresh_session(orind, state_dir)
        env = make_envelope("heartbeat", seq=2, nonce=nonce, session_key=key)
        env["surprise"] = 1
        writer.write(encode_frame(env))
        await writer.drain()
        with pytest.raises((asyncio.IncompleteReadError, asyncio.TimeoutError)):
            await asyncio.wait_for(self._read_frame(reader), timeout=2.0)
        writer.close()

    async def test_oversize_frame_disconnects(self, orind: TestOrind, state_dir: Path) -> None:
        reader, writer, _nonce, _key = await self._fresh_session(orind, state_dir)
        writer.write(b"\xff\xff\xff\xff" + b"x" * 128)
        await writer.drain()
        with pytest.raises((asyncio.IncompleteReadError, asyncio.TimeoutError)):
            await asyncio.wait_for(self._read_frame(reader), timeout=2.0)
        writer.close()

    async def test_flood_rate_limited_daemon_survives(
        self, orind: TestOrind, state_dir: Path
    ) -> None:
        reader, writer, nonce, key = await self._fresh_session(orind, state_dir)
        for i in range(300):
            env = make_envelope("heartbeat", seq=i + 2, nonce=nonce, session_key=key)
            writer.write(encode_frame(env))
        await writer.drain()
        allowed = 0
        rate_limited = 0
        for _ in range(300):
            try:
                resp = await asyncio.wait_for(self._read_frame(reader), timeout=5.0)
            except (asyncio.IncompleteReadError, TimeoutError):
                break
            if resp.get("code") == "rate_limited":
                rate_limited += 1
            elif resp.get("ok"):
                allowed += 1
        assert rate_limited > 0, "token bucket never engaged"
        writer.close()
        # daemon still serves new sessions
        reader2, writer2, nonce2, key2 = await self._fresh_session(orind, state_dir)
        env = make_envelope("heartbeat", seq=2, nonce=nonce2, session_key=key2)
        writer2.write(encode_frame(env))
        await writer2.drain()
        assert (await self._read_frame(reader2)).get("ok") is True
        writer2.close()

    async def test_session_key_file_is_one_shot(self, orind: TestOrind, state_dir: Path) -> None:
        reader, writer, _nonce, _key = await self._fresh_session(orind, state_dir)
        writer.close()
        # the key file was unlinked by the client read (one-shot property)
        key_file = state_dir / "orin" / f"session-{os.getpid()}.key"
        assert not key_file.exists()

    async def test_cell_socket_rejects_declared_pid_when_kernel_pid_is_zero(
        self,
        state_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        declared_pid = os.getpid()
        with TestOrind(state_dir=state_dir, stage_b=True) as orind:
            daemon = orind.daemon
            daemon._expected_cell_caps_by_pid[declared_pid] = frozenset(  # noqa: SLF001
                {"cell.file"}
            )
            monkeypatch.setattr(
                daemon,
                "_check_peer",
                lambda _writer: (os.geteuid(), 0),
            )
            reader, writer = await asyncio.open_unix_connection(
                path=str(daemon.cell_socket_path)
            )
            hello = make_envelope(
                "hello",
                seq=1,
                nonce=secrets.token_hex(16),
                session_key=None,
                caps=["cell.file"],
                pid=declared_pid,
            )
            writer.write(encode_frame(hello))
            try:
                await writer.drain()
            except ConnectionError:
                pass
            try:
                with pytest.raises((asyncio.IncompleteReadError, TimeoutError)):
                    await asyncio.wait_for(reader.readexactly(4), timeout=1.0)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass
            assert daemon._cell_by_cap("cell.file") is None  # noqa: SLF001
            assert not (state_dir / "orin" / f"session-{declared_pid}.key").exists()
            assert any(
                event.get("event") == "handshake_rejected"
                and event.get("reason") == "cell peer pid unavailable"
                for event in daemon.audit_events()
            )

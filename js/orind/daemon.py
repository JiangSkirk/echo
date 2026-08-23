"""orind daemon: single-threaded asyncio server over a Unix domain socket.

Connection lifecycle (orin/v1):

1. ``accept`` → peer credentials checked (macOS ``LOCAL_PEERTOKEN``
   audit token when available, ``getpeereid`` fallback; the check is
   fail-closed: no credentials, no session).
2. ``hello`` → orind generates a fresh 32-byte session key, publishes it
   at ``<state_dir>/orin/session-<peer_pid>.key`` (0600, one-shot), and
   replies ``hello_ack``. A new connection (i.e. a main-process restart)
   always gets a fresh key — keys rotate per connection.
3. Every later frame must carry a valid HMAC (session key) and a strictly
   monotonic ``seq``; regression, replay, or bad MAC drops the connection
   and is audited.
4. Per-connection token bucket (100 req/s, burst 200); exhausted buckets
   answer ``rate_limited`` error acks. Clients that never read responses
   (write-buffer flooding) are disconnected.

The decision path never calls a model, a classifier, or content semantics.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
import socket
import stat
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any

from js.orin.protocol import (
    HEARTBEAT_INTERVAL_S,
    MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
    RATE_LIMIT_BURST,
    RATE_LIMIT_PER_SECOND,
    SERVER_CAPS,
    SERVER_QUEUE_DEPTH,
    SESSION_KEY_BYTES,
    ProtocolError,
    encode_frame,
    make_envelope,
    parse_frame,
    verify_mac,
)
from js.orind.gatekeeper import GateKeeper
from js.orind.keybox import KeyBox, KeyBoxError
from js.orind.store import OrinStore

SOL_LOCAL = 0
LOCAL_PEERCRED = 1
LOCAL_PEERTOKEN = 2

WRITE_BUFFER_HIGH_WATER = MAX_FRAME_BYTES * 128
"""Disconnect clients that let our response backlog grow past this."""


class OrinDaemonError(Exception):
    """Daemon failed to start."""


def peer_credentials(sock: socket.socket) -> tuple[int, int] | None:
    """Return ``(euid, pid)`` for the connected peer, or ``None``.

    macOS empirics (verified on this platform): ``LOCAL_PEERTOKEN`` may
    return a 4-byte pid-only value or the full 32-byte audit_token_t
    (euid at val[1], pid at val[5]); ``LOCAL_PEERCRED`` returns
    ``struct ucred`` whose pid is often 0 but whose uid is reliable.
    Linux: ``SO_PEERCRED`` (pid, uid, gid). The caller treats ``None``
    as a validation failure (fail closed); a zero pid means "unknown"
    and callers fall back to the client-declared pid.
    """

    system = sys.platform
    if system == "darwin":
        euid: int | None = None
        pid: int | None = None
        with contextlib.suppress(OSError):
            token = sock.getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN, 32)
            if len(token) >= 32:
                values = [int.from_bytes(token[i : i + 4], "little") for i in range(0, 32, 4)]
                euid = values[1]
                pid = values[5]
            elif len(token) >= 4:
                pid = int.from_bytes(token[:4], "little")
        with contextlib.suppress(OSError):
            cred = sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, 12)
            if len(cred) >= 12:
                _cpid, uid, _gid = struct_unpack("iii", cred)
                if euid is None:
                    euid = int(uid)
                if not pid:
                    pid = int(_cpid) or pid
        if euid is None:
            return None
        return (euid, pid or 0)
    if system.startswith("linux"):
        with contextlib.suppress(OSError):
            cred = sock.getsockopt(socket.SOL_SOCKET, LOCAL_PEERCRED, 12)
            if len(cred) >= 12:
                cpid, uid, _gid = struct_unpack("iii", cred)
                return (int(uid), int(cpid))
        return None
    return None


def struct_unpack(fmt: str, data: bytes) -> tuple[int, ...]:
    import struct

    return struct.unpack(fmt, data)


class _TokenBucket:
    """Classic token bucket: ``rate`` tokens/s, capacity ``burst``."""

    __slots__ = ("_rate", "_burst", "_tokens", "_last")

    def __init__(
        self, rate: float = RATE_LIMIT_PER_SECOND, burst: float = RATE_LIMIT_BURST
    ) -> None:
        self._rate = float(rate)
        self._burst = float(burst)
        self._tokens = float(burst)
        self._last = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        self._tokens = min(self._burst, self._tokens + (now - self._last) * self._rate)
        self._last = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class _Session:
    """One authenticated client connection."""

    def __init__(
        self,
        *,
        session_key: bytes,
        session_nonce: str,
        peer: tuple[int, int],
    ) -> None:
        self.session_key = session_key
        self.session_nonce = session_nonce
        self.peer = peer
        self.last_client_seq = 0
        self.last_server_seq = 0
        self.bucket = _TokenBucket()
        self.frames_seen = 0
        self.created_at = time.monotonic()
        self.audit: deque[dict[str, Any]] = deque(maxlen=256)

    def next_server_seq(self) -> int:
        self.last_server_seq += 1
        return self.last_server_seq


class OrinDaemon:
    """Serves the orin/v1 protocol on one Unix domain socket."""

    def __init__(
        self,
        *,
        state_dir: Path,
        socket_path: Path | None = None,
        orin_dir: Path | None = None,
        keybox_tier: str = "dev",
        policy_profile: str = "conservative",
        shadow_mode: bool = False,
        canary_enabled: bool = True,
        responder_lock_l0: bool = False,
        patrol_record_only: bool = False,
        now_fn: Any = None,
    ) -> None:
        self._state_dir = state_dir
        self._socket_path = socket_path or (state_dir / "orin" / "orind.sock")
        self._orin_dir = orin_dir or self._socket_path.parent
        self._orin_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._orin_dir, 0o700)
        try:
            self._keybox = KeyBox(state_dir, tier=keybox_tier)
        except KeyBoxError as exc:
            raise OrinDaemonError(str(exc)) from exc
        self._store = OrinStore(self._orin_dir / "orind_state.db")
        gate_kwargs: dict[str, Any] = {
            "mac_key": self._keybox.key,
            "ledger_path": state_dir / "echo_tool_lease.jsonl",
            "store": self._store,
            "key_dir": self._orin_dir,
            "policy_profile": policy_profile,
            "shadow_mode": shadow_mode,
            "canary_enabled": canary_enabled,
            "responder_lock_l0": responder_lock_l0,
            "patrol_record_only": patrol_record_only,
        }
        if now_fn is not None:
            gate_kwargs["now_fn"] = now_fn
        self._gatekeeper = GateKeeper(**gate_kwargs)
        self._server: asyncio.AbstractServer | None = None
        self._sessions: dict[asyncio.StreamWriter, _Session] = {}
        self._handler_tasks: set[asyncio.Task[None]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._audit_log: deque[dict[str, Any]] = deque(maxlen=1024)

    # -- lifecycle -----------------------------------------------------------
    @property
    def socket_path(self) -> Path:
        return self._socket_path

    @property
    def gatekeeper(self) -> GateKeeper:
        return self._gatekeeper

    @property
    def keybox_tier(self) -> str:
        return self._keybox.active_tier

    def audit_events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._audit_log)

    def _audit(self, event: str, **fields: Any) -> None:
        record = {"event": event, **fields}
        self._audit_log.append(record)

    async def start(self) -> None:
        if self._server is not None:
            return
        self._loop = asyncio.get_running_loop()
        with contextlib.suppress(FileNotFoundError):
            self._socket_path.unlink()
        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=str(self._socket_path),
        )
        os.chmod(self._socket_path, 0o600)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for task in tuple(self._handler_tasks):
            task.cancel()
        for session_writer in tuple(self._sessions.keys()):
            session_writer.close()
        if self._handler_tasks:
            await asyncio.gather(*self._handler_tasks, return_exceptions=True)
        self._handler_tasks.clear()
        with contextlib.suppress(FileNotFoundError):
            self._socket_path.unlink()
        self._store.close()

    # -- freeze push (WP3 Responder drives this) ------------------------------
    def push_freeze(self, reason_code: str) -> None:
        """Send a one-way ``freeze`` to every connected client."""

        if self._loop is None or self._loop.is_closed():
            return
        for writer, session in list(self._sessions.items()):
            self._loop.call_soon_threadsafe(self._send_freeze_to, writer, session, reason_code)

    # -- connection handling ---------------------------------------------------
    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._handler_tasks.add(task)
        try:
            peer = self._check_peer(writer)
            if peer is None:
                writer.close()
                return
            session = await self._handshake(reader, writer, peer)
            if session is None:
                writer.close()
                return
            self._sessions[writer] = session
            await self._serve(reader, writer, session)
        finally:
            self._handler_tasks.discard(asyncio.current_task())
            self._sessions.pop(writer, None)
            writer.close()

    def _check_peer(self, writer: asyncio.StreamWriter) -> tuple[int, int] | None:
        sock = writer.get_extra_info("socket")
        if sock is None:
            return None
        creds = peer_credentials(sock)
        if creds is None:
            self._audit("peer_rejected", reason="no credentials")
            return None
        euid, pid = creds
        if euid != os.geteuid():
            self._audit("peer_rejected", reason="euid mismatch", peer_euid=euid, peer_pid=pid)
            return None
        return (euid, pid)

    async def _handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer: tuple[int, int],
    ) -> _Session | None:
        try:
            envelope = await self._read_frame(reader)
        except (ProtocolError, asyncio.IncompleteReadError, ConnectionError):
            return None
        if envelope is None or envelope["type"] != "hello":
            self._audit("handshake_rejected", reason="first frame not hello")
            return None
        caps = envelope.get("caps") or []
        if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
            return None
        observed_euid, observed_pid = peer
        declared_pid = envelope.get("pid")
        if observed_pid:
            if not isinstance(declared_pid, int) or declared_pid != observed_pid:
                self._audit(
                    "handshake_rejected",
                    reason="declared pid disagrees with peer credentials",
                    observed_pid=observed_pid,
                )
                return None
            session_pid = observed_pid
        elif isinstance(declared_pid, int) and declared_pid > 0:
            session_pid = declared_pid
        else:
            self._audit("handshake_rejected", reason="no usable peer pid")
            return None
        client_nonce = envelope["nonce"]
        session_key = secrets.token_bytes(SESSION_KEY_BYTES)
        key_file = self._orin_dir / f"session-{session_pid}.key"
        if not self._publish_session_key(key_file, session_key):
            return None
        server_nonce = secrets.token_hex(16)
        session = _Session(
            session_key=session_key,
            session_nonce=client_nonce + server_nonce,
            peer=(observed_euid, session_pid),
        )
        ack = make_envelope(
            "hello_ack",
            seq=session.next_server_seq(),
            nonce=session.session_nonce,
            session_key=None,
            ok=True,
            caps=list(SERVER_CAPS),
            server_nonce=server_nonce,
        )
        writer.write(encode_frame(ack))
        await writer.drain()
        self._audit("handshake_ok", peer_pid=session_pid)
        return session

    def _publish_session_key(self, key_file: Path, key: bytes) -> bool:
        try:
            with contextlib.suppress(FileNotFoundError):
                key_file.unlink()
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
            return stat.S_IMODE(key_file.lstat().st_mode) == 0o600
        except OSError:
            self._audit("session_key_publish_failed", path=str(key_file))
            return False

    async def _serve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session: _Session,
    ) -> None:
        while True:
            try:
                envelope = await self._read_frame(reader)
            except (ProtocolError, asyncio.IncompleteReadError, ConnectionError):
                self._audit("connection_dropped", peer_pid=session.peer[1])
                return
            if envelope is None:
                continue
            if not self._enforce_stream(writer, session, envelope):
                return
            if not session.bucket.allow():
                self._send_ack(
                    writer,
                    session,
                    envelope,
                    {
                        "ok": False,
                        "code": "rate_limited",
                        "reason": "token bucket exhausted",
                    },
                )
                session.frames_seen += 1
                if session.frames_seen > SERVER_QUEUE_DEPTH:
                    self._audit("slow_client_disconnected", peer_pid=session.peer[1])
                    return
                continue
            response = self._dispatch(envelope, session)
            self._send_ack(writer, session, envelope, response)

    def _enforce_stream(
        self,
        writer: asyncio.StreamWriter,
        session: _Session,
        envelope: dict[str, Any],
    ) -> bool:
        seq = envelope["seq"]
        if envelope["type"] in ("hello", "hello_ack"):
            self._audit("protocol_violation", reason="hello inside session", seq=seq)
            return False
        if not verify_mac(session.session_key, envelope):
            self._audit("protocol_violation", reason="bad mac", seq=seq, peer_pid=session.peer[1])
            return False
        if seq <= session.last_client_seq:
            self._audit("protocol_violation", reason="seq regression or replay", seq=seq)
            return False
        session.last_client_seq = seq
        session.frames_seen += 1
        if writer.transport.get_write_buffer_size() > WRITE_BUFFER_HIGH_WATER:
            self._audit("backpressure_disconnect", peer_pid=session.peer[1])
            return False
        return True

    def _dispatch(self, envelope: dict[str, Any], session: _Session) -> dict[str, Any]:
        message_type = envelope["type"]
        if message_type == "heartbeat":
            return {"ok": True, "healthy": True}
        if message_type == "issue":
            return self._gatekeeper.handle_issue(
                envelope.get("lease") or {},
                envelope.get("context"),
                context_taint=int(envelope.get("context_taint") or 0),
                arg_taint=int(envelope.get("arg_taint") or 0),
                clearance=int(envelope.get("clearance") or 1),
            )
        if message_type == "consume":
            return self._gatekeeper.handle_consume(
                str(envelope.get("mode", "")),
                envelope.get("lease"),
                envelope.get("context"),
                envelope.get("expected"),
                context_taint=int(envelope.get("context_taint") or 0),
                arg_taint=int(envelope.get("arg_taint") or 0),
                clearance=int(envelope.get("clearance") or 1),
                scan_text=str(envelope.get("scan_text") or ""),
                scan_surface=str(envelope.get("scan_surface") or ""),
                session_id=str(envelope.get("session_id") or ""),
            )
        if message_type == "revoke":
            return self._gatekeeper.handle_revoke(
                str(envelope.get("op") or ""),
                envelope.get("lease_id"),
                envelope.get("owner_key_hash"),
                envelope.get("session_id"),
            )
        self._audit("protocol_violation", reason=f"client sent {message_type}")
        return {"ok": False, "code": "bad_message", "reason": "unexpected message"}

    def _send_ack(
        self,
        writer: asyncio.StreamWriter,
        session: _Session,
        request: dict[str, Any],
        response: dict[str, Any],
    ) -> None:
        message_type = request["type"]
        ack_type = "hello_ack" if message_type == "hello" else message_type + "_ack"
        envelope = make_envelope(
            ack_type,
            seq=request["seq"],
            nonce=session.session_nonce,
            session_key=session.session_key,
            **response,
        )
        try:
            writer.write(encode_frame(envelope))
        except (ConnectionError, RuntimeError):
            pass

    def _send_freeze_to(
        self,
        writer: asyncio.StreamWriter,
        session: _Session,
        reason_code: str,
    ) -> None:
        envelope = make_envelope(
            "freeze",
            seq=session.next_server_seq(),
            nonce=session.session_nonce,
            session_key=session.session_key,
            reason_code=reason_code,
        )
        try:
            writer.write(encode_frame(envelope))
        except (ConnectionError, RuntimeError):
            pass

    async def _read_frame(self, reader: asyncio.StreamReader) -> dict[str, Any] | None:
        header = await reader.readexactly(4)
        length = int.from_bytes(header, "big")
        if length <= 0 or length > MAX_FRAME_BYTES:
            raise ProtocolError("frame length out of bounds")
        payload = await reader.readexactly(length)
        envelope = parse_frame(payload)
        if envelope["v"] != PROTOCOL_VERSION:
            raise ProtocolError("unsupported protocol version")
        return envelope


async def run_daemon(
    *,
    state_dir: Path,
    socket_path: Path | None = None,
    keybox_tier: str = "dev",
) -> None:
    """Foreground entry (``--dev`` mode); launchd manages restarts in prod."""

    daemon = OrinDaemon(
        state_dir=state_dir,
        socket_path=socket_path,
        keybox_tier=keybox_tier,
    )
    await daemon.start()
    print(f"orind listening on {daemon.socket_path} (keybox tier: {daemon.keybox_tier})")
    try:
        await asyncio.Event().wait()
    finally:
        await daemon.stop()


__all__ = [
    "HEARTBEAT_INTERVAL_S",
    "OrinDaemon",
    "OrinDaemonError",
    "peer_credentials",
    "run_daemon",
]

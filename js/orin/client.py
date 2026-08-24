"""Main-process Orin client: the IPC lease-authority adapter.

``OrinLeaseClientAdapter`` implements the :class:`LeaseAuthority` method
surface over the orin/v1 protocol. It never holds the lease MAC key, never
subclasses :class:`LeaseAuthority` (the handle check rejects subclasses),
and fails closed: when orind is unreachable it raises :class:`OrinUnavailable`
— except under ``fail_mode='readonly'`` where read-only tools may draw
ephemeral in-memory leases from a *separate* random key (the adopted
legacy key is never read by the main process once Orin is enabled).

Context signing: the adapter asks orind to sign the execution context at
issue time (``issue_ack.context_signature``) and serves it through
:meth:`sign_execution_context`. A context that was not freshly issued
through this adapter cannot be signed — fail closed.

Threading: the adapter owns a dedicated background event-loop thread.
Sync calls block on ``run_coroutine_threadsafe`` futures for the IPC round
trip (sub-millisecond); async callers block for that duration in Stage A.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar, cast

from js.echo.capability import (
    LeaseAuthority,
    LeaseConsumeReceipt,
    LeaseContextMismatch,
    LeaseDenied,
    LeaseMacInvalid,
    _lease_from_payload,
    _lease_to_payload,
)
from js.echo.types import CapabilityLease
from js.orin.hooks import install_canary_sink, installed_canary_sink
from js.orin.protocol import (
    CLIENT_CAPS,
    HEARTBEAT_INTERVAL_S,
    MAX_FRAME_BYTES,
    STAGE_B_CLIENT_CAPS,
    EchoContextPayload,
    ProtocolError,
    encode_frame,
    make_envelope,
    parse_frame,
    verify_mac,
)
from js.orind.canary import FREEZE_TEXT, REFUSAL_TEXT

REQUEST_TIMEOUT_S = 10.0
CONNECT_TIMEOUT_S = 5.0

_T = TypeVar("_T")

_FUTURES_ERRORS = (ConnectionError, OSError, ProtocolError)

_FILE_COMPONENT_MAX_BYTES = 255
_FILE_PATH_MAX_BYTES = 1_024
_FILE_TOOL_NAMES = frozenset({"file_write", "file_edit"})
_FILE_RESULT_FIELDS = frozenset(
    {
        "status",
        "error",
        "remote_operation_id",
        "duplicate",
        "files",
        "bytes_written",
        "diff_hash",
        "overwrites",
        "commit_guarantee",
    }
)


@dataclass(frozen=True, slots=True)
class _FileBinding:
    """One AppShell-confirmed task/DirectoryHandle binding held in memory."""

    appshell_owner: str
    appshell_session: str
    profile: str
    appshell_epoch: int
    installation_owner: str
    product_id: str
    task_id: str
    directory_handle_id: str
    workspace_root: str
    expires_at_ms: int


_FileBindingKey = tuple[str, str, str, int]


class OrinUnavailable(LeaseDenied):
    """orind is unreachable or misbehaving; callers must fail closed."""


class OrinRateLimited(LeaseDenied):
    """orind's token bucket rejected the request (backpressure)."""


class OrinPolicyDeny(LeaseDenied):
    """The orind policy table denied the action outright."""


class OrinApprovalRequired(LeaseDenied):
    """The orind policy table requires user approval for this action."""


class OrinExportGateRequired(LeaseDenied):
    """SECRET-context egress needs the export gate (Stage B mechanism)."""


class OrinUnknownIntent(LeaseDenied):
    """No trusted active IntentEnvelope covers the task (Stage B)."""


class OrinUnknownHandle(LeaseDenied):
    """Referenced OriginHandle is unknown, unsealed, or expired (Stage B)."""


CODE_TO_EXC: dict[str, type[LeaseDenied]] = {
    "mac_invalid": LeaseMacInvalid,
    "expired": LeaseDenied,
    "replay": LeaseDenied,
    "revoked": LeaseDenied,
    "exhausted": LeaseDenied,
    "binding_mismatch": LeaseDenied,
    "context_mismatch": LeaseContextMismatch,
    "parent_missing": LeaseDenied,
    "denied": LeaseDenied,
    "policy_deny": OrinPolicyDeny,
    "approval_required": OrinApprovalRequired,
    "export_gate": OrinExportGateRequired,
    "readonly_mode": LeaseDenied,
    "frozen": LeaseDenied,
    "unsupported": LeaseDenied,
    "unknown_intent": OrinUnknownIntent,
    "unknown_handle": OrinUnknownHandle,
    "stale_state": LeaseDenied,
}


def _error_to_exc(code: str, reason: str) -> LeaseDenied:
    if code == "rate_limited":
        return OrinRateLimited(f"orind rate limited: {reason}")
    if code in ("internal", "bad_message"):
        return OrinUnavailable(f"orind {code}: {reason}")
    exc_class = CODE_TO_EXC.get(code, LeaseDenied)
    return exc_class(f"orind {code}: {reason}")


def _read_session_key_file(path: Path) -> bytes:
    """Strict one-shot read of the per-connection session key file."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise OrinUnavailable(f"orind session key missing: {path}") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise OrinUnavailable("orind session key file failed strict checks")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise OrinUnavailable("orind session key file changed while opening")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            key = handle.read(32)
        if len(key) != 32:
            raise OrinUnavailable("orind session key has wrong length")
    finally:
        if fd >= 0:
            os.close(fd)
    if stat.S_IMODE(path.lstat().st_mode) != 0o600:
        raise OrinUnavailable("orind session key file must be 0600")
    try:
        path.unlink()
    except OSError as exc:
        raise OrinUnavailable("orind session key could not be made one-shot") from exc
    return key


class _OrinConnection:
    """One authenticated connection to orind (lives on the client loop)."""

    def __init__(
        self,
        *,
        socket_path: Path,
        state_dir: Path,
        on_freeze: Callable[[dict[str, Any]], None] | None = None,
        stage_b: bool = False,
    ) -> None:
        self._socket_path = socket_path
        self._state_dir = state_dir
        self._on_freeze = on_freeze
        self._stage_b = stage_b
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._session_key: bytes | None = None
        self._session_nonce = ""
        self._last_client_seq = 0
        self._last_server_seq = 0
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._lock = asyncio.Lock()
        self._reader_task: asyncio.Task[None] | None = None
        self._closed = False

    async def connect(self) -> None:
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_unix_connection(path=str(self._socket_path)),
                timeout=CONNECT_TIMEOUT_S,
            )
        except (TimeoutError, OSError) as exc:
            raise OrinUnavailable(f"cannot connect to orind at {self._socket_path}") from exc
        client_nonce = secrets.token_hex(16)
        caps = list(CLIENT_CAPS) + (list(STAGE_B_CLIENT_CAPS) if self._stage_b else [])
        hello = make_envelope(
            "hello",
            seq=1,
            nonce=client_nonce,
            session_key=None,
            caps=caps,
            pid=os.getpid(),
        )
        assert self._writer is not None
        self._writer.write(encode_frame(hello))
        await self._writer.drain()
        ack = await asyncio.wait_for(
            self._read_frame(authenticated=False), timeout=CONNECT_TIMEOUT_S
        )
        if ack["type"] != "hello_ack" or not ack.get("ok", True):
            raise OrinUnavailable("orind handshake rejected")
        server_nonce = str(ack.get("server_nonce", ""))
        if not server_nonce:
            raise OrinUnavailable("orind handshake missing server nonce")
        self._session_nonce = client_nonce + server_nonce
        self._last_client_seq = 1
        key_path = self._state_dir / "orin" / f"session-{os.getpid()}.key"
        loop = asyncio.get_running_loop()
        self._session_key = await loop.run_in_executor(None, _read_session_key_file, key_path)
        self._reader_task = loop.create_task(self._reader_loop())

    async def close(self) -> None:
        self._closed = True
        if self._reader_task is not None:
            self._reader_task.cancel()
            self._reader_task = None
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass

    @property
    def closed(self) -> bool:
        return self._closed

    async def request(self, message_type: str, **fields: Any) -> dict[str, Any]:
        if self._session_key is None or self._closed:
            raise OrinUnavailable("orind connection is not established")
        async with self._lock:
            self._last_client_seq += 1
            seq = self._last_client_seq
            envelope = make_envelope(
                message_type,
                seq=seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                **fields,
            )
            future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
            self._pending[seq] = future
            assert self._writer is not None
            try:
                self._writer.write(encode_frame(envelope))
                await self._writer.drain()
                return await asyncio.wait_for(future, timeout=REQUEST_TIMEOUT_S)
            finally:
                self._pending.pop(seq, None)

    async def heartbeat(self) -> None:
        await self.request("heartbeat")

    async def _reader_loop(self) -> None:
        try:
            while not self._closed:
                envelope = await self._read_frame()
                message_type = envelope["type"]
                if message_type == "freeze":
                    seq = envelope["seq"]
                    if seq <= self._last_server_seq:
                        raise ProtocolError("server seq regression")
                    self._last_server_seq = seq
                    if self._on_freeze is not None:
                        self._on_freeze(envelope)
                    continue
                future = self._pending.get(envelope["seq"])
                if future is None or future.done():
                    raise ProtocolError("unsolicited ack")
                future.set_result(envelope)
        except (asyncio.IncompleteReadError, ProtocolError, ConnectionError, OSError):
            self._closed = True
            for pending in self._pending.values():
                if not pending.done():
                    pending.set_exception(OrinUnavailable("orind connection dropped"))
            self._pending.clear()

    async def _read_frame(self, *, authenticated: bool = True) -> dict[str, Any]:
        assert self._reader is not None
        header = await self._reader.readexactly(4)
        length = int.from_bytes(header, "big")
        if length <= 0 or length > MAX_FRAME_BYTES:
            raise ProtocolError("frame length out of bounds")
        payload = await self._reader.readexactly(length)
        envelope = parse_frame(payload)
        if not authenticated:
            return envelope
        if self._session_key is None or not verify_mac(self._session_key, envelope):
            raise ProtocolError("bad mac from orind")
        return envelope


def _lease_kwargs_to_params(kwargs: dict[str, Any]) -> dict[str, Any]:
    params: dict[str, Any] = {
        "owner_key_hash": str(kwargs["owner_key_hash"]),
        "run_id": str(kwargs["run_id"]),
        "tool_name": str(kwargs["tool_name"]),
        "args_schema": str(kwargs["args_schema"]),
        "resource_scope": str(kwargs["resource_scope"]),
        "max_bytes": int(kwargs["max_bytes"]),
        "max_duration_ms": int(kwargs["max_duration_ms"]),
        "ttl_ms": int(kwargs["ttl_ms"]),
    }
    list_keys = ("fs_roots", "network_hosts")
    str_keys = ("network_policy", "parent_lease_id", "product_id", "session_id")
    for key in (*list_keys, *str_keys, "max_invocations"):
        value = kwargs.get(key)
        if value is None:
            continue
        if key in list_keys:
            params[key] = [str(item) for item in value]
        elif key == "max_invocations":
            params[key] = int(value)
        else:
            params[key] = str(value)
    return params


def _bound_expected_payload(expected: dict[str, Any]) -> dict[str, Any]:
    return {
        "product_id": str(expected["expected_product_id"]),
        "owner_key_hash": str(expected["expected_owner"]),
        "session_id": str(expected["expected_session"]),
        "run_id": str(expected["expected_run"]),
        "tool_name": str(expected["expected_tool"]),
        "args_schema": str(expected["expected_args_schema"]),
        "resource_scope": str(expected["expected_resource_scope"]),
        "fs_roots": [str(i) for i in expected.get("expected_fs_roots", ())],
        "network_policy": str(expected["expected_network_policy"]),
        "network_hosts": [str(i) for i in expected.get("expected_network_hosts", ())],
        "max_bytes": int(expected["expected_max_bytes"]),
        "max_duration_ms": int(expected["expected_max_duration_ms"]),
        "require_single_use": bool(expected.get("require_single_use", True)),
    }


def _context_to_payload(context: Any) -> dict[str, Any]:
    return {
        "product_id": str(getattr(context, "product_id", "")),
        "owner_key_hash": str(getattr(context, "owner_key_hash", "")),
        "session_id": str(getattr(context, "session_id", "")),
        "run_id": str(getattr(context, "run_id", "")),
        "profile": str(getattr(context, "profile", "")),
        "tool_name": str(getattr(context, "tool_name", "")),
        "args_hash": str(getattr(context, "args_hash", "")),
        "resource_scope": str(getattr(context, "resource_scope", "")),
        "fs_roots": [str(i) for i in getattr(context, "fs_roots", ())],
        "network_policy": str(getattr(context, "network_policy", "deny")),
        "network_hosts": [str(i) for i in getattr(context, "network_hosts", ())],
        "max_bytes": int(getattr(context, "max_bytes", 0)),
        "max_duration_ms": int(getattr(context, "max_duration_ms", 0)),
        "lease_id": str(getattr(context, "lease_id", "")),
        "lease_mac": str(getattr(context, "lease_mac", "")),
        "signature": str(getattr(context, "signature", "")),
    }


def _normalize_file_change_path(raw: Any) -> tuple[str, tuple[str, ...]]:
    """Mirror the File Cell's portable relative-path admission boundary."""

    import unicodedata

    if type(raw) is not str:
        raise ValueError("File Cell change path must be a string")
    if not raw or any(unicodedata.category(char).startswith("C") for char in raw):
        raise ValueError("File Cell change path contains control or invisible text")
    if raw.startswith(("/", "\\")) or "\\" in raw:
        raise ValueError("File Cell change path must be a portable relative path")
    parts = tuple(raw.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("File Cell change path contains an empty, dot, or parent component")
    if tuple(unicodedata.normalize("NFC", part) for part in parts) != parts:
        raise ValueError("File Cell change path must already be NFC normalized")
    for part in parts:
        if any(unicodedata.category(char).startswith("C") for char in part):
            raise ValueError("File Cell change path contains control or invisible text")
        if len(part.encode("utf-8")) > _FILE_COMPONENT_MAX_BYTES:
            raise ValueError("File Cell change path component exceeds 255 UTF-8 bytes")
        if part.casefold() == ".git":
            raise ValueError("File Cell never writes Git metadata")
    normalized = "/".join(parts)
    if len(normalized.encode("utf-8")) > _FILE_PATH_MAX_BYTES:
        raise ValueError("File Cell change path exceeds the path bound")
    return normalized, parts


def _resolved_directory(path: Path | str) -> Path | None:
    try:
        resolved = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError, TypeError):
        return None
    return resolved if resolved.is_dir() else None


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _roots_cover_target(target: Path, roots: tuple[Any, ...]) -> bool:
    for raw_root in roots:
        root = _resolved_directory(raw_root)
        if root is not None and _path_within(target, root):
            return True
    return False


class OrinLeaseClientAdapter:
    """Synchronous LeaseAuthority-method surface over IPC to orind."""

    def __init__(
        self,
        *,
        socket_path: Path,
        state_dir: Path,
        fail_mode: str = "closed",
        readonly_tool_classifier: Callable[[str], bool] | None = None,
        on_freeze: Callable[[dict[str, Any]], None] | None = None,
        stage_b: bool = False,
    ) -> None:
        self._socket_path = socket_path
        self._state_dir = state_dir
        self._fail_mode = fail_mode
        self._readonly_tool_classifier = readonly_tool_classifier
        self._on_freeze = on_freeze
        self._stage_b = stage_b
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._conn: _OrinConnection | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._start_lock = threading.Lock()
        self._file_binding_lock = threading.Lock()
        self._file_bindings: dict[_FileBindingKey, _FileBinding] = {}
        self._local_lease_ids: set[str] = set()
        self._local_authority: Any = None
        self._context_signatures: dict[str, str] = {}
        self._lease_taints: dict[str, tuple[int, int, int]] = {}
        self._readonly_fallback_count = 0
        self._closed = False
        install_canary_sink(self.scan_canary)

    # -- thread/loop plumbing ---------------------------------------------------
    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._start_lock:
            if self._thread is not None and self._thread.is_alive() and self._loop is not None:
                return self._loop
            self._ready.clear()
            self._thread = threading.Thread(target=self._run_loop, name="orin-client", daemon=True)
            self._thread.start()
        if not self._ready.wait(timeout=10.0):
            raise OrinUnavailable("orin client loop failed to start")
        assert self._loop is not None
        return self._loop

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    def _call(
        self,
        coro_factory: Callable[[], Coroutine[Any, Any, _T]],
        *,
        timeout: float = REQUEST_TIMEOUT_S,
    ) -> _T:
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(coro_factory(), loop)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            future.cancel()
            raise OrinUnavailable("orind request timed out") from exc
        except _FUTURES_ERRORS as exc:
            raise OrinUnavailable(f"orind call failed: {exc}") from exc

    # -- connection management ------------------------------------------------------
    async def _connection(self) -> _OrinConnection:
        conn = self._conn
        if conn is not None and not conn.closed:
            return conn
        if self._closed:
            raise OrinUnavailable("orin client is shut down")
        conn = _OrinConnection(
            socket_path=self._socket_path,
            state_dir=self._state_dir,
            on_freeze=self._on_freeze,
            stage_b=self._stage_b,
        )
        await conn.connect()
        self._conn = conn
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.get_running_loop().create_task(
                self._heartbeat_loop(conn)
            )
        return conn

    async def _heartbeat_loop(self, conn: _OrinConnection) -> None:
        while not conn.closed and not self._closed:
            await asyncio.sleep(HEARTBEAT_INTERVAL_S)
            try:
                await conn.heartbeat()
            except (TimeoutError, OrinUnavailable, ProtocolError, OSError):
                await conn.close()
                return

    async def _request(self, message_type: str, **fields: Any) -> dict[str, Any]:
        conn = await self._connection()
        response = await conn.request(message_type, **fields)
        if not response.get("ok", True):
            code = str(response.get("code", "internal"))
            reason = str(response.get("reason", ""))
            raise _error_to_exc(code, reason)
        return response

    # -- LeaseAuthority surface ---------------------------------------------------
    def issue(self, **kwargs: Any) -> CapabilityLease:
        try:
            return self._call(lambda: self._issue_coro(kwargs))
        except OrinUnavailable:
            if self._fail_mode == "readonly" and self._is_read_only_tool(
                str(kwargs.get("tool_name", ""))
            ):
                return self._readonly_fallback_issue(kwargs)
            raise

    def issue_with_context(self, *, profile: str = "", **kwargs: Any) -> CapabilityLease:
        """Issue a lease and pre-sign its execution context (orind-side).

        Orin taint kwargs (``context_taint`` / ``arg_taint`` /
        ``clearance``) ride the issue request so orind stamps them into
        the lease v2 fields and evaluates the policy table.
        """

        try:
            return self._call(lambda: self._issue_coro(kwargs, profile=profile))
        except OrinUnavailable:
            if self._fail_mode == "readonly" and self._is_read_only_tool(
                str(kwargs.get("tool_name", ""))
            ):
                return self._readonly_fallback_issue(kwargs)
            raise

    async def _issue_coro(
        self, kwargs: dict[str, Any], *, profile: str | None = None
    ) -> CapabilityLease:
        params = _lease_kwargs_to_params(kwargs)
        fields: dict[str, Any] = {"lease": params}
        if profile is not None:
            fields["context"] = {"profile": profile}
        for taint_key in ("context_taint", "arg_taint", "clearance"):
            if kwargs.get(taint_key) is not None:
                fields[taint_key] = int(kwargs[taint_key])
        response = await self._request("issue", **fields)
        lease = _lease_from_payload(response["lease"])
        signature = str(response.get("context_signature", ""))
        if profile is not None and signature:
            self._context_signatures[lease.lease_id] = signature
        if any(kwargs.get(key) is not None for key in ("context_taint", "arg_taint", "clearance")):
            raw_clearance = kwargs.get("clearance")
            self._lease_taints[lease.lease_id] = (
                int(kwargs.get("context_taint") or 0),
                int(kwargs.get("arg_taint") or 0),
                1 if raw_clearance is None else int(raw_clearance),
            )
        return lease

    def _readonly_fallback_issue(self, kwargs: dict[str, Any]) -> CapabilityLease:
        authority = self._ensure_local_authority()
        local_kwargs = {
            key: value
            for key, value in kwargs.items()
            if key not in ("context_taint", "arg_taint", "clearance")
        }
        lease = authority.issue(**local_kwargs)
        self._local_lease_ids.add(lease.lease_id)
        self._readonly_fallback_count += 1
        return lease

    def _ensure_local_authority(self) -> LeaseAuthority:
        if self._local_authority is None:
            from js.echo.capability import LeaseAuthority

            self._local_authority = LeaseAuthority(
                mac_key=secrets.token_bytes(32),
                now_fn=lambda: int(time.time() * 1000),
                ledger_path=None,
            )
        return cast("LeaseAuthority", self._local_authority)

    def _is_read_only_tool(self, tool_name: str) -> bool:
        if self._readonly_tool_classifier is None:
            return False
        try:
            return bool(self._readonly_tool_classifier(tool_name))
        except Exception:  # noqa: BLE001 - classifier must fail closed
            return False

    def _is_local(self, lease_id: str) -> bool:
        return lease_id in self._local_lease_ids

    def _taint_fields(self, lease_id: str | None = None) -> dict[str, int]:
        """Taint payload for consume requests (issue cache → ContextVar)."""

        if lease_id is not None and lease_id in self._lease_taints:
            context_taint, arg_taint, clearance = self._lease_taints[lease_id]
            return {
                "context_taint": context_taint,
                "arg_taint": arg_taint,
                "clearance": clearance,
            }
        from js.orin.taint import current_tool_taint_snapshot

        snapshot = current_tool_taint_snapshot()
        if snapshot is None:
            return {}
        return {
            "context_taint": snapshot.context_taint,
            "arg_taint": 0,
            "clearance": snapshot.clearance,
        }

    def _now(self) -> int:
        return int(time.time() * 1000)

    # -- verify / consume ------------------------------------------------------
    def verify(
        self,
        lease: CapabilityLease,
        *,
        expected_owner: str,
        expected_tool: str,
        expected_scope: str,
        now: int,
    ) -> None:
        if self._is_local(lease.lease_id):
            self._ensure_local_authority().verify(
                lease,
                expected_owner=expected_owner,
                expected_tool=expected_tool,
                expected_scope=expected_scope,
                now=now,
            )
            return
        self._call(
            lambda: self._request(
                "consume",
                mode="verify",
                lease=_lease_to_payload(lease),
                expected={
                    "owner": expected_owner,
                    "tool": expected_tool,
                    "scope": expected_scope,
                },
                **self._taint_fields(lease.lease_id),
            )
        )

    def verify_bound(self, lease: CapabilityLease, **expected: Any) -> None:
        if self._is_local(lease.lease_id):
            self._ensure_local_authority().verify_bound(lease, **expected)
            return
        self._call(
            lambda: self._request(
                "consume",
                mode="preflight",
                lease=_lease_to_payload(lease),
                expected=_bound_expected_payload(expected),
                **self._taint_fields(lease.lease_id),
            )
        )

    def consume_bound(self, lease: CapabilityLease, **expected: Any) -> LeaseConsumeReceipt:
        if self._is_local(lease.lease_id):
            return self._ensure_local_authority().consume_bound(lease, **expected)
        response = self._call(
            lambda: self._request(
                "consume",
                mode="consume",
                lease=_lease_to_payload(lease),
                expected=_bound_expected_payload(expected),
                **self._taint_fields(lease.lease_id),
            )
        )
        self._context_signatures.pop(lease.lease_id, None)
        self._lease_taints.pop(lease.lease_id, None)
        receipt = response.get("receipt") or {}
        return LeaseConsumeReceipt(
            lease_id=str(receipt.get("lease_id", lease.lease_id)),
            nonce=str(receipt.get("nonce", "")),
            consumed_at=int(receipt.get("consumed_at", 0)),
            ledger_seq=int(receipt.get("ledger_seq", 0)),
            ledger_record_hash=str(receipt.get("ledger_record_hash", "")),
        )

    def scan_canary(self, text: str, surface: str, session_id: str) -> str | None:
        """Ask orind to match ``text``; return the fixed refusal/freeze line."""

        try:
            self._call(
                lambda: self._request(
                    "consume",
                    mode="scan",
                    scan_text=text[:8000],
                    scan_surface=surface,
                    session_id=session_id,
                )
            )
        except OrinUnavailable:
            # Daemon-down is a lease fail-closed concern, not a canary hit.
            # Mapping it to REFUSAL_TEXT would block unrelated writes.
            return None
        except LeaseDenied as exc:
            detail = str(exc)
            if FREEZE_TEXT in detail:
                return FREEZE_TEXT
            return REFUSAL_TEXT
        return None

    def consume(self, lease: CapabilityLease, *, now: int) -> None:
        if self._is_local(lease.lease_id):
            self._ensure_local_authority().consume(lease, now=now)
            return
        self._call(
            lambda: self._request(
                "consume",
                mode="consume",
                lease=_lease_to_payload(lease),
                **self._taint_fields(lease.lease_id),
            )
        )
        self._context_signatures.pop(lease.lease_id, None)
        self._lease_taints.pop(lease.lease_id, None)

    def consume_execution_context(self, context: Any, *, now: int) -> None:
        lease_id = str(getattr(context, "lease_id", ""))
        if self._is_local(lease_id):
            self._ensure_local_authority().consume_execution_context(context, now=now)
            return
        self._call(
            lambda: self._request(
                "consume",
                mode="context",
                context=_context_to_payload(context),
                **self._taint_fields(lease_id),
            )
        )
        self._context_signatures.pop(lease_id, None)
        self._lease_taints.pop(lease_id, None)

    def sign_execution_context(self, context: Any, lease: CapabilityLease, now: int) -> str:
        lease_id = lease.lease_id
        if self._is_local(lease_id):
            from js.echo.capability import sign_tool_execution_context

            signed = sign_tool_execution_context(
                context,
                lease=lease,
                authority=self._ensure_local_authority(),
                now=now,
            )
            return str(getattr(signed, "signature", ""))
        signature = self._context_signatures.get(lease_id)
        if not signature:
            raise LeaseContextMismatch("execution context signature unavailable for this lease")
        return signature

    # -- revoke / queries --------------------------------------------------------
    def revoke(self, lease_id: str) -> None:
        if self._is_local(lease_id):
            self._ensure_local_authority().revoke(lease_id)
            return
        self._call(lambda: self._request("revoke", op="lease", lease_id=lease_id))

    def revoke_for_session(self, *, owner_key_hash: str, session_id: str) -> tuple[str, ...]:
        response = self._call(
            lambda: self._request(
                "revoke",
                op="session",
                owner_key_hash=owner_key_hash,
                session_id=session_id,
            )
        )
        revoked = response.get("revoked") or []
        return tuple(str(item) for item in revoked)

    def active_session_ids_for_owner(self, *, owner_key_hash: str) -> tuple[str, ...]:
        response = self._call(
            lambda: self._request("revoke", op="active_sessions", owner_key_hash=owner_key_hash)
        )
        sessions = response.get("sessions") or []
        return tuple(str(item) for item in sessions)

    def is_revoked(self, lease_id: str) -> bool:
        if self._is_local(lease_id):
            return self._ensure_local_authority().is_revoked(lease_id)
        response = self._call(lambda: self._request("revoke", op="is_revoked", lease_id=lease_id))
        return bool(response.get("is_revoked", False))

    # -- stage B surface (WP5): owner intents and drafts ---------------------------
    def _require_stage_b(self) -> None:
        if not self._stage_b:
            raise OrinUnavailable("stage B is disabled on this orin client")

    def register_file_binding(
        self,
        intent_data: dict[str, Any],
        *,
        appshell_owner: str,
        appshell_session: str,
        appshell_epoch: int,
        workspace_root: Path | str,
    ) -> dict[str, Any]:
        """Register one AppShell-confirmed task and its DirectoryHandle.

        The signed intent keeps the Orin installation owner.  The physical
        AppShell principal is used only to partition this process-local cache
        and to bind the privileged ``intent(register)`` grant sent to orind.
        """

        from js.orin.handles import (
            AppShellDirectoryBindingV1,
            canonical_workspace_root,
            derive_appshell_directory_handle_id,
        )
        from js.orin.intent import intent_from_dict

        self._require_stage_b()
        intent = intent_from_dict(intent_data, verify_signature=True)
        if intent.profile not in {"personal", "work"}:
            raise LeaseDenied("Orin file binding requires a Personal or Work intent")
        if "file.commit" not in intent.allowed_effect_classes:
            raise LeaseDenied("Orin file binding intent does not authorize file.commit")
        if intent.expires_at_ms <= self._now():
            raise LeaseDenied("Orin file binding intent is expired")

        root_nfc = canonical_workspace_root(workspace_root)
        expected_handle_id = derive_appshell_directory_handle_id(
            installation_owner_hash=intent.owner_key_hash,
            product_id=intent.product_id,
            task_id=intent.task_id,
            profile=intent.profile,
            principal_owner=appshell_owner,
            principal_session=appshell_session,
            principal_epoch=appshell_epoch,
            workspace_root=root_nfc,
        )
        directory_handles = tuple(
            handle
            for handle in intent.allowed_resource_handles
            if handle.startswith("dirh:")
        )
        if directory_handles != (expected_handle_id,):
            raise LeaseDenied("signed intent does not contain the exact AppShell file binding")

        wire_intent = intent.to_dict()
        grant = AppShellDirectoryBindingV1(
            principal_owner=appshell_owner,
            principal_epoch=appshell_epoch,
            product_id=intent.product_id,
            workspace_root=root_nfc,
        ).to_dict()
        binding = _FileBinding(
            appshell_owner=appshell_owner,
            appshell_session=appshell_session,
            profile=intent.profile,
            appshell_epoch=appshell_epoch,
            installation_owner=intent.owner_key_hash,
            product_id=intent.product_id,
            task_id=intent.task_id,
            directory_handle_id=expected_handle_id,
            workspace_root=root_nfc,
            expires_at_ms=intent.expires_at_ms,
        )
        key: _FileBindingKey = (
            appshell_owner,
            appshell_session,
            intent.profile,
            appshell_epoch,
        )

        # Serialize confirmations for a principal key so a slower, older
        # request cannot overwrite a newer successful confirmation.
        with self._file_binding_lock:
            response = self._call(
                lambda: self._request(
                    "intent",
                    op="register",
                    intent=wire_intent,
                    grant=grant,
                    session_id=appshell_session,
                )
            )
            returned_handle_id = response.get("directory_handle_id")
            if response.get("ok") is not True or (
                returned_handle_id is not None and returned_handle_id != expected_handle_id
            ):
                raise OrinUnavailable("orind returned an invalid AppShell file binding ack")
            self._file_bindings[key] = binding
        return {"ok": True, "directory_handle_id": expected_handle_id}

    def run_file_change(self, change: dict[str, Any]) -> dict[str, Any]:
        """Commit one exact workspace change through the strict draft chain."""

        from js.echo.turn_context import current_runtime_context, runtime_context_error
        from js.orin import taint as orin_taint
        from js.orin.draft import EffectDraft
        from js.orin.handles import canonical_workspace_root
        from js.orin.protocol import canonical_json
        from js.tools.registry import current_tool_execution_context

        self._require_stage_b()
        if type(change) is not dict or set(change) != {"path", "content"}:
            raise ValueError("File Cell change must contain exactly path and content")
        raw_path = change.get("path")
        content = change.get("content")
        if type(raw_path) is not str or type(content) is not str:
            raise ValueError("File Cell path and content must be strings")
        normalized_path, path_parts = _normalize_file_change_path(raw_path)

        runtime = current_runtime_context()
        if runtime is None or runtime_context_error(runtime) is not None:
            raise LeaseDenied("Orin file binding requires a verified RuntimeContext")
        epoch_binding = runtime.appshell_epoch_binding
        if (
            epoch_binding is None
            or type(epoch_binding.owner) is not str
            or type(epoch_binding.session) is not str
            or epoch_binding.active_mode not in {"personal", "work"}
            or type(epoch_binding.epoch) is not int
            or isinstance(epoch_binding.epoch, bool)
            or epoch_binding.epoch < 0
        ):
            raise LeaseDenied("Orin file binding requires a verified AppShell epoch")
        if runtime.owner_key_hash != epoch_binding.owner:
            raise LeaseDenied("Orin file binding principal owner mismatch")

        key: _FileBindingKey = (
            epoch_binding.owner,
            epoch_binding.session,
            epoch_binding.active_mode,
            epoch_binding.epoch,
        )
        with self._file_binding_lock:
            binding = self._file_bindings.get(key)
            if binding is not None and binding.expires_at_ms <= self._now():
                self._file_bindings.pop(key, None)
                binding = None
        if binding is None:
            raise LeaseDenied("Orin AppShell file binding is missing or expired")
        if (
            binding.appshell_owner != epoch_binding.owner
            or binding.appshell_session != epoch_binding.session
            or binding.profile != epoch_binding.active_mode
            or binding.appshell_epoch != epoch_binding.epoch
            or binding.product_id != runtime.product_id
        ):
            raise LeaseDenied("Orin AppShell file binding identity mismatch")

        try:
            runtime_root_nfc = canonical_workspace_root(runtime.workspace)
        except ProtocolError as exc:
            raise LeaseDenied("Orin RuntimeContext workspace is unavailable") from exc
        if runtime_root_nfc != binding.workspace_root:
            raise LeaseDenied("Orin RuntimeContext workspace does not match the file binding")
        runtime_root = _resolved_directory(runtime.workspace)
        if runtime_root is None:
            raise LeaseDenied("Orin RuntimeContext workspace is unavailable")
        try:
            target = runtime_root.joinpath(*path_parts).resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as exc:
            raise LeaseDenied("Orin file target could not be resolved") from exc
        if not _path_within(target, runtime_root):
            raise LeaseDenied("Orin file target escapes the bound workspace")
        if not _roots_cover_target(target, cast("tuple[Any, ...]", runtime.fs_roots)):
            raise LeaseDenied("Orin RuntimeContext filesystem roots deny the file target")

        tool_context = current_tool_execution_context()
        if tool_context is None:
            raise LeaseDenied("Orin file binding requires a verified ToolExecutionContext")
        if (
            type(tool_context.owner_key_hash) is not str
            or type(tool_context.product_id) is not str
            or type(tool_context.session_id) is not str
            or type(tool_context.run_id) is not str
            or type(tool_context.profile) is not str
            or type(tool_context.tool_name) is not str
            or type(tool_context.fs_roots) is not tuple
            or tool_context.owner_key_hash != runtime.owner_key_hash
            or tool_context.product_id != runtime.product_id
            or tool_context.session_id != runtime.session_id
            or tool_context.run_id != runtime.run_id
            or tool_context.profile != runtime.profile
            or tool_context.tool_name not in _FILE_TOOL_NAMES
            or tool_context.tool_name not in runtime.capabilities
        ):
            raise LeaseDenied("Orin file tool execution identity mismatch")
        if not _roots_cover_target(target, cast("tuple[Any, ...]", tool_context.fs_roots)):
            raise LeaseDenied("Orin tool filesystem roots deny the file target")

        exact_change = {"path": normalized_path, "content": content}
        draft = EffectDraft(
            draft_id=f"draft:{secrets.token_hex(16)}",
            task_id=binding.task_id,
            effect_type="file.commit",
            arguments={
                "directory_handle": binding.directory_handle_id,
                "changes": [exact_change],
            },
            declared_expectation={
                "external_visibility": "private",
                "reversibility": "reversible_until_stage",
            },
        )
        taint_fields = self._taint_fields(None)
        snapshot = orin_taint.current_tool_taint_snapshot()
        arg_taint = int(taint_fields.get("arg_taint", 0))
        if snapshot is not None and snapshot.dirty_samples:
            arg_taint = orin_taint.arg_taint(
                canonical_json(exact_change),
                list(snapshot.dirty_samples),
            )
        proposed = self.submit_draft(
            draft.to_dict(),
            context_taint=int(taint_fields.get("context_taint", 0)),
            arg_taint=arg_taint,
            clearance=int(
                taint_fields.get("clearance", orin_taint.CLEARANCE_INTERNAL)
            ),
        )
        if (
            proposed.get("ok") is not True
            or proposed.get("verdict") != "deny_missing_witness"
            or proposed.get("missing") != ["state_witness"]
        ):
            raise LeaseDenied("Orin file draft was not accepted for witness preflight")
        preflight = self.preflight_draft(draft.draft_id, "cell.file")
        if preflight.get("ok") is not True:
            raise LeaseDenied("Orin File Cell preflight failed")
        result = self.consume_draft(draft.draft_id)
        if type(result) is not dict:
            raise OrinUnavailable("orind returned an invalid File Cell result")
        return {key: result[key] for key in _FILE_RESULT_FIELDS if key in result}

    def register_intent(self, intent_data: dict[str, Any]) -> dict[str, Any]:
        """Submit a signed IntentEnvelope for verification + registration."""

        self._require_stage_b()
        return self._call(lambda: self._request("intent", op="register", intent=intent_data))

    def active_intent(self, task_id: str) -> dict[str, Any] | None:
        """Return the currently trusted intent for a task, or ``None``."""

        self._require_stage_b()
        try:
            return self._call(lambda: self._request("intent", op="active", task_id=task_id))
        except OrinUnknownIntent:
            return None

    def admin_unfreeze(self, intent_data: dict[str, Any], *, session_id: str) -> dict[str, Any]:
        """R3 de-escalation backed by a dual-control admin intent."""

        self._require_stage_b()
        return self._call(
            lambda: self._request(
                "intent", op="admin_unfreeze", intent=intent_data, session_id=session_id
            )
        )

    def submit_draft(
        self,
        draft_data: dict[str, Any],
        *,
        context_taint: int = 0,
        arg_taint: int = 0,
        clearance: int = 1,
    ) -> dict[str, Any]:
        """Ask the Gate Kernel to assess an EffectDraft; returns verdict class."""

        self._require_stage_b()
        return self._call(
            lambda: self._request(
                "draft",
                draft=draft_data,
                context_taint=context_taint,
                arg_taint=arg_taint,
                clearance=clearance,
            )
        )

    def preflight_draft(
        self,
        draft_id: str,
        executor_id: str | None = None,
    ) -> dict[str, Any]:
        """Request a read-only Cell preflight for a registered draft.

        ``executor_id`` is advisory compatibility data only.  The daemon
        always derives the authoritative Cell from its sealed manifest and
        never accepts a client-supplied package.
        """

        self._require_stage_b()
        if not draft_id.startswith("draft:") or len(draft_id) > 256:
            raise ValueError("draft_id must be a bounded 'draft:' id")
        fields: dict[str, Any] = {"draft_id": draft_id}
        if executor_id is not None:
            fields["executor_id"] = executor_id
        return self._call(lambda: self._request("preflight", **fields))

    def consume_draft(self, draft_id: str) -> dict[str, Any]:
        """Commit a registered draft through its unique ``draft_id`` path.

        No effect bytes, handles, clearance, or capability can be supplied
        here; the daemon reloads every authoritative field it recorded when
        the draft was submitted.
        """

        self._require_stage_b()
        if not draft_id.startswith("draft:") or len(draft_id) > 256:
            raise ValueError("draft_id must be a bounded 'draft:' id")
        response = self._call(
            lambda: self._request(
                "consume",
                mode="cell",
                payload={"draft_id": draft_id},
            )
        )
        return dict(response.get("cell") or {})

    def seed_handles(self, kind: str | None = None) -> list[dict[str, Any]]:
        """List pre-registered candidate objects Echo may select (M§3.2-2)."""

        self._require_stage_b()
        response = self._call(lambda: self._request("handle", op="seed_list", kind=kind))
        return list(response.get("candidates") or [])

    def run_in_build_cell(
        self,
        payload: dict[str, Any],
        *,
        context_taint: int | None = None,
        arg_taint: int = 0,
        clearance: int = 1,
    ) -> dict[str, Any]:
        """Authorize + proxy one build effect into the resident Build Cell.

        The policy table runs orind-side; no license or permit ever lands in
        this process — only the finished (untrusted) tool result comes back.
        Taint defaults to the current thread's snapshot; callers outside a
        turn-loop thread pass it explicitly. Raises :class:`LeaseDenied`
        subclasses when the effect class is denied or the cell is
        unavailable (fail closed per class).
        """

        return self.run_in_cell(
            "cell.build",
            payload,
            context_taint=context_taint,
            arg_taint=arg_taint,
            clearance=clearance,
        )

    def run_in_cell(
        self,
        cap: str,
        payload: dict[str, Any],
        *,
        context_taint: int | None = None,
        arg_taint: int = 0,
        clearance: int = 1,
    ) -> dict[str, Any]:
        """Authorize + proxy one effect into a scheduled cell (WP7/WP8).

        The policy table runs orind-side; no license or permit ever lands in
        this process — only the finished (untrusted) tool result comes back.
        Taint defaults to the current thread's snapshot; callers outside a
        turn-loop thread pass it explicitly. Raises :class:`LeaseDenied`
        subclasses when the effect class is denied or the cell is
        unavailable (fail closed per class).
        """

        self._require_stage_b()
        if context_taint is None:
            snapshot = self._taint_fields(None)
            resolved_context = int(snapshot.get("context_taint", 0))
            arg_taint = int(snapshot.get("arg_taint", 0))
        else:
            resolved_context = int(context_taint)
        wire_payload = {"cell": cap, **payload}
        response = self._call(
            lambda: self._request(
                "consume",
                mode="cell",
                payload=wire_payload,
                context_taint=resolved_context,
                arg_taint=int(arg_taint),
                clearance=int(clearance),
            )
        )
        return dict(response.get("cell") or {})

    def grant_export(self, pass_data: dict[str, Any], *, task_id: str) -> dict[str, Any]:
        """Submit a signed ExportPass for registration (two-phase egress)."""

        self._require_stage_b()
        return self._call(
            lambda: self._request("intent", op="grant_export", grant=pass_data, task_id=task_id)
        )

    # -- introspection --------------------------------------------------------------
    def healthy(self) -> bool:
        try:
            self._call(
                lambda: self._request("heartbeat"),
                timeout=HEARTBEAT_INTERVAL_S * 2,
            )
            return True
        except (OrinUnavailable, concurrent.futures.TimeoutError):
            return False

    @property
    def readonly_fallback_count(self) -> int:
        return self._readonly_fallback_count

    def close(self) -> None:
        self._closed = True
        if installed_canary_sink() == self.scan_canary:
            install_canary_sink(None)
        loop = self._loop
        if loop is not None and not loop.is_closed():
            shutdown = asyncio.run_coroutine_threadsafe(self._shutdown(), loop)
            try:
                shutdown.result(timeout=REQUEST_TIMEOUT_S)
            except (concurrent.futures.TimeoutError, Exception):
                pass
            loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=REQUEST_TIMEOUT_S)

    async def _shutdown(self) -> None:
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None
        if self._conn is not None:
            await self._conn.close()


__all__ = [
    "CODE_TO_EXC",
    "EchoContextPayload",
    "OrinLeaseClientAdapter",
    "OrinRateLimited",
    "OrinUnavailable",
]

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
import hashlib
import json
import os
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from js.orin.desktop import DesktopTargetBindingV1, normalize_desktop_safe_projection
from js.orin.draft import (
    CellPackage,
    CommitPermit,
    EffectDraft,
    ExactCommitApprovalV1,
    draft_from_dict,
    exact_commit_approval_from_dict,
    export_pass_from_dict,
    signed_receipt_from_dict,
    witness_from_dict,
)
from js.orin.handles import (
    OriginHandle,
    appshell_directory_binding_from_dict,
    canonical_workspace_root,
    derive_appshell_directory_handle_id,
    handle_from_dict,
)
from js.orin.handles import (
    appshell_desktop_app_binding_from_dict as appshell_desktop_app_binding_from_dict,
)
from js.orin.handles import (
    derive_appshell_application_handle_id as derive_appshell_application_handle_id,
)
from js.orin.intent import intent_from_dict
from js.orin.protocol import (
    CELL_CONNECT_CAPS,
    HEARTBEAT_INTERVAL_S,
    MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
    REQUIRED_CAP,
    SERVER_CAPS,
    SERVER_QUEUE_DEPTH,
    SESSION_KEY_BYTES,
    STAGE_B_SERVER_CAPS,
    ProtocolError,
    encode_frame,
    make_envelope,
    parse_frame,
    verify_mac,
)
from js.orin.taint import CLEARANCE_INTERNAL, CLEARANCE_SECRET
from js.orind.broker import HandleBroker
from js.orind.cell_identity import CELL_IDENTITY_ENV, LAUNCH_TICKETS_ENV, ORIND_PID_ENV
from js.orind.daemon_net import (
    _TokenBucket,
    peer_credentials,
)
from js.orind.gatekeeper import GateKeeper
from js.orind.intent_store import IntentStore
from js.orind.kernel import (
    EXPORT_EFFECTS,
    GateInputs,
    GateKernel,
    canonical_effect_hash_of,
    handle_refs,
)
from js.orind.keybox import KeyBox, KeyBoxError
from js.orind.membrane import (
    AdmissionBackpressure,
    BudgetExhausted,
    CommitMembrane,
    CommitState,
    ExactApprovalUnavailable,
    ExportPassUnavailable,
    InvalidTransition,
    MembraneError,
    OperationConflict,
    OperationSnapshot,
    OperationSpec,
)
from js.orind.private_paths import (
    PathIdentity,
    PrivatePathError,
    ensure_private_dir,
    safe_unlink_if_same,
    safe_unlink_socket_if_same,
    verify_private_file,
    verify_private_socket,
    write_private_file_exclusive,
)
from js.orind.store import OrinStore

WRITE_BUFFER_HIGH_WATER = MAX_FRAME_BYTES * 128
"""Disconnect clients that let our response backlog grow past this."""


class OrinDaemonError(Exception):
    """Daemon failed to start."""


class _Session:
    """One authenticated client connection."""

    def __init__(
        self,
        *,
        session_key: bytes,
        session_nonce: str,
        peer: tuple[int, int],
        caps: frozenset[str] = frozenset(),
    ) -> None:
        self.session_key = session_key
        self.session_nonce = session_nonce
        self.peer = peer
        self.caps = caps
        self.last_client_seq = 0
        self.last_server_seq = 0
        self.bucket = _TokenBucket()
        self.frames_seen = 0
        self.created_at = time.monotonic()
        self.audit: deque[dict[str, Any]] = deque(maxlen=256)
        # server→client outstanding commands (stage-B cells): seq → future
        self.pending_server: dict[int, tuple[str, asyncio.Future[dict[str, Any]]]] = {}

    def next_server_seq(self) -> int:
        self.last_server_seq += 1
        return self.last_server_seq


CELL_SOCKET_MAX_PATH = 100
"""macOS AF_UNIX sun_path cap minus margin; mirrors js.orin.testing."""


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
        stage_b: bool = False,
        cell_build: bool = False,
        cell_net: bool = False,
        cell_secret: bool = False,
        cell_file: bool = False,
        cell_desktop: bool = False,
        cell_memory: bool = False,
        commit_membrane: bool = False,
        orin_enforce: bool = False,
        cell_identity_enforce: bool = False,
        c1_test_harness: bool = False,
        desktop_script_path: Path | None = None,
        membrane_fault_hook: Callable[[str, str], None] | None = None,
        witness_public_keys: tuple[str, ...] = (),
        now_fn: Any = None,
    ) -> None:

        # Refuse enforce before creating directories, keys, sockets, or
        # databases unless the §6.1 conjunction is fully observed.
        if orin_enforce:
            from types import SimpleNamespace

            from js.orin.stage_c import evaluate_stage_c_conjunction

            report = evaluate_stage_c_conjunction(
                SimpleNamespace(
                    enabled=True,
                    stage_b=stage_b,
                    cell_build=cell_build,
                    cell_secret=cell_secret,
                    cell_net=cell_net,
                    cell_file=cell_file,
                    commit_membrane=commit_membrane,
                    cell_desktop=cell_desktop,
                    cell_memory=cell_memory,
                    cell_identity_enforce=cell_identity_enforce,
                    echo_minimal_os=False,
                )
            )
            if not report.ok:
                raise OrinDaemonError(report.reject_message())
        self._c1_test_harness = bool(c1_test_harness)
        self._orin_enforce = bool(orin_enforce)
        self._cell_identity_enforce = bool(cell_identity_enforce)

        self._state_dir = state_dir
        self._socket_path = socket_path or (state_dir / "orin" / "orind.sock")
        self._orin_dir = orin_dir or (Path(state_dir) / "orin")
        if self._cell_identity_enforce:
            try:
                ensure_private_dir(self._state_dir)
                ensure_private_dir(self._orin_dir)
            except PrivatePathError as exc:
                raise OrinDaemonError("C1 private state directory contract failed") from exc
        else:
            self._orin_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self._orin_dir, 0o700)
        try:
            self._keybox = KeyBox(
                state_dir,
                tier=keybox_tier,
                strict_paths=self._cell_identity_enforce,
            )
        except KeyBoxError as exc:
            raise OrinDaemonError(str(exc)) from exc
        self._store = OrinStore(
            self._orin_dir / "orind_state.db",
            strict_paths=self._cell_identity_enforce,
        )
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
        self._policy_profile = str(policy_profile)
        # -- stage B surfaces (all off unless stage_b=True) --------------------
        self._stage_b = stage_b
        self._cell_build_enabled = bool(cell_build) and stage_b
        self._cell_net_enabled = bool(cell_net) and stage_b
        self._cell_secret_enabled = bool(cell_secret) and stage_b
        self._cell_file_enabled = bool(cell_file) and stage_b
        from js.orin.stage_c import desktop_memory_cells_allowed

        allow_desktop_memory = desktop_memory_cells_allowed(
            identity=self._cell_identity_enforce,
            harness=self._c1_test_harness,
            enforce=self._orin_enforce,
        )
        self._cells_kept_resident = True
        self._cell_desktop_enabled = bool(cell_desktop) and stage_b and allow_desktop_memory
        self._cell_memory_enabled = bool(cell_memory) and stage_b and allow_desktop_memory
        self._desktop_script_path = desktop_script_path
        desired_service_caps: set[str] = set()
        if self._cell_net_enabled:
            desired_service_caps.update(("cell.net", "cell.connector"))
        if self._cell_secret_enabled:
            desired_service_caps.add("cell.secret")
        self._desired_service_caps = frozenset(desired_service_caps)
        self._services_enabled = bool(self._desired_service_caps)
        self._socket_identities: dict[Path, PathIdentity] = {}
        self._cell_socket_pointer_path: Path | None = None
        self._cell_socket_pointer_identity: PathIdentity | None = None
        self._cell_socket_temp_root: Path | None = None
        self._cell_socket_temp_identity: PathIdentity | None = None
        self._cell_socket_path = self._resolve_cell_socket(self._orin_dir / "cells.sock")
        self._cell_server: asyncio.AbstractServer | None = None
        self._cell_sessions: dict[asyncio.StreamWriter, _Session] = {}
        self._cell_ready_caps: set[str] = set()
        self._cell_tasks: set[asyncio.Task[None]] = set()
        self._cell_procs: set[subprocess.Popen[bytes]] = set()
        self._expected_cell_caps_by_pid: dict[int, frozenset[str]] = {}
        self._expected_cell_launch_by_pid: dict[int, dict[str, str]] = {}
        self._used_cell_launch_nonces: set[str] = set()
        self._cell_runtime_roots: dict[int, Path] = {}
        self._strict_session_key_identities: dict[Path, PathIdentity] = {}
        self._build_proc: subprocess.Popen[bytes] | None = None
        self._services_proc: subprocess.Popen[bytes] | None = None
        self._file_proc: subprocess.Popen[bytes] | None = None
        self._desktop_proc: subprocess.Popen[bytes] | None = None
        self._memory_proc: subprocess.Popen[bytes] | None = None
        self._parent_sessions: dict[str, str] = {}
        self._cell_reconcile_tasks: set[asyncio.Task[None]] = set()
        self._spawn_build_cells = bool(cell_build)
        self._shutting_down = False
        self._kernel: GateKernel | None = None
        self._manifest: Any = None
        self._intents: IntentStore | None = None
        self._broker: HandleBroker | None = None
        self._now_ms: Callable[[], int] = (
            now_fn if now_fn is not None else (lambda: time.time_ns() // 1_000_000)
        )
        self._secret_bit = 0
        self._membrane_fault_hook = membrane_fault_hook
        self._membrane: CommitMembrane | None = None
        if stage_b:
            from js.orin.taint import SECRET
            from js.orin.witness import load_published_public_key
            from js.orind.manifest import builtin_manifest

            self._secret_bit = SECRET
            self._manifest = builtin_manifest(
                self._keybox.key,
                include_desktop=self._cell_desktop_enabled,
                include_memory=self._cell_memory_enabled,
            )
            self._kernel = GateKernel(
                secret_taint_bit=SECRET,
                manifest=self._manifest,
            )
            self._intents = IntentStore(store=self._store, trusted_public_keys=witness_public_keys)
            published = load_published_public_key(state_dir)
            if published:
                self._intents.register_witness_key(published)
            self._broker = HandleBroker(store=self._store, mac_key=self._keybox.key)
            if commit_membrane:
                self._membrane = CommitMembrane(
                    self._orin_dir / "orind_state.db",
                    enabled=True,
                    strict_paths=self._cell_identity_enforce,
                    now_fn=self._now_ms,
                )
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
    def membrane(self) -> CommitMembrane | None:
        return self._membrane

    @property
    def cell_socket_path(self) -> Path:
        return self._cell_socket_path

    def _resolve_cell_socket(self, requested: Path) -> Path:
        if len(str(requested)) <= CELL_SOCKET_MAX_PATH:
            return requested
        short_dir = Path(tempfile.mkdtemp(prefix="orind-cells-"))
        if self._cell_identity_enforce:
            try:
                self._cell_socket_temp_identity = ensure_private_dir(short_dir)
            except PrivatePathError as exc:
                raise OrinDaemonError("C1 short Cell socket root is unsafe") from exc
            self._cell_socket_temp_root = short_dir
        resolved = short_dir / "cells.sock"
        pointer = requested.with_suffix(".sock.path")
        if self._cell_identity_enforce:
            try:
                try:
                    existing = verify_private_file(pointer)
                except PrivatePathError:
                    try:
                        pointer.lstat()
                    except FileNotFoundError:
                        existing = None
                    else:
                        raise
                if existing is not None:
                    safe_unlink_if_same(pointer, existing)
                self._cell_socket_pointer_identity = write_private_file_exclusive(
                    pointer,
                    os.fspath(resolved).encode("utf-8"),
                )
                self._cell_socket_pointer_path = pointer
            except (OSError, PrivatePathError) as exc:
                raise OrinDaemonError("C1 Cell socket pointer contract failed") from exc
            return resolved
        try:
            pointer.parent.mkdir(parents=True, exist_ok=True)
            pointer.write_text(str(resolved), encoding="utf-8")
            pointer.chmod(0o600)
        except OSError:
            pass
        return resolved

    @staticmethod
    def _socket_identity(path: Path) -> PathIdentity:
        try:
            return verify_private_socket(path)
        except PrivatePathError as exc:
            raise OrinDaemonError(f"private socket path contract failed: {path}") from exc

    def _prepare_strict_socket_path(self, path: Path) -> None:
        try:
            ensure_private_dir(path.parent)
        except PrivatePathError as exc:
            raise OrinDaemonError(f"private socket parent contract failed: {path}") from exc
        try:
            existing = self._socket_identity(path)
        except OrinDaemonError:
            try:
                path.lstat()
            except FileNotFoundError:
                return
            raise

        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.1)
            try:
                probe.connect(os.fspath(path))
            except (ConnectionRefusedError, FileNotFoundError):
                pass
            else:
                raise OrinDaemonError(f"private socket is already serving: {path}")
        finally:
            probe.close()
        if self._socket_identity(path) != existing:
            raise OrinDaemonError(f"private socket changed before stale cleanup: {path}")
        try:
            safe_unlink_socket_if_same(path, existing)
        except PrivatePathError as exc:
            raise OrinDaemonError(f"private stale socket cannot be removed: {path}") from exc

    def _pin_strict_socket(self, path: Path) -> None:
        self._socket_identities[path] = self._socket_identity(path)

    def _strict_socket_is_current(self, path: Path) -> bool:
        expected = self._socket_identities.get(path)
        if expected is None:
            return False
        try:
            return self._socket_identity(path) == expected
        except OrinDaemonError:
            return False

    def _unlink_strict_socket(self, path: Path) -> None:
        expected = self._socket_identities.pop(path, None)
        if expected is None:
            return
        with contextlib.suppress(PrivatePathError):
            safe_unlink_socket_if_same(path, expected)

    @property
    def keybox_tier(self) -> str:
        return self._keybox.active_tier

    def audit_events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._audit_log)

    def _audit(self, event: str, **fields: Any) -> None:
        record = {"event": event, **fields}
        self._audit_log.append(record)

    @staticmethod
    def _clearance_of(envelope: dict[str, Any]) -> int:
        """Preserve an explicit PUBLIC clearance; only absence defaults INTERNAL."""

        value = envelope.get("clearance", CLEARANCE_INTERNAL)
        return int(value)

    async def start(self) -> None:
        if self._server is not None:
            return
        self._loop = asyncio.get_running_loop()
        if self._cell_identity_enforce:
            self._prepare_strict_socket_path(self._socket_path)
        else:
            with contextlib.suppress(FileNotFoundError):
                self._socket_path.unlink()
        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=str(self._socket_path),
        )
        os.chmod(self._socket_path, 0o600)
        if self._cell_identity_enforce:
            self._pin_strict_socket(self._socket_path)
        if self._stage_b:
            if self._cell_identity_enforce:
                self._prepare_strict_socket_path(self._cell_socket_path)
            else:
                with contextlib.suppress(FileNotFoundError):
                    self._cell_socket_path.unlink()
            self._cell_server = await asyncio.start_unix_server(
                self._handle_cell_connection,
                path=str(self._cell_socket_path),
            )
            os.chmod(self._cell_socket_path, 0o600)
            if self._cell_identity_enforce:
                self._pin_strict_socket(self._cell_socket_path)
            if self._spawn_build_cells and self._cell_build_enabled:
                self._spawn_build_cell()
            if self._services_enabled:
                self._spawn_services_cell()
            if self._cell_file_enabled:
                self._spawn_file_cell()
            if self._cell_desktop_enabled:
                self._spawn_desktop_cell()
            if self._cell_memory_enabled:
                self._spawn_memory_cell()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                # Python 3.12 wait_closed() also waits for live handler tasks;
                # a peer that never sends EOF must not block shutdown.
                await asyncio.wait_for(self._server.wait_closed(), timeout=1.0)
            except TimeoutError:
                pass
            self._server = None
        for task in tuple(self._handler_tasks):
            task.cancel()
        for session_writer in tuple(self._sessions.keys()):
            session_writer.close()
        if self._handler_tasks:
            await asyncio.gather(*self._handler_tasks, return_exceptions=True)
        self._handler_tasks.clear()
        # -- stage B cells ------------------------------------------------------
        self._shutting_down = True
        if self._cell_server is not None:
            self._cell_server.close()
            try:
                await asyncio.wait_for(self._cell_server.wait_closed(), timeout=1.0)
            except TimeoutError:
                pass
            self._cell_server = None
        for task in tuple(self._cell_tasks):
            task.cancel()
        for writer in tuple(self._cell_sessions.keys()):
            writer.close()
        if self._cell_tasks:
            await asyncio.gather(*self._cell_tasks, return_exceptions=True)
        self._cell_tasks.clear()
        self._cell_ready_caps.clear()
        for task in tuple(self._cell_reconcile_tasks):
            task.cancel()
        if self._cell_reconcile_tasks:
            await asyncio.gather(*self._cell_reconcile_tasks, return_exceptions=True)
        self._cell_reconcile_tasks.clear()
        for proc in tuple(self._cell_procs):
            if proc.poll() is None:
                proc.terminate()
        for proc in tuple(self._cell_procs):
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=3.0)
        self._cell_procs.clear()
        self._expected_cell_caps_by_pid.clear()
        self._expected_cell_launch_by_pid.clear()
        self._used_cell_launch_nonces.clear()
        for key_file, identity in tuple(self._strict_session_key_identities.items()):
            self._cleanup_strict_session_key(key_file, identity)
        for runtime_root in tuple(self._cell_runtime_roots.values()):
            self._discard_cell_runtime_root(runtime_root)
        self._cell_runtime_roots.clear()
        self._build_proc = None
        self._services_proc = None
        self._file_proc = None
        self._desktop_proc = None
        self._memory_proc = None
        if self._cell_identity_enforce:
            self._unlink_strict_socket(self._socket_path)
            self._unlink_strict_socket(self._cell_socket_path)
            if (
                self._cell_socket_pointer_path is not None
                and self._cell_socket_pointer_identity is not None
            ):
                with contextlib.suppress(PrivatePathError):
                    safe_unlink_if_same(
                        self._cell_socket_pointer_path,
                        self._cell_socket_pointer_identity,
                    )
            if (
                self._cell_socket_temp_root is not None
                and self._cell_socket_temp_identity is not None
            ):
                try:
                    current = ensure_private_dir(self._cell_socket_temp_root)
                    if current == self._cell_socket_temp_identity:
                        self._cell_socket_temp_root.rmdir()
                except (OSError, PrivatePathError):
                    pass
        else:
            with contextlib.suppress(FileNotFoundError):
                self._socket_path.unlink()
            with contextlib.suppress(FileNotFoundError):
                self._cell_socket_path.unlink()
            with contextlib.suppress(FileNotFoundError):
                (self._orin_dir / "cells.sock.path").unlink(missing_ok=True)
        if self._membrane is not None:
            self._membrane.close()
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
            if self._cell_identity_enforce and not self._strict_socket_is_current(
                self._socket_path
            ):
                self._audit("peer_rejected", reason="orind socket path replaced")
                writer.close()
                return
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
        supported = set(SERVER_CAPS)
        if self._stage_b:
            supported |= set(STAGE_B_SERVER_CAPS)
            supported |= set(CELL_CONNECT_CAPS)
        negotiated = frozenset(c for c in caps if c in supported)
        session = _Session(
            session_key=session_key,
            session_nonce=client_nonce + server_nonce,
            peer=(observed_euid, session_pid),
            caps=negotiated,
        )
        ack = make_envelope(
            "hello_ack",
            seq=session.next_server_seq(),
            nonce=session.session_nonce,
            session_key=None,
            ok=True,
            caps=sorted(negotiated),
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

    def _publish_strict_session_key(
        self,
        key_file: Path,
        key: bytes,
    ) -> PathIdentity | None:
        """Publish a C1 one-shot key without deleting or repairing an object."""

        try:
            identity = write_private_file_exclusive(key_file, key)
        except (OSError, PrivatePathError):
            self._audit("session_key_publish_failed", reason="private-file contract")
            return None
        self._strict_session_key_identities[key_file] = identity
        return identity

    def _cleanup_strict_session_key(
        self,
        key_file: Path,
        expected: PathIdentity,
    ) -> None:
        """Remove only the one-shot key inode published by this daemon."""

        try:
            safe_unlink_if_same(key_file, expected)
        except PrivatePathError:
            self._audit("session_key_cleanup_skipped", reason="path replaced")
        finally:
            self._strict_session_key_identities.pop(key_file, None)

    async def _strict_cell_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer: tuple[int, int],
    ) -> _Session | None:
        """Authenticate one daemon-launched Cell before publishing authority."""

        observed_euid, observed_pid = peer
        if observed_pid <= 0:
            self._audit("handshake_rejected", reason="cell peer pid unavailable")
            return None
        try:
            envelope = await asyncio.wait_for(self._read_frame(reader), timeout=5.0)
        except (ProtocolError, asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            return None
        if envelope is None or envelope.get("type") != "hello" or envelope.get("seq") != 1:
            self._audit("handshake_rejected", reason="invalid Cell hello")
            return None
        if envelope.get("pid") != observed_pid:
            self._audit("handshake_rejected", reason="Cell declared pid mismatch")
            return None
        raw_caps = envelope.get("caps")
        if (
            not isinstance(raw_caps, list)
            or len(raw_caps) != 1
            or not isinstance(raw_caps[0], str)
            or raw_caps[0] not in CELL_CONNECT_CAPS
        ):
            self._audit("handshake_rejected", reason="Cell hello cap mismatch")
            return None
        cap = raw_caps[0]
        expected_caps = self._expected_cell_caps_by_pid.get(observed_pid)
        launch_tickets = self._expected_cell_launch_by_pid.get(observed_pid)
        presented_ticket = envelope.get("nonce")
        expected_ticket = launch_tickets.get(cap) if launch_tickets is not None else None
        if (
            expected_caps is None
            or cap not in expected_caps
            or expected_ticket is None
            or not isinstance(presented_ticket, str)
            or not secrets.compare_digest(expected_ticket, presented_ticket)
            or presented_ticket in self._used_cell_launch_nonces
        ):
            self._audit("handshake_rejected", reason="Cell launch binding mismatch")
            return None
        if any(
            cap in session.caps and not other_writer.is_closing()
            for other_writer, session in self._cell_sessions.items()
        ):
            self._audit("handshake_rejected", reason="duplicate cell cap")
            return None

        # Consume the per-cap launch authority before publishing a session
        # key.  A failed proof cannot be retried with the same hello.
        assert launch_tickets is not None
        launch_tickets.pop(cap)
        self._used_cell_launch_nonces.add(presented_ticket)
        if not launch_tickets:
            self._expected_cell_launch_by_pid.pop(observed_pid, None)

        client_nonce = str(envelope["nonce"])
        session_key = secrets.token_bytes(SESSION_KEY_BYTES)
        key_file = self._orin_dir / f"session-{observed_pid}.key"
        key_identity = self._publish_strict_session_key(key_file, session_key)
        if key_identity is None:
            return None
        server_nonce = secrets.token_hex(16)
        session = _Session(
            session_key=session_key,
            session_nonce=client_nonce + server_nonce,
            peer=(observed_euid, observed_pid),
            caps=frozenset({cap}),
        )
        hello_ack = make_envelope(
            "hello_ack",
            seq=session.next_server_seq(),
            nonce=session.session_nonce,
            session_key=None,
            ok=True,
            caps=[cap],
            server_nonce=server_nonce,
        )
        try:
            writer.write(encode_frame(hello_ack))
            await writer.drain()
            proof = await asyncio.wait_for(self._read_frame(reader), timeout=5.0)
            if (
                proof is None
                or proof.get("type") != "heartbeat"
                or proof.get("seq") != 2
                or proof.get("nonce") != session.session_nonce
                or not verify_mac(session.session_key, proof)
                or key_file.exists()
                or key_file.is_symlink()
            ):
                raise ProtocolError("Cell proof-of-key failed")
            session.last_client_seq = 2
            session.last_server_seq = 2
            proof_ack = make_envelope(
                "heartbeat_ack",
                seq=2,
                nonce=session.session_nonce,
                session_key=session.session_key,
                ok=True,
                healthy=True,
            )
            writer.write(encode_frame(proof_ack))
            await writer.drain()
        except (
            ProtocolError,
            asyncio.IncompleteReadError,
            ConnectionError,
            RuntimeError,
            TimeoutError,
        ):
            self._cleanup_strict_session_key(key_file, key_identity)
            self._audit("handshake_rejected", reason="Cell proof-of-key failed")
            return None
        self._strict_session_key_identities.pop(key_file, None)
        self._audit("handshake_ok", peer_pid=observed_pid, cell_cap=cap)
        return session

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
            response = await self._dispatch(envelope, session)
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
        required_cap = REQUIRED_CAP.get(envelope["type"])
        if required_cap is not None and required_cap not in session.caps:
            self._audit(
                "cap_violation",
                reason=f"{envelope['type']} without negotiated {required_cap}",
                peer_pid=session.peer[1],
            )
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

    async def _dispatch(self, envelope: dict[str, Any], session: _Session) -> dict[str, Any]:
        message_type = envelope["type"]
        if message_type == "heartbeat":
            return {"ok": True, "healthy": True}
        if message_type == "consume" and str(envelope.get("mode") or "") == "cell":
            return await self._dispatch_cell(
                envelope,
                session_id=session.session_nonce,
                parent_session=str(envelope.get("session_id") or ""),
            )
        if message_type == "preflight":
            return await self._on_preflight(envelope)
        if message_type == "issue":
            return self._gatekeeper.handle_issue(
                envelope.get("lease") or {},
                envelope.get("context"),
                context_taint=int(envelope.get("context_taint") or 0),
                arg_taint=int(envelope.get("arg_taint") or 0),
                clearance=self._clearance_of(envelope),
                channel=str(envelope.get("channel") or ""),
            )
        if message_type == "consume":
            return self._gatekeeper.handle_consume(
                str(envelope.get("mode", "")),
                envelope.get("lease"),
                envelope.get("context"),
                envelope.get("expected"),
                context_taint=int(envelope.get("context_taint") or 0),
                arg_taint=int(envelope.get("arg_taint") or 0),
                clearance=self._clearance_of(envelope),
                scan_text=str(envelope.get("scan_text") or ""),
                scan_surface=str(envelope.get("scan_surface") or ""),
                session_id=str(envelope.get("session_id") or ""),
                channel=str(envelope.get("channel") or ""),
            )
        if message_type == "revoke":
            return self._gatekeeper.handle_revoke(
                str(envelope.get("op") or ""),
                envelope.get("lease_id"),
                envelope.get("owner_key_hash"),
                envelope.get("session_id"),
            )
        if message_type == "intent":
            return self._on_intent(envelope)
        if message_type == "handle":
            return self._on_handle(envelope)
        if message_type == "draft":
            return self._on_draft(envelope)
        self._audit("protocol_violation", reason=f"client sent {message_type}")
        return {"ok": False, "code": "bad_message", "reason": "unexpected message"}

    # -- stage B handlers (reachable only with negotiated caps) ---------------
    def _on_intent(self, envelope: dict[str, Any]) -> dict[str, Any]:
        intents = self._intents
        if intents is None:  # pragma: no cover - cap gating prevents this
            return {"ok": False, "code": "unsupported", "reason": "stage B disabled"}
        op = str(envelope.get("op") or "")
        if op == "register":
            data = envelope.get("intent")
            if not isinstance(data, dict):
                return {"ok": False, "code": "bad_message", "reason": "register requires intent"}
            raw_grant = envelope.get("grant")
            if raw_grant is None:
                # Generic signed intent registration remains a valid, non-issuing
                # operation.  Only the AppShell binding grant below may mint a
                # DirectoryHandle.
                registered = intents.register(data, now_ms=self._now_ms())
                if registered.get("ok"):
                    self._remember_parent_session(data, str(envelope.get("session_id") or ""))
                return registered
            if not isinstance(raw_grant, dict):
                return {
                    "ok": False,
                    "code": "bad_message",
                    "reason": "register grant must be an object",
                }
            if raw_grant.get("schema") == "AppShellDesktopAppBindingV1":
                return self._register_desktop_app_binding(envelope, data, raw_grant)
            session_id = str(envelope.get("session_id") or "")
            if not session_id:
                return {
                    "ok": False,
                    "code": "bad_message",
                    "reason": "AppShell directory binding requires parent session",
                }
            try:
                binding = appshell_directory_binding_from_dict(raw_grant)
                intent = intent_from_dict(data)
                root = canonical_workspace_root(binding.workspace_root)
            except Exception as exc:
                return {"ok": False, "code": "bad_message", "reason": str(exc)}
            if root != binding.workspace_root:
                return {
                    "ok": False,
                    "code": "denied",
                    "reason": "workspace root is not canonical NFC",
                }
            if (
                intent.issued_by != "appshell:owner-witness"
                or intent.profile not in {"personal", "work"}
                or "file.commit" not in intent.allowed_effect_classes
                or binding.product_id != intent.product_id
            ):
                return {
                    "ok": False,
                    "code": "denied",
                    "reason": "intent is not an AppShell file binding",
                }
            try:
                expected_handle_id = derive_appshell_directory_handle_id(
                    installation_owner_hash=intent.owner_key_hash,
                    product_id=intent.product_id,
                    task_id=intent.task_id,
                    profile=intent.profile,
                    principal_owner=binding.principal_owner,
                    principal_session=session_id,
                    principal_epoch=binding.principal_epoch,
                    workspace_root=root,
                )
            except Exception as exc:
                return {"ok": False, "code": "bad_message", "reason": str(exc)}
            directory_handles = tuple(
                handle_id
                for handle_id in intent.allowed_resource_handles
                if handle_id.startswith("dirh:")
            )
            if directory_handles != (expected_handle_id,):
                return {
                    "ok": False,
                    "code": "denied",
                    "reason": "signed DirectoryHandle commitment mismatch",
                }
            registered = intents.register(data, now_ms=self._now_ms())
            if not registered.get("ok"):
                return registered
            broker = self._broker
            if broker is None:  # pragma: no cover - stage_b initializes it
                return {"ok": False, "code": "unsupported", "reason": "handle broker unavailable"}
            issued = broker.issue(
                kind="DirectoryHandle",
                token=expected_handle_id.partition(":")[2],
                owner_key_hash=intent.owner_key_hash,
                tenant=intent.profile,
                object_digest=root,
                capabilities=("read", "stage", "write"),
                expires_at_ms=intent.expires_at_ms,
                approved=True,
                now_ms=self._now_ms(),
            )
            if not issued.get("ok"):
                return issued
            # Never return the sealed handle or its root over the Echo-facing
            # connection.  The AppShell adapter already knows the committed id.
            self._remember_parent_session(data, session_id)
            return {"ok": True}
        if op == "active":
            task_id = str(envelope.get("task_id") or "")
            if not task_id:
                return {"ok": False, "code": "bad_message", "reason": "active requires task_id"}
            active = intents.active_envelope(task_id, now_ms=self._now_ms())
            if active is None:
                return {"ok": False, "code": "unknown_intent", "reason": "no active intent"}
            return {"ok": True, "intent": active.to_dict()}
        if op == "admin_unfreeze":
            return self._on_admin_unfreeze(envelope)
        if op == "grant_export":
            raw_grant = dict(envelope.get("grant") or {})
            try:
                export_pass = export_pass_from_dict(raw_grant)
            except Exception as exc:
                return {"ok": False, "code": "bad_message", "reason": str(exc)}
            if str(envelope.get("task_id") or "") != export_pass.task_id:
                return {"ok": False, "code": "denied", "reason": "task binding mismatch"}
            now = self._now_ms()
            raw_witness = self._store.state_witness_by_id(export_pass.witness_id, now_ms=now)
            if not isinstance(raw_witness, dict):
                return {"ok": False, "code": "stale_state", "reason": "unknown witness"}
            try:
                witness = witness_from_dict(raw_witness)
            except Exception as exc:
                return {"ok": False, "code": "stale_state", "reason": str(exc)}
            current_witness = self._store.current_state_witness(witness.draft_id, now_ms=now)
            if (
                not isinstance(current_witness, dict)
                or str(current_witness.get("witness_id") or "") != witness.witness_id
            ):
                return {"ok": False, "code": "stale_state", "reason": "witness superseded"}
            record = self._store.get_effect_draft(witness.draft_id, now_ms=now)
            if not isinstance(record, dict):
                return {"ok": False, "code": "expired", "reason": "draft expired"}
            try:
                draft = draft_from_dict(dict(record.get("draft") or {}))
            except Exception as exc:
                return {"ok": False, "code": "bad_message", "reason": str(exc)}
            entry = self._manifest_entry(draft)
            if entry is None:
                return {"ok": False, "code": "denied", "reason": "manifest unavailable"}
            destinations = self._destination_handles(draft, entry)
            active = intents.active_envelope(draft.task_id, now_ms=now)
            if active is None:
                return {"ok": False, "code": "unknown_intent", "reason": "no active intent"}
            _handles, handle_error = self._resolve_draft_handles(
                draft,
                intent=active,
                clearance=int(record.get("clearance", CLEARANCE_INTERNAL)),
                require_all=True,
            )
            if handle_error is not None:
                return {"ok": False, "code": "unknown_handle", "reason": handle_error}
            expected = {
                "task_id": draft.task_id,
                "payload_hash": str(record.get("canonical_effect_hash") or ""),
                "destination_handles": destinations,
                "witness_id": witness.witness_id,
            }
            grant_result = intents.grant_export(
                raw_grant,
                now_ms=now,
                expected_binding=expected,
                profile=active.profile,
                standing=active.profile == "work",
            )
            if not grant_result.get("ok"):
                return grant_result
            return {"ok": True}
        if op == "grant_exact":
            raw_grant = dict(envelope.get("grant") or {})
            try:
                approval = exact_commit_approval_from_dict(raw_grant)
            except Exception as exc:
                return {"ok": False, "code": "bad_message", "reason": str(exc)}
            if str(envelope.get("task_id") or "") != approval.task_id:
                return {"ok": False, "code": "denied", "reason": "task binding mismatch"}
            now = self._now_ms()
            record = self._store.get_effect_draft(approval.draft_id, now_ms=now)
            if not isinstance(record, dict):
                return {"ok": False, "code": "expired", "reason": "draft expired"}
            try:
                draft = draft_from_dict(dict(record.get("draft") or {}))
            except Exception as exc:
                return {"ok": False, "code": "bad_message", "reason": str(exc)}
            if draft.task_id != approval.task_id or draft.effect_type != "file.commit":
                return {
                    "ok": False,
                    "code": "denied",
                    "reason": "approval is not bound to a Personal file commit",
                }
            entry = self._manifest_entry(draft)
            if entry is None or str(getattr(entry, "executor_id", "")) != "cell.file":
                return {"ok": False, "code": "denied", "reason": "manifest unavailable"}
            effect_hash = str(record.get("canonical_effect_hash") or "")
            if effect_hash != approval.canonical_effect_hash:
                return {"ok": False, "code": "denied", "reason": "effect hash mismatch"}
            raw_witness = self._store.state_witness_by_id(approval.witness_id, now_ms=now)
            current_witness = self._store.current_state_witness(draft.draft_id, now_ms=now)
            if (
                not isinstance(raw_witness, dict)
                or not isinstance(current_witness, dict)
                or str(current_witness.get("witness_id") or "") != approval.witness_id
            ):
                return {"ok": False, "code": "stale_state", "reason": "witness superseded"}
            try:
                witness = witness_from_dict(raw_witness)
            except Exception as exc:
                return {"ok": False, "code": "stale_state", "reason": str(exc)}
            if (
                witness.draft_id != draft.draft_id
                or witness.executor_id != "cell.file"
                or witness.canonical_effect_hash != effect_hash
                or witness.expired(now)
            ):
                return {"ok": False, "code": "stale_state", "reason": "witness mismatch"}
            active = self._authority_for_draft(draft, now_ms=now)
            if (
                active is None
                or active.profile != "personal"
                or active.approval_policy != "exact_commit_required"
                or "file.commit" not in active.allowed_effect_classes
            ):
                return {
                    "ok": False,
                    "code": "denied",
                    "reason": "exact approval requires a Personal exact-commit intent",
                }
            directory_handle_id = self._file_directory_handle_id(draft)
            if not directory_handle_id or directory_handle_id != approval.directory_handle_id:
                return {
                    "ok": False,
                    "code": "denied",
                    "reason": "DirectoryHandle binding mismatch",
                }
            _handles, handle_error = self._resolve_draft_handles(
                draft,
                intent=active,
                clearance=int(record.get("clearance", CLEARANCE_INTERNAL)),
                require_all=True,
            )
            if handle_error is not None:
                return {"ok": False, "code": "unknown_handle", "reason": handle_error}
            grant_result = intents.grant_exact(
                raw_grant,
                now_ms=now,
                expected_binding={
                    "task_id": draft.task_id,
                    "draft_id": draft.draft_id,
                    "witness_id": witness.witness_id,
                    "canonical_effect_hash": effect_hash,
                    "directory_handle_id": directory_handle_id,
                },
            )
            if not grant_result.get("ok"):
                return grant_result
            return {"ok": True}
        return {"ok": False, "code": "unsupported", "reason": f"unknown intent op {op!r}"}

    def _on_admin_unfreeze(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """K§16.3: unfreeze / policy rollback is R3 and needs an admin intent."""

        from js.orin.intent import intent_from_dict
        from js.orind.responder import LEVEL_FREEZE

        assert self._intents is not None  # cap gating guarantees stage_b
        data = envelope.get("intent")
        if not isinstance(data, dict):
            return {"ok": False, "code": "bad_message", "reason": "admin_unfreeze requires intent"}
        ack = self._intents.register(data, now_ms=self._now_ms())
        if not ack.get("ok"):
            return ack
        try:
            admin_intent = intent_from_dict(data)
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        if (
            "admin.unfreeze" not in admin_intent.allowed_effect_classes
            or admin_intent.approval_policy != "dual_control"
        ):
            return {
                "ok": False,
                "code": "denied",
                "reason": "unfreeze requires dual-control admin.unfreeze intent",
            }
        responder = self._gatekeeper.responder
        target = str(envelope.get("session_id") or "")
        sessions = (target,) if target else self._store.frozen_sessions()
        frozen = tuple(s for s in sessions if responder.level_of(s) >= LEVEL_FREEZE)
        now = self._now_ms()
        for session_id in frozen:
            responder.unfreeze(
                session_id,
                now_ms=now,
                evidence=f"intent={admin_intent.intent_id}",
            )
        self._audit("admin_unfreeze", sessions=frozen, intent_id=admin_intent.intent_id)
        return {"ok": True, "unfrozen": list(frozen)}

    def _register_desktop_app_binding(
        self,
        envelope: dict[str, Any],
        data: dict[str, Any],
        raw_grant: dict[str, Any],
    ) -> dict[str, Any]:
        intents = self._intents
        if intents is None:  # pragma: no cover - caller already checked
            return {"ok": False, "code": "unsupported", "reason": "stage B disabled"}
        session_id = str(envelope.get("session_id") or "")
        if not session_id:
            return {
                "ok": False,
                "code": "bad_message",
                "reason": "AppShell desktop app binding requires parent session",
            }
        try:
            binding = appshell_desktop_app_binding_from_dict(raw_grant)
            intent = intent_from_dict(data)
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        if (
            intent.issued_by != "appshell:owner-witness"
            or intent.profile not in {"personal", "work"}
            or "desktop.observe" not in intent.allowed_effect_classes
            or "desktop.action" not in intent.allowed_effect_classes
            or binding.product_id != intent.product_id
        ):
            return {
                "ok": False,
                "code": "denied",
                "reason": "intent is not an AppShell desktop app binding",
            }
        try:
            expected_handle_id = derive_appshell_application_handle_id(
                installation_owner_hash=intent.owner_key_hash,
                product_id=intent.product_id,
                task_id=intent.task_id,
                profile=intent.profile,
                principal_owner=binding.principal_owner,
                principal_session=session_id,
                principal_epoch=binding.principal_epoch,
                bundle_id=binding.bundle_id,
            )
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        application_handles = tuple(
            handle_id
            for handle_id in intent.allowed_resource_handles
            if handle_id.startswith("app:")
        )
        if expected_handle_id not in application_handles:
            return {
                "ok": False,
                "code": "denied",
                "reason": "signed ApplicationHandle commitment mismatch",
            }
        registered = intents.register(data, now_ms=self._now_ms())
        if not registered.get("ok"):
            return registered
        broker = self._broker
        if broker is None:  # pragma: no cover - stage_b initializes it
            return {"ok": False, "code": "unsupported", "reason": "handle broker unavailable"}
        issued = broker.issue(
            kind="ApplicationHandle",
            token=expected_handle_id.partition(":")[2],
            owner_key_hash=intent.owner_key_hash,
            tenant=intent.profile,
            object_digest=binding.bundle_id,
            capabilities=("read", "use"),
            expires_at_ms=intent.expires_at_ms,
            approved=True,
            now_ms=self._now_ms(),
        )
        if not issued.get("ok"):
            return issued
        self._parent_sessions[intent.task_id] = session_id
        return {"ok": True}

    def _on_handle(self, envelope: dict[str, Any]) -> dict[str, Any]:
        broker = self._broker
        if broker is None:  # pragma: no cover - cap gating prevents this
            return {"ok": False, "code": "unsupported", "reason": "stage B disabled"}
        op = str(envelope.get("op") or "")
        if op == "issue":
            # One-time user approval flows through AppShell (WP6); a plain
            # protocol client can never mark its own issuance approved.
            return {
                "ok": False,
                "code": "unsupported",
                "reason": "issuance requires the approval channel (WP6)",
            }
        if op == "resolve":
            ref = envelope.get("handle")
            handle_id = ""
            if isinstance(ref, dict):
                handle_id = str(ref.get("handle_id") or "")
            elif isinstance(ref, str):
                handle_id = ref
            if not handle_id:
                return {"ok": False, "code": "bad_message", "reason": "resolve requires a handle"}
            if handle_id.startswith("desktop:"):
                # Echo receives only the opaque id from the observation
                # projection.  The complete sealed target remains on the
                # internal broker -> Cell package path.
                return {
                    "ok": False,
                    "code": "unsupported",
                    "reason": "DesktopTargetHandle is Cell-private",
                }
            return broker.resolve(handle_id, now_ms=self._now_ms())
        kind = envelope.get("kind")
        candidates = broker.seed_list(kind if isinstance(kind, str) else None)
        return {"ok": True, "candidates": candidates}

    def _manifest_entry(self, draft: EffectDraft) -> Any | None:
        manifest = self._manifest
        return manifest.get(draft.effect_type) if manifest is not None else None

    @staticmethod
    def _destination_handles(draft: EffectDraft, entry: Any) -> tuple[str, ...]:
        destinations: list[str] = []
        permission_args = getattr(entry, "permission_args", {})
        for name, prefix in permission_args.items():
            if prefix != "rcpt":
                continue
            value = draft.arguments.get(name)
            values = value if isinstance(value, list) else [value]
            destinations.extend(item for item in values if isinstance(item, str))
        return tuple(sorted(destinations))

    @staticmethod
    def _file_directory_handle_id(draft: EffectDraft) -> str:
        if draft.effect_type != "file.commit":
            return ""
        value = draft.arguments.get("directory_handle")
        if not isinstance(value, str) or not value.startswith("dirh:"):
            return ""
        return value

    def _authority_for_draft(self, draft: EffectDraft, *, now_ms: int) -> Any | None:
        """Return the enforcement view, never the broad informational view for files."""

        intents = self._intents
        if intents is None:
            return None
        if draft.effect_type == "file.commit":
            return intents.effective_grant(draft.task_id, now_ms=now_ms)
        return intents.active_envelope(draft.task_id, now_ms=now_ms)

    def _application_handles_for_intent(self, intent: Any) -> dict[str, OriginHandle]:
        broker = self._broker
        if broker is None:
            return {}
        now = self._now_ms()
        resolved: dict[str, OriginHandle] = {}
        for handle_id in intent.allowed_resource_handles:
            if not isinstance(handle_id, str) or not handle_id.startswith("app:"):
                continue
            handle = broker.valid_handle(handle_id, now_ms=now)
            if (
                handle is None
                or handle.kind != "ApplicationHandle"
                or handle.owner_key_hash != intent.owner_key_hash
                or handle.tenant != intent.profile
                or "use" not in handle.capabilities
            ):
                continue
            resolved[handle_id] = handle
        return resolved

    def _memory_scope_error(
        self,
        draft: EffectDraft,
        *,
        intent: Any,
        session_id: str = "",
    ) -> str | None:
        if not draft.effect_type.startswith("memory."):
            return None
        if intent is None:
            return "memory effect has no active owner intent"
        args = draft.arguments
        if args.get("owner_key_hash") != intent.owner_key_hash:
            return "memory owner mismatch"
        if args.get("profile") != intent.profile:
            return "memory profile mismatch"
        if args.get("task_id") not in {None, draft.task_id}:
            return "memory task mismatch"
        claimed_session = args.get("session_id")
        if type(claimed_session) is not str or not claimed_session or len(claimed_session) > 256:
            return "memory session is required"
        bound = self._parent_sessions.get(draft.task_id, "")
        if bound and session_id and bound != session_id:
            return "memory session mismatch"
        parent = session_id or bound
        if not parent:
            return "memory parent session is required"
        if claimed_session != parent:
            return "memory session mismatch"
        return None

    def _remember_parent_session(self, intent_data: dict[str, Any], session_id: str) -> None:
        if not session_id:
            return
        try:
            intent = intent_from_dict(intent_data)
        except Exception:
            return
        self._parent_sessions[intent.task_id] = session_id

    def _active_personal_file_approvals(
        self,
        draft: EffectDraft,
        *,
        active: Any,
        witness: Any,
        canonical_effect_hash: str,
        now_ms: int,
    ) -> tuple[ExactCommitApprovalV1, ...]:
        """Return exact owner approvals only for Personal ``file.commit``.

        The profile/effect guard intentionally precedes the store call: Work
        keeps its standing template path and must never query or claim this
        one-shot Personal authority.
        """

        intents = self._intents
        if (
            intents is None
            or draft.effect_type != "file.commit"
            or active is None
            or active.profile != "personal"
            or active.approval_policy != "exact_commit_required"
        ):
            return ()
        directory_handle_id = self._file_directory_handle_id(draft)
        if not directory_handle_id:
            return ()
        rows = intents.active_exact_commit_approvals(
            task_id=draft.task_id,
            draft_id=draft.draft_id,
            witness_id=str(witness.witness_id),
            canonical_effect_hash=canonical_effect_hash,
            directory_handle_id=directory_handle_id,
            now_ms=now_ms,
        )
        parsed: list[ExactCommitApprovalV1] = []
        for row in rows:
            with contextlib.suppress(Exception):
                parsed.append(exact_commit_approval_from_dict(row))
        return tuple(parsed)

    @staticmethod
    def _commit_approval_satisfied(
        draft: EffectDraft,
        *,
        active: Any,
        export_passes_present: bool = False,
        personal_export_claimed: bool = False,
        exact_approvals_present: bool = False,
        personal_exact_claimed: bool = False,
    ) -> bool:
        if draft.effect_type in EXPORT_EFFECTS and (
            export_passes_present or personal_export_claimed
        ):
            return True
        if (
            draft.effect_type not in EXPORT_EFFECTS
            and active.approval_policy == "preauthorized_exact_template"
        ):
            return True
        return bool(
            draft.effect_type == "file.commit"
            and active.profile == "personal"
            and active.approval_policy == "exact_commit_required"
            and (exact_approvals_present or personal_exact_claimed)
        )

    def _resolve_draft_handles(
        self,
        draft: EffectDraft,
        *,
        intent: Any | None,
        clearance: int,
        require_all: bool = False,
    ) -> tuple[dict[str, OriginHandle], str | None]:
        broker = self._broker
        if broker is None:
            return ({}, "handle broker unavailable")
        now = self._now_ms()
        resolved: dict[str, OriginHandle] = {}
        for ref in sorted(handle_refs(draft.arguments)):
            handle = broker.valid_handle(ref, now_ms=now)
            if handle is None:
                if require_all:
                    return ({}, f"unresolved handle {ref}")
                continue
            if intent is not None and handle.owner_key_hash != intent.owner_key_hash:
                return ({}, "handle owner mismatch")
            if handle.confidentiality == "SECRET" and clearance < CLEARANCE_SECRET:
                return ({}, "clearance below SECRET")
            required_cap = {
                "RecipientHandle": "send",
                "EndpointHandle": "read",
                "SecretHandle": "use",
                "DesktopTargetHandle": "use",
            }.get(handle.kind)
            if required_cap is not None and required_cap not in handle.capabilities:
                return ({}, f"handle capability mismatch for {ref}")
            if handle.kind in {"DirectoryHandle", "ArtifactHandle"}:
                if intent is None:
                    if require_all:
                        return ({}, "resource handle requires an active owner intent")
                else:
                    if ref not in intent.allowed_resource_handles:
                        return ({}, f"resource handle {ref} is not granted by owner intent")
                    if handle.tenant != intent.profile:
                        return ({}, f"resource handle tenant mismatch for {ref}")
                    required_resource_caps = {
                        "file.commit": frozenset({"stage", "write"}),
                        "artifact.stage": frozenset({"stage"}),
                    }.get(draft.effect_type, frozenset({"read"}))
                    if not required_resource_caps.issubset(handle.capabilities):
                        return ({}, f"resource handle capability mismatch for {ref}")
            if handle.kind == "DesktopTargetHandle":
                if intent is None:
                    if require_all:
                        return ({}, "desktop target requires an active owner intent")
                elif handle.tenant != intent.profile:
                    return ({}, f"desktop target tenant mismatch for {ref}")
            resolved[ref] = handle
        if require_all and set(resolved) != handle_refs(draft.arguments):
            return ({}, "package handle set is incomplete")
        if intent is not None and intent.profile == "work":
            entry = self._manifest_entry(draft)
            if entry is not None:
                destinations = self._destination_handles(draft, entry)
                standing = set(intent.allowed_sink_handles)
                if "*" in standing or any(item not in standing for item in destinations):
                    return ({}, "work destination is not pre-registered")
        return (resolved, None)

    def _gate_inputs_for_record(
        self,
        draft: EffectDraft,
        record: dict[str, Any],
        *,
        include_passes: bool = True,
    ) -> tuple[GateInputs, str | None]:
        assert self._intents is not None
        now = self._now_ms()
        active = self._authority_for_draft(draft, now_ms=now)
        resolved, error = self._resolve_draft_handles(
            draft,
            intent=active,
            clearance=int(record.get("clearance", CLEARANCE_INTERNAL)),
        )
        inputs = GateInputs(
            now_ms=now,
            intent=active,
            canonical_effect_hash=str(record.get("canonical_effect_hash") or ""),
            expected_executor_id=str(record.get("executor_id") or ""),
            context_has_secret=bool(int(record.get("context_taint", 0)) & self._secret_bit),
            freeze_active=bool(self._store.frozen_sessions()),
            policy_profile=self._policy_profile,
        )
        if self._membrane is not None:
            operation = self._membrane.operation_for_draft(draft.draft_id)
            inputs.reconciliation_pending = operation is not None and operation.state in {
                CommitState.COMMITTING,
                CommitState.UNKNOWN_COMMIT,
            }
        inputs.handles_by_id = resolved
        raw_witness = self._store.current_state_witness(draft.draft_id)
        if isinstance(raw_witness, dict):
            try:
                inputs.witness = witness_from_dict(raw_witness)
            except Exception:
                inputs.witness = None
        if include_passes and draft.effect_type in EXPORT_EFFECTS:
            passes = self._intents.export_passes_for_task(draft.task_id)
            parsed = []
            for raw_pass in passes:
                try:
                    parsed.append(export_pass_from_dict(raw_pass))
                except Exception:
                    continue
            inputs.export_passes = tuple(parsed)
        return inputs, error

    def _desktop_preflight_inputs(
        self,
        draft: EffectDraft,
        record: dict[str, Any],
    ) -> tuple[GateInputs | None, str | None]:
        """Re-authorize a harness Desktop preflight without invoking the Cell."""

        kernel = self._kernel
        if kernel is None:  # pragma: no cover - Desktop requires Stage B
            return None, "stage B disabled"
        now = self._now_ms()
        if int(record.get("expires_at_ms", 0)) <= now:
            return None, "draft expired"
        inputs, handle_error = self._gate_inputs_for_record(draft, record)
        if handle_error is not None:
            return None, handle_error
        decision = kernel.assess(draft, inputs)
        if inputs.intent is None:
            return None, "Desktop Cell preflight has no active owner intent"
        if draft.effect_type == "desktop.observe":
            accepted = decision.verdict == "allow_read"
        elif draft.effect_type == "desktop.action":
            accepted = (
                decision.verdict == "deny_missing_witness"
                and decision.reason_code == "no_state_witness"
                and decision.missing == ("state_witness",)
            ) or decision.verdict == "require_approval"
        else:
            accepted = False
        if not accepted:
            return None, "Desktop Cell preflight is not authorized"
        return inputs, None

    def _on_draft(self, envelope: dict[str, Any]) -> dict[str, Any]:
        kernel = self._kernel
        intents = self._intents
        broker = self._broker
        if kernel is None or intents is None or broker is None:  # pragma: no cover
            return {"ok": False, "code": "unsupported", "reason": "stage B disabled"}
        raw = envelope.get("draft")
        try:
            draft = kernel.parse_draft(raw if isinstance(raw, dict) else {})
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        entry = self._manifest_entry(draft)
        if entry is None or not str(getattr(entry, "executor_id", "")).startswith("cell."):
            return {
                "ok": True,
                "verdict": "deny_policy",
                "missing": [],
                "payload_hash": canonical_effect_hash_of(draft),
            }
        now = self._now_ms()
        effect_hash = canonical_effect_hash_of(draft)
        record = {
            "draft_id": draft.draft_id,
            "task_id": draft.task_id,
            "effect_type": draft.effect_type,
            "executor_id": entry.executor_id,
            "canonical_effect_hash": effect_hash,
            "context_taint": int(envelope.get("context_taint", 0)),
            "arg_taint": int(envelope.get("arg_taint", 0)),
            "clearance": self._clearance_of(envelope),
            "created_at_ms": now,
            "expires_at_ms": now + 10 * 60 * 1000,
            "draft": draft.to_dict(),
        }
        stored = self._store.record_effect_draft(record)
        if stored == "conflict":
            return {
                "ok": False,
                "code": "denied",
                "reason": "draft id replayed with different security content",
            }
        current = self._store.get_effect_draft(draft.draft_id, now_ms=now)
        if not isinstance(current, dict):
            return {"ok": False, "code": "expired", "reason": "draft expired"}
        inputs, handle_error = self._gate_inputs_for_record(draft, current)
        if handle_error is not None:
            return {
                "ok": True,
                "verdict": "deny_policy",
                "missing": [],
                "payload_hash": effect_hash,
            }
        decision = kernel.assess(draft, inputs)
        return {
            "ok": True,
            "verdict": decision.verdict,
            "missing": list(decision.missing),
            "payload_hash": effect_hash,
        }

    async def _on_preflight(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Run the real, side-effect-free Cell preflight for a stored draft."""

        if "package" in envelope:
            return {
                "ok": False,
                "code": "denied",
                "reason": "clients cannot supply Cell packages",
            }
        draft_id = str(envelope.get("draft_id") or "")
        now = self._now_ms()
        record = self._store.get_effect_draft(draft_id, now_ms=now)
        if not isinstance(record, dict):
            return {"ok": False, "code": "expired", "reason": "draft is missing or expired"}
        raw_draft = record.get("draft")
        try:
            draft = draft_from_dict(raw_draft if isinstance(raw_draft, dict) else {})
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        entry = self._manifest_entry(draft)
        executor_id = str(getattr(entry, "executor_id", "") if entry is not None else "")
        advisory = str(envelope.get("executor_id") or "")
        if not executor_id or (advisory and advisory != executor_id):
            return {"ok": False, "code": "denied", "reason": "executor mismatch"}
        if executor_id == "cell.desktop":
            gate_inputs, gate_error = self._desktop_preflight_inputs(draft, record)
            if gate_inputs is None:
                return {"ok": False, "code": "denied", "reason": str(gate_error)}
            active = gate_inputs.intent
            handles = dict(gate_inputs.handles_by_id)
            if active is not None:
                handles.update(self._application_handles_for_intent(active))
            handle_error = None
        else:
            active = self._authority_for_draft(draft, now_ms=now)
            handles, handle_error = self._resolve_draft_handles(
                draft,
                intent=active,
                clearance=int(record.get("clearance", CLEARANCE_INTERNAL)),
                require_all=True,
            )
        if handle_error is not None:
            return {"ok": False, "code": "unknown_handle", "reason": handle_error}
        if executor_id == "cell.memory":
            scope_error = self._memory_scope_error(
                draft,
                intent=active,
                session_id=str(envelope.get("session_id") or ""),
            )
            if scope_error is not None:
                return {"ok": False, "code": "denied", "reason": scope_error}
        package = CellPackage(
            draft=draft,
            executor_id=executor_id,
            canonical_effect_hash=str(record.get("canonical_effect_hash") or ""),
            resolved_handles=tuple(handles[key] for key in sorted(handles)),
            clearance=int(record.get("clearance", CLEARANCE_INTERNAL)),
        )
        try:
            package.validate_binding()
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        desktop_session = (
            self._cell_session_by_cap("cell.desktop") if executor_id == "cell.desktop" else None
        )
        response = await self._request_cell(
            executor_id,
            "preflight",
            draft_id=draft.draft_id,
            executor_id=executor_id,
            package=package.to_dict(),
        )
        if response is None:
            return {"ok": False, "code": "unsupported", "reason": "effect cell unavailable"}
        if not response.get("ok"):
            return {
                "ok": False,
                "code": str(response.get("code") or "internal"),
                "reason": str(response.get("reason") or "preflight failed"),
            }
        if executor_id == "cell.desktop":
            # The Cell call can cross both the intent and handle expiry
            # boundary.  Re-run the same closed-world gate before recording a
            # witness or turning an observation into a broker handle.
            gate_inputs, gate_error = self._desktop_preflight_inputs(draft, record)
            if gate_inputs is None:
                return {"ok": False, "code": "denied", "reason": str(gate_error)}
            active = gate_inputs.intent
            handles = gate_inputs.handles_by_id
            now = self._now_ms()
        raw_witness = response.get("witness")
        try:
            witness = witness_from_dict(raw_witness if isinstance(raw_witness, dict) else {})
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        if (
            witness.draft_id != draft.draft_id
            or witness.executor_id != executor_id
            or witness.canonical_effect_hash != package.canonical_effect_hash
            or witness.expired(now)
            or witness.expires_at_ms > now + 65_000
        ):
            return {"ok": False, "code": "stale_state", "reason": "witness binding invalid"}
        desktop_projection: dict[str, Any] | None = None
        if executor_id == "cell.desktop":
            raw_projection = response.get("result")
            try:
                desktop_projection = self._safe_cell_projection(
                    draft.effect_type,
                    dict(raw_projection) if isinstance(raw_projection, dict) else {},
                )
            except ProtocolError:
                return {
                    "ok": False,
                    "code": "bad_message",
                    "reason": "Desktop Cell projection is invalid",
                }
            required_projection = (
                {
                    "desktop_target_handle_id",
                    "display_id",
                    "height",
                    "pixel_hash",
                    "scale",
                    "target_kind",
                    "width",
                }
                if draft.effect_type == "desktop.observe"
                else {"action", "before_digest"}
            )
            if not required_projection.issubset(desktop_projection):
                return {
                    "ok": False,
                    "code": "bad_message",
                    "reason": "Desktop Cell projection is incomplete",
                }
            if (
                draft.effect_type == "desktop.observe"
                and desktop_projection["desktop_target_handle_id"] != witness.target_version
            ):
                return {
                    "ok": False,
                    "code": "bad_message",
                    "reason": "Desktop Cell target projection does not match witness",
                }
        stored = self._store.record_state_witness(witness.to_dict())
        if stored in {"conflict", "stale"}:
            return {"ok": False, "code": "stale_state", "reason": "witness rejected"}
        if executor_id == "cell.memory":
            raw_memory = response.get("result")
            memory_projection = {
                key: raw_memory[key]
                for key in (
                    "status",
                    "record_id",
                    "value",
                    "source",
                    "taint",
                    "clearance",
                    "key",
                    "effect",
                )
                if isinstance(raw_memory, dict) and key in raw_memory
            }
            return {"ok": True, "witness": witness.to_dict(), "result": memory_projection}
        if executor_id != "cell.desktop":
            return {"ok": True, "witness": witness.to_dict()}
        if draft.effect_type != "desktop.observe":
            result: dict[str, Any] = {"ok": True, "witness": witness.to_dict()}
            if desktop_projection:
                result["result"] = desktop_projection
            return result
        if (
            desktop_session is None
            or self._cell_session_by_cap("cell.desktop") is not desktop_session
            or active is None
            or self._broker is None
            or not witness.target_version.startswith("desktop:")
        ):
            return {
                "ok": False,
                "code": "unknown_handle",
                "reason": "Desktop Cell observation session changed",
            }
        expires_at_ms = min(witness.expires_at_ms, active.expires_at_ms, now + 60_000)
        binding = DesktopTargetBindingV1(
            task_id=draft.task_id,
            draft_id=draft.draft_id,
            witness_id=witness.witness_id,
            canonical_effect_hash=package.canonical_effect_hash,
            owner_key_hash=active.owner_key_hash,
            tenant=active.profile,
            expires_at_ms=expires_at_ms,
        )
        handle_response = await self._request_cell(
            "cell.desktop",
            "handle",
            op="resolve",
            handle={"handle_id": witness.target_version},
            spec=binding.to_dict(),
        )
        if (
            handle_response is None
            or not handle_response.get("ok")
            or self._cell_session_by_cap("cell.desktop") is not desktop_session
        ):
            return {
                "ok": False,
                "code": "unknown_handle",
                "reason": "Desktop Cell target sealing failed",
            }
        fresh_inputs, gate_error = self._desktop_preflight_inputs(draft, record)
        fresh_active = fresh_inputs.intent if fresh_inputs is not None else None
        fresh_now = self._now_ms()
        if (
            fresh_active is None
            or active is None
            or fresh_active.intent_id != active.intent_id
            or fresh_active.owner_key_hash != binding.owner_key_hash
            or fresh_active.profile != binding.tenant
            or expires_at_ms <= fresh_now
            or witness.expired(fresh_now)
        ):
            return {
                "ok": False,
                "code": "denied",
                "reason": str(gate_error or "Desktop owner authority changed"),
            }
        active = fresh_active
        now = fresh_now
        raw_handle = handle_response.get("handle")
        if not isinstance(raw_handle, dict):
            return {"ok": False, "code": "unknown_handle", "reason": "target missing"}
        registered = self._broker.register_desktop_cell_handle(
            raw_handle,
            cell_session_key=desktop_session.session_key,
            expected_handle_id=witness.target_version,
            owner_key_hash=active.owner_key_hash,
            tenant=active.profile,
            expires_at_ms=expires_at_ms,
            now_ms=now,
        )
        if not registered.get("ok"):
            return {
                "ok": False,
                "code": "unknown_handle",
                "reason": "Desktop Cell target handle rejected",
            }
        projection = dict(desktop_projection or {})
        projection["desktop_target_handle_id"] = witness.target_version
        return {
            "ok": True,
            "witness": witness.to_dict(),
            "result": projection,
        }

    # -- stage B cell scheduling (WP7) -----------------------------------------
    async def _dispatch_cell(
        self,
        envelope: dict[str, Any],
        *,
        session_id: str = "",
        parent_session: str = "",
    ) -> dict[str, Any]:
        payload = envelope.get("payload")
        if not isinstance(payload, dict):  # parse_frame already enforced this
            return {"ok": False, "code": "bad_message", "reason": "cell requires payload"}
        if set(payload) == {"draft_id"}:
            return await self._consume_draft(
                str(payload["draft_id"]),
                session_id=session_id,
                parent_session=parent_session,
            )
        cap = str(payload.get("cell") or "")
        if cap == "cell.net":
            authz = self._gatekeeper.authorize_cell(
                payload,
                context_taint=int(envelope.get("context_taint") or 0),
                arg_taint=int(envelope.get("arg_taint") or 0),
                clearance=self._clearance_of(envelope),
                channel=str(envelope.get("channel") or ""),
            )
            if not authz.get("ok"):
                return authz
            return await self._dispatch_net_fetch(payload, authz)
        if cap != "cell.build":
            return {
                "ok": False,
                "code": "denied",
                "reason": "non-Build effects require draft/preflight/consume(draft_id)",
            }
        authz = self._gatekeeper.authorize_cell(
            payload,
            context_taint=int(envelope.get("context_taint") or 0),
            arg_taint=int(envelope.get("arg_taint") or 0),
            clearance=self._clearance_of(envelope),
            channel=str(envelope.get("channel") or ""),
        )
        if not authz.get("ok"):
            return authz
        timeout_ms = int(payload.get("timeout_ms") or 60_000)
        result = await self._proxy_cell(cap, payload, timeout_s=min(timeout_ms / 1000, 300.0))
        if result is None:
            # Fail closed: the effect class stops, everything else continues.
            return {
                "ok": False,
                "code": "unsupported",
                "reason": f"effect cell {cap} is not available",
            }
        if not result.get("ok"):
            return {
                "ok": False,
                "code": str(result.get("code") or "internal"),
                "reason": str(result.get("reason") or "cell execution failed"),
            }
        merged = dict(authz)
        cell_result = result.get("result")
        merged["cell"] = dict(cell_result) if isinstance(cell_result, dict) else {}
        return merged

    async def _dispatch_net_fetch(
        self,
        payload: dict[str, Any],
        authz: dict[str, Any],
    ) -> dict[str, Any]:
        """R0 ingress path: strict package/permit, never an ExportPass query."""

        allowed = {"cell", "tool", "url", "max_chars", "timeout_ms"}
        if set(payload) - allowed:
            return {
                "ok": False,
                "code": "bad_message",
                "reason": "net.fetch forbids bodies, credentials, handles, and extra fields",
            }
        if str(payload.get("tool") or "") not in {"browser_fetch", "net.fetch"}:
            return {"ok": False, "code": "denied", "reason": "cell.net accepts fetch only"}
        url = payload.get("url")
        if not isinstance(url, str) or not url or len(url) > 4096:
            return {"ok": False, "code": "bad_message", "reason": "invalid fetch URL"}
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return {"ok": False, "code": "denied", "reason": "unsafe fetch origin"}
        try:
            from js.security.net_guard import resolve_and_validate

            resolve_and_validate(url)
            host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except Exception as exc:
            return {"ok": False, "code": "denied", "reason": f"unsafe fetch target: {exc}"}
        origin = f"{parsed.scheme.lower()}://{host}:{port}"
        now = self._now_ms()
        digest = "sha256:" + hashlib.sha256(origin.encode()).hexdigest()
        base = OriginHandle(
            handle_id=f"ep:{hashlib.sha256(origin.encode()).hexdigest()[:32]}",
            kind="EndpointHandle",
            owner_key_hash="sha256:" + "0" * 64,
            tenant="network-r0",
            source_class="TRUSTED_LOCAL",
            integrity="trusted_local_object",
            confidentiality="PUBLIC",
            object_digest=digest,
            capabilities=("read",),
            issuer="orind:broker",
            created_at_ms=now,
            expires_at_ms=now + 60_000,
        )
        endpoint = base.sealed_by(self._keybox.key, "orind:broker", now)
        draft = EffectDraft(
            draft_id=f"draft:{secrets.token_hex(16)}",
            task_id=f"task:net-fetch-{secrets.token_hex(12)}",
            effect_type="net.fetch",
            arguments={
                "endpoint_handle": endpoint.handle_id,
                "url": url,
                "max_chars": min(max(int(payload.get("max_chars") or 48 * 1024), 1), 48 * 1024),
                "timeout_s": min(max(int(payload.get("timeout_ms") or 15_000) / 1000, 1), 30),
            },
            declared_expectation={},
        )
        effect_hash = canonical_effect_hash_of(draft)
        preflight_package = CellPackage(
            draft=draft,
            executor_id="cell.net",
            canonical_effect_hash=effect_hash,
            resolved_handles=(endpoint,),
            clearance=CLEARANCE_INTERNAL,
        )
        preflight = await self._request_cell(
            "cell.net",
            "preflight",
            draft_id=draft.draft_id,
            executor_id="cell.net",
            package=preflight_package.to_dict(),
        )
        if preflight is None or not preflight.get("ok"):
            return {"ok": False, "code": "unsupported", "reason": "network preflight failed"}
        try:
            witness = witness_from_dict(dict(preflight.get("witness") or {}))
        except Exception as exc:
            return {"ok": False, "code": "stale_state", "reason": str(exc)}
        permit = CommitPermit(
            permit_id=f"permit:{secrets.token_hex(16)}",
            intent_id="intent:network-r0",
            draft_id=draft.draft_id,
            state_witness_id=witness.witness_id,
            executor_id="cell.net",
            canonical_effect_hash=effect_hash,
            idempotency_key="idem:" + hashlib.sha256(draft.payload().encode()).hexdigest(),
            sequence=1,
            not_before_ms=now,
            expires_at_ms=min(now + 60_000, witness.expires_at_ms),
        )
        commit_package = CellPackage(
            draft=draft,
            executor_id="cell.net",
            canonical_effect_hash=effect_hash,
            resolved_handles=(endpoint,),
            clearance=CLEARANCE_INTERNAL,
            state_witness=witness,
        )
        commit = await self._request_cell(
            "cell.net",
            "commit",
            permit=permit.to_dict(),
            package=commit_package.to_dict(),
        )
        if commit is None or not commit.get("ok"):
            return {"ok": False, "code": "internal", "reason": "network fetch failed"}
        raw_result = commit.get("result")
        merged = dict(authz)
        merged["cell"] = self._safe_cell_projection(
            "net.fetch", dict(raw_result) if isinstance(raw_result, dict) else {}
        )
        return merged

    @staticmethod
    def _effect_content_text(draft: EffectDraft, entry: Any) -> str:
        parts: list[str] = []
        remaining = MAX_FRAME_BYTES
        for name in getattr(entry, "content_args", ()):
            value = draft.arguments.get(name)
            if name == "changes":
                # Only scan bounded file-content leaves.  Paths and
                # permission fields never enter the canary input/result.
                if not isinstance(value, list) or len(value) > 128:
                    continue
                for change in value:
                    if not isinstance(change, dict):
                        continue
                    content = change.get("content")
                    if not isinstance(content, str) or remaining <= 0:
                        continue
                    bounded = content[:remaining]
                    parts.append(bounded)
                    remaining -= len(bounded)
                continue
            if isinstance(value, str):
                bounded = value[:remaining]
                parts.append(bounded)
                remaining -= len(bounded)
            elif isinstance(value, list):
                for item in value[:128]:
                    if not isinstance(item, str) or remaining <= 0:
                        continue
                    bounded = item[:remaining]
                    parts.append(bounded)
                    remaining -= len(bounded)
        return "\n".join(parts)

    @staticmethod
    def _safe_cell_projection(effect_type: str, result: dict[str, Any]) -> dict[str, Any]:
        common = {"status", "error", "remote_operation_id", "duplicate"}
        allowed = set(common)
        if effect_type == "email.send_exact":
            allowed.update({"recipients", "bytes_out"})
        elif effect_type == "net.fetch":
            allowed.update({"output", "content_hash", "final_url", "status_code"})
        elif effect_type == "file.commit":
            allowed.update({"files", "bytes_written", "diff_hash", "overwrites"})
        elif effect_type == "desktop.observe":
            allowed.update(
                {
                    "accessibility",
                    "apps",
                    "available",
                    "dependencies",
                    "desktop_target_handle_id",
                    "display_id",
                    "height",
                    "image_base64",
                    "image_mime_type",
                    "mode",
                    "mouse",
                    "observed_at_ms",
                    "operation_count",
                    "owner_pid",
                    "pixel_hash",
                    "platform",
                    "scale",
                    "screen_recording",
                    "target_kind",
                    "target_label",
                    "width",
                    "window_number",
                    "windows",
                }
            )
        elif effect_type == "desktop.action":
            allowed.update({"action", "after_digest", "before_digest", "receipt_id"})
        elif effect_type in {"memory.read", "memory.write", "memory.mutate"}:
            allowed.update(
                {
                    "clearance",
                    "effect",
                    "key",
                    "record_id",
                    "source",
                    "taint",
                    "value",
                }
            )
        projection = {key: result[key] for key in allowed if key in result}
        if effect_type in {"desktop.observe", "desktop.action"}:
            return normalize_desktop_safe_projection(
                projection,
                effect_type=effect_type,
            )
        return projection

    @staticmethod
    def _operation_spec_from_snapshot(
        operation: OperationSnapshot,
        *,
        session_id: str,
    ) -> OperationSpec:
        return OperationSpec(
            operation_id=operation.operation_id,
            draft_id=operation.draft_id,
            task_id=operation.task_id,
            owner_key_hash=operation.owner_key_hash,
            session_id=session_id or operation.session_id,
            effect_type=operation.effect_type,
            executor_id=operation.executor_id,
            side_effect_class=operation.side_effect_class,
            canonical_effect_hash=operation.canonical_effect_hash,
            witness_id=operation.witness_id,
            intent_id=operation.intent_id,
            profile=operation.profile,
            destinations=operation.destinations,
            bytes_out=operation.bytes_out,
            idempotency_key=operation.idempotency_key,
            directory_handle_id=operation.directory_handle_id,
        )

    @staticmethod
    def _receipt_id(operation: OperationSnapshot) -> str:
        material = f"{operation.operation_id}\x00{operation.permit_id}".encode()
        return "receipt:" + hashlib.sha256(material).hexdigest()

    @staticmethod
    def _membrane_ack(operation: OperationSnapshot) -> dict[str, Any]:
        safe = operation.safe_result
        if not safe:
            safe = {"status": "RECONCILED_COMMITTED"}
        return {
            "ok": True,
            "verdict": "allow",
            "receipt_id": operation.receipt_id,
            "cell": safe,
        }

    def _membrane_fault(self, label: str, draft_id: str) -> None:
        hook = self._membrane_fault_hook
        if hook is not None:
            hook(label, draft_id)

    def _membrane_package(
        self,
        operation: OperationSnapshot,
    ) -> tuple[CellPackage, EffectDraft, dict[str, Any]]:
        """Rebuild one Cell-only package from durable authority metadata.

        This reads Orind's private authority rows only in the daemon.  The
        resulting package still crosses exclusively over authenticated
        ``cells.sock``; Cells never receive a database path or shared package.
        """

        record = self._store.get_effect_draft(operation.draft_id)
        if not isinstance(record, dict):
            raise MembraneError("durable operation draft is unavailable")
        draft = draft_from_dict(dict(record.get("draft") or {}))
        if (
            draft.task_id != operation.task_id
            or draft.effect_type != operation.effect_type
            or str(record.get("executor_id") or "") != operation.executor_id
            or str(record.get("canonical_effect_hash") or "") != operation.canonical_effect_hash
            or self._file_directory_handle_id(draft) != operation.directory_handle_id
        ):
            raise OperationConflict("durable operation draft authority changed")
        raw_witness = self._store.state_witness_by_id(operation.witness_id)
        if not isinstance(raw_witness, dict):
            raise MembraneError("durable operation witness is unavailable")
        witness = witness_from_dict(raw_witness)
        if (
            witness.draft_id != operation.draft_id
            or witness.executor_id != operation.executor_id
            or witness.canonical_effect_hash != operation.canonical_effect_hash
        ):
            raise OperationConflict("durable operation witness authority changed")
        handles: list[OriginHandle] = []
        for handle_id in sorted(handle_refs(draft.arguments)):
            raw_handle = self._store.get_handle(handle_id)
            if not isinstance(raw_handle, dict):
                raise MembraneError("durable operation handle is unavailable")
            handle = handle_from_dict(raw_handle, require_signature=True)
            if not handle.verify_seal(self._keybox.key):
                raise OperationConflict("durable operation handle seal changed")
            if handle.owner_key_hash != operation.owner_key_hash:
                raise OperationConflict("durable operation handle owner changed")
            handles.append(handle)
        if operation.executor_id == "cell.desktop" and self._intents is not None:
            active = self._intents.active_envelope(operation.task_id, now_ms=self._now_ms())
            if active is not None:
                seen = {item.handle_id for item in handles}
                for handle in self._application_handles_for_intent(active).values():
                    if handle.handle_id in seen:
                        continue
                    handles.append(handle)
                    seen.add(handle.handle_id)
        package = CellPackage(
            draft=draft,
            executor_id=operation.executor_id,
            canonical_effect_hash=operation.canonical_effect_hash,
            resolved_handles=tuple(handles),
            clearance=int(record.get("clearance", CLEARANCE_INTERNAL)),
            state_witness=witness,
        )
        package.validate_binding(operation.to_commit_permit(), require_witness=True)
        return package, draft, record

    def _finalize_membrane_receipt(
        self,
        operation: OperationSnapshot,
    ) -> OperationSnapshot:
        membrane = self._membrane
        if membrane is None:  # pragma: no cover - caller is membrane-only
            raise MembraneError("commit membrane is disabled")
        if operation.state is CommitState.RECEIPTED:
            return operation
        if operation.state is not CommitState.COMMITTED:
            raise InvalidTransition("only COMMITTED operations can be receipted")
        return membrane.transition(
            operation.operation_id,
            CommitState.RECEIPTED,
            receipt_id=self._receipt_id(operation),
        )

    def _revalidate_membrane_prepared(
        self,
        operation: OperationSnapshot,
    ) -> str | None:
        """Recheck live authority before dispatching or rotating PREPARED.

        Personal ExportPass authority is represented by the durable atomic
        claim on the PREPARED row, so it is deliberately not queried again.
        Work standing passes remain live authority and must still match the
        exact task/hash/destinations/witness binding.
        """

        kernel = self._kernel
        intents = self._intents
        if kernel is None or intents is None:
            return "stage B authority is unavailable"
        now = self._now_ms()
        record = self._store.get_effect_draft(operation.draft_id, now_ms=now)
        if not isinstance(record, dict):
            return "prepared draft is missing or expired"
        try:
            draft = draft_from_dict(dict(record.get("draft") or {}))
        except (ProtocolError, TypeError, ValueError):
            return "prepared draft is invalid"
        entry = self._manifest_entry(draft)
        if (
            entry is None
            or draft.draft_id != operation.draft_id
            or draft.task_id != operation.task_id
            or draft.effect_type != operation.effect_type
            or str(getattr(entry, "executor_id", "")) != operation.executor_id
            or str(getattr(entry, "side_effect_class", "")) != operation.side_effect_class
            or str(record.get("canonical_effect_hash") or "") != operation.canonical_effect_hash
            or self._file_directory_handle_id(draft) != operation.directory_handle_id
        ):
            return "prepared operation identity changed"
        active = self._authority_for_draft(draft, now_ms=now)
        if (
            active is None
            or active.intent_id != operation.intent_id
            or active.owner_key_hash != operation.owner_key_hash
            or active.profile != operation.profile
        ):
            return "prepared owner authority is no longer active"
        _handles, handle_error = self._resolve_draft_handles(
            draft,
            intent=active,
            clearance=int(record.get("clearance", CLEARANCE_INTERNAL)),
            require_all=True,
        )
        if handle_error is not None:
            return "prepared handle authority is no longer valid"
        raw_witness = self._store.state_witness_by_id(operation.witness_id, now_ms=now)
        current_witness = self._store.current_state_witness(operation.draft_id, now_ms=now)
        if (
            not isinstance(raw_witness, dict)
            or not isinstance(current_witness, dict)
            or str(current_witness.get("witness_id") or "") != operation.witness_id
        ):
            return "prepared witness is no longer current"
        try:
            witness = witness_from_dict(raw_witness)
        except (ProtocolError, TypeError, ValueError):
            return "prepared witness is invalid"
        if (
            witness.draft_id != operation.draft_id
            or witness.executor_id != operation.executor_id
            or witness.canonical_effect_hash != operation.canonical_effect_hash
            or witness.expired(now)
        ):
            return "prepared witness binding is no longer valid"
        destinations = self._destination_handles(draft, entry)
        if destinations != operation.destinations:
            return "prepared destination binding changed"
        parsed_passes = []
        if draft.effect_type in EXPORT_EFFECTS:
            if operation.profile == "personal":
                if not operation.export_pass_id or not operation.export_pass_claimed:
                    return "prepared Personal export authority is unavailable"
            elif operation.profile == "work":
                rows = intents.active_exact_export_passes(
                    task_id=operation.task_id,
                    payload_hash=operation.canonical_effect_hash,
                    destination_handles=operation.destinations,
                    witness_id=operation.witness_id,
                    now_ms=now,
                )
                for row in rows:
                    with contextlib.suppress(Exception):
                        parsed_passes.append(export_pass_from_dict(row))
                if not any(
                    export_pass.pass_id == operation.export_pass_id for export_pass in parsed_passes
                ):
                    return "prepared Work export authority is no longer active"
            else:
                return "prepared export profile is invalid"
        personal_exact_claimed = bool(
            draft.effect_type == "file.commit"
            and operation.profile == "personal"
            and operation.exact_approval_id
            and operation.exact_approval_claimed
        )
        if (
            draft.effect_type == "file.commit"
            and operation.profile == "personal"
            and not personal_exact_claimed
        ):
            return "prepared Personal exact approval is unavailable"
        inputs, gate_handle_error = self._gate_inputs_for_record(
            draft,
            record,
            include_passes=False,
        )
        if gate_handle_error is not None:
            return "prepared handle authority is no longer valid"
        inputs.witness = witness
        inputs.export_passes = tuple(parsed_passes)
        inputs.approval_satisfied = self._commit_approval_satisfied(
            draft,
            active=active,
            export_passes_present=bool(parsed_passes),
            personal_export_claimed=(
                operation.profile == "personal" and operation.export_pass_claimed
            ),
            personal_exact_claimed=personal_exact_claimed,
        )
        blockers = kernel.commit_blockers(draft, inputs)
        if operation.profile == "personal" and operation.export_pass_claimed:
            blockers = tuple(
                blocker
                for blocker in blockers
                if blocker not in {"export_pass", "export_pass_required"}
            )
        if blockers:
            return "prepared policy authority is no longer valid"
        canary = self._gatekeeper.authorize_egress_text(
            self._effect_content_text(draft, entry),
            surface="connector",
        )
        if not canary.get("ok"):
            return "prepared content policy is no longer valid"
        return None

    async def _commit_membrane_prepared(
        self,
        operation: OperationSnapshot,
    ) -> dict[str, Any]:
        membrane = self._membrane
        if membrane is None:  # pragma: no cover - caller is membrane-only
            return {"ok": False, "code": "unsupported", "reason": "membrane disabled"}
        authority_error = self._revalidate_membrane_prepared(operation)
        if authority_error is not None:
            return {"ok": False, "code": "stale_state", "reason": authority_error}
        now = self._now_ms()
        if operation.permit_expires_at_ms <= now:
            operation = membrane.rotate_prepared_permit(
                operation.operation_id,
                expected_permit_id=operation.permit_id,
                expected_intent_id=operation.intent_id,
                expected_witness_id=operation.witness_id,
                expected_export_pass_id=operation.export_pass_id or None,
                expected_exact_approval_id=operation.exact_approval_id or None,
                now_ms=now,
            )
        try:
            package, draft, _record = self._membrane_package(operation)
        except (MembraneError, ProtocolError, ValueError) as exc:
            return {"ok": False, "code": "denied", "reason": str(exc)[:512]}
        committing = membrane.begin_commit(operation.operation_id)
        self._membrane_fault("after_committing_persisted", operation.draft_id)
        response = await self._request_cell(
            operation.executor_id,
            "commit",
            permit=committing.to_commit_permit().to_dict(),
            package=package.to_dict(),
        )
        if response is None or not response.get("ok"):
            membrane.mark_ambiguous(operation.operation_id, "commit acknowledgement unavailable")
            return {
                "ok": False,
                "code": "stale_state",
                "reason": "commit outcome requires reconciliation",
            }
        raw_result = response.get("result")
        safe = self._safe_cell_projection(
            draft.effect_type,
            dict(raw_result) if isinstance(raw_result, dict) else {},
        )
        if safe.get("status") not in {"COMMITTED", "RECONCILED_COMMITTED"}:
            membrane.mark_ambiguous(operation.operation_id, "cell did not confirm commit")
            return {
                "ok": False,
                "code": "stale_state",
                "reason": "commit outcome requires reconciliation",
            }
        try:
            committed = membrane.transition(
                operation.operation_id,
                CommitState.COMMITTED,
                remote_operation_id=str(safe.get("remote_operation_id") or ""),
                safe_result=safe,
            )
            receipted = self._finalize_membrane_receipt(committed)
        except (MembraneError, ValueError):
            current = membrane.get(operation.operation_id)
            if current.state is CommitState.COMMITTING:
                membrane.mark_ambiguous(
                    operation.operation_id,
                    "commit result could not be durably receipted",
                )
            return {
                "ok": False,
                "code": "stale_state",
                "reason": "commit outcome requires reconciliation",
            }
        return self._membrane_ack(receipted)

    async def _reconcile_membrane_operation(
        self,
        operation: OperationSnapshot,
        *,
        allow_unready_cell: bool = False,
    ) -> OperationSnapshot:
        membrane = self._membrane
        if membrane is None:  # pragma: no cover - caller is membrane-only
            raise MembraneError("commit membrane is disabled")
        if operation.state is CommitState.COMMITTING:
            operation = membrane.mark_ambiguous(
                operation.operation_id,
                "commit was in flight without a durable acknowledgement",
            )
        if operation.state is not CommitState.UNKNOWN_COMMIT:
            return operation
        if (
            self._cell_writer_by_cap(
                operation.executor_id,
                allow_unready=allow_unready_cell,
            )
            is None
        ):
            return operation
        if operation.executor_id == "cell.connector":
            probe: dict[str, Any] = {
                "idempotency_key": operation.idempotency_key,
                "canonical_effect_hash": operation.canonical_effect_hash,
                "destination_handles": list(operation.destinations),
            }
        elif operation.executor_id == "cell.file":
            try:
                package, _draft, _record = self._membrane_package(operation)
            except (MembraneError, ProtocolError, ValueError):
                return operation
            probe = {
                "permit": operation.to_commit_permit().to_dict(),
                "package": package.to_dict(),
            }
        else:
            return operation
        response = await self._request_cell(
            operation.executor_id,
            "reconcile",
            _allow_unready=allow_unready_cell,
            effect_id=operation.operation_id,
            probe=probe,
        )
        if response is None or not response.get("ok"):
            return operation
        outcome = str(response.get("state") or "unknown")
        if outcome not in {"committed", "absent", "unknown"}:
            outcome = "unknown"
        safe = {"status": "RECONCILED_COMMITTED"} if outcome == "committed" else None
        reconciled = membrane.reconcile(
            operation.operation_id,
            outcome,
            safe_result=safe,
        )
        if reconciled.state is CommitState.COMMITTED:
            reconciled = self._finalize_membrane_receipt(reconciled)
        return reconciled

    async def _resume_membrane_operation(
        self,
        operation: OperationSnapshot,
    ) -> dict[str, Any]:
        membrane = self._membrane
        if membrane is None:  # pragma: no cover - caller is membrane-only
            return {"ok": False, "code": "unsupported", "reason": "membrane disabled"}
        if operation.state is CommitState.RECEIPTED:
            if operation.profile == "personal":
                exact_file = operation.effect_type == "file.commit"
                return {
                    "ok": False,
                    "code": "denied" if exact_file else "export_gate",
                    "reason": (
                        "Personal exact approval has already been consumed"
                        if exact_file
                        else "Personal operation has already been consumed"
                    ),
                }
            return self._membrane_ack(operation)
        if operation.state is CommitState.COMMITTED:
            return self._membrane_ack(self._finalize_membrane_receipt(operation))
        if operation.state is CommitState.COMMITTING:
            return {
                "ok": False,
                "code": "stale_state",
                "reason": "operation commit is still in progress",
            }
        if operation.state is CommitState.UNKNOWN_COMMIT:
            reconciled = await self._reconcile_membrane_operation(operation)
            if reconciled.state is CommitState.RECEIPTED:
                if reconciled.profile == "personal":
                    exact_file = reconciled.effect_type == "file.commit"
                    return {
                        "ok": False,
                        "code": "denied" if exact_file else "export_gate",
                        "reason": (
                            "Personal exact approval has already been consumed"
                            if exact_file
                            else "Personal operation has already been consumed"
                        ),
                    }
                return self._membrane_ack(reconciled)
            return {
                "ok": False,
                "code": "stale_state",
                "reason": "operation was reconciled; retry only when PREPARED",
            }
        if operation.state is CommitState.PREPARED:
            return await self._commit_membrane_prepared(operation)
        if operation.state is CommitState.DENIED:
            return {"ok": False, "code": "denied", "reason": "operation was denied"}
        return await self._authorize_existing_membrane_operation(operation)

    async def _authorize_existing_membrane_operation(
        self,
        operation: OperationSnapshot,
    ) -> dict[str, Any]:
        """Resume a crash before PREPARED without weakening any conjunct."""

        membrane = self._membrane
        kernel = self._kernel
        intents = self._intents
        if membrane is None or kernel is None or intents is None:
            return {"ok": False, "code": "unsupported", "reason": "stage B disabled"}
        now = self._now_ms()
        record = self._store.get_effect_draft(operation.draft_id, now_ms=now)
        if not isinstance(record, dict):
            return {"ok": False, "code": "expired", "reason": "draft expired"}
        draft = draft_from_dict(dict(record.get("draft") or {}))
        entry = self._manifest_entry(draft)
        active = self._authority_for_draft(draft, now_ms=now)
        if entry is None or active is None or active.intent_id != operation.intent_id:
            return {"ok": False, "code": "denied", "reason": "owner authority changed"}
        raw_witness = self._store.state_witness_by_id(operation.witness_id, now_ms=now)
        if not isinstance(raw_witness, dict):
            return {"ok": False, "code": "stale_state", "reason": "witness expired"}
        witness = witness_from_dict(raw_witness)
        destinations = self._destination_handles(draft, entry)
        directory_handle_id = self._file_directory_handle_id(draft)
        if directory_handle_id != operation.directory_handle_id:
            return {"ok": False, "code": "denied", "reason": "resource binding changed"}
        rows: list[dict[str, Any]] = []
        if draft.effect_type in EXPORT_EFFECTS:
            rows = intents.active_exact_export_passes(
                task_id=draft.task_id,
                payload_hash=operation.canonical_effect_hash,
                destination_handles=destinations,
                witness_id=witness.witness_id,
                now_ms=now,
            )
        parsed = []
        for row in rows:
            with contextlib.suppress(Exception):
                parsed.append(export_pass_from_dict(row))
        exact_approvals = self._active_personal_file_approvals(
            draft,
            active=active,
            witness=witness,
            canonical_effect_hash=operation.canonical_effect_hash,
            now_ms=now,
        )
        inputs, handle_error = self._gate_inputs_for_record(
            draft,
            record,
            include_passes=False,
        )
        if handle_error is not None:
            return {"ok": False, "code": "unknown_handle", "reason": handle_error}
        inputs.witness = witness
        inputs.export_passes = tuple(parsed)
        inputs.approval_satisfied = self._commit_approval_satisfied(
            draft,
            active=active,
            export_passes_present=bool(parsed),
            exact_approvals_present=bool(exact_approvals),
        )
        if kernel.commit_blockers(draft, inputs):
            return {"ok": False, "code": "denied", "reason": "commit prerequisites missing"}
        if operation.state is CommitState.PROPOSED:
            operation = membrane.transition(operation.operation_id, CommitState.PREFLIGHTED)
        pass_id = parsed[0].pass_id if parsed else None
        exact_approval_id = exact_approvals[0].approval_id if exact_approvals else None
        try:
            prepared = membrane.prepare(
                operation.operation_id,
                max_invocations=active.budgets.max_invocations,
                max_bytes_out=active.budgets.max_bytes_out,
                export_pass_id=pass_id,
                require_personal_pass=(
                    active.profile == "personal" and draft.effect_type in EXPORT_EFFECTS
                ),
                exact_approval_id=exact_approval_id,
                require_personal_exact=(
                    active.profile == "personal" and draft.effect_type == "file.commit"
                ),
                now_ms=now,
            )
        except (
            BudgetExhausted,
            ExactApprovalUnavailable,
            ExportPassUnavailable,
            InvalidTransition,
        ):
            return {"ok": False, "code": "denied", "reason": "prepare failed"}
        self._membrane_fault("after_prepared_tx", draft.draft_id)
        return await self._commit_membrane_prepared(prepared)

    async def _consume_draft_membrane(
        self,
        draft_id: str,
        *,
        session_id: str,
    ) -> dict[str, Any]:
        membrane = self._membrane
        kernel = self._kernel
        intents = self._intents
        if membrane is None or kernel is None or intents is None:
            return {"ok": False, "code": "unsupported", "reason": "stage B disabled"}
        existing = membrane.operation_for_draft(draft_id)
        if existing is not None:
            admission_spec = self._operation_spec_from_snapshot(
                existing,
                session_id=session_id,
            )
            try:
                ticket = membrane.admit(admission_spec)
            except AdmissionBackpressure:
                return {"ok": False, "code": "backpressure", "reason": "membrane busy"}
            try:
                return await self._resume_membrane_operation(existing)
            finally:
                membrane.release(ticket)

        now = self._now_ms()
        record = self._store.get_effect_draft(draft_id, now_ms=now)
        if not isinstance(record, dict):
            return {"ok": False, "code": "expired", "reason": "draft is missing or expired"}
        try:
            draft = draft_from_dict(dict(record.get("draft") or {}))
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        entry = self._manifest_entry(draft)
        if entry is None or str(getattr(entry, "executor_id", "")) not in {
            "cell.file",
            "cell.connector",
        }:
            return {
                "ok": False,
                "code": "denied",
                "reason": "effect is outside the commit membrane",
            }
        raw_witness = self._store.current_state_witness(draft.draft_id, now_ms=now)
        if not isinstance(raw_witness, dict):
            return {"ok": False, "code": "stale_state", "reason": "preflight required"}
        witness = witness_from_dict(raw_witness)
        active = self._authority_for_draft(draft, now_ms=now)
        if active is None:
            return {"ok": False, "code": "unknown_intent", "reason": "no active intent"}
        handles, handle_error = self._resolve_draft_handles(
            draft,
            intent=active,
            clearance=int(record.get("clearance", CLEARANCE_INTERNAL)),
            require_all=True,
        )
        if handle_error is not None:
            return {"ok": False, "code": "unknown_handle", "reason": handle_error}
        destinations = self._destination_handles(draft, entry)
        directory_handle_id = self._file_directory_handle_id(draft)
        exact_rows: list[dict[str, Any]] = []
        if draft.effect_type in EXPORT_EFFECTS:
            exact_rows = intents.active_exact_export_passes(
                task_id=draft.task_id,
                payload_hash=str(record.get("canonical_effect_hash") or ""),
                destination_handles=destinations,
                witness_id=witness.witness_id,
                now_ms=now,
            )
        parsed_passes = []
        for row in exact_rows:
            with contextlib.suppress(Exception):
                parsed_passes.append(export_pass_from_dict(row))
        exact_approvals = self._active_personal_file_approvals(
            draft,
            active=active,
            witness=witness,
            canonical_effect_hash=str(record.get("canonical_effect_hash") or ""),
            now_ms=now,
        )
        inputs, gate_handle_error = self._gate_inputs_for_record(
            draft,
            record,
            include_passes=False,
        )
        if gate_handle_error is not None:
            return {"ok": False, "code": "unknown_handle", "reason": gate_handle_error}
        inputs.witness = witness
        inputs.export_passes = tuple(parsed_passes)
        inputs.approval_satisfied = self._commit_approval_satisfied(
            draft,
            active=active,
            export_passes_present=bool(parsed_passes),
            exact_approvals_present=bool(exact_approvals),
        )
        blockers = kernel.commit_blockers(draft, inputs)
        if blockers:
            code = "export_gate" if "export_pass" in blockers else "denied"
            return {"ok": False, "code": code, "reason": "commit prerequisites missing"}
        canary = self._gatekeeper.authorize_egress_text(
            self._effect_content_text(draft, entry),
            surface="connector",
        )
        if not canary.get("ok"):
            return canary
        effect_hash = str(record.get("canonical_effect_hash") or "")
        idem_material = "|".join((draft.task_id, draft.draft_id, witness.witness_id, effect_hash))
        operation_id = (
            "operation:"
            + hashlib.sha256(("orin-operation-v1\x00" + draft.draft_id).encode()).hexdigest()
        )
        spec = OperationSpec(
            operation_id=operation_id,
            draft_id=draft.draft_id,
            task_id=draft.task_id,
            owner_key_hash=active.owner_key_hash,
            session_id=session_id or "session:internal",
            effect_type=draft.effect_type,
            executor_id=str(entry.executor_id),
            side_effect_class=str(entry.side_effect_class),
            canonical_effect_hash=effect_hash,
            witness_id=witness.witness_id,
            intent_id=active.intent_id,
            profile=active.profile,
            destinations=destinations,
            bytes_out=int(witness.impact.bytes_out),
            idempotency_key="idem:" + hashlib.sha256(idem_material.encode()).hexdigest(),
            directory_handle_id=directory_handle_id,
        )
        try:
            ticket = membrane.admit(spec)
        except AdmissionBackpressure:
            return {"ok": False, "code": "backpressure", "reason": "membrane busy"}
        try:
            proposed = membrane.propose(spec)
            if proposed.state is CommitState.PROPOSED:
                proposed = membrane.transition(operation_id, CommitState.PREFLIGHTED)
            pass_id = parsed_passes[0].pass_id if parsed_passes else None
            exact_approval_id = exact_approvals[0].approval_id if exact_approvals else None
            prepared = membrane.prepare(
                operation_id,
                max_invocations=active.budgets.max_invocations,
                max_bytes_out=active.budgets.max_bytes_out,
                export_pass_id=pass_id,
                require_personal_pass=(
                    active.profile == "personal" and draft.effect_type in EXPORT_EFFECTS
                ),
                exact_approval_id=exact_approval_id,
                require_personal_exact=(
                    active.profile == "personal" and draft.effect_type == "file.commit"
                ),
                now_ms=now,
            )
            self._membrane_fault("after_prepared_tx", draft.draft_id)
            return await self._commit_membrane_prepared(prepared)
        except (BudgetExhausted, ExactApprovalUnavailable, ExportPassUnavailable):
            return {"ok": False, "code": "denied", "reason": "prepare failed"}
        except OperationConflict:
            return {"ok": False, "code": "denied", "reason": "operation identity conflict"}
        finally:
            membrane.release(ticket)

    async def _consume_draft(
        self,
        draft_id: str,
        *,
        session_id: str = "",
        parent_session: str = "",
    ) -> dict[str, Any]:
        if self._membrane is not None:
            return await self._consume_draft_membrane(draft_id, session_id=session_id)
        kernel = self._kernel
        intents = self._intents
        if kernel is None or intents is None:
            return {"ok": False, "code": "unsupported", "reason": "stage B disabled"}
        now = self._now_ms()
        record = self._store.get_effect_draft(draft_id, now_ms=now)
        if not isinstance(record, dict):
            return {"ok": False, "code": "expired", "reason": "draft is missing or expired"}
        try:
            draft = draft_from_dict(dict(record.get("draft") or {}))
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        entry = self._manifest_entry(draft)
        if entry is None:
            return {"ok": False, "code": "denied", "reason": "manifest unavailable"}
        executor_id = str(getattr(entry, "executor_id", ""))
        if executor_id in {"", "cell.build"}:
            return {"ok": False, "code": "denied", "reason": "invalid draft executor"}
        witness_raw = self._store.current_state_witness(draft.draft_id)
        if not isinstance(witness_raw, dict):
            return {"ok": False, "code": "stale_state", "reason": "preflight required"}
        try:
            witness = witness_from_dict(witness_raw)
        except Exception as exc:
            return {"ok": False, "code": "stale_state", "reason": str(exc)}
        active = self._authority_for_draft(draft, now_ms=now)
        if active is None:
            return {"ok": False, "code": "unknown_intent", "reason": "no active intent"}
        handles, handle_error = self._resolve_draft_handles(
            draft,
            intent=active,
            clearance=int(record.get("clearance", CLEARANCE_INTERNAL)),
            require_all=True,
        )
        if handle_error is not None:
            return {"ok": False, "code": "unknown_handle", "reason": handle_error}
        if str(getattr(entry, "executor_id", "")) == "cell.desktop":
            handles.update(self._application_handles_for_intent(active))
        if str(getattr(entry, "executor_id", "")) == "cell.memory":
            scope_error = self._memory_scope_error(
                draft,
                intent=active,
                session_id=parent_session,
            )
            if scope_error is not None:
                return {"ok": False, "code": "denied", "reason": scope_error}
        destinations = self._destination_handles(draft, entry)
        directory_handle_id = self._file_directory_handle_id(draft)
        exact_rows: list[dict[str, Any]] = []
        if draft.effect_type in EXPORT_EFFECTS:
            exact_rows = intents.active_exact_export_passes(
                task_id=draft.task_id,
                payload_hash=str(record.get("canonical_effect_hash") or ""),
                destination_handles=destinations,
                witness_id=witness.witness_id,
                now_ms=now,
            )
        inputs, gate_handle_error = self._gate_inputs_for_record(
            draft, record, include_passes=False
        )
        if gate_handle_error is not None:
            return {"ok": False, "code": "unknown_handle", "reason": gate_handle_error}
        parsed_passes = []
        for row in exact_rows:
            try:
                parsed_passes.append(export_pass_from_dict(row))
            except Exception:
                continue
        exact_approvals = self._active_personal_file_approvals(
            draft,
            active=active,
            witness=witness,
            canonical_effect_hash=str(record.get("canonical_effect_hash") or ""),
            now_ms=now,
        )
        inputs.export_passes = tuple(parsed_passes)
        inputs.witness = witness
        inputs.approval_satisfied = self._commit_approval_satisfied(
            draft,
            active=active,
            export_passes_present=bool(parsed_passes),
            exact_approvals_present=bool(exact_approvals),
        )
        blockers = kernel.commit_blockers(draft, inputs)
        if blockers:
            code = "export_gate" if "export_pass" in blockers else "denied"
            return {"ok": False, "code": code, "reason": "commit prerequisites missing"}
        canary = self._gatekeeper.authorize_egress_text(
            self._effect_content_text(draft, entry), surface="connector"
        )
        if not canary.get("ok"):
            return canary
        if active.profile == "personal" and draft.effect_type in EXPORT_EFFECTS:
            if not parsed_passes:
                return {"ok": False, "code": "export_gate", "reason": "export pass required"}
            claimed = intents.claim_personal_export_pass(
                pass_id=parsed_passes[0].pass_id,
                task_id=draft.task_id,
                payload_hash=str(record.get("canonical_effect_hash") or ""),
                destination_handles=destinations,
                witness_id=witness.witness_id,
                now_ms=now,
            )
            if not claimed:
                return {"ok": False, "code": "export_gate", "reason": "export pass consumed"}
        if active.profile == "personal" and draft.effect_type == "file.commit":
            if not exact_approvals:
                return {"ok": False, "code": "denied", "reason": "exact approval required"}
            exact_claimed = intents.claim_personal_exact_commit_approval(
                approval_id=exact_approvals[0].approval_id,
                task_id=draft.task_id,
                draft_id=draft.draft_id,
                witness_id=witness.witness_id,
                canonical_effect_hash=str(record.get("canonical_effect_hash") or ""),
                directory_handle_id=directory_handle_id,
                now_ms=now,
            )
            if not exact_claimed:
                return {"ok": False, "code": "denied", "reason": "exact approval consumed"}
        bytes_out = int(witness.impact.bytes_out)
        sequence = self._store.reserve_effect_budget(
            draft.task_id,
            max_invocations=active.budgets.max_invocations,
            max_bytes_out=active.budgets.max_bytes_out,
            bytes_out=bytes_out,
        )
        if sequence is None:
            return {"ok": False, "code": "denied", "reason": "effect budget exhausted"}
        effect_hash = str(record.get("canonical_effect_hash") or "")
        idem_material = "|".join((draft.task_id, draft.draft_id, witness.witness_id, effect_hash))
        permit = CommitPermit(
            permit_id=f"permit:{secrets.token_hex(16)}",
            intent_id=active.intent_id,
            draft_id=draft.draft_id,
            state_witness_id=witness.witness_id,
            executor_id=executor_id,
            canonical_effect_hash=effect_hash,
            idempotency_key="idem:" + hashlib.sha256(idem_material.encode()).hexdigest(),
            sequence=sequence,
            not_before_ms=now,
            expires_at_ms=min(now + 60_000, witness.expires_at_ms, active.expires_at_ms),
        )
        package = CellPackage(
            draft=draft,
            executor_id=executor_id,
            canonical_effect_hash=effect_hash,
            resolved_handles=tuple(handles[key] for key in sorted(handles)),
            clearance=int(record.get("clearance", CLEARANCE_INTERNAL)),
            state_witness=witness,
        )
        try:
            package.validate_binding(permit, require_witness=True)
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        response = await self._request_cell(
            executor_id,
            "commit",
            permit=permit.to_dict(),
            package=package.to_dict(),
        )
        if response is None:
            return {"ok": False, "code": "unsupported", "reason": "effect cell unavailable"}
        if not response.get("ok"):
            return {
                "ok": False,
                "code": str(response.get("code") or "internal"),
                "reason": str(response.get("reason") or "cell commit failed"),
            }
        raw_result = response.get("result")
        raw_dict = dict(raw_result) if isinstance(raw_result, dict) else {}
        if executor_id in {"cell.desktop", "cell.memory"}:
            receipt_error = self._verify_signed_cell_receipt(
                raw_dict,
                permit=permit,
                executor_id=executor_id,
            )
            if receipt_error is not None:
                return {"ok": False, "code": "denied", "reason": receipt_error}
        safe = self._safe_cell_projection(draft.effect_type, raw_dict)
        if executor_id in {"cell.connector", "cell.desktop", "cell.file"}:
            safe["commit_guarantee"] = "best_effort"
            self._audit(
                "best_effort_commit",
                draft_id=draft.draft_id,
                effect_type=draft.effect_type,
                executor_id=executor_id,
            )
        if draft.effect_type == "desktop.action":
            self._persist_desktop_action_receipt(
                permit_id=permit.permit_id,
                draft_id=draft.draft_id,
                before_digest=str(raw_dict.get("before_digest") or safe.get("before_digest") or ""),
                after_digest=str(raw_dict.get("after_digest") or safe.get("after_digest") or ""),
                target_digest=str(raw_dict.get("target_digest") or ""),
                state="committed" if safe.get("status") == "COMMITTED" else "unknown",
                created_at_ms=now,
            )
        return {"ok": True, "verdict": "allow", "cell": safe}

    def _verify_signed_cell_receipt(
        self,
        raw: dict[str, Any],
        *,
        permit: CommitPermit,
        executor_id: str,
    ) -> str | None:
        if raw.get("status") != "COMMITTED" or raw.get("duplicate") is True:
            return None
        blob = raw.get("signed_receipt")
        if type(blob) is not str or not blob:
            return "signed cell receipt is required"
        try:
            payload = json.loads(blob)
        except json.JSONDecodeError:
            return "signed cell receipt is invalid"
        try:
            signed = signed_receipt_from_dict(payload, mac_key=self._keybox.key)
        except ProtocolError:
            return "signed cell receipt seal is invalid"
        receipt = signed.receipt
        if (
            receipt.permit_id != permit.permit_id
            or receipt.executor_id != executor_id
            or receipt.status != "COMMITTED"
        ):
            return "signed cell receipt binding is invalid"
        return None

    def _persist_desktop_action_receipt(
        self,
        *,
        permit_id: str,
        draft_id: str,
        before_digest: str,
        after_digest: str,
        target_digest: str,
        state: str,
        created_at_ms: int,
    ) -> None:
        """Durably record a desktop.action outcome; never a consume decision."""

        self._store.record_desktop_action_receipt(
            permit_id=permit_id,
            draft_id=draft_id,
            before_digest=before_digest,
            after_digest=after_digest,
            target_digest=target_digest,
            state=state,
            created_at_ms=created_at_ms,
        )

    async def _reconcile_desktop_action(
        self,
        *,
        permit_id: str = "",
        draft_id: str = "",
    ) -> dict[str, str]:
        """Answer committed|absent|unknown without replaying the OS action."""

        stored = self._store.desktop_action_receipt(
            permit_id=permit_id or None,
            draft_id=draft_id or None,
        )
        if stored is not None and stored.get("state") == "committed" and stored.get("after_digest"):
            return {"state": "committed"}
        response = await self._request_cell(
            "cell.desktop",
            "reconcile",
            effect_id=draft_id or permit_id or "desktop-reconcile",
            probe={"permit_id": permit_id, "draft_id": draft_id},
        )
        if response is None or not response.get("ok"):
            return {"state": "unknown"}
        outcome = str(response.get("state") or "unknown")
        if outcome not in {"committed", "absent", "unknown"}:
            outcome = "unknown"
        if outcome == "committed":
            self._persist_desktop_action_receipt(
                permit_id=permit_id
                or str(stored.get("permit_id") if stored else "")
                or f"permit:reconciled-{draft_id}",
                draft_id=draft_id or str(stored.get("draft_id") if stored else ""),
                before_digest=str(
                    response.get("before_digest") or (stored or {}).get("before_digest") or ""
                ),
                after_digest=str(
                    response.get("after_digest") or (stored or {}).get("after_digest") or ""
                ),
                target_digest=str(
                    response.get("target_digest") or (stored or {}).get("target_digest") or ""
                ),
                state="committed",
                created_at_ms=self._now_ms(),
            )
        elif outcome == "unknown" and stored is None and (permit_id or draft_id):
            self._persist_desktop_action_receipt(
                permit_id=permit_id or f"permit:unknown-{draft_id}",
                draft_id=draft_id,
                before_digest="",
                after_digest="",
                target_digest="",
                state="unknown",
                created_at_ms=self._now_ms(),
            )
        return {"state": outcome}

    def _cell_writer_by_cap(
        self,
        cap: str,
        *,
        allow_unready: bool,
    ) -> asyncio.StreamWriter | None:
        for writer, session in self._cell_sessions.items():
            if (
                cap in session.caps
                and not writer.is_closing()
                and (allow_unready or cap in self._cell_ready_caps)
            ):
                return writer
        return None

    def _cell_by_cap(self, cap: str) -> asyncio.StreamWriter | None:
        """Return only a Cell that has finished its startup reconciliation."""

        return self._cell_writer_by_cap(cap, allow_unready=False)

    def _cell_session_by_cap(self, cap: str) -> _Session | None:
        writer = self._cell_by_cap(cap)
        return self._cell_sessions.get(writer) if writer is not None else None

    async def _proxy_cell(
        self,
        cap: str,
        payload: dict[str, Any],
        *,
        timeout_s: float = 90.0,
    ) -> dict[str, Any] | None:
        return await self._request_cell(
            cap,
            "commit",
            timeout_s=timeout_s,
            permit=payload,
        )

    async def _request_cell(
        self,
        cap: str,
        message_type: str,
        *,
        timeout_s: float = 90.0,
        _allow_unready: bool = False,
        **fields: Any,
    ) -> dict[str, Any] | None:
        writer = self._cell_writer_by_cap(cap, allow_unready=_allow_unready)
        if writer is None:
            return None
        session = self._cell_sessions[writer]
        loop = asyncio.get_running_loop()
        seq = session.next_server_seq()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        session.pending_server[seq] = (message_type + "_ack", future)
        try:
            envelope = make_envelope(
                message_type,
                seq=seq,
                nonce=session.session_nonce,
                session_key=session.session_key,
                **fields,
            )
            writer.write(encode_frame(envelope))
            await writer.drain()
            return await asyncio.wait_for(future, timeout=timeout_s)
        except (TimeoutError, ConnectionError, RuntimeError, ProtocolError, ValueError):
            return None
        finally:
            session.pending_server.pop(seq, None)

    async def _reconcile_membrane_for_caps(self, caps: frozenset[str]) -> None:
        """Finish durable recovery before a newly connected Cell is schedulable."""

        membrane = self._membrane
        if membrane is None:
            return
        for executor_id in sorted(caps & {"cell.connector", "cell.file"}):
            operations = membrane.operations_in_states(
                (CommitState.COMMITTING, CommitState.UNKNOWN_COMMIT),
                executor_id=executor_id,
            )
            for operation in operations:
                try:
                    await self._reconcile_membrane_operation(
                        operation,
                        allow_unready_cell=True,
                    )
                except (MembraneError, ProtocolError, ValueError):
                    # Recovery remains fail-closed: the durable row stays
                    # UNKNOWN_COMMIT and a later observation may retry only
                    # this read-only reconciliation probe.
                    self._audit(
                        "cell_reconciliation_pending",
                        executor_id=executor_id,
                        operation_id=operation.operation_id,
                    )

    async def _serve_cell_after_reconciliation(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session: _Session,
    ) -> None:
        """Serve Cell acks while hiding the Cell until recovery is stable."""

        serve_task = asyncio.create_task(self._serve_cells(reader, writer, session))
        reconcile_task = asyncio.create_task(self._reconcile_membrane_for_caps(session.caps))
        self._cell_reconcile_tasks.add(reconcile_task)
        try:
            done, _pending = await asyncio.wait(
                {serve_task, reconcile_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if serve_task in done:
                reconcile_task.cancel()
                await asyncio.gather(reconcile_task, return_exceptions=True)
                return
            await reconcile_task
            self._cell_ready_caps.update(session.caps)
            self._audit("cell_ready", caps=sorted(session.caps))
            await serve_task
        finally:
            self._cell_reconcile_tasks.discard(reconcile_task)
            for task in (serve_task, reconcile_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(serve_task, reconcile_task, return_exceptions=True)

    def _spawn_build_cell(self) -> None:
        """Launch the resident Build Cell subprocess (M§3.2-3 常驻池)."""

        caps = frozenset({"cell.build"})
        tickets, runtime_root = self._new_cell_launch("build", caps)
        if self._cell_identity_enforce:
            env = self._cell_environment(
                kind="build",
                caps=caps,
                tickets=tickets,
                runtime_root=runtime_root,
            )
        else:
            env = self._legacy_cell_environment()
            env["ORIN_CELLS_SOCKET"] = str(self._cell_socket_path)
            env["ORIN_STATE_DIR"] = str(self._state_dir)
        env = self._file_build_carrier_env("build", env, runtime_root)
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                [sys.executable, "-m", "js.orind.cells.build"],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            self._discard_cell_runtime_root(runtime_root)
            self._audit("build_cell_spawn_failed")
            return
        self._cell_procs.add(proc)
        self._build_proc = proc
        self._expected_cell_caps_by_pid[proc.pid] = caps
        if self._cell_identity_enforce:
            assert runtime_root is not None
            self._expected_cell_launch_by_pid[proc.pid] = tickets
            self._cell_runtime_roots[proc.pid] = runtime_root
        self._audit("build_cell_spawned", pid=proc.pid)

    def _spawn_services_cell(self) -> None:
        """Launch the net/secret/connector services subprocess (WP8)."""

        caps = sorted(self._desired_service_caps)
        if not caps:
            return
        cap_set = frozenset(caps)
        tickets, runtime_root = self._new_cell_launch("services", cap_set)
        if self._cell_identity_enforce:
            env = self._cell_environment(
                kind="services",
                caps=cap_set,
                tickets=tickets,
                runtime_root=runtime_root,
            )
        else:
            env = self._legacy_cell_environment()
            env["ORIN_CELLS_SOCKET"] = str(self._cell_socket_path)
            env["ORIN_STATE_DIR"] = str(self._state_dir)
            env["ORIN_CELLS_CAPS"] = ",".join(caps)
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                [sys.executable, "-m", "js.orind.cells.services"],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            self._discard_cell_runtime_root(runtime_root)
            self._audit("services_cell_spawn_failed")
            return
        self._cell_procs.add(proc)
        self._services_proc = proc
        self._expected_cell_caps_by_pid[proc.pid] = cap_set
        if self._cell_identity_enforce:
            assert runtime_root is not None
            self._expected_cell_launch_by_pid[proc.pid] = tickets
            self._cell_runtime_roots[proc.pid] = runtime_root
        self._audit("services_cell_spawned", pid=proc.pid, caps=caps)

    def _spawn_file_cell(self) -> None:
        """Launch the independent strict File Cell subprocess (WP9)."""

        caps = frozenset({"cell.file"})
        tickets, runtime_root = self._new_cell_launch("file", caps)
        if self._cell_identity_enforce:
            env = self._cell_environment(
                kind="file",
                caps=caps,
                tickets=tickets,
                runtime_root=runtime_root,
            )
        else:
            env = self._legacy_cell_environment()
            env["ORIN_CELLS_SOCKET"] = str(self._cell_socket_path)
            env["ORIN_STATE_DIR"] = str(self._state_dir)
            env["ORIN_KEYBOX_TIER"] = self._keybox.active_tier
        env = self._file_build_carrier_env("file", env, runtime_root)
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                [sys.executable, "-m", "js.orind.cells.file"],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            self._discard_cell_runtime_root(runtime_root)
            self._audit("file_cell_spawn_failed")
            return
        self._cell_procs.add(proc)
        self._file_proc = proc
        self._expected_cell_caps_by_pid[proc.pid] = caps
        if self._cell_identity_enforce:
            assert runtime_root is not None
            self._expected_cell_launch_by_pid[proc.pid] = tickets
            self._cell_runtime_roots[proc.pid] = runtime_root
        self._audit("file_cell_spawned", pid=proc.pid)

    def _spawn_desktop_cell(self) -> None:
        """Launch the WP-C2 Desktop Cell only for the explicit strict harness."""

        if not self._cell_desktop_enabled or not self._cell_identity_enforce:
            return
        caps = frozenset({"cell.desktop"})
        tickets, runtime_root = self._new_cell_launch("desktop", caps)
        env = self._cell_environment(
            kind="desktop",
            caps=caps,
            tickets=tickets,
            runtime_root=runtime_root,
        )
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                [sys.executable, "-m", "js.orind.cells.desktop"],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            self._discard_cell_runtime_root(runtime_root)
            self._audit("desktop_cell_spawn_failed")
            return
        self._cell_procs.add(proc)
        self._desktop_proc = proc
        self._expected_cell_caps_by_pid[proc.pid] = caps
        assert runtime_root is not None
        self._expected_cell_launch_by_pid[proc.pid] = tickets
        self._cell_runtime_roots[proc.pid] = runtime_root
        self._audit("desktop_cell_spawned", pid=proc.pid)

    def _spawn_memory_cell(self) -> None:
        """Launch the WP-C3 Memory Cell only for the explicit harness or enforce."""

        if not self._cell_memory_enabled or not self._cell_identity_enforce:
            return
        caps = frozenset({"cell.memory"})
        tickets, runtime_root = self._new_cell_launch("memory", caps)
        env = self._cell_environment(
            kind="memory",
            caps=caps,
            tickets=tickets,
            runtime_root=runtime_root,
        )
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                [sys.executable, "-m", "js.orind.cells.memory"],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            self._discard_cell_runtime_root(runtime_root)
            self._audit("memory_cell_spawn_failed")
            return
        self._cell_procs.add(proc)
        self._memory_proc = proc
        self._expected_cell_caps_by_pid[proc.pid] = caps
        assert runtime_root is not None
        self._expected_cell_launch_by_pid[proc.pid] = tickets
        self._cell_runtime_roots[proc.pid] = runtime_root
        self._audit("memory_cell_spawned", pid=proc.pid)

    def _new_cell_launch(
        self,
        kind: str,
        caps: frozenset[str],
    ) -> tuple[dict[str, str], Path | None]:
        """Create harness-only per-cap tickets and a private runtime root."""

        if not self._cell_identity_enforce:
            return {}, None
        runtime_parent = self._orin_dir / "cell-runtime"
        try:
            ensure_private_dir(runtime_parent)
            runtime_root = Path(tempfile.mkdtemp(prefix=f"{kind}-", dir=runtime_parent))
            ensure_private_dir(runtime_root)
        except (OSError, PrivatePathError) as exc:
            raise OrinDaemonError("C1 Cell runtime root contract failed") from exc
        tickets = {cap: secrets.token_hex(16) for cap in sorted(caps)}
        return tickets, runtime_root

    @staticmethod
    def _legacy_cell_environment() -> dict[str, str]:
        """Preserve the B environment except for C1's reserved harness keys."""

        environment = dict(os.environ)
        for key in (CELL_IDENTITY_ENV, LAUNCH_TICKETS_ENV, ORIND_PID_ENV):
            environment.pop(key, None)
        return environment

    def _cell_environment(
        self,
        *,
        kind: str,
        caps: frozenset[str],
        tickets: dict[str, str],
        runtime_root: Path | None,
    ) -> dict[str, str]:
        """Build the exact C1 Cell environment from an empty mapping."""

        if runtime_root is None:  # pragma: no cover - strict callers always allocate it
            raise OrinDaemonError("C1 Cell runtime root is missing")
        home = runtime_root / "home"
        temp_dir = runtime_root / "tmp"
        for directory in (home, temp_dir):
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
        trusted_path = os.pathsep.join(
            dict.fromkeys(
                (
                    str(Path(sys.executable).resolve().parent),
                    "/usr/bin",
                    "/bin",
                    "/usr/sbin",
                    "/sbin",
                )
            )
        )
        env = {
            "HOME": str(home),
            "LC_ALL": "C",
            "ORIN_CELLS_SOCKET": str(self._cell_socket_path),
            "ORIN_CELL_IDENTITY_ENFORCE": "1",
            "ORIN_CELL_LAUNCH_TICKETS": json.dumps(tickets, sort_keys=True, separators=(",", ":")),
            "ORIN_ORIND_PID": str(os.getpid()),
            "ORIN_STATE_DIR": str(self._state_dir),
            "PATH": trusted_path,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "TMPDIR": str(temp_dir),
        }
        if kind == "build":
            build_workspace = runtime_root / "build-workspace"
            build_workspace.mkdir(mode=0o700)
            os.chmod(build_workspace, 0o700)
            env["ORIN_BUILD_WORKSPACE"] = str(build_workspace)
        elif kind == "services":
            env["ORIN_CELLS_CAPS"] = ",".join(sorted(caps))
            env["ORIN_KEYBOX_TIER"] = self._keybox.active_tier
        elif kind == "file":
            env["ORIN_KEYBOX_TIER"] = self._keybox.active_tier
        elif kind == "desktop":
            env["ORIN_KEYBOX_TIER"] = self._keybox.active_tier
            if self._desktop_script_path is not None:
                env["ORIN_DESKTOP_SCRIPT_PATH"] = str(self._desktop_script_path)
        elif kind == "memory":
            env["ORIN_KEYBOX_TIER"] = self._keybox.active_tier
            private_state = runtime_root / "state"
            private_state.mkdir(mode=0o700)
            os.chmod(private_state, 0o700)
            env["ORIN_CELL_PRIVATE_STATE"] = str(private_state)
        else:  # pragma: no cover - all callers use a closed internal enum
            raise OrinDaemonError("unknown C1 Cell kind")
        return env

    def _file_build_carrier_env(
        self,
        kind: str,
        env: dict[str, str],
        runtime_root: Path | None,
    ) -> dict[str, str]:
        from js.orind.cells.container_vm import prepare_file_build_env

        return prepare_file_build_env(
            kind,
            env=env,
            state_dir=self._state_dir,
            workspace=self._state_dir / "guest-workspace",
            runtime_root=runtime_root,
            socket_path=self._cell_socket_path,
            mac_key=self._keybox.key,
            argv=[sys.executable, "-m", f"js.orind.cells.{kind}"],
        )

    @staticmethod
    def _discard_cell_runtime_root(runtime_root: Path | None) -> None:
        if runtime_root is None:
            return
        # Spawn failure happens before the Cell can create arbitrary content;
        # remove only the exact private directories this function created.
        for child in (
            runtime_root / "build-workspace",
            runtime_root / "tmp",
            runtime_root / "home",
            runtime_root / "state",
        ):
            with contextlib.suppress(OSError):
                child.rmdir()
        with contextlib.suppress(OSError):
            runtime_root.rmdir()

    def _respawn_watchdog(self) -> None:
        if self._shutting_down or not self._stage_b:
            return
        dead = {proc for proc in self._cell_procs if proc.poll() is not None}
        for proc in dead:
            self._expected_cell_caps_by_pid.pop(proc.pid, None)
            self._expected_cell_launch_by_pid.pop(proc.pid, None)
            runtime_root = self._cell_runtime_roots.pop(proc.pid, None)
            self._discard_cell_runtime_root(runtime_root)
        self._cell_procs.difference_update(dead)
        if self._build_proc is not None and self._build_proc.poll() is not None:
            self._build_proc = None
        if self._services_proc is not None and self._services_proc.poll() is not None:
            self._services_proc = None
        if self._file_proc is not None and self._file_proc.poll() is not None:
            self._file_proc = None
        if self._desktop_proc is not None and self._desktop_proc.poll() is not None:
            self._desktop_proc = None
        if self._memory_proc is not None and self._memory_proc.poll() is not None:
            self._memory_proc = None
        connected_caps = {
            cap for writer in self._cell_sessions for cap in self._cell_sessions[writer].caps
        }
        if (
            self._cell_build_enabled
            and self._spawn_build_cells
            and "cell.build" not in connected_caps
            and self._build_proc is None
        ):
            self._spawn_build_cell()
        if (
            self._services_enabled
            and not self._desired_service_caps.issubset(connected_caps)
            and self._services_proc is None
        ):
            self._spawn_services_cell()
        if (
            self._cell_file_enabled
            and "cell.file" not in connected_caps
            and self._file_proc is None
        ):
            self._spawn_file_cell()
        if (
            self._cell_desktop_enabled
            and "cell.desktop" not in connected_caps
            and self._desktop_proc is None
        ):
            self._spawn_desktop_cell()
        if (
            self._cell_memory_enabled
            and "cell.memory" not in connected_caps
            and self._memory_proc is None
        ):
            self._spawn_memory_cell()

    async def _handle_cell_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._cell_tasks.add(task)
        try:
            if self._cell_identity_enforce and not self._strict_socket_is_current(
                self._cell_socket_path
            ):
                self._audit("peer_rejected", reason="Cell socket path replaced")
                writer.close()
                return
            peer = self._check_peer(writer)
            if peer is None:
                writer.close()
                return
            if peer[1] <= 0:
                self._audit(
                    "handshake_rejected",
                    reason="cell peer pid unavailable",
                )
                writer.close()
                return
            if self._cell_identity_enforce:
                session = await self._strict_cell_handshake(reader, writer, peer)
            else:
                session = await self._handshake(reader, writer, peer)
            if session is None:
                writer.close()
                return
            allowed = self._expected_cell_caps_by_pid.get(session.peer[1])
            if (
                allowed is None
                or not session.caps
                or any(not cap.startswith("cell.") for cap in session.caps)
                or not session.caps.issubset(allowed)
            ):
                self._audit(
                    "handshake_rejected",
                    reason="cell pid/cap is not daemon-authorized",
                    peer_pid=session.peer[1],
                )
                writer.close()
                return
            connected = {
                cap
                for other_writer, other_session in self._cell_sessions.items()
                if not other_writer.is_closing()
                for cap in other_session.caps
            }
            if connected & session.caps:
                self._audit("handshake_rejected", reason="duplicate cell cap")
                writer.close()
                return
            self._cell_sessions[writer] = session
            self._audit("cell_connected", caps=sorted(session.caps))
            await self._serve_cell_after_reconciliation(reader, writer, session)
        finally:
            self._cell_tasks.discard(asyncio.current_task())
            dropped = self._cell_sessions.pop(writer, None)
            if dropped is not None:
                self._cell_ready_caps.difference_update(dropped.caps)
                for _expected, future in dropped.pending_server.values():
                    if not future.done():
                        future.set_result({"ok": False, "code": "internal", "reason": "cell lost"})
                loop = self._loop
                if self._stage_b and not self._shutting_down and loop is not None:
                    loop.call_later(1.0, self._respawn_watchdog)
            writer.close()

    async def _serve_cells(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session: _Session,
    ) -> None:
        while True:
            try:
                envelope = await self._read_frame(reader)
            except (ProtocolError, asyncio.IncompleteReadError, ConnectionError):
                self._audit("cell_connection_dropped", peer_pid=session.peer[1])
                return
            if envelope is None:
                continue
            if not verify_mac(session.session_key, envelope):
                self._audit("protocol_violation", reason="bad mac from cell")
                return
            if self._cell_identity_enforce and envelope.get("nonce") != session.session_nonce:
                self._audit("protocol_violation", reason="cell session nonce mismatch")
                return
            if envelope["seq"] <= session.last_client_seq:
                self._audit("protocol_violation", reason="cell seq regression")
                return
            session.last_client_seq = envelope["seq"]
            message_type = envelope["type"]
            if message_type.endswith("_ack"):
                pending = session.pending_server.get(envelope["seq"])
                if pending is None:
                    self._audit("protocol_violation", reason="unsolicited cell ack")
                    return
                expected_type, future = pending
                if message_type != expected_type:
                    self._audit(
                        "protocol_violation",
                        reason=f"cell ack type {message_type} != {expected_type}",
                    )
                    return
                if not future.done():
                    future.set_result(envelope)
                continue
            if message_type == "heartbeat":
                ack = make_envelope(
                    "heartbeat_ack",
                    seq=session.next_server_seq(),
                    nonce=session.session_nonce,
                    session_key=session.session_key,
                    ok=True,
                    healthy=True,
                )
                with contextlib.suppress(ConnectionError, RuntimeError):
                    writer.write(encode_frame(ack))
                    await writer.drain()
                continue
            self._audit("protocol_violation", reason=f"cell sent {message_type}")
            return

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
    stage_b: bool = False,
    cell_build: bool = False,
    cell_secret: bool = False,
    cell_net: bool = False,
    cell_file: bool = False,
    commit_membrane: bool = False,
    cell_identity_enforce: bool = False,
) -> None:
    """Foreground entry (``--dev`` mode); launchd manages restarts in prod."""

    daemon = OrinDaemon(
        state_dir=state_dir,
        socket_path=socket_path,
        keybox_tier=keybox_tier,
        stage_b=stage_b,
        cell_build=cell_build,
        cell_secret=cell_secret,
        cell_net=cell_net,
        cell_file=cell_file,
        commit_membrane=commit_membrane,
        cell_identity_enforce=cell_identity_enforce,
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

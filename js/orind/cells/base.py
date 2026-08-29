"""Effect Cell base: an orind-scheduled executor process.

A Cell is a separate process that connects BACK to orind's cell socket
(``<state_dir>/orin/cells.sock``), authenticates with the same one-shot
session-key handshake as Echo, and then waits. It never listens on a
network socket and holds no ambient authority beyond what its handler
explicitly uses. orind dispatches ``commit`` commands; the Cell executes
them locally under its own restrictions and answers ``commit_ack``
(bounded untrusted output rides in ``output`` — TOOL_RESULT downstream,
never secret material).

Fail semantics: if the Cell dies, orind's proxy returns "cell not
available" for that effect class only — every other tool keeps working.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from js.orin.draft import (
    CellPackage,
    StateWitness,
    cell_package_from_dict,
    permit_from_dict,
    witness_from_dict,
)
from js.orin.handles import OriginHandle, handle_from_dict
from js.orin.protocol import (
    HEARTBEAT_INTERVAL_S,
    ProtocolError,
    encode_frame,
    make_envelope,
    parse_frame,
    verify_mac,
)
from js.orind.cell_identity import (
    CELL_IDENTITY_ENV,
    load_cell_launch_identity,
    peer_credentials,
    read_session_key_once,
    require_same_socket,
    verify_owned_socket,
)

_CONNECT_TIMEOUT_S = 5.0
_RESULT_KEY_PARTS = re.compile(r"[a-z0-9]+")
_CAMEL_KEY_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_SENSITIVE_RESULT_PARTS = frozenset(
    {
        "auth",
        "authentication",
        "authorization",
        "bearer",
        "body",
        "cookie",
        "credential",
        "package",
        "password",
        "permit",
        "secret",
        "subject",
        "token",
    }
)


def _read_session_key_file(path: Path) -> bytes:
    key = path.read_bytes()
    try:
        path.unlink()
    except OSError:
        pass
    if len(key) != 32:
        raise ProtocolError("session key must be 32 bytes")
    return key


class CellBase:
    """Background-thread Cell speaking orin/v1 from the cell side."""

    def __init__(
        self,
        *,
        cap: str,
        socket_path: Path,
        state_dir: Path,
        handler: Callable[..., Any],
        preflight_handler: Callable[[CellPackage], Any] | None = None,
        handle_handler: Callable[[str, dict[str, Any]], Any] | None = None,
        reconcile_handler: Callable[[str, dict[str, Any]], Any] | None = None,
        strict_effect_protocol: bool = False,
    ) -> None:
        self._cap = cap
        self._socket_path = socket_path
        self._state_dir = state_dir
        self._handler = handler
        self._preflight_handler = preflight_handler
        self._handle_handler = handle_handler
        self._reconcile_handler = reconcile_handler
        self._strict_effect_protocol = strict_effect_protocol
        self._identity_enforce = os.environ.get(CELL_IDENTITY_ENV) == "1"
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._session_key: bytes | None = None
        self._session_nonce = ""
        self._last_client_seq = 0  # frames WE send to orind
        self._last_server_seq = 0  # frames orind sends to us
        self._stopped = False

    # -- lifecycle ------------------------------------------------------------
    @property
    def cap(self) -> str:
        return self._cap

    def attach_signed_receipt(
        self,
        public: dict[str, Any],
        *,
        permit_id: str,
        executor_id: str,
        effect_hash: str,
        receipt_id: str,
    ) -> dict[str, Any]:
        """Seal a Cell public result. Missing session key leaves the result unsigned."""

        mac_key = self._session_key
        if not isinstance(mac_key, bytes) or len(mac_key) != 32:
            return public
        from js.orin.draft import seal_signed_effect_receipt
        from js.orin.protocol import canonical_json

        sealed = dict(public)
        started = int(time.time() * 1000)
        sealed["signed_receipt"] = seal_signed_effect_receipt(
            mac_key=mac_key,
            permit_id=permit_id,
            executor_id=executor_id,
            status=str(public.get("status") or "COMMITTED"),
            canonical_effect_hash=effect_hash,
            result_digest="sha256:"
            + hashlib.sha256(canonical_json(public).encode("utf-8")).hexdigest(),
            started_at_ms=started,
            finished_at_ms=started,
            receipt_id=receipt_id,
        )
        return sealed

    def _seal_commit_result(
        self,
        result: dict[str, Any],
        *,
        permit: Any,
        package: Any | None = None,
    ) -> dict[str, Any]:
        """Attach a K§8.5 receipt once. Missing session key leaves the result unsigned."""

        if "signed_receipt" in result:
            return result
        permit_id = getattr(permit, "permit_id", None)
        if not permit_id and isinstance(permit, dict):
            permit_id = permit.get("permit_id") or permit.get("id")
        effect_hash = getattr(package, "canonical_effect_hash", None)
        if not effect_hash and isinstance(permit, dict):
            effect_hash = permit.get("canonical_effect_hash") or permit.get("hash")
        return self.attach_signed_receipt(
            result,
            permit_id=str(permit_id or "permit"),
            executor_id=self._cap,
            effect_hash=str(effect_hash or ("sha256:" + "0" * 64)),
            receipt_id="receipt:" + str(permit_id or "permit"),
        )

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._ready.clear()
        self._startup_error = None
        self._thread = threading.Thread(
            target=self._run, name=f"orin-cell-{self._cap}", daemon=True
        )
        self._thread.start()
        if not self._ready.wait(timeout=_CONNECT_TIMEOUT_S + 5.0):
            raise RuntimeError(f"cell {self._cap} failed to start")
        if self._identity_enforce and self._startup_error is not None:
            raise RuntimeError(
                f"cell {self._cap} strict identity handshake failed"
            ) from self._startup_error

    def stop(self) -> None:
        self._stopped = True
        loop = self._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._connect_and_serve())
        except Exception as exc:  # noqa: BLE001 - a dead cell fails closed at orind
            self._startup_error = exc
        finally:
            self._ready.set()
            self._loop.close()

    async def _connect_and_serve(self) -> None:
        socket_identity = None
        daemon_pid = 0
        launch_ticket = ""
        if self._identity_enforce:
            socket_identity = verify_owned_socket(self._socket_path)
            daemon_pid, launch_ticket = load_cell_launch_identity(self._cap)
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(path=str(self._socket_path)),
            timeout=_CONNECT_TIMEOUT_S,
        )
        self._writer = writer
        if self._identity_enforce:
            assert socket_identity is not None
            require_same_socket(self._socket_path, socket_identity)
            sock = writer.get_extra_info("socket")
            credentials = peer_credentials(sock) if sock is not None else None
            if credentials != (os.geteuid(), daemon_pid):
                raise ProtocolError("Cell socket peer is not the launching orind")
        # In the strict harness the one-shot launch ticket is also the
        # existing hello nonce.  This preserves Stage-A's exact hello schema
        # instead of adding a field that non-enforce peers would accept.
        client_nonce = launch_ticket if self._identity_enforce else secrets.token_hex(16)
        hello = make_envelope(
            "hello",
            seq=1,
            nonce=client_nonce,
            session_key=None,
            caps=[self._cap],
            pid=os.getpid(),
        )
        writer.write(encode_frame(hello))
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(4), timeout=_CONNECT_TIMEOUT_S)
        payload = await reader.readexactly(int.from_bytes(header, "big"))
        ack = parse_frame(payload)
        if ack["type"] != "hello_ack" or not ack.get("ok", True):
            raise ProtocolError("cell handshake rejected")
        server_nonce = str(ack.get("server_nonce") or "")
        if not server_nonce:
            raise ProtocolError("handshake missing server nonce")
        self._session_nonce = client_nonce + server_nonce
        self._last_client_seq = 1
        key_file = self._state_dir / "orin" / f"session-{os.getpid()}.key"
        loop = asyncio.get_running_loop()
        key_reader = read_session_key_once if self._identity_enforce else _read_session_key_file
        self._session_key = await loop.run_in_executor(None, key_reader, key_file)
        if self._identity_enforce:
            if (
                int(ack["seq"]) != 1
                or ack.get("caps") != [self._cap]
                or ack.get("nonce") != self._session_nonce
            ):
                raise ProtocolError("Cell hello acknowledgement is not launch-bound")
            proof = make_envelope(
                "heartbeat",
                seq=2,
                nonce=self._session_nonce,
                session_key=self._session_key,
            )
            writer.write(encode_frame(proof))
            await writer.drain()
            proof_header = await asyncio.wait_for(reader.readexactly(4), timeout=_CONNECT_TIMEOUT_S)
            proof_payload = await reader.readexactly(int.from_bytes(proof_header, "big"))
            proof_ack = parse_frame(proof_payload)
            if (
                proof_ack.get("type") != "heartbeat_ack"
                or proof_ack.get("ok") is not True
                or int(proof_ack.get("seq", 0)) != 2
                or proof_ack.get("nonce") != self._session_nonce
                or not verify_mac(self._session_key, proof_ack)
            ):
                raise ProtocolError("Cell proof-of-key acknowledgement is invalid")
            self._last_client_seq = 2
            self._last_server_seq = 2
        self._ready.set()
        while not self._stopped:
            header = await reader.readexactly(4)
            body = await reader.readexactly(int.from_bytes(header, "big"))
            envelope = parse_frame(body)
            if self._session_key is None or not verify_mac(self._session_key, envelope):
                raise ProtocolError("cell command MAC verification failed")
            if self._identity_enforce and envelope.get("nonce") != self._session_nonce:
                raise ProtocolError("cell command session nonce mismatch")
            seq = int(envelope["seq"])
            if seq <= self._last_server_seq:
                raise ProtocolError("seq regression")
            self._last_server_seq = seq
            message_type = envelope["type"]
            if message_type == "preflight":
                if not self._strict_effect_protocol:
                    raise ProtocolError("legacy cell does not accept preflight")
                await self._on_preflight(envelope)
                continue
            if message_type == "handle":
                if not self._strict_effect_protocol:
                    raise ProtocolError("legacy cell does not accept handle resolution")
                await self._on_handle(envelope)
                continue
            if message_type == "commit":
                await self._on_commit(envelope)
                continue
            if message_type == "reconcile":
                await self._on_reconcile(envelope)
                continue

            if message_type == "heartbeat":
                reply = make_envelope(
                    "heartbeat_ack",
                    seq=seq,
                    nonce=self._session_nonce,
                    session_key=self._session_key,
                    ok=True,
                    healthy=True,
                )
                self._last_client_seq = max(self._last_client_seq, seq)
                writer.write(encode_frame(reply))
                await writer.drain()
                continue
            if message_type == "freeze":
                break
            # anything else from orind on the cell socket is a violation
            raise ProtocolError(f"unexpected {message_type} on cell socket")

    async def _on_preflight(self, envelope: dict[str, Any]) -> None:
        """Validate an Orind-only package and compute a read-only witness."""

        assert self._writer is not None
        request_seq = int(envelope["seq"])
        self._last_client_seq = max(self._last_client_seq, request_seq)
        try:
            raw_package = envelope.get("package")
            if not isinstance(raw_package, dict):
                raise ProtocolError("strict preflight requires a package object")
            package = cell_package_from_dict(raw_package)
            if package.state_witness is not None:
                raise ProtocolError("preflight package must not contain a state_witness")
            if package.executor_id != self._cap:
                raise ProtocolError("preflight package executor does not match cell")
            if envelope.get("draft_id") != package.draft.draft_id:
                raise ProtocolError("preflight draft does not match package")
            if envelope.get("executor_id") != package.executor_id:
                raise ProtocolError("preflight executor does not match package")
            if self._preflight_handler is None:
                raise ProtocolError("cell has no preflight handler")
            raw_result = self._preflight_handler(package)
            if asyncio.iscoroutine(raw_result):
                raw_result = await raw_result
            projection: dict[str, Any] | None = None
            raw_witness = raw_result
            if hasattr(raw_result, "witness") and hasattr(raw_result, "projection"):
                raw_witness = raw_result.witness
                raw_projection = raw_result.projection
                if not isinstance(raw_projection, dict):
                    raise ProtocolError("preflight projection must be an object")
                projection = self._bounded_strict_result(raw_projection)
            witness = self._parse_preflight_witness(raw_witness, package)
            fields: dict[str, Any] = {
                "ok": True,
                "witness": witness.to_dict(),
            }
            if projection is not None:
                fields["result"] = projection
            reply = make_envelope(
                "preflight_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                **fields,
            )
        except ProtocolError as exc:
            reply = make_envelope(
                "preflight_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=False,
                code="bad_message",
                reason=str(exc)[:512],
            )
        except Exception:  # noqa: BLE001 - no package content in the error channel
            reply = make_envelope(
                "preflight_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=False,
                code="internal",
                reason="cell preflight failed",
            )
        self._writer.write(encode_frame(reply))
        await self._writer.drain()

    async def _on_handle(self, envelope: dict[str, Any]) -> None:
        """Resolve a Cell-private observed target on the existing handle wire."""

        assert self._writer is not None
        request_seq = int(envelope["seq"])
        self._last_client_seq = max(self._last_client_seq, request_seq)
        try:
            if envelope.get("op") != "resolve" or self._handle_handler is None:
                raise ProtocolError("cell accepts only internal handle resolution")
            raw_ref = envelope.get("handle")
            spec = envelope.get("spec")
            if not isinstance(raw_ref, dict) or set(raw_ref) != {"handle_id"}:
                raise ProtocolError("cell handle resolution requires one handle id")
            handle_id = raw_ref.get("handle_id")
            if not isinstance(handle_id, str) or not handle_id.startswith("desktop:"):
                raise ProtocolError("cell handle id is invalid")
            if not isinstance(spec, dict):
                raise ProtocolError("cell handle resolution requires a binding spec")
            raw_handle = self._handle_handler(handle_id, spec)
            if asyncio.iscoroutine(raw_handle):
                raw_handle = await raw_handle
            handle = (
                raw_handle
                if isinstance(raw_handle, OriginHandle)
                else handle_from_dict(raw_handle, require_signature=True)
            )
            if handle.handle_id != handle_id or handle.kind != "DesktopTargetHandle":
                raise ProtocolError("cell resolved the wrong DesktopTargetHandle")
            reply = make_envelope(
                "handle_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=True,
                handle=handle.to_dict(),
            )
        except ProtocolError as exc:
            reply = make_envelope(
                "handle_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=False,
                code="bad_message",
                reason=str(exc)[:512],
            )
        except Exception:  # noqa: BLE001 - no private observation in errors
            reply = make_envelope(
                "handle_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=False,
                code="internal",
                reason="cell handle resolution failed",
            )
        self._writer.write(encode_frame(reply))
        await self._writer.drain()

    async def _on_reconcile(self, envelope: dict[str, Any]) -> None:
        """Run a read-only Cell probe through the existing reconcile wire.

        Cell handlers use the membrane's state names internally.  The wire
        vocabulary predates WP10, so the three outcomes are projected onto
        its existing ``committed`` / ``absent`` / ``unknown`` values.  No
        handler diagnostics are reflected into the acknowledgement.
        """

        assert self._writer is not None
        request_seq = int(envelope["seq"])
        self._last_client_seq = max(self._last_client_seq, request_seq)
        try:
            if not self._strict_effect_protocol:
                raise ProtocolError("legacy cell does not accept reconcile")
            if self._reconcile_handler is None:
                raise ProtocolError("cell has no reconcile handler")
            effect_id = envelope.get("effect_id")
            probe = envelope.get("probe", {})
            if not isinstance(effect_id, str) or not effect_id:
                raise ProtocolError("reconcile requires an effect_id")
            if not isinstance(probe, dict):
                raise ProtocolError("reconcile probe must be an object")
            raw_result = self._reconcile_handler(effect_id, probe)
            if asyncio.iscoroutine(raw_result):
                raw_result = await raw_result
            if not isinstance(raw_result, dict):
                raise ProtocolError("reconcile handler must return a state object")
            state = raw_result.get("state")
            if not isinstance(state, str):
                raise ProtocolError("reconcile handler returned an invalid state")
            wire_states = {
                "COMMITTED": "committed",
                "PREPARED": "absent",
                "UNKNOWN_COMMIT": "unknown",
            }
            wire_state = wire_states.get(state)
            if wire_state is None:
                raise ProtocolError("reconcile handler returned an invalid state")
            reply = make_envelope(
                "reconcile_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=True,
                state=wire_state,
                **{
                    key: value
                    for key in ("before_digest", "after_digest", "target_digest")
                    for value in (raw_result.get(key),)
                    if type(value) is str and value.startswith("sha256:") and len(value) == 71
                },
            )
        except ProtocolError:
            reply = make_envelope(
                "reconcile_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=False,
                code="bad_message",
                reason="cell reconcile request rejected",
            )
        except Exception:  # noqa: BLE001 - never reflect probe or authority data
            reply = make_envelope(
                "reconcile_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=False,
                code="internal",
                reason="cell reconcile failed",
            )
        self._writer.write(encode_frame(reply))
        await self._writer.drain()

    def _parse_preflight_witness(
        self,
        raw_witness: Any,
        package: CellPackage,
    ) -> StateWitness:
        if isinstance(raw_witness, StateWitness):
            witness = raw_witness
        elif isinstance(raw_witness, dict):
            witness = witness_from_dict(raw_witness)
        else:
            raise ProtocolError("preflight handler must return a StateWitness")
        if witness.draft_id != package.draft.draft_id:
            raise ProtocolError("preflight witness draft mismatch")
        if witness.executor_id != package.executor_id:
            raise ProtocolError("preflight witness executor mismatch")
        if witness.canonical_effect_hash != package.canonical_effect_hash:
            raise ProtocolError("preflight witness canonical hash mismatch")
        now_ms = time.time_ns() // 1_000_000
        if witness.created_at_ms > now_ms + 5_000 or witness.expires_at_ms <= now_ms:
            raise ProtocolError("preflight witness is outside its validity window")
        return witness

    async def _on_commit(self, envelope: dict[str, Any]) -> None:
        assert self._writer is not None
        request_seq = int(envelope["seq"])
        self._last_client_seq = max(self._last_client_seq, request_seq)
        permit = envelope.get("permit")
        if not isinstance(permit, dict):
            reply = make_envelope(
                "commit_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=False,
                code="bad_message",
                reason="commit requires a permit object",
            )
        elif self._strict_effect_protocol:
            reply = await self._strict_commit_reply(envelope, permit, request_seq)
        elif "package" in envelope:
            # The WP7 Build frame is frozen: permit is the original payload
            # and a package is never accepted on that legacy branch.
            reply = make_envelope(
                "commit_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=False,
                code="bad_message",
                reason="legacy cell commit must not carry a package",
            )
        else:
            try:
                result = self._handler(permit)
                if asyncio.iscoroutine(result):
                    result = await result
                if not isinstance(result, dict):
                    result = {"status": "COMMITTED", "raw": str(result)[:4096]}
                result = self._seal_commit_result(result, permit=permit)
                bounded = dict(result)
                if "output" in bounded:
                    bounded["output"] = str(bounded["output"])[: 64 * 1024]
                reply = make_envelope(
                    "commit_ack",
                    seq=request_seq,
                    nonce=self._session_nonce,
                    session_key=self._session_key,
                    ok=True,
                    result=bounded,
                )
            except Exception as exc:  # noqa: BLE001 - reported, never crash the cell
                reply = make_envelope(
                    "commit_ack",
                    seq=request_seq,
                    nonce=self._session_nonce,
                    session_key=self._session_key,
                    ok=False,
                    code="internal",
                    reason=str(exc)[:512],
                )
        self._writer.write(encode_frame(reply))
        await self._writer.drain()

    async def _strict_commit_reply(
        self,
        envelope: dict[str, Any],
        raw_permit: dict[str, Any],
        request_seq: int,
    ) -> dict[str, Any]:
        try:
            raw_package = envelope.get("package")
            if not isinstance(raw_package, dict):
                raise ProtocolError("strict commit requires a package object")
            permit = permit_from_dict(raw_permit)
            package = cell_package_from_dict(
                raw_package,
                require_witness=True,
                permit=permit,
            )
            if permit.executor_id != self._cap or package.executor_id != self._cap:
                raise ProtocolError("commit executor does not match cell")
            now_ms = time.time_ns() // 1_000_000
            if permit.not_before_ms > now_ms or permit.expires_at_ms <= now_ms:
                raise ProtocolError("commit permit is outside its validity window")
            if permit.expires_at_ms <= permit.not_before_ms:
                raise ProtocolError("commit permit has an invalid validity window")
            witness = package.state_witness
            if witness is None or witness.expires_at_ms <= now_ms:
                raise ProtocolError("commit state witness is expired")
            result = self._handler(permit, package)
            if asyncio.iscoroutine(result):
                result = await result
            if not isinstance(result, dict):
                raise ProtocolError("strict cell handler must return a result object")
            bounded = self._bounded_strict_result(result)
            bounded = self._seal_commit_result(bounded, permit=permit, package=package)
            return make_envelope(
                "commit_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=True,
                result=bounded,
            )
        except ProtocolError as exc:
            return make_envelope(
                "commit_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=False,
                code="bad_message",
                reason=str(exc)[:512],
            )
        except Exception:  # noqa: BLE001 - never reflect package/secret data
            return make_envelope(
                "commit_ack",
                seq=request_seq,
                nonce=self._session_nonce,
                session_key=self._session_key,
                ok=False,
                code="internal",
                reason="cell commit failed",
            )

    @staticmethod
    def _bounded_strict_result(result: dict[str, Any]) -> dict[str, Any]:
        """Keep authority objects and credential-shaped fields off the ack."""

        def sensitive_key(key: Any) -> bool:
            raw = _CAMEL_KEY_BOUNDARY.sub(r"\1_\2", str(key)).casefold()
            parts = tuple(_RESULT_KEY_PARTS.findall(raw))
            if any(part in _SENSITIVE_RESULT_PARTS for part in parts):
                return True
            # Treat all common spellings of api-key as credential material,
            # including APIKey, api_key, x-api-key, and apikey.
            compact = "".join(parts)
            return "apikey" in compact or ("api" in parts and "key" in parts)

        def reject_authority(value: Any) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if sensitive_key(key):
                        raise ProtocolError("strict cell result contains authority material")
                    reject_authority(child)
            elif isinstance(value, (list, tuple)):
                for child in value:
                    reject_authority(child)

        bounded = dict(result)
        reject_authority(bounded)
        if "output" in bounded:
            bounded["output"] = str(bounded["output"])[: 48 * 1024]
        return bounded

    def _next_seq(self) -> int:
        self._last_client_seq += 1
        return self._last_client_seq

    def healthy(self) -> bool:
        return (
            self._thread is not None
            and self._thread.is_alive()
            and self._writer is not None
            and not self._writer.is_closing()
            and self._session_key is not None
        )


__all__ = ["CellBase", "HEARTBEAT_INTERVAL_S"]

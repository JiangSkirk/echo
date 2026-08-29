"""Tiered approval system: manual, auto-approve, auto-deny, cron-deny.

Inspired by Hermes:
- Manual: interactive prompt for dangerous operations
- Gateway: async queue for WebSocket sessions
- Cron mode: deny all dangerous ops in scheduled jobs
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from js.security.secrets import redact_known_secrets
from js.utils.log import get_logger
from js.utils.metrics import get_metrics

logger = get_logger("js.approvals")


def _secure_str_eq(left: str | None, right: str | None) -> bool:
    """Constant-time equality for optional UTF-8 identity strings."""
    a = (left or "").encode("utf-8")
    b = (right or "").encode("utf-8")
    if len(a) != len(b):
        # Still touch both digests so length mismatch is not a pure short-circuit oracle.
        hmac.compare_digest(hashlib.sha256(a).digest(), hashlib.sha256(b).digest())
        return False
    return hmac.compare_digest(a, b)


DEFAULT_APPROVAL_TIMEOUT = 300.0  # 5 minutes


class ApprovalMode(StrEnum):
    MANUAL = "manual"
    AUTO_APPROVE = "auto_approve"
    AUTO_DENY = "auto_deny"
    CRON_DENY = "cron_deny"


class ApprovalDecisionType(StrEnum):
    PENDING = "pending"
    APPROVE = "approve"
    EDIT = "edit"
    REJECT = "reject"
    RESPOND = "respond"


@dataclass(frozen=True)
class ApprovalDecision:
    action: ApprovalDecisionType
    request_id: str = ""
    edited_arguments: dict[str, Any] | None = None
    response: str = ""
    reason: str = ""

    @property
    def approved(self) -> bool:
        return self.action in {ApprovalDecisionType.APPROVE, ApprovalDecisionType.EDIT}


@dataclass
class ApprovalRequest:
    id: str
    tool_name: str
    arguments: dict[str, Any]
    timestamp: float
    context: str  # "cli", "web", "cron", "subagent"
    timeout_seconds: float = field(default=DEFAULT_APPROVAL_TIMEOUT)
    session_id: str | None = None
    run_id: str | None = None
    owner_key_hash: str | None = None
    approval_mode: ApprovalMode = ApprovalMode.MANUAL
    resolved: bool = False
    approved: bool = False
    decision: ApprovalDecision | None = None

    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.timeout_seconds


ApprovalCallback = Callable[[ApprovalRequest], bool | ApprovalDecision]


@dataclass(frozen=True)
class _CallbackRegistration:
    callback: ApprovalCallback
    owner_key_hash: str | None = None
    run_id: str | None = None
    tool_name: str | None = None
    arguments_hash: str | None = None


@dataclass(frozen=True)
class _ResolvedDecisionRecord:
    decision: ApprovalDecision
    owner_key_hash: str | None
    session_id: str
    run_id: str
    tool_name: str
    arguments_hash: str
    requested_at: float
    expires_at: float
    approval_mode: ApprovalMode


class ApprovalEchoAuthority:
    """Typed, sealed authority for atomic approval claims in EchoLedger.

    Created by ``EchoSafetyService``, passed to ``ApprovalQueue`` via
    ``set_echo_authority()`` (set-once).  Once sealed, cannot be replaced.
    All three methods (``claim_once``, ``lookup_claim``, ``record_event``)
    operate on the same Echo journal partition.
    """

    __slots__ = ("_service", "_product_id", "_sealed")

    def __init__(self, service: Any, *, product_id: str) -> None:
        self._service = service
        self._product_id = product_id
        self._sealed = False

    def seal(self) -> None:
        self._sealed = True

    def claim_once(
        self,
        *,
        tenant_id: str,
        session_id: str,
        run_id: str,
        request_id: str,
        tool_name: str,
        arguments_hash: str,
        approval_mode: str,
        expires_at: float,
        requested_at: float,
    ) -> Any:
        """Atomically claim one approval binding in the Echo journal."""
        return self._service.claim_approval_binding_once(
            tenant_id=tenant_id,
            product_id=self._product_id,
            session_id=session_id,
            run_id=run_id,
            request_id=request_id,
            tool_name=tool_name,
            arguments_hash=arguments_hash,
            approval_mode=approval_mode,
            expires_at=expires_at,
            requested_at=requested_at,
        )

    def lookup_claim(
        self,
        *,
        tenant_id: str,
        session_id: str,
        request_id: str,
    ) -> Any | None:
        """Query whether a claim exists in the Echo journal."""
        return self._service.lookup_approval_claim(
            tenant_id=tenant_id,
            product_id=self._product_id,
            session_id=session_id,
            request_id=request_id,
        )

    def record_event(
        self,
        *,
        tenant_id: str,
        session_id: str,
        run_id: str,
        event_type: str,
        request_id: str,
        tool_name: str,
        arguments_hash: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record a non-claim approval event (e.g. finalize)."""
        self._service.record_approval_event(
            tenant_id=tenant_id,
            product_id=self._product_id,
            session_id=session_id,
            run_id=run_id,
            event_type=event_type,
            request_id=request_id,
            tool_name=tool_name,
            arguments_hash=arguments_hash,
            extra=extra,
        )


class ApprovalQueue:
    """Async approval queue with session-scoped callbacks."""

    def __init__(
        self,
        default_mode: ApprovalMode = ApprovalMode.MANUAL,
        input_stream: Callable[[str], str] | None = None,
        default_timeout: float = DEFAULT_APPROVAL_TIMEOUT,
        ledger_path: Path | None = None,
    ) -> None:
        self._default_mode = default_mode
        self._input_stream = input_stream or input
        self._default_timeout = default_timeout
        self._pending: dict[str, ApprovalRequest] = {}
        self._callbacks: dict[str, _CallbackRegistration] = {}
        self._lock = threading.RLock()
        self._counter = 0
        self._history: dict[str, int] = {"total": 0, "approved": 0, "denied": 0}
        self._ledger_path = ledger_path
        if ledger_path is not None and ledger_path.is_symlink():
            raise ValueError("approval ledger must not be a symlink")
        self._ledger_seq = 0
        self._ledger_prev_hash = "0" * 64
        self._ledger_mac_key = self._derive_ledger_mac_key()
        self._resolved_decisions: OrderedDict[str, _ResolvedDecisionRecord] = OrderedDict()
        # Authoritative EchoLedger sink for approval lifecycle events.  The
        # local JSONL file is only a derived mirror; the EchoLedger scope
        # partition journal is the system of record.
        self._echo_event_sink: Callable[[dict[str, Any]], None] | None = None
        # Typed, sealed Echo authority for atomic approval claims.
        self._echo_authority: ApprovalEchoAuthority | None = None
        self._echo_authority_sealed = False
        self._load_ledger_sequence()

    def set_echo_event_sink(self, sink: Callable[[dict[str, Any]], None] | None) -> None:
        """Install the authoritative EchoLedger sink for lifecycle events.

        Once installed, every approval lifecycle event is recorded into the
        EchoLedger scope partition journal (atomically ordered with the Echo
        run it belongs to).  Sink failures propagate: the approval flow fails
        closed rather than proceeding on the derived JSONL mirror alone.
        """
        self._echo_event_sink = sink

    def set_echo_authority(self, authority: ApprovalEchoAuthority) -> None:
        """Install the typed, sealed Echo authority for atomic claims.

        Set-once: a second call raises ``RuntimeError``.  Once installed,
        ``consume_approved_binding`` uses the authority's atomic
        ``claim_once`` instead of trusting the local mirror.
        """
        if self._echo_authority_sealed:
            raise RuntimeError("echo authority is already sealed")
        self._echo_authority = authority
        self._echo_authority_sealed = True
        authority.seal()
        # Also wire the sink for non-claim events (approve, finalize, etc.)
        if self._echo_event_sink is None:
            self._echo_event_sink = lambda event: authority.record_event(
                tenant_id=str(event.get("owner_key_hash") or "local"),
                session_id=str(event.get("session_id") or ""),
                run_id=str(event.get("run_id") or ""),
                event_type=str(event["event_type"]),
                request_id=str(event.get("request_id") or ""),
                tool_name=str(event.get("tool_name") or ""),
                arguments_hash=str(event.get("arguments_hash") or ""),
                extra={
                    k: v
                    for k, v in event.items()
                    if k not in _SINK_CORE_FIELDS and k != "timestamp"
                },
            )

    def _derive_ledger_mac_key(self) -> bytes:
        """Derive a per-installation MAC key from a secret file.

        Never hardcode the MAC key in source: an attacker with source access
        could forge ledger entries.  The key is derived from a random secret
        stored alongside the ledger (mode 0600) so each installation signs
        with a different key.

        When a persistent ledger is configured, any failure is fatal: falling
        back to an ephemeral in-memory key would split the MAC domain between
        processes and silently invalidate the chain, so we fail closed.

        Key material is opened via ``dir_fd`` + ``O_NOFOLLOW`` + ``fstat``,
        created with a random ``O_EXCL`` temp file, and published with
        ``link`` so concurrent first-init cannot observe a partial key.
        """
        if self._ledger_path is None:
            # No ledger -> ephemeral random key for this process.
            return os.urandom(32)

        parent = self._ledger_path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        key_name = ".approval_ledger_mac_key"
        secret_path = parent / key_name
        if secret_path.is_symlink():
            raise ValueError("approval ledger mac key must not be a symlink")

        nofollow = getattr(os, "O_NOFOLLOW", 0)
        dir_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | nofollow
        )
        use_dir_fd = (
            hasattr(os, "O_DIRECTORY")
            and os.open in getattr(os, "supports_dir_fd", set())
            and os.stat in getattr(os, "supports_dir_fd", set())
        )

        def _validate_and_read(fd: int) -> bytes:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("approval ledger mac key must be a regular file")
            # Existing keys must already be 0600. Never chmod-then-accept a key
            # that may have been world/group-readable (possible leak).
            mode = stat.S_IMODE(metadata.st_mode)
            if mode != 0o600:
                raise PermissionError(
                    f"approval ledger mac key permissions too open: {oct(mode)}; expected 0o600"
                )
            key = os.read(fd, 33)
            if len(key) != 32:
                raise ValueError("approval ledger mac key file is invalid: expected exact 32 bytes")
            return key

        def _create_key(dir_fd: int | None) -> None:
            key = os.urandom(32)
            tmp_name = f".{key_name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
            open_kwargs: dict[str, Any] = {}
            if dir_fd is not None:
                open_kwargs["dir_fd"] = dir_fd
            fd = os.open(
                tmp_name if dir_fd is not None else str(parent / tmp_name),
                os.O_CREAT | os.O_WRONLY | os.O_EXCL | nofollow,
                0o600,
                **open_kwargs,
            )
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, key)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                if dir_fd is not None and os.link in getattr(os, "supports_dir_fd", set()):
                    os.link(tmp_name, key_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                else:
                    os.link(str(parent / tmp_name), str(secret_path))
            except FileExistsError:
                # Another process won the race; fall through and use its key.
                pass
            finally:
                try:
                    if dir_fd is not None and os.unlink in getattr(os, "supports_dir_fd", set()):
                        os.unlink(tmp_name, dir_fd=dir_fd)
                    else:
                        (parent / tmp_name).unlink(missing_ok=True)
                except FileNotFoundError:
                    pass
            if dir_fd is not None:
                os.fsync(dir_fd)
            else:
                sync_fd = os.open(str(parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(sync_fd)
                finally:
                    os.close(sync_fd)

        dir_fd = -1
        try:
            if use_dir_fd:
                dir_fd = os.open(str(parent), dir_flags)
                dir_meta = os.fstat(dir_fd)
                if not stat.S_ISDIR(dir_meta.st_mode):
                    raise ValueError("approval ledger mac key parent must be a directory")
                try:
                    fd = os.open(key_name, os.O_RDONLY | nofollow, dir_fd=dir_fd)
                except FileNotFoundError:
                    _create_key(dir_fd)
                    fd = os.open(key_name, os.O_RDONLY | nofollow, dir_fd=dir_fd)
                try:
                    key = _validate_and_read(fd)
                finally:
                    os.close(fd)
            else:
                parent_fd = os.open(str(parent), dir_flags)
                try:
                    parent_meta = os.fstat(parent_fd)
                    if not stat.S_ISDIR(parent_meta.st_mode):
                        raise ValueError("approval ledger mac key parent must be a directory")
                finally:
                    os.close(parent_fd)
                try:
                    fd = os.open(str(secret_path), os.O_RDONLY | nofollow)
                except FileNotFoundError:
                    _create_key(None)
                    fd = os.open(str(secret_path), os.O_RDONLY | nofollow)
                except OSError as exc:
                    raise ValueError("approval ledger mac key must be a regular file") from exc
                try:
                    key = _validate_and_read(fd)
                finally:
                    os.close(fd)
        except PermissionError:
            # Unwritable ledger directory must fail closed as OSError so callers
            # never fall back to an ephemeral MAC key.
            raise
        except OSError as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            raise ValueError("approval ledger mac key must be a regular file") from exc
        finally:
            if dir_fd >= 0:
                os.close(dir_fd)

        return key

    @property
    def default_mode(self) -> ApprovalMode:
        return self._default_mode

    @default_mode.setter
    def default_mode(self, value: ApprovalMode) -> None:
        """Immutable after init — reject runtime changes for safety."""
        prev = getattr(self, "_default_mode", None)
        if prev is not None and prev != value:
            logger.error(
                "Rejected attempt to change approval default_mode from %s to %s",
                prev,
                value,
            )
            raise RuntimeError(
                f"Cannot change approval mode from {prev} to {value} at runtime. "
                "Create a new ApprovalQueue with the desired mode."
            )
        self._default_mode = value

    def _next_id(self) -> str:
        return f"approval_{uuid.uuid4().hex}"

    def _load_ledger_sequence(self) -> None:
        if self._ledger_path is None or not self._ledger_path.exists():
            return
        max_sequence = -1
        prev_hash = "0" * 64
        try:
            with self._ledger_path.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    if not raw_line.strip():
                        continue
                    try:
                        row = json.loads(raw_line)
                        sequence = int(row["seq"])
                    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                        if max_sequence < 0:
                            logger.error(
                                "Echo approval ledger first record is corrupt; failing closed"
                            )
                            raise ValueError("approval ledger first record is corrupt") from None
                        logger.warning("Ignoring invalid Echo approval ledger tail")
                        break
                    # Verify hash chain and MAC
                    expected_prev = row.get("prev_hash", "")
                    if expected_prev != prev_hash:
                        logger.error("Echo approval ledger hash chain broken at seq %d", sequence)
                        raise ValueError(f"approval ledger hash chain broken at seq {sequence}")
                    record_hash = row.get("record_hash", "")
                    mac = row.get("mac", "")
                    canonical = json.dumps(
                        {k: v for k, v in row.items() if k not in ("record_hash", "mac")},
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    ).encode("utf-8")
                    expected_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
                    if record_hash != expected_hash:
                        logger.error(
                            "Echo approval ledger record_hash mismatch at seq %d", sequence
                        )
                        raise ValueError(f"approval ledger record_hash mismatch at seq {sequence}")
                    expected_mac = hmac.new(
                        self._ledger_mac_key, canonical, hashlib.sha256
                    ).hexdigest()
                    if not hmac.compare_digest(str(mac), expected_mac):
                        logger.error("Echo approval ledger MAC mismatch at seq %d", sequence)
                        raise ValueError(f"approval ledger MAC mismatch at seq {sequence}")
                    max_sequence = max(max_sequence, sequence)
                    prev_hash = record_hash.removeprefix("sha256:")
        except OSError:
            logger.warning("Could not read Echo approval ledger", exc_info=True)
            raise
        self._ledger_seq = max_sequence + 1
        self._ledger_prev_hash = prev_hash

    def _store_resolved_decision(
        self,
        decision: ApprovalDecision,
        request: ApprovalRequest,
    ) -> None:
        self._resolved_decisions[decision.request_id] = _ResolvedDecisionRecord(
            decision=decision,
            owner_key_hash=request.owner_key_hash,
            session_id=request.session_id or "",
            run_id=request.run_id or "",
            tool_name=request.tool_name,
            arguments_hash=self._argument_hash(request.arguments),
            requested_at=request.timestamp,
            expires_at=request.timestamp + request.timeout_seconds,
            approval_mode=request.approval_mode,
        )
        self._resolved_decisions.move_to_end(decision.request_id)
        while len(self._resolved_decisions) > 1024:
            self._resolved_decisions.popitem(last=False)

    def _record_outcome(self, approved: bool) -> None:
        with self._lock:
            self._history["total"] += 1
            if approved:
                self._history["approved"] += 1
            else:
                self._history["denied"] += 1

    @staticmethod
    def _argument_hash(arguments: dict[str, Any]) -> str:
        payload = json.dumps(arguments, ensure_ascii=False, sort_keys=True, default=str)
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def arguments_hash(cls, arguments: dict[str, Any]) -> str:
        """Return the exact safe hash used by approval binding snapshots."""

        if type(arguments) is not dict:
            raise TypeError("approval arguments must be an exact dict")
        return cls._argument_hash(arguments)

    @classmethod
    def _redact_ledger_value(cls, value: Any) -> Any:
        """Recursively scrub client-controlled ledger fields before persistence."""
        try:
            if isinstance(value, str):
                return redact_known_secrets(value)
            if isinstance(value, dict):
                return {str(key): cls._redact_ledger_value(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [cls._redact_ledger_value(item) for item in value]
            if value is None or isinstance(value, (bool, int, float)):
                return value
            return redact_known_secrets(str(value))
        except Exception:
            return "[SUPPRESSED:ledger_redaction_failed]"

    def _append_ledger(self, event_type: str, req: ApprovalRequest, **extra: Any) -> None:
        event = {
            "event_type": event_type,
            "request_id": req.id,
            "tool_name": req.tool_name,
            "context": req.context,
            "session_id": req.session_id or "",
            "run_id": req.run_id or "",
            "owner_key_hash": req.owner_key_hash or "",
            "arguments_hash": self._argument_hash(req.arguments),
            "timestamp": req.timestamp,
            "requested_at": req.timestamp,
            "expires_at": req.timestamp + req.timeout_seconds,
            "approval_mode": req.approval_mode.value,
            **extra,
        }
        event = self._redact_ledger_value(event)
        # The EchoLedger scope partition journal is the authoritative record.
        # Call it before the derived mirror so a sink failure cannot leave a
        # locally claimable approval that the authoritative journal never saw.
        if self._echo_event_sink is not None:
            self._echo_event_sink(dict(event))
        if self._ledger_path is not None:
            with self._lock:
                self._append_ledger_mirror(event)

    def _append_ledger_mirror(self, event: dict[str, Any]) -> None:
        """Append to the derived local JSONL mirror (not the system of record)."""
        assert self._ledger_path is not None
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(
            self._ledger_path,
            os.O_APPEND | os.O_CREAT | os.O_WRONLY,
            0o600,
        )
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            # Re-read the tail under the exclusive file lock so concurrent
            # ApprovalQueue instances (or processes) cannot write with a
            # stale prev_hash/seq and break the hash chain.
            seq, prev_hash = self._read_ledger_tail_locked()
            record = {
                "seq": seq,
                **event,
                "prev_hash": prev_hash,
            }
            canonical = json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
            record_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
            mac = hmac.new(self._ledger_mac_key, canonical, hashlib.sha256).hexdigest()
            record["record_hash"] = record_hash
            record["mac"] = mac
            payload = (
                json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                )
                + "\n"
            )
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
            fcntl.flock(fd, fcntl.LOCK_UN)
            self._ledger_seq = seq + 1
            self._ledger_prev_hash = record_hash.removeprefix("sha256:")
        finally:
            os.close(fd)

    def _read_ledger_tail_locked(self) -> tuple[int, str]:
        """Read the last valid record's (seq, prev_hash_for_next) under the file lock.

        Returns ``(0, "0"*64)`` when the ledger is empty or does not exist.
        Validates the hash chain of the full file on first read so a corrupt
        tail cannot silently propagate.
        """
        if self._ledger_path is None or not self._ledger_path.exists():
            return 0, "0" * 64
        prev_hash = "0" * 64
        max_seq = -1
        with self._ledger_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                if not raw_line.strip():
                    continue
                try:
                    row = json.loads(raw_line)
                    seq = int(row["seq"])
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    if max_seq < 0:
                        raise ValueError("approval ledger first record is corrupt") from None
                    break
                expected_prev = row.get("prev_hash", "")
                if expected_prev != prev_hash:
                    raise ValueError(f"approval ledger hash chain broken at seq {seq}")
                record_hash = row.get("record_hash", "")
                canonical = json.dumps(
                    {k: v for k, v in row.items() if k not in ("record_hash", "mac")},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8")
                expected_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
                if record_hash != expected_hash:
                    raise ValueError(f"approval ledger record_hash mismatch at seq {seq}")
                expected_mac = hmac.new(self._ledger_mac_key, canonical, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(str(row.get("mac", "")), expected_mac):
                    raise ValueError(f"approval ledger MAC mismatch at seq {seq}")
                max_seq = max(max_seq, seq)
                prev_hash = record_hash.removeprefix("sha256:")
        return (max_seq + 1) if max_seq >= 0 else 0, prev_hash

    def _verified_ledger_rows(self) -> list[dict[str, Any]]:
        """Read the complete approval mirror with exact chain/MAC validation."""

        if self._ledger_path is None or not self._ledger_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        prev_hash = "0" * 64
        expected_seq = 0
        with self._ledger_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                if not raw_line.strip():
                    continue
                try:
                    row = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    raise ValueError("approval ledger contains invalid JSON") from exc
                if type(row) is not dict or int(row.get("seq", -1)) != expected_seq:
                    raise ValueError("approval ledger sequence is invalid")
                if row.get("prev_hash") != prev_hash:
                    raise ValueError("approval ledger hash chain is invalid")
                canonical = json.dumps(
                    {key: value for key, value in row.items() if key not in ("record_hash", "mac")},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8")
                record_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
                if row.get("record_hash") != record_hash:
                    raise ValueError("approval ledger record hash is invalid")
                expected_mac = hmac.new(self._ledger_mac_key, canonical, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(str(row.get("mac", "")), expected_mac):
                    raise ValueError("approval ledger MAC is invalid")
                rows.append(cast("dict[str, Any]", row))
                expected_seq += 1
                prev_hash = record_hash.removeprefix("sha256:")
        return rows

    def _emit_metrics(
        self,
        tool_name: str,
        mode: ApprovalMode,
        approved: bool,
    ) -> None:
        try:
            get_metrics().approval_requests_total.labels(
                tool_name=tool_name,
                mode=mode.value,
                outcome="approved" if approved else "denied",
            ).inc()
        except Exception:
            logger.warning("Failed to emit approval metrics", exc_info=True)

    def _audit_log(
        self,
        req: ApprovalRequest,
        outcome: str,
        reason: str = "",
    ) -> None:
        elapsed = time.time() - req.timestamp
        logger.info(
            "AUDIT approval_id=%s tool=%s context=%s mode=%s outcome=%s elapsed=%.2fs %s",
            req.id,
            req.tool_name,
            req.context,
            self.default_mode.value,
            outcome,
            elapsed,
            f"reason={reason}" if reason else "",
        )

    def _cleanup_stale(self) -> int:
        """Remove expired pending requests. Returns count removed."""
        removed = 0
        with self._lock:
            stale_ids = [
                req_id
                for req_id, req in self._pending.items()
                if not req.resolved and req.is_expired()
            ]
            for req_id in stale_ids:
                req = self._pending.pop(req_id)
                req.resolved = True
                req.approved = False
                req.decision = ApprovalDecision(
                    ApprovalDecisionType.REJECT,
                    request_id=req.id,
                    reason="timeout",
                )
                self._store_resolved_decision(req.decision, req)
                self._record_outcome(False)
                self._append_ledger("approval_expired", req, reason="timeout")
                self._audit_log(req, "expired", "timeout")
                self._emit_metrics(req.tool_name, self.default_mode, False)
                removed += 1
        if removed:
            logger.warning("Cleaned up %d stale approval requests", removed)
        return removed

    def set_callback(
        self,
        session_id: str,
        callback: ApprovalCallback,
        *,
        owner_key_hash: str | None = None,
        run_id: str | None = None,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        """Set a session callback bound to one exact Echo effect."""
        if not session_id:
            raise ValueError("approval callback session_id must not be empty")
        if not owner_key_hash or not run_id or not tool_name or arguments is None:
            raise ValueError("approval callback requires a complete Echo effect binding")
        with self._lock:
            self._callbacks[session_id] = _CallbackRegistration(
                callback=callback,
                owner_key_hash=owner_key_hash,
                run_id=run_id,
                tool_name=tool_name,
                arguments_hash=(self._argument_hash(arguments) if arguments is not None else None),
            )

    def remove_callback(self, session_id: str) -> None:
        """Remove a session callback."""
        with self._lock:
            self._callbacks.pop(session_id, None)

    def revoke_for_session(
        self,
        *,
        owner_key_hash: str,
        session_id: str,
        reason: str = "session_revoked",
    ) -> tuple[str, ...]:
        """Reject pending approvals bound to one verified owner/session.

        AppShell mode changes call this beside capability-lease revocation so
        a decision queued in the departing mode cannot be approved after the
        browser reconnects to a different runtime.
        """
        if not owner_key_hash or not session_id:
            raise ValueError("approval revocation requires owner_key_hash and session_id")
        revoked: list[ApprovalRequest] = []
        with self._lock:
            for request_id, request in tuple(self._pending.items()):
                if request.resolved or request.session_id != session_id:
                    continue
                if not _secure_str_eq(request.owner_key_hash, owner_key_hash):
                    continue
                decision = ApprovalDecision(
                    ApprovalDecisionType.REJECT,
                    request_id=request.id,
                    reason=reason,
                )
                request.resolved = True
                request.approved = False
                request.decision = decision
                self._pending.pop(request_id, None)
                self._store_resolved_decision(decision, request)
                revoked.append(request)

            registration = self._callbacks.get(session_id)
            if registration is not None and _secure_str_eq(
                registration.owner_key_hash,
                owner_key_hash,
            ):
                self._callbacks.pop(session_id, None)

        for request in revoked:
            self._record_outcome(False)
            self._emit_metrics(request.tool_name, self.default_mode, False)
            self._append_ledger("approval_rejected", request, reason=reason)
            self._audit_log(request, "denied", reason)
        return tuple(request.id for request in revoked)

    def request(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: str = "cli",
        mode: ApprovalMode | None = None,
        session_id: str | None = None,
        timeout_seconds: float | None = None,
    ) -> bool:
        """Request approval for a dangerous operation. Returns True if approved."""
        decision = self.request_decision(
            tool_name=tool_name,
            arguments=arguments,
            context=context,
            mode=mode,
            session_id=session_id,
            timeout_seconds=timeout_seconds,
            queue_if_unhandled=False,
        )
        return decision.approved

    def request_decision(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: str = "cli",
        mode: ApprovalMode | None = None,
        session_id: str | None = None,
        timeout_seconds: float | None = None,
        *,
        run_id: str | None = None,
        owner_key_hash: str | None = None,
        queue_if_unhandled: bool = False,
    ) -> ApprovalDecision:
        """Request an Echo approval decision for a dangerous operation."""
        # Periodic cleanup of stale requests
        self._cleanup_stale()

        resolved_mode = mode or self.default_mode

        if resolved_mode == ApprovalMode.AUTO_APPROVE:
            auto_req = ApprovalRequest(
                id=self._next_id(),
                tool_name=tool_name,
                arguments=arguments,
                timestamp=time.time(),
                context=context,
                timeout_seconds=timeout_seconds or self._default_timeout,
                session_id=session_id,
                run_id=run_id,
                owner_key_hash=owner_key_hash,
                approval_mode=resolved_mode,
            )
            # AUTO_APPROVE must still honor an existing session callback binding
            # so a cross-owner / cross-run request cannot skip the Echo gate.
            if session_id:
                with self._lock:
                    registration = self._callbacks.get(session_id)
                if registration is not None:
                    binding_mismatch = any(
                        (
                            registration.owner_key_hash is not None
                            and not _secure_str_eq(
                                registration.owner_key_hash, auto_req.owner_key_hash
                            ),
                            registration.run_id is not None
                            and not _secure_str_eq(registration.run_id, auto_req.run_id),
                            registration.tool_name is not None
                            and registration.tool_name != auto_req.tool_name,
                            registration.arguments_hash is not None
                            and registration.arguments_hash
                            != self._argument_hash(auto_req.arguments),
                        )
                    )
                    if binding_mismatch:
                        logger.warning(
                            "Auto-approve denied %s due to session binding mismatch",
                            tool_name,
                        )
                        self._record_outcome(False)
                        self._emit_metrics(tool_name, resolved_mode, False)
                        self._append_ledger("approval_requested", auto_req)
                        self._append_ledger(
                            "approval_rejected",
                            auto_req,
                            reason="auto_approve_binding_mismatch",
                        )
                        self._audit_log(auto_req, "denied", "auto_approve_binding_mismatch")
                        return ApprovalDecision(
                            ApprovalDecisionType.REJECT,
                            request_id=auto_req.id,
                            reason="auto_approve_binding_mismatch",
                        )
            logger.info("Auto-approved %s (auto_approve mode)", tool_name)
            self._record_outcome(True)
            self._emit_metrics(tool_name, resolved_mode, True)
            self._append_ledger("approval_requested", auto_req)
            self._append_ledger("approval_approved", auto_req, reason="auto_approve")
            self._audit_log(auto_req, "approved", "auto_approve")
            return ApprovalDecision(
                ApprovalDecisionType.APPROVE,
                request_id=auto_req.id,
                reason="auto_approve",
            )

        if resolved_mode == ApprovalMode.AUTO_DENY:
            logger.warning("Auto-denied %s (auto_deny mode)", tool_name)
            self._record_outcome(False)
            self._emit_metrics(tool_name, resolved_mode, False)
            auto_req = ApprovalRequest(
                id=self._next_id(),
                tool_name=tool_name,
                arguments=arguments,
                timestamp=time.time(),
                context=context,
                timeout_seconds=timeout_seconds or self._default_timeout,
                session_id=session_id,
                run_id=run_id,
                owner_key_hash=owner_key_hash,
                approval_mode=resolved_mode,
            )
            self._append_ledger("approval_requested", auto_req)
            self._append_ledger("approval_rejected", auto_req, reason="auto_deny")
            self._audit_log(auto_req, "denied", "auto_deny")
            return ApprovalDecision(
                ApprovalDecisionType.REJECT,
                request_id=auto_req.id,
                reason="auto_deny",
            )

        if resolved_mode == ApprovalMode.CRON_DENY and context == "cron":
            logger.warning("Auto-denied %s (cron_deny mode)", tool_name)
            self._record_outcome(False)
            self._emit_metrics(tool_name, resolved_mode, False)
            auto_req = ApprovalRequest(
                id=self._next_id(),
                tool_name=tool_name,
                arguments=arguments,
                timestamp=time.time(),
                context=context,
                timeout_seconds=timeout_seconds or self._default_timeout,
                session_id=session_id,
                run_id=run_id,
                owner_key_hash=owner_key_hash,
                approval_mode=resolved_mode,
            )
            self._append_ledger("approval_requested", auto_req)
            self._append_ledger("approval_rejected", auto_req, reason="cron_deny")
            self._audit_log(auto_req, "denied", "cron_deny")
            return ApprovalDecision(
                ApprovalDecisionType.REJECT,
                request_id=auto_req.id,
                reason="cron_deny",
            )

        # MANUAL mode: check for callback or block
        req = ApprovalRequest(
            id=self._next_id(),
            tool_name=tool_name,
            arguments=arguments,
            timestamp=time.time(),
            context=context,
            timeout_seconds=timeout_seconds or self._default_timeout,
            session_id=session_id,
            run_id=run_id,
            owner_key_hash=owner_key_hash,
            approval_mode=resolved_mode,
        )

        with self._lock:
            self._pending[req.id] = req
        self._append_ledger("approval_requested", req)

        # Try session callback first (lookup under lock to avoid TOCTOU)
        callback: ApprovalCallback | None = None
        callback_binding_mismatch = False
        if session_id:
            with self._lock:
                registration = self._callbacks.get(session_id)
            if registration is not None:
                callback_binding_mismatch = any(
                    (
                        (
                            registration.owner_key_hash is not None
                            and not _secure_str_eq(registration.owner_key_hash, req.owner_key_hash)
                        ),
                        (registration.run_id is not None and registration.run_id != req.run_id),
                        (
                            registration.tool_name is not None
                            and registration.tool_name != req.tool_name
                        ),
                        (
                            registration.arguments_hash is not None
                            and registration.arguments_hash != self._argument_hash(req.arguments)
                        ),
                    ),
                )
                if not callback_binding_mismatch:
                    callback = registration.callback

        if callback:
            try:
                callback_result = callback(req)
                if isinstance(callback_result, ApprovalDecision):
                    decision = callback_result
                else:
                    decision = ApprovalDecision(
                        ApprovalDecisionType.APPROVE
                        if bool(callback_result)
                        else ApprovalDecisionType.REJECT,
                        request_id=req.id,
                        reason="callback",
                    )
                approved = decision.approved
                event_type = (
                    "approval_edited"
                    if decision.action == ApprovalDecisionType.EDIT
                    else "approval_approved"
                    if approved
                    else "approval_rejected"
                )
                self._append_ledger(event_type, req, reason=decision.reason)
                with self._lock:
                    req.resolved = True
                    req.approved = approved
                    req.decision = decision
                    self._store_resolved_decision(decision, req)
                    self._pending.pop(req.id, None)
                self._record_outcome(approved)
                self._emit_metrics(tool_name, resolved_mode, approved)
                self._audit_log(req, "approved" if approved else "denied", "callback")
                return decision
            except Exception as e:
                logger.error("Approval callback failed: %s", e)

        # CLI fallback: synchronous prompt
        if context == "cli":
            approved = self._cli_prompt(req)
            decision = ApprovalDecision(
                ApprovalDecisionType.APPROVE if approved else ApprovalDecisionType.REJECT,
                request_id=req.id,
                reason="cli_prompt",
            )
            req.decision = decision
            self._append_ledger(
                "approval_approved" if approved else "approval_rejected",
                req,
                reason="cli_prompt",
            )
            self._record_outcome(approved)
            with self._lock:
                self._store_resolved_decision(decision, req)
                self._pending.pop(req.id, None)
            self._emit_metrics(tool_name, resolved_mode, approved)
            self._audit_log(req, "approved" if approved else "denied", "cli_prompt")
            return decision

        if queue_if_unhandled:
            logger.info(
                "Queued approval request %s for %s (context=%s)",
                req.id,
                tool_name,
                context,
            )
            return ApprovalDecision(
                ApprovalDecisionType.PENDING,
                request_id=req.id,
                reason=("callback_binding_mismatch" if callback_binding_mismatch else ""),
            )

        # Unknown context (not cli, not cron, not web): deny for safety.
        # This closes the "or 'cli'" fallback gap — when _run_context is
        # not properly set, operations are denied instead of silently
        # treated as interactive.
        logger.warning(
            "No approval handler for %s (context=%s), defaulting to deny",
            tool_name,
            context,
        )
        req.resolved = True
        req.approved = False
        req.decision = ApprovalDecision(
            ApprovalDecisionType.REJECT,
            request_id=req.id,
            reason="no_handler",
        )
        self._record_outcome(False)
        with self._lock:
            self._pending.pop(req.id, None)
        self._emit_metrics(tool_name, resolved_mode, False)
        self._append_ledger("approval_rejected", req, reason="no_handler")
        self._audit_log(req, "denied", "no_handler")
        return req.decision

    def _cli_prompt(self, req: ApprovalRequest) -> bool:
        """Synchronous CLI prompt for approval."""
        try:
            from js.security.approval_display import sanitize_approval_display

            card = sanitize_approval_display(
                tool_name=req.tool_name,
                arguments=req.arguments,
            )
            prompt_text = f"\n[Approval] {card}\nApprove? [y/N]: "
            response = self._input_stream(prompt_text).strip().lower()
            approved = response in ("y", "yes")
            req.resolved = True
            req.approved = approved
            return approved
        except (EOFError, KeyboardInterrupt):
            req.resolved = True
            req.approved = False
            return False

    def resolve(self, request_id: str, approved: bool) -> bool:
        """Resolve a pending approval request (e.g., from the desktop Host)."""
        decision = self.decide(
            request_id,
            ApprovalDecisionType.APPROVE if approved else ApprovalDecisionType.REJECT,
            reason="resolved",
        )
        return decision.action != ApprovalDecisionType.PENDING

    def decide(
        self,
        request_id: str,
        action: ApprovalDecisionType,
        *,
        edited_arguments: dict[str, Any] | None = None,
        response: str = "",
        reason: str = "",
        owner_key_hash: str | None = None,
    ) -> ApprovalDecision:
        """Resolve a pending Echo approval with approve/edit/reject/respond."""
        if action == ApprovalDecisionType.PENDING:
            raise ValueError("pending is not a resolution action")
        with self._lock:
            req = self._pending.get(request_id)
            if req and not req.resolved:
                # 校验 owner：跨 owner decide 返回 PENDING
                if owner_key_hash is not None and not _secure_str_eq(
                    req.owner_key_hash, owner_key_hash
                ):
                    return ApprovalDecision(ApprovalDecisionType.PENDING, request_id=request_id)
                # Reject resolution of expired requests
                if req.is_expired():
                    logger.warning("Attempted to resolve expired approval request %s", request_id)
                    decision = ApprovalDecision(
                        ApprovalDecisionType.REJECT,
                        request_id=req.id,
                        reason="late_resolution",
                    )
                    self._append_ledger("approval_expired", req, reason="late_resolution")
                    req.resolved = True
                    req.approved = False
                    req.decision = decision
                    self._store_resolved_decision(decision, req)
                    self._record_outcome(False)
                    self._pending.pop(request_id, None)
                    self._audit_log(req, "expired", "late_resolution")
                    self._emit_metrics(req.tool_name, self.default_mode, False)
                    return decision
                approved = action in {
                    ApprovalDecisionType.APPROVE,
                    ApprovalDecisionType.EDIT,
                }
                if action == ApprovalDecisionType.EDIT and not isinstance(edited_arguments, dict):
                    raise ValueError("edited_arguments are required for edit approval")
                if action == ApprovalDecisionType.RESPOND and not response:
                    raise ValueError("response is required for respond approval")
                decision = ApprovalDecision(
                    action,
                    request_id=request_id,
                    edited_arguments=edited_arguments,
                    response=response,
                    reason=reason,
                )
                event_type = {
                    ApprovalDecisionType.APPROVE: "approval_approved",
                    ApprovalDecisionType.EDIT: "approval_edited",
                    ApprovalDecisionType.REJECT: "approval_rejected",
                    ApprovalDecisionType.RESPOND: "approval_responded",
                }[action]
                # Persist both authoritative event and durable exact snapshot
                # before removing the pending record. Sink/ledger failure leaves
                # the request pending and therefore cannot authorize execution.
                self._append_ledger(event_type, req, reason=reason)
                req.resolved = True
                req.approved = approved
                req.decision = decision
                self._store_resolved_decision(decision, req)
                self._record_outcome(approved)
                self._pending.pop(request_id, None)
                self._emit_metrics(req.tool_name, self.default_mode, approved)
                self._audit_log(req, "approved" if approved else "denied", "resolved")
                return decision
        return ApprovalDecision(ApprovalDecisionType.PENDING, request_id=request_id)

    def get_pending(
        self,
        *,
        owner_key_hash: str | None = None,
    ) -> list[ApprovalRequest]:
        """Get all unresolved approval requests."""
        self._cleanup_stale()
        with self._lock:
            return [
                request
                for request in self._pending.values()
                if not request.resolved
                and (
                    owner_key_hash is None or _secure_str_eq(request.owner_key_hash, owner_key_hash)
                )
            ]

    def get_pending_request(
        self,
        request_id: str,
        *,
        owner_key_hash: str | None = None,
    ) -> ApprovalRequest | None:
        self._cleanup_stale()
        with self._lock:
            request = self._pending.get(request_id)
            if request is None or request.resolved:
                return None
            if owner_key_hash is not None and not _secure_str_eq(
                request.owner_key_hash, owner_key_hash
            ):
                return None
            return request

    def pending_arguments_hash(
        self,
        request_id: str,
        *,
        owner_key_hash: str,
    ) -> str:
        """Return the canonical argument hash for one exact pending request.

        This is a read-only projection accessor.  It never returns arguments
        and refuses a request that is no longer pending or belongs to another
        owner.
        """
        request = self.get_pending_request(
            request_id,
            owner_key_hash=owner_key_hash,
        )
        if request is None:
            raise KeyError("pending approval request is unavailable")
        return self._argument_hash(request.arguments)

    @contextmanager
    def _approval_claim_transaction(self) -> Iterator[None]:
        """Serialize approval preflight/claim across queue instances and processes."""

        if self._ledger_path is None:
            yield
            return
        lock_path = self._ledger_path.with_suffix(self._ledger_path.suffix + ".claim.lock")
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def _durable_resolved_record(self, request_id: str) -> _ResolvedDecisionRecord | None:
        record: _ResolvedDecisionRecord | None = None
        for row in self._verified_ledger_rows():
            if row.get("request_id") != request_id:
                continue
            event_type = str(row.get("event_type", ""))
            if event_type == "approval_approved":
                try:
                    approval_mode = ApprovalMode(str(row["approval_mode"]))
                    requested_at = float(row["requested_at"])
                    expires_at = float(row["expires_at"])
                    owner_key_hash = str(row["owner_key_hash"])
                    session_id = str(row["session_id"])
                    run_id = str(row["run_id"])
                    tool_name = str(row["tool_name"])
                    arguments_hash = str(row["arguments_hash"])
                except (KeyError, TypeError, ValueError):
                    # Pre-R4 approval rows do not have the complete immutable
                    # snapshot and therefore require fresh manual approval.
                    record = None
                    continue
                record = _ResolvedDecisionRecord(
                    decision=ApprovalDecision(
                        ApprovalDecisionType.APPROVE,
                        request_id=request_id,
                    ),
                    owner_key_hash=owner_key_hash,
                    session_id=session_id,
                    run_id=run_id,
                    tool_name=tool_name,
                    arguments_hash=arguments_hash,
                    requested_at=requested_at,
                    expires_at=expires_at,
                    approval_mode=approval_mode,
                )
            elif event_type in {
                "approval_edited",
                "approval_rejected",
                "approval_responded",
                "approval_expired",
                "approval_execution_claimed",
            }:
                record = None
        # If mirror has no claim but Echo authority is available, check Echo
        # for a durable claim.  This detects mirror truncation.
        if record is not None and self._echo_authority is not None:
            echo_claim = self._echo_authority.lookup_claim(
                tenant_id=record.owner_key_hash or "",
                session_id=record.session_id,
                request_id=request_id,
            )
            if echo_claim is not None:
                # Echo has a claim that mirror is missing -> rebuild consumed
                return None
        return record

    def _resolved_record_for_claim(self, request_id: str) -> _ResolvedDecisionRecord | None:
        if self._ledger_path is not None:
            return self._durable_resolved_record(request_id)
        return self._resolved_decisions.get(request_id)

    @staticmethod
    def _validate_approved_record(
        record: _ResolvedDecisionRecord | None,
        *,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
        tool_name: str,
        arguments_hash: str,
        require_manual: bool,
    ) -> _ResolvedDecisionRecord:
        matches = record is not None and all(
            (
                record.decision.action is ApprovalDecisionType.APPROVE,
                _secure_str_eq(record.owner_key_hash, owner_key_hash),
                _secure_str_eq(record.session_id, session_id),
                _secure_str_eq(record.run_id, run_id),
                record.tool_name == tool_name,
                _secure_str_eq(record.arguments_hash, arguments_hash),
                not require_manual or record.approval_mode is ApprovalMode.MANUAL,
                time.time() <= record.expires_at,
            )
        )
        if not matches or record is None:
            raise PermissionError("approved binding is unavailable or does not match")
        return record

    def validate_approved_binding(
        self,
        request_id: str,
        *,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
        tool_name: str,
        arguments_hash: str,
        require_manual: bool,
    ) -> ApprovalDecision:
        """Read-only preflight for one exact resolved approval snapshot."""

        with self._lock, self._approval_claim_transaction():
            record = self._validate_approved_record(
                self._resolved_record_for_claim(request_id),
                owner_key_hash=owner_key_hash,
                session_id=session_id,
                run_id=run_id,
                tool_name=tool_name,
                arguments_hash=arguments_hash,
                require_manual=require_manual,
            )
            return record.decision

    def consume_approved_binding(
        self,
        request_id: str,
        *,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
        tool_name: str,
        arguments_hash: str,
        require_manual: bool,
    ) -> ApprovalDecision:
        """Durably claim one exact manual approval at most once.

        When an :class:`ApprovalEchoAuthority` is installed, the claim is
        performed atomically in the Echo journal's cross-process lock
        (``claim_once``).  The local mirror is updated only as a cache;
        mirror failure is non-fatal.  If the Echo authority is unavailable,
        the claim fails closed and does NOT fall back to mirror-only trust.

        Without an Echo authority (legacy/test mode), falls back to the
        mirror-based claim with cross-process file lock.
        """

        with self._lock, self._approval_claim_transaction():
            record = self._validate_approved_record(
                self._resolved_record_for_claim(request_id),
                owner_key_hash=owner_key_hash,
                session_id=session_id,
                run_id=run_id,
                tool_name=tool_name,
                arguments_hash=arguments_hash,
                require_manual=require_manual,
            )

            # --- Echo authority path (production) ---
            if self._echo_authority is not None:
                self._echo_authority.claim_once(
                    tenant_id=record.owner_key_hash or "",
                    session_id=record.session_id,
                    run_id=record.run_id,
                    request_id=request_id,
                    tool_name=record.tool_name,
                    arguments_hash=record.arguments_hash,
                    approval_mode=record.approval_mode.value,
                    expires_at=record.expires_at,
                    requested_at=record.requested_at,
                )
                # receipt.claimed_now == False means already claimed (idempotent
                # recovery).  Either way, the binding is consumed; we must NOT
                # re-authorize execution from an already_claimed receipt.
                # Mirror is cache-only:
                event = self._redact_ledger_value(
                    {
                        "event_type": "approval_execution_claimed",
                        "request_id": request_id,
                        "tool_name": record.tool_name,
                        "context": "runtime",
                        "session_id": record.session_id,
                        "run_id": record.run_id,
                        "owner_key_hash": record.owner_key_hash or "",
                        "arguments_hash": record.arguments_hash,
                        "timestamp": time.time(),
                        "requested_at": record.requested_at,
                        "expires_at": record.expires_at,
                        "approval_mode": record.approval_mode.value,
                    }
                )
                if self._ledger_path is not None:
                    try:
                        self._append_ledger_mirror(cast("dict[str, Any]", event))
                    except Exception:
                        pass  # mirror failure is non-fatal; Echo is authoritative
                self._resolved_decisions.pop(request_id, None)
                return record.decision

            # --- Legacy mirror-only path (test/no-Echo mode) ---
            event = self._redact_ledger_value(
                {
                    "event_type": "approval_execution_claimed",
                    "request_id": request_id,
                    "tool_name": record.tool_name,
                    "context": "runtime",
                    "session_id": record.session_id,
                    "run_id": record.run_id,
                    "owner_key_hash": record.owner_key_hash or "",
                    "arguments_hash": record.arguments_hash,
                    "timestamp": time.time(),
                    "requested_at": record.requested_at,
                    "expires_at": record.expires_at,
                    "approval_mode": record.approval_mode.value,
                }
            )
            if self._ledger_path is not None:
                self._append_ledger_mirror(cast("dict[str, Any]", event))
            if self._echo_event_sink is not None:
                self._echo_event_sink(cast("dict[str, Any]", dict(event)))
            self._resolved_decisions.pop(request_id, None)
            return record.decision

    def take_decision(
        self,
        request_id: str,
        *,
        owner_key_hash: str | None = None,
    ) -> ApprovalDecision | None:
        """Consume one externally resolved decision exactly once."""
        with self._lock:
            record = self._resolved_decisions.get(request_id)
            if record is None:
                return None
            if owner_key_hash is not None and not _secure_str_eq(
                record.owner_key_hash, owner_key_hash
            ):
                return None
            self._resolved_decisions.pop(request_id, None)
            return record.decision

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            pending_count = sum(1 for r in self._pending.values() if not r.resolved)
            return {
                "total_requests": self._history["total"],
                "resolved": self._history["approved"] + self._history["denied"],
                "approved": self._history["approved"],
                "denied": self._history["denied"],
                "pending": pending_count,
            }


# Fields consumed by the sink itself; everything else is forwarded as extra
# payload for the authoritative EchoLedger approval record.
_SINK_CORE_FIELDS = frozenset(
    {
        "event_type",
        "request_id",
        "tool_name",
        "session_id",
        "run_id",
        "owner_key_hash",
        "arguments_hash",
    }
)


def wire_echo_approval_sink(
    service: Any,
    *,
    product_id: str,
) -> Callable[[dict[str, Any]], None]:
    """Bind an ApprovalQueue to the authoritative EchoLedger.

    The returned sink records every approval lifecycle event into the Echo
    scope partition journal (``EchoSafetyService.record_approval_event``), so
    approval state is atomically ordered with the Echo run it belongs to.
    The queue's local JSONL file remains only a derived mirror.
    """

    def _sink(event: dict[str, Any]) -> None:
        service.record_approval_event(
            tenant_id=str(event.get("owner_key_hash") or "local"),
            product_id=product_id,
            session_id=str(event.get("session_id") or ""),
            run_id=str(event.get("run_id") or ""),
            event_type=str(event["event_type"]),
            request_id=str(event.get("request_id") or ""),
            tool_name=str(event.get("tool_name") or ""),
            arguments_hash=str(event.get("arguments_hash") or ""),
            extra={
                key: value
                for key, value in event.items()
                if key not in _SINK_CORE_FIELDS and key != "timestamp"
            },
        )

    return _sink


def wire_echo_approval_authority(
    service: Any,
    *,
    product_id: str,
) -> ApprovalEchoAuthority:
    """Create a typed, sealed ``ApprovalEchoAuthority`` for an ApprovalQueue.

    The authority provides atomic ``claim_once`` and ``lookup_claim``
    operations backed by the Echo journal's cross-process lock.
    """

    return ApprovalEchoAuthority(service, product_id=product_id)

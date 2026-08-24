"""WP-C1 local Cell identity primitives.

These helpers are used only by the explicit C1 identity harness.  Stage A/B
keeps its frozen handshake and filesystem behavior while the switch is lazy.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from struct import unpack
from typing import Any

from js.orin.protocol import CELL_CONNECT_CAPS, ProtocolError
from js.orind.private_paths import (
    PrivatePathError,
    read_once_private_file,
    verify_private_socket,
)

SOL_LOCAL = 0
LOCAL_PEERCRED = 1
LOCAL_PEERTOKEN = 2

CELL_IDENTITY_ENV = "ORIN_CELL_IDENTITY_ENFORCE"
ORIND_PID_ENV = "ORIN_ORIND_PID"
LAUNCH_TICKETS_ENV = "ORIN_CELL_LAUNCH_TICKETS"
_TICKET_RE = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True)
class SocketIdentity:
    """Pinned identity of one owned 0600 Unix-domain socket node."""

    device: int
    inode: int


def peer_credentials(sock: Any) -> tuple[int, int] | None:
    """Return the connected peer's effective uid and PID, fail-closed.

    This deliberately mirrors the daemon's established macOS/Linux probes so
    the Cell can authenticate orind in the opposite direction without
    importing the daemon (which would create a Cell/authority dependency).
    """

    if sys.platform == "darwin":
        euid: int | None = None
        pid: int | None = None
        with contextlib.suppress(OSError):
            token = sock.getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN, 32)
            if len(token) >= 32:
                values = [
                    int.from_bytes(token[index : index + 4], "little")
                    for index in range(0, 32, 4)
                ]
                euid = values[1]
                pid = values[5]
            elif len(token) >= 4:
                pid = int.from_bytes(token[:4], "little")
        with contextlib.suppress(OSError):
            cred = sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, 12)
            if len(cred) >= 12:
                raw_pid, uid, _gid = unpack("iii", cred)
                if euid is None:
                    euid = int(uid)
                if not pid:
                    pid = int(raw_pid) or pid
        if euid is None:
            return None
        return euid, pid or 0
    if sys.platform.startswith("linux"):
        with contextlib.suppress(OSError):
            cred = sock.getsockopt(socket.SOL_SOCKET, LOCAL_PEERCRED, 12)
            if len(cred) >= 12:
                pid, uid, _gid = unpack("iii", cred)
                return int(uid), int(pid)
    return None


def verify_owned_socket(path: Path) -> SocketIdentity:
    """Verify a Cell socket through a no-symlink parent descriptor."""

    try:
        identity = verify_private_socket(path)
    except PrivatePathError as exc:
        raise ProtocolError("Cell socket path is unavailable") from exc
    return SocketIdentity(identity.dev, identity.ino)


def require_same_socket(path: Path, expected: SocketIdentity) -> None:
    current = verify_owned_socket(path)
    if current != expected:
        raise ProtocolError("Cell socket path was replaced")


def load_cell_launch_identity(cap: str) -> tuple[int, str]:
    """Parse the daemon PID and per-cap one-shot launch ticket from env."""

    raw_pid = os.environ.get(ORIND_PID_ENV, "")
    try:
        daemon_pid = int(raw_pid)
    except ValueError as exc:
        raise ProtocolError("Cell launch is missing the orind PID") from exc
    if daemon_pid <= 0:
        raise ProtocolError("Cell launch has an invalid orind PID")

    raw_tickets = os.environ.get(LAUNCH_TICKETS_ENV, "")
    if not raw_tickets or len(raw_tickets) > 4096:
        raise ProtocolError("Cell launch tickets are missing")
    try:
        parsed = json.loads(raw_tickets)
    except json.JSONDecodeError as exc:
        raise ProtocolError("Cell launch tickets are malformed") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise ProtocolError("Cell launch tickets are malformed")
    if any(
        not isinstance(key, str)
        or key not in CELL_CONNECT_CAPS
        or not isinstance(value, str)
        or _TICKET_RE.fullmatch(value) is None
        for key, value in parsed.items()
    ):
        raise ProtocolError("Cell launch tickets are malformed")
    if len(set(parsed.values())) != len(parsed):
        raise ProtocolError("Cell launch tickets must be unique")
    ticket = parsed.get(cap)
    if not isinstance(ticket, str):
        raise ProtocolError("Cell cap has no launch ticket")
    return daemon_pid, ticket


def read_session_key_once(path: Path) -> bytes:
    """Read and consume a strict 32-byte session key without following links."""

    try:
        path.lstat()
    except OSError as exc:
        raise ProtocolError("Cell session key is unavailable") from exc
    try:
        key = read_once_private_file(path, max_bytes=32)
    except PrivatePathError as exc:
        raise ProtocolError("Cell session key violates the private-file contract") from exc
    if len(key) != 32:
        raise ProtocolError("Cell session key must be exactly 32 bytes")
    return key


__all__ = [
    "CELL_IDENTITY_ENV",
    "LAUNCH_TICKETS_ENV",
    "ORIND_PID_ENV",
    "SocketIdentity",
    "load_cell_launch_identity",
    "peer_credentials",
    "read_session_key_once",
    "require_same_socket",
    "verify_owned_socket",
]

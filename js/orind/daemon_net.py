"""Peer-credential and rate-limit helpers for OrinDaemon."""

from __future__ import annotations

import contextlib
import socket
import sys
import time

from js.orin.protocol import RATE_LIMIT_BURST, RATE_LIMIT_PER_SECOND

SOL_LOCAL = 0
LOCAL_PEERCRED = 1
LOCAL_PEERTOKEN = 2


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

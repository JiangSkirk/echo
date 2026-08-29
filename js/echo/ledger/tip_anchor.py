"""External tip-anchor backends.

v1 resists a state_dir-only rewind: the monotonic counter lives outside the
journal directory (macOS Keychain, or a caller-supplied sibling path).

This is not TPM, not remote notarization, and not a defense against root or
a compromised Keychain/anchor directory.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from js.echo.ledger.tip_seal import TipSealError

_SERVICE = "js.echo.tip-anchor"
_ACCOUNT_PREFIX = "echo-tip:"


_MAX_SEEN_MACS = 32


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    counter: int
    tip_mac: str
    seen_macs: tuple[str, ...] = ()


class AnchorBackend(Protocol):
    def read(self, name: str) -> AnchorRecord | None: ...

    def commit(
        self,
        name: str,
        *,
        counter: int,
        tip_mac: str,
        seen_macs: tuple[str, ...] = (),
    ) -> None: ...


class FileAnchorBackend:
    """JSON file that must live *outside* the journal directory."""

    def __init__(self, path: Path, *, journal_dir: Path) -> None:
        resolved = path.expanduser().resolve()
        journal = journal_dir.expanduser().resolve()
        if resolved == journal or journal in resolved.parents:
            raise TipSealError("file tip anchor must not live under the journal directory")
        self._path = resolved

    def read(self, name: str) -> AnchorRecord | None:
        if not self._path.exists():
            return None
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise TipSealError("file tip anchor is not an object")
        row = raw.get(name)
        if row is None:
            return None
        if not isinstance(row, dict):
            raise TipSealError("file tip anchor row is invalid")
        try:
            seen_raw = row.get("seen_macs") or ()
            seen = tuple(str(item) for item in seen_raw) if isinstance(seen_raw, list) else ()
            return AnchorRecord(
                counter=int(row["counter"]),
                tip_mac=str(row["tip_mac"]),
                seen_macs=seen,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TipSealError("file tip anchor fields are invalid") from exc

    def commit(
        self,
        name: str,
        *,
        counter: int,
        tip_mac: str,
        seen_macs: tuple[str, ...] = (),
    ) -> None:
        payload: dict[str, object] = {}
        if self._path.exists():
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                payload = raw
        payload[name] = {
            "counter": int(counter),
            "tip_mac": str(tip_mac),
            "seen_macs": list(seen_macs[-_MAX_SEEN_MACS:]),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(encoded + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if fd >= 0:
                os.close(fd)


class KeychainAnchorBackend:
    """macOS Keychain generic-password slot. Not an official TCC claim."""

    def read(self, name: str) -> AnchorRecord | None:
        try:
            completed = subprocess.run(
                [
                    "security",
                    "find-generic-password",
                    "-s",
                    _SERVICE,
                    "-a",
                    _ACCOUNT_PREFIX + name,
                    "-w",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TipSealError("keychain tip anchor is unavailable") from exc
        if completed.returncode != 0:
            return None
        raw = json.loads(completed.stdout.strip() or "{}")
        if not isinstance(raw, dict):
            raise TipSealError("keychain tip anchor is not an object")
        try:
            seen_raw = raw.get("seen_macs") or ()
            seen = tuple(str(item) for item in seen_raw) if isinstance(seen_raw, list) else ()
            return AnchorRecord(
                counter=int(raw["counter"]),
                tip_mac=str(raw["tip_mac"]),
                seen_macs=seen,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TipSealError("keychain tip anchor fields are invalid") from exc

    def commit(
        self,
        name: str,
        *,
        counter: int,
        tip_mac: str,
        seen_macs: tuple[str, ...] = (),
    ) -> None:
        body = json.dumps(
            {
                "counter": int(counter),
                "tip_mac": str(tip_mac),
                "seen_macs": list(seen_macs[-_MAX_SEEN_MACS:]),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        account = _ACCOUNT_PREFIX + name
        try:
            subprocess.run(
                ["security", "delete-generic-password", "-s", _SERVICE, "-a", account],
                check=False,
                capture_output=True,
                timeout=5,
            )
            completed = subprocess.run(
                [
                    "security",
                    "add-generic-password",
                    "-s",
                    _SERVICE,
                    "-a",
                    account,
                    "-w",
                    body,
                    "-U",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TipSealError("keychain tip anchor write failed") from exc
        if completed.returncode != 0:
            raise TipSealError("keychain tip anchor write was refused")


_active: AnchorBackend | None = None


def set_tip_anchor(backend: AnchorBackend | None) -> None:
    global _active
    _active = backend


def current_tip_anchor() -> AnchorBackend | None:
    return _active


def default_tip_anchor(*, journal_dir: Path, enabled: bool) -> AnchorBackend | None:
    if not enabled:
        return None
    if platform.system() == "Darwin":
        return KeychainAnchorBackend()
    return FileAnchorBackend(
        journal_dir.expanduser().resolve().parent / ".echo-tip-anchor.json",
        journal_dir=journal_dir,
    )


def verify_or_commit_anchor(
    backend: AnchorBackend | None,
    name: str,
    *,
    counter: int,
    tip_mac: str,
) -> None:
    """Reject a rewind against the external counter. Missing slot is first-write."""

    if backend is None:
        return
    existing = backend.read(name)
    if existing is None:
        backend.commit(name, counter=counter, tip_mac=tip_mac, seen_macs=(tip_mac,))
        return
    if counter < existing.counter:
        raise TipSealError("external tip anchor rejected a rewind")
    seen = existing.seen_macs or ((existing.tip_mac,) if existing.tip_mac else ())
    if counter == existing.counter:
        if tip_mac == existing.tip_mac:
            return
        if tip_mac in seen:
            raise TipSealError("external tip anchor rejected a forged tip")
        backend.commit(
            name,
            counter=counter,
            tip_mac=tip_mac,
            seen_macs=(*seen, tip_mac)[-_MAX_SEEN_MACS:],
        )
        return
    backend.commit(
        name,
        counter=counter,
        tip_mac=tip_mac,
        seen_macs=(*seen, tip_mac)[-_MAX_SEEN_MACS:],
    )


__all__ = [
    "AnchorBackend",
    "AnchorRecord",
    "FileAnchorBackend",
    "KeychainAnchorBackend",
    "current_tip_anchor",
    "default_tip_anchor",
    "set_tip_anchor",
    "verify_or_commit_anchor",
]

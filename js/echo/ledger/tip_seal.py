"""Local monotonic tip seal.

This is a same-directory counter + tip MAC. It detects journal/lease rewind
when the attacker changes the chain but leaves the seal file alone.

It is not an external anchor. An attacker who replaces the journal and the
seal together is out of scope for this wave.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SEAL_NAME = "echo_tip_seal.json"
SEAL_DOMAIN = b"echo-local-tip-seal-v1:"


class TipSealError(ValueError):
    """Local tip seal rejected a rewind or a forged seal file."""


@dataclass(frozen=True, slots=True)
class LocalTipSeal:
    counter: int
    tip_hash: str
    lease_snapshot_hash: str
    mac: str

    def payload(self) -> dict[str, Any]:
        return {
            "version": 1,
            "counter": self.counter,
            "tip_hash": self.tip_hash,
            "lease_snapshot_hash": self.lease_snapshot_hash,
        }


def seal_path_for(target: Path) -> Path:
    return Path(target).parent / SEAL_NAME


def compute_seal_mac(
    mac_key: bytes,
    *,
    counter: int,
    tip_hash: str,
    lease_snapshot_hash: str = "",
) -> str:
    if not isinstance(mac_key, (bytes, bytearray)) or len(mac_key) < 16:
        raise TipSealError("tip seal MAC key is missing")
    body = json.dumps(
        {
            "version": 1,
            "counter": int(counter),
            "tip_hash": str(tip_hash),
            "lease_snapshot_hash": str(lease_snapshot_hash),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(bytes(mac_key), SEAL_DOMAIN + body, hashlib.sha256).hexdigest()


def build_seal(
    mac_key: bytes,
    *,
    counter: int,
    tip_hash: str,
    lease_snapshot_hash: str = "",
) -> LocalTipSeal:
    if counter < 0:
        raise TipSealError("tip seal counter must be >= 0")
    if not tip_hash:
        raise TipSealError("tip seal requires a tip hash")
    mac = compute_seal_mac(
        mac_key,
        counter=counter,
        tip_hash=tip_hash,
        lease_snapshot_hash=lease_snapshot_hash,
    )
    return LocalTipSeal(
        counter=counter,
        tip_hash=tip_hash,
        lease_snapshot_hash=lease_snapshot_hash,
        mac=mac,
    )


def _sync_external_anchor(path: Path, seal: LocalTipSeal) -> None:
    from js.echo.ledger.tip_anchor import current_tip_anchor, verify_or_commit_anchor

    verify_or_commit_anchor(
        current_tip_anchor(),
        str(path.resolve()),
        counter=seal.counter,
        tip_mac=seal.mac,
    )


def write_seal(path: Path, seal: LocalTipSeal) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    payload = {**seal.payload(), "mac": seal.mac}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(encoded + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
        _sync_external_anchor(path, seal)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def load_seal(path: Path, mac_key: bytes) -> LocalTipSeal | None:
    if not path.exists():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TipSealError("tip seal is not an object")
    try:
        counter = int(raw["counter"])
        tip_hash = str(raw["tip_hash"])
        lease_snapshot_hash = str(raw.get("lease_snapshot_hash") or "")
        mac = str(raw["mac"])
    except (KeyError, TypeError, ValueError) as exc:
        raise TipSealError("tip seal fields are invalid") from exc
    expected = compute_seal_mac(
        mac_key,
        counter=counter,
        tip_hash=tip_hash,
        lease_snapshot_hash=lease_snapshot_hash,
    )
    if not hmac.compare_digest(mac, expected):
        raise TipSealError("tip seal MAC mismatch")
    seal = LocalTipSeal(
        counter=counter,
        tip_hash=tip_hash,
        lease_snapshot_hash=lease_snapshot_hash,
        mac=mac,
    )
    from js.echo.ledger.tip_anchor import current_tip_anchor, verify_or_commit_anchor

    verify_or_commit_anchor(
        current_tip_anchor(),
        str(path.resolve()),
        counter=seal.counter,
        tip_mac=seal.mac,
    )
    return seal


def known_tips_include(known_tips: tuple[str, ...], tip_hash: str) -> bool:
    return tip_hash in known_tips


def verify_current_tip(
    *,
    sealed: LocalTipSeal,
    current_tip: str,
    known_tips: tuple[str, ...],
) -> None:
    """Fail closed on rewind/fork. Forward append of the sealed tip is allowed."""
    if current_tip == sealed.tip_hash:
        return
    if sealed.tip_hash in known_tips:
        return
    raise TipSealError("local tip seal rejected a rewind or fork")


def ensure_seal(
    path: Path,
    mac_key: bytes,
    *,
    current_tip: str,
    known_tips: tuple[str, ...],
    lease_snapshot_hash: str = "",
) -> LocalTipSeal:
    existing = load_seal(path, mac_key)
    if existing is None:
        seal = build_seal(
            mac_key,
            counter=0,
            tip_hash=current_tip,
            lease_snapshot_hash=lease_snapshot_hash,
        )
        write_seal(path, seal)
        return seal
    verify_current_tip(sealed=existing, current_tip=current_tip, known_tips=known_tips)
    return existing


def refresh_seal_tip(
    path: Path,
    mac_key: bytes,
    *,
    new_tip: str,
    lease_snapshot_hash: str | None = None,
) -> LocalTipSeal:
    """Update the sealed tip without incrementing the compact counter."""
    existing = load_seal(path, mac_key)
    counter = 0 if existing is None else existing.counter
    snapshot_hash = (
        existing.lease_snapshot_hash
        if existing is not None and lease_snapshot_hash is None
        else str(lease_snapshot_hash or "")
    )
    seal = build_seal(
        mac_key,
        counter=counter,
        tip_hash=new_tip,
        lease_snapshot_hash=snapshot_hash,
    )
    write_seal(path, seal)
    return seal


def bump_seal(
    path: Path,
    mac_key: bytes,
    *,
    new_tip: str,
    lease_snapshot_hash: str = "",
) -> LocalTipSeal:
    existing = load_seal(path, mac_key)
    counter = 1 if existing is None else existing.counter + 1
    seal = build_seal(
        mac_key,
        counter=counter,
        tip_hash=new_tip,
        lease_snapshot_hash=lease_snapshot_hash,
    )
    write_seal(path, seal)
    return seal

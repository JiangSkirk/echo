"""Trusted skill public-key registry with revocation.

TRUSTED requires a key listed here and not revoked. Self-signatures that
are merely valid Ed25519 no longer grant TRUSTED. Built-in keys stay on
the signer whitelist and are not stored in this file.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REGISTRY_NAME = "trusted_skill_keys.json"
REGISTRY_VERSION = 1


@dataclass(frozen=True, slots=True)
class TrustedKey:
    public_key: str
    name: str
    revoked: bool
    added_at: int


class TrustedKeyRegistry:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._keys: dict[str, TrustedKey] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or int(raw.get("version") or 0) != REGISTRY_VERSION:
            raise ValueError("trusted skill key registry version is invalid")
        rows = raw.get("keys")
        if not isinstance(rows, list):
            raise ValueError("trusted skill key registry keys must be a list")
        keys: dict[str, TrustedKey] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("trusted skill key row must be an object")
            public_key = str(row.get("public_key") or "")
            if not public_key:
                raise ValueError("trusted skill key is missing public_key")
            keys[public_key] = TrustedKey(
                public_key=public_key,
                name=str(row.get("name") or ""),
                revoked=bool(row.get("revoked")),
                added_at=int(row.get("added_at") or 0),
            )
        self._keys = keys

    def _write(self) -> None:
        payload: dict[str, Any] = {
            "version": REGISTRY_VERSION,
            "keys": [
                {
                    "public_key": key.public_key,
                    "name": key.name,
                    "revoked": key.revoked,
                    "added_at": key.added_at,
                }
                for key in sorted(self._keys.values(), key=lambda item: item.public_key)
            ],
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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

    def register(self, public_key: str, *, name: str = "") -> TrustedKey:
        key = TrustedKey(
            public_key=public_key,
            name=name,
            revoked=False,
            added_at=int(time.time()),
        )
        self._keys[public_key] = key
        self._write()
        return key

    def revoke(self, public_key: str) -> TrustedKey:
        existing = self._keys.get(public_key)
        if existing is None:
            raise KeyError(public_key)
        revoked = TrustedKey(
            public_key=existing.public_key,
            name=existing.name,
            revoked=True,
            added_at=existing.added_at,
        )
        self._keys[public_key] = revoked
        self._write()
        return revoked

    def is_trusted(self, public_key: str) -> bool:
        row = self._keys.get(public_key)
        return row is not None and not row.revoked


def registry_path(state_dir: Path) -> Path:
    return Path(state_dir) / REGISTRY_NAME


def load_registry(state_dir: Path) -> TrustedKeyRegistry:
    return TrustedKeyRegistry(registry_path(state_dir))


def is_trusted_public_key(state_dir: Path | None, public_key: str) -> bool:
    if state_dir is None or not public_key:
        return False
    try:
        return load_registry(state_dir).is_trusted(public_key)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


__all__ = [
    "REGISTRY_NAME",
    "TrustedKey",
    "TrustedKeyRegistry",
    "is_trusted_public_key",
    "load_registry",
    "registry_path",
]

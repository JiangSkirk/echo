from __future__ import annotations

import asyncio
import hashlib
import weakref

_session_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = weakref.WeakValueDictionary()
_session_locks_guard = asyncio.Lock()


def _lock_key(session_id: str | None, owner_key_hash: str | None = None) -> str | None:
    if not session_id:
        return None
    owner = owner_key_hash or "local"
    digest = hashlib.sha256(f"{owner}\0{session_id}".encode()).hexdigest()
    return digest[:32]


async def get_session_lock(
    session_id: str | None,
    owner_key_hash: str | None = None,
) -> asyncio.Lock:
    key = _lock_key(session_id, owner_key_hash)
    if key is None:
        return asyncio.Lock()
    async with _session_locks_guard:
        lock = _session_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _session_locks[key] = lock
        return lock

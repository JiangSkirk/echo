"""Owner-scoped paths for profile markdown files."""

from __future__ import annotations

import hashlib
from pathlib import Path

_LOCAL_PROFILE_OWNERS = frozenset({"", "local", "local-user", "__legacy_local__"})


def scoped_profile_path(
    state_dir: Path,
    name: str,
    owner_key_hash: str | None = None,
) -> Path:
    """Resolve a profile file without allowing owner or name path traversal."""
    safe_name = Path(name).name
    if not safe_name or safe_name.startswith(".") or safe_name == "..":
        raise ValueError(f"Invalid memory file name: {name}")

    memory_root = (state_dir / "memory").resolve()
    owner = (owner_key_hash or "").strip()
    if owner in _LOCAL_PROFILE_OWNERS:
        directory = memory_root
    else:
        owner_digest = hashlib.sha256(owner.encode("utf-8")).hexdigest()
        directory = memory_root / "owners" / owner_digest

    target = (directory / f"{safe_name}.md").resolve()
    try:
        target.relative_to(memory_root)
    except ValueError as exc:
        raise ValueError(f"Memory file path escapes allowed directory: {name}") from exc
    return target


__all__ = ["scoped_profile_path"]

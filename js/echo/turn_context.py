"""Echo turn-scoped context shared by every runtime surface."""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from js.appshell.principal import AppShellEpochBindingV1
    from js.echo.mode_contract import TaskRef

_MAX_RUNTIME_IDENTITY_CHARS = 512
# Keep session_id charset/length aligned with js.web.ids.validate_session_id.
_MAX_RUNTIME_SESSION_ID_CHARS = 192
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_SESSION_ID_FORBIDDEN = frozenset("\"'<>`\\\n\r\t")
_MAX_RUNTIME_CONTROL_SCOPE_CHARS = 128
_MAX_RUNTIME_CAPABILITIES = 256
_MAX_RUNTIME_CAPABILITY_CHARS = 256
_MAX_RUNTIME_FS_ROOTS = 64
_MAX_RUNTIME_NETWORK_HOSTS = 256
_MAX_RUNTIME_NETWORK_HOST_CHARS = 253
_MAX_RUNTIME_PATH_CHARS = 4_096


def _session_id_format_error(session_id: str) -> str | None:
    """Return why ``session_id`` fails the shared web/Echo identifier rules."""
    if unicodedata.normalize("NFC", session_id) != session_id:
        return "Echo runtime context session_id must be NFC-normalized"
    if session_id.strip() != session_id:
        return "Echo runtime context session_id must not have surrounding whitespace"
    if len(session_id) > _MAX_RUNTIME_SESSION_ID_CHARS:
        return "Echo runtime context session_id exceeds limit"
    if any(unicodedata.category(ch).startswith("C") for ch in session_id):
        return "Echo runtime context session_id contains control characters"
    if any(ch in _SESSION_ID_FORBIDDEN for ch in session_id):
        return "Echo runtime context session_id contains forbidden characters"
    if _SESSION_ID_RE.fullmatch(session_id) is None:
        return "Echo runtime context session_id has an invalid format"
    return None


@dataclass(frozen=True)
class RuntimeContext:
    """Immutable identity and capability envelope for one Echo turn."""

    product_id: str
    channel: str
    owner_key_hash: str
    session_id: str
    run_id: str
    role: str
    profile: str
    capabilities: tuple[str, ...]
    workspace: Path
    state_dir: Path
    fs_roots: tuple[Path, ...] = ()
    network_allowlist: tuple[str, ...] = ()
    deadline_ms: int | None = field(default_factory=lambda: int(time.monotonic() * 1000) + 900_000)
    cancel_token: Any | None = field(default_factory=asyncio.Event)
    control_scope: str = ""
    authority_mac: str = ""
    task_ref: TaskRef | None = None
    appshell_epoch_binding: AppShellEpochBindingV1 | None = None
    surface: str = ""


def runtime_context_error(context: RuntimeContext) -> str | None:
    """Return why a turn context is incomplete or already unusable."""

    required_text = {
        "product_id": context.product_id,
        "channel": context.channel,
        "owner_key_hash": context.owner_key_hash,
        "session_id": context.session_id,
        "run_id": context.run_id,
        "role": context.role,
        "profile": context.profile,
    }
    non_text = [name for name, value in required_text.items() if not isinstance(value, str)]
    if non_text:
        return "Echo runtime context identity fields must be text: " + ", ".join(non_text)
    missing = [name for name, value in required_text.items() if not value.strip()]
    if missing:
        return "Echo runtime context missing: " + ", ".join(missing)
    oversized = [
        name
        for name, value in required_text.items()
        if name != "session_id" and len(value) > _MAX_RUNTIME_IDENTITY_CHARS
    ]
    if oversized:
        return "Echo runtime context identity field exceeds limit: " + ", ".join(oversized)
    session_error = _session_id_format_error(context.session_id)
    if session_error is not None:
        return session_error
    if not isinstance(context.capabilities, tuple):
        return "Echo runtime context capabilities must be immutable"
    if len(context.capabilities) > _MAX_RUNTIME_CAPABILITIES:
        return "Echo runtime context capability count exceeds limit"
    if any(
        not isinstance(capability, str)
        or not capability.strip()
        or len(capability) > _MAX_RUNTIME_CAPABILITY_CHARS
        for capability in context.capabilities
    ):
        return "Echo runtime context capability is invalid or exceeds limit"
    try:
        workspace = Path(context.workspace)
        state_dir = Path(context.state_dir)
    except (TypeError, ValueError):
        return "Echo runtime context paths are invalid"
    if (
        len(str(workspace)) > _MAX_RUNTIME_PATH_CHARS
        or len(str(state_dir)) > _MAX_RUNTIME_PATH_CHARS
    ):
        return "Echo runtime context path exceeds limit"
    if not workspace.is_absolute() or not state_dir.is_absolute():
        return "Echo runtime context paths must be absolute"
    if not isinstance(context.fs_roots, tuple):
        return "Echo runtime context filesystem roots must be immutable"
    if not context.fs_roots:
        return "Echo runtime context requires filesystem roots"
    if len(context.fs_roots) > _MAX_RUNTIME_FS_ROOTS:
        return "Echo runtime context filesystem root count exceeds limit"
    for root in context.fs_roots:
        try:
            path = Path(root)
        except (TypeError, ValueError):
            return "Echo runtime context filesystem root is invalid"
        if len(str(path)) > _MAX_RUNTIME_PATH_CHARS or not path.is_absolute():
            return "Echo runtime context filesystem root is invalid or exceeds limit"
    if not isinstance(context.network_allowlist, tuple):
        return "Echo runtime context network allowlist must be immutable"
    if len(context.network_allowlist) > _MAX_RUNTIME_NETWORK_HOSTS:
        return "Echo runtime context network host count exceeds limit"
    if any(
        not isinstance(host, str) or not host.strip() or len(host) > _MAX_RUNTIME_NETWORK_HOST_CHARS
        for host in context.network_allowlist
    ):
        return "Echo runtime context network host is invalid or exceeds limit"
    if not isinstance(context.control_scope, str):
        return "Echo runtime context control scope must be text"
    if len(context.control_scope) > _MAX_RUNTIME_CONTROL_SCOPE_CHARS:
        return "Echo runtime context control scope exceeds limit"
    if context.deadline_ms is None or isinstance(context.deadline_ms, bool):
        return "Echo runtime context deadline is required"
    if context.deadline_ms <= int(time.monotonic() * 1000):
        return "Echo runtime context deadline expired"
    token = context.cancel_token
    if token is None or not callable(getattr(token, "is_set", None)):
        return "Echo runtime context cancel token is required"
    if bool(token.is_set()):
        return "Echo runtime context is cancelled"
    if not isinstance(context.surface, str):
        return "Echo runtime context surface must be text"
    if len(context.surface) > 32:
        return "Echo runtime context surface exceeds limit"
    return None


_session_owner_hash: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "session_owner_hash", default=None
)
_runtime_context: contextvars.ContextVar[RuntimeContext | None] = contextvars.ContextVar(
    "echo_runtime_context", default=None
)


def current_owner_key_hash(default: str | None = None) -> str | None:
    owner = _session_owner_hash.get(None)
    return owner if owner is not None else default


def set_current_owner_key_hash(owner_key_hash: str | None) -> contextvars.Token[str | None]:
    return _session_owner_hash.set(owner_key_hash)


def reset_current_owner_key_hash(token: contextvars.Token[str | None]) -> None:
    _session_owner_hash.reset(token)


def current_runtime_context() -> RuntimeContext | None:
    return _runtime_context.get(None)


def set_runtime_context(
    context: RuntimeContext,
) -> contextvars.Token[RuntimeContext | None]:
    return _runtime_context.set(context)


def reset_runtime_context(token: contextvars.Token[RuntimeContext | None]) -> None:
    _runtime_context.reset(token)


def runtime_partition_key(
    product_id: str,
    owner_key_hash: str | None,
    session_id: str,
) -> str:
    """Return the internal product- and owner-scoped key for runtime state."""
    owner = owner_key_hash or "local-user"
    payload = (
        f"{len(product_id)}:{product_id}{len(owner)}:{owner}{len(session_id)}:{session_id}"
    ).encode()
    return "echo-session:" + hashlib.sha256(payload).hexdigest()


def runtime_channel_key(
    product_id: str,
    owner_key_hash: str | None,
    channel: str,
) -> str:
    """Partition pulse backpressure without exposing owner identity."""
    owner = owner_key_hash or "local-user"
    digest = hashlib.sha256(f"{len(owner)}:{owner}".encode()).hexdigest()[:20]
    return f"{product_id}:{channel}:{digest}"


__all__ = [
    "RuntimeContext",
    "current_owner_key_hash",
    "current_runtime_context",
    "reset_current_owner_key_hash",
    "reset_runtime_context",
    "runtime_context_error",
    "runtime_channel_key",
    "runtime_partition_key",
    "set_current_owner_key_hash",
    "set_runtime_context",
]

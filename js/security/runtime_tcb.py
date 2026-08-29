"""Runtime trusted computing base (TCB) write deny.

When the agent workspace is the install tree (local dogfood), file/shell/sandbox
writes can overwrite the next host import of any ``js/`` module.  If the
installed package root sits inside the current workspace, the **entire package**
is read-only except a narrow dogfood allowlist (``web/static/``).  ``tests/``,
``docs/``, and other repo paths outside the package stay writable.

Tests inject a fake package root with :func:`override_runtime_package_root`.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

# Relative to the installed ``js/`` package root.  Everything else under the
# package is TCB (host-importable runtime).
RUNTIME_TCB_WRITE_ALLOW_PREFIXES: tuple[str, ...] = ("web/static",)

_package_root_override: ContextVar[Path | None] = ContextVar(
    "runtime_tcb_package_root",
    default=None,
)


def runtime_package_root() -> Path:
    """Return the installed ``js/`` directory (overridable in tests)."""
    override = _package_root_override.get()
    if override is not None:
        return override
    import js

    return Path(js.__file__).resolve().parent


@contextmanager
def override_runtime_package_root(root: Path) -> Iterator[Path]:
    """Point TCB matching at a fake ``js/`` tree for tests."""
    resolved = root.resolve()
    token = _package_root_override.set(resolved)
    try:
        yield resolved
    finally:
        _package_root_override.reset(token)


def _relative_is_write_allowed(relative: Path) -> bool:
    posix = relative.as_posix().casefold()
    if posix in {".", ""}:
        return False
    for prefix in RUNTIME_TCB_WRITE_ALLOW_PREFIXES:
        folded = prefix.casefold()
        if posix == folded or posix.startswith(folded + "/"):
            return True
    return False


def is_runtime_tcb_write(target: Path, *, workspace: Path) -> bool:
    """True when ``target`` is inside ``workspace`` and the installed ``js/`` package.

    ``web/static/`` is the dogfood exception.  The package root itself is TCB.
    """
    try:
        workspace_root = workspace.resolve()
        package_root = runtime_package_root()
        candidate = target if target.is_absolute() else workspace_root / target
        candidate = candidate.resolve()
        candidate.relative_to(workspace_root)
        relative = candidate.relative_to(package_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return not _relative_is_write_allowed(relative)


def runtime_tcb_write_error(target: Path, *, workspace: Path) -> str | None:
    if not is_runtime_tcb_write(target, workspace=workspace):
        return None
    return f"Runtime TCB path cannot be modified: {target}"


def token_is_runtime_tcb_write(token: str, *, workspace: Path) -> bool:
    """Lexical path token (shell argv) that would write a workspace TCB path.

    Tokens containing ``$`` are not classified here; callers must deny them
    via ``CommandNode.arg_vars`` on write-path commands.
    """
    if not token or token in {".", "-"} or "\x00" in token:
        return False
    if token.startswith("~"):
        return False
    normalized = os.path.normpath(token.replace("\\", "/"))
    if normalized in {".", ""}:
        return False
    parts = tuple(part for part in Path(normalized).parts if part not in ("", "."))
    if any(part == ".." for part in parts):
        return False
    candidate = Path(normalized)
    if not candidate.is_absolute():
        candidate = workspace / Path(*parts)
    return is_runtime_tcb_write(candidate, workspace=workspace)


def workspace_tcb_deny_targets(workspace: Path) -> tuple[tuple[Path, bool], ...]:
    """Package root to deny when it sits inside ``workspace``.

    Each entry is ``(absolute_path, is_directory)``.  Missing paths are still
    returned so macOS can deny future creates; Linux callers skip non-existent
    paths.
    """
    try:
        workspace_root = workspace.resolve()
        package_root = runtime_package_root()
        package_root.relative_to(workspace_root)
    except (OSError, RuntimeError, ValueError):
        return ()
    return ((package_root, True),)


def workspace_tcb_allow_targets(workspace: Path) -> tuple[tuple[Path, bool], ...]:
    """Dogfood write exceptions under the package, when the package is in workspace."""
    try:
        workspace_root = workspace.resolve()
        package_root = runtime_package_root()
        package_root.relative_to(workspace_root)
    except (OSError, RuntimeError, ValueError):
        return ()
    return tuple((package_root / prefix, True) for prefix in RUNTIME_TCB_WRITE_ALLOW_PREFIXES)

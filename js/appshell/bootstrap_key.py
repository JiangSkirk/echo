"""Shared Personal/Work bootstrap admin key minting for AppShell."""

from __future__ import annotations

import os
from pathlib import Path

from js.config import JSSettings
from js.utils.log import get_logger
from js.web.auth import AuthManager, _generate_key

logger = get_logger("js.appshell")

_PROVISION_KEY_TRUTHY = frozenset({"1", "true", "yes", "on"})
_BOOTSTRAP_KEY_NAME = "appshell-bootstrap"
_BOOTSTRAP_KEY_ROLE = "admin"


def appshell_provision_key_enabled() -> bool:
    """Return whether ``JS_APPSHELL_PROVISION_KEY`` requests startup minting."""
    raw = os.environ.get("JS_APPSHELL_PROVISION_KEY", "")
    return raw.strip().lower() in _PROVISION_KEY_TRUTHY


def provision_shared_bootstrap_key(
    personal_settings: JSSettings,
    work_settings: JSSettings,
) -> str | None:
    """Mint one shared admin key for Personal and Work when none exists.

    Returns the new plaintext, or ``None`` when auth is optional or Personal
    already has an admin (idempotent). Persistence failure rolls back both
    stores and raises ``RuntimeError`` so startup cannot continue half-configured.
    """
    if not bool(getattr(personal_settings.security, "api_key_required", True)):
        return None
    personal_auth = AuthManager(personal_settings.state_dir)
    if personal_auth.has_admin():
        return None

    work_auth = AuthManager(work_settings.state_dir)
    api_key = _generate_key()
    personal_identity = personal_auth.provision_existing_key(
        api_key,
        name=_BOOTSTRAP_KEY_NAME,
        role=_BOOTSTRAP_KEY_ROLE,
    )
    key_hash = str(personal_identity["key_hash"])
    key_file = personal_settings.state_dir / "bootstrap_admin_key.txt"
    try:
        work_auth.provision_existing_key(
            api_key,
            name=_BOOTSTRAP_KEY_NAME,
            role=_BOOTSTRAP_KEY_ROLE,
        )
        _persist_key(key_file, api_key)
    except Exception as exc:
        personal_auth.revoke_key(key_hash)
        try:
            work_auth.revoke_key(key_hash)
        except Exception:
            pass
        logger.warning(
            "Could not persist AppShell bootstrap admin key; refusing an unrecoverable key",
            error_type=type(exc).__name__,
        )
        raise RuntimeError("Could not persist bootstrap admin key; startup aborted") from exc

    logger.warning("Bootstrap admin key created for first run; saved to %s", key_file)
    return api_key


def _persist_key(path: Path, key: str) -> None:
    """Write via the Host facade so existing persist monkeypatches still apply."""
    from js.web import server as web_server
    from js.web.bootstrap import _persist_bootstrap_admin_key as default_persist

    persist_fn = getattr(web_server, "_persist_bootstrap_admin_key", default_persist)
    persist_fn(path, key)

"""Global AppShell preferences (ADR 0002 whitelist only).

Stores chrome-level prefs shared across Personal and Work: language, timezone,
theme, and backend base URLs. Never stores API keys, memory, sessions, or
ledger material.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

APPSHELL_PREFS_SCHEMA = "js-appshell-global-prefs-v2"
APPSHELL_PREFS_SCHEMA_V1 = "js-appshell-global-prefs-v1"
DEFAULT_PERSONAL_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_WORK_BASE_URL = "http://127.0.0.1:8765"
DEFAULT_HOST_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_PERSONAL_PATH = "/personal"
DEFAULT_WORK_PATH = "/work"


@dataclass(frozen=True)
class GlobalPrefs:
    schema_version: str = APPSHELL_PREFS_SCHEMA
    language: str = "zh-CN"
    timezone: str = "Asia/Shanghai"
    theme: str = "system"
    # v2 single-host fields
    host_base_url: str = DEFAULT_HOST_BASE_URL
    personal_path: str = DEFAULT_PERSONAL_PATH
    work_path: str = DEFAULT_WORK_PATH
    # v1 legacy fields (kept for rollback compatibility)
    personal_base_url: str = DEFAULT_PERSONAL_BASE_URL
    work_base_url: str = DEFAULT_WORK_BASE_URL
    # Optional state dirs written by ``js appshell`` so loopback handoff can
    # mint a bootstrap entry URL for the *other* product. Never store keys here.
    personal_state_dir: str | None = None
    work_state_dir: str | None = None
    # Credential *references* only - opaque ids, never raw secrets.
    credential_refs: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["credential_refs"] = list(self.credential_refs)
        return payload


def default_prefs_path() -> Path:
    override = os.environ.get("JS_APPSHELL_PREFS_PATH")
    if override:
        return Path(override).expanduser().resolve()
    home = Path.home()
    return (home / ".js-appshell" / "prefs.json").resolve()


def _validate_url(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.startswith(("http://", "https://")):
        raise ValueError(f"{field} must be an http(s) URL")
    if any(ch.isspace() for ch in value):
        raise ValueError(f"{field} must not contain whitespace")
    return value.rstrip("/")


def _optional_state_dir(value: object, *, field: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or any(ch.isspace() for ch in value):
        raise ValueError(f"{field} must be an absolute path string")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{field} must be an absolute path")
    return str(path.resolve())


def prefs_from_mapping(data: dict[str, Any]) -> GlobalPrefs:
    refs_raw = data.get("credential_refs", ())
    if refs_raw is None:
        refs_raw = ()
    if not isinstance(refs_raw, (list, tuple)):
        raise ValueError("credential_refs must be a list of opaque reference ids")
    refs: list[str] = []
    for item in refs_raw:
        if not isinstance(item, str) or not item or any(ch.isspace() for ch in item):
            raise ValueError("credential_refs entries must be non-empty opaque strings")
        lowered = item.lower()
        if lowered.startswith(("sk-", "Bearer ", "-----begin")) or "api_key" in lowered:
            raise ValueError("credential_refs must not contain raw secret material")
        refs.append(item)
    # v2 single-host fields, with v1 fallback
    host_base_url = _validate_url(
        data.get("host_base_url") or DEFAULT_HOST_BASE_URL,
        field="host_base_url",
    )
    personal_path = str(data.get("personal_path") or DEFAULT_PERSONAL_PATH)
    work_path = str(data.get("work_path") or DEFAULT_WORK_PATH)
    # Keep v1 URLs for rollback
    personal_base_url = _validate_url(
        data.get("personal_base_url") or DEFAULT_PERSONAL_BASE_URL,
        field="personal_base_url",
    )
    work_base_url = _validate_url(
        data.get("work_base_url") or DEFAULT_WORK_BASE_URL,
        field="work_base_url",
    )
    return GlobalPrefs(
        schema_version=str(data.get("schema_version") or APPSHELL_PREFS_SCHEMA),
        language=str(data.get("language") or "zh-CN"),
        timezone=str(data.get("timezone") or "Asia/Shanghai"),
        theme=str(data.get("theme") or "system"),
        host_base_url=host_base_url,
        personal_path=personal_path,
        work_path=work_path,
        personal_base_url=personal_base_url,
        work_base_url=work_base_url,
        personal_state_dir=_optional_state_dir(
            data.get("personal_state_dir"), field="personal_state_dir"
        ),
        work_state_dir=_optional_state_dir(data.get("work_state_dir"), field="work_state_dir"),
        credential_refs=tuple(refs),
    )


def load_global_prefs(path: Path | None = None) -> GlobalPrefs:
    target = path or default_prefs_path()
    if not target.is_file():
        return GlobalPrefs()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return GlobalPrefs()
    if not isinstance(raw, dict):
        return GlobalPrefs()
    try:
        return prefs_from_mapping(raw)
    except ValueError:
        return GlobalPrefs()


def save_global_prefs(prefs: GlobalPrefs, path: Path | None = None) -> Path:
    target = path or default_prefs_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(prefs.as_dict(), indent=2, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
    return target

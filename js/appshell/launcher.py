"""Compatibility launcher for the single parent AppShell host."""

from __future__ import annotations

from pathlib import Path

from js.appshell.global_prefs import (
    DEFAULT_PERSONAL_BASE_URL,
    DEFAULT_WORK_BASE_URL,
    GlobalPrefs,
    load_global_prefs,
    save_global_prefs,
)


def _parse_host_port(base_url: str) -> tuple[str, int]:
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, int(port)


def _state_dir_from_config(config_path: str | None) -> str | None:
    if not config_path:
        return None
    path = Path(config_path).expanduser()
    if not path.is_file():
        return None
    try:
        import yaml

        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    state_dir = raw.get("state_dir")
    if not isinstance(state_dir, str) or not state_dir.strip():
        return None
    return str(Path(state_dir).expanduser().resolve())


def launch_appshell(
    *,
    personal_config: str | None = None,
    work_config: str | None = None,
    personal_base_url: str = DEFAULT_PERSONAL_BASE_URL,
    work_base_url: str = DEFAULT_WORK_BASE_URL,
    open_browser: bool = False,
    prefs_path: Path | None = None,
    echo_minimal_os: bool = False,
) -> int:
    """Serve both isolated runtimes behind one uvicorn process and one port.

    ``work_base_url`` remains accepted only so older invocations parse; it is
    persisted for rollback metadata but never bound or contacted.
    ``open_browser`` is ignored: AppShell never opens a system browser.
    ``echo_minimal_os`` is off by default.  When requested, the Darwin
    deny-default carrier must exist or launch fails closed; this host still
    serves AppShell in-process, so AppShell/Echo separation stays unobserved.
    """
    del open_browser
    if echo_minimal_os:
        from js.orin.echo_os import require_echo_minimal_os_carrier

        require_echo_minimal_os_carrier()
    prefs = load_global_prefs(prefs_path)
    host_base_url = personal_base_url or prefs.host_base_url
    prefs = GlobalPrefs(
        schema_version=prefs.schema_version,
        language=prefs.language,
        timezone=prefs.timezone,
        theme=prefs.theme,
        host_base_url=host_base_url,
        personal_path=prefs.personal_path,
        work_path=prefs.work_path,
        personal_base_url=host_base_url,
        work_base_url=work_base_url or prefs.work_base_url,
        personal_state_dir=_state_dir_from_config(personal_config) or prefs.personal_state_dir,
        work_state_dir=_state_dir_from_config(work_config) or prefs.work_state_dir,
        credential_refs=prefs.credential_refs,
    )
    save_global_prefs(prefs, prefs_path)

    host, port = _parse_host_port(host_base_url)
    from js.appshell.server import create_appshell_app
    from js.web.local_host import run_local_host

    app = create_appshell_app(
        personal_config=personal_config,
        work_config=work_config,
        host=host,
        port=port,
        manage_orind=True,
    )
    personal = getattr(app.state, "personal_app", None)
    runtime_settings = getattr(getattr(personal, "state", None), "runtime_settings", None)
    if runtime_settings is not None:
        from js.appshell.echo_process_split import maybe_enable_product_process_split

        maybe_enable_product_process_split(runtime_settings)
    run_local_host(
        app,
        host=host,
        port=port,
        notes=(
            f"AppShell: {host_base_url}",
            "Personal and Work are isolated runtimes behind this one trusted host.",
        ),
    )
    return 0

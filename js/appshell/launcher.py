"""AppShell dual-backend launcher — Personal + Work under one operator command.

Does not merge state_dirs. Starts two uvicorn processes with isolated configs
and prints the unified chrome entry URL (Personal host by default; UI switches
to Work via /api/workspace/switch + navigation).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
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


def launch_appshell(
    *,
    personal_config: str | None = None,
    work_config: str | None = None,
    personal_base_url: str = DEFAULT_PERSONAL_BASE_URL,
    work_base_url: str = DEFAULT_WORK_BASE_URL,
    open_browser: bool = True,
    prefs_path: Path | None = None,
) -> int:
    """Spawn Personal and Work web servers; block until interrupted."""
    prefs = load_global_prefs(prefs_path)
    prefs = GlobalPrefs(
        schema_version=prefs.schema_version,
        language=prefs.language,
        timezone=prefs.timezone,
        theme=prefs.theme,
        personal_base_url=personal_base_url or prefs.personal_base_url,
        work_base_url=work_base_url or prefs.work_base_url,
        credential_refs=prefs.credential_refs,
    )
    save_global_prefs(prefs, prefs_path)

    personal_host, personal_port = _parse_host_port(prefs.personal_base_url)
    work_host, work_port = _parse_host_port(prefs.work_base_url)

    repo_python = sys.executable
    env_base = os.environ.copy()
    # Ensure child processes do not inherit a conflicting single-product override
    # that would collapse isolation.
    for key in ("JS_CONFIG_PATH", "JS_WORK_CONFIG_PATH", "JS_STATE_DIR", "JS_WORK_STATE_DIR"):
        env_base.pop(key, None)

    # Prefer CLI entrypoints that honor -c / runtime_settings.
    personal_cli = [
        repo_python,
        "-m",
        "js",
        "web",
        "--host",
        personal_host,
        "--port",
        str(personal_port),
    ]
    if personal_config:
        personal_cli.extend(["--config", personal_config])

    # Work places --config on the parent group: `js-work -c FILE web ...`
    work_cli = [repo_python, "-m", "js_work"]
    if work_config:
        work_cli.extend(["--config", work_config])
    work_cli.extend(
        [
            "web",
            "--host",
            work_host,
            "--port",
            str(work_port),
        ]
    )

    procs: list[subprocess.Popen[bytes]] = []
    try:
        procs.append(subprocess.Popen(personal_cli, env=env_base))
        procs.append(subprocess.Popen(work_cli, env=env_base))
        if open_browser:
            import threading
            import webbrowser

            def _open() -> None:
                time.sleep(1.5)
                webbrowser.open(prefs.personal_base_url)

            threading.Thread(target=_open, daemon=True).start()

        print(f"AppShell Personal: {prefs.personal_base_url}")
        print(f"AppShell Work:     {prefs.work_base_url}")
        print("Switch products in the header; data planes stay isolated.")
        # Wait until either child exits or we receive SIGINT/SIGTERM.
        while True:
            for proc in procs:
                code = proc.poll()
                if code is not None:
                    print(f"child exited pid={proc.pid} code={code}", file=sys.stderr)
                    return int(code)
            time.sleep(0.5)
    except KeyboardInterrupt:
        return 0
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
        deadline = time.time() + 10
        for proc in procs:
            remaining = max(0.1, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                proc.kill()

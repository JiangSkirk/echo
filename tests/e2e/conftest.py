"""Self-contained Playwright fixtures for the browser hard gate."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from playwright.sync_api import Browser, Page, Playwright, sync_playwright

SYSTEM_CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_LIVE_SERVER_API_KEY = ""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


@pytest.fixture(scope="session")
def live_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Start an isolated local server; startup failures fail the gate."""

    base = tmp_path_factory.mktemp("browser-gate")
    workspace = base / "workspace"
    state_dir = base / "state"
    workspace.mkdir()
    state_dir.mkdir()
    config_path = base / "config.yaml"
    config_path.write_text(
        "\n".join(
            (
                'version: "0.1.5"',
                f'workspace: "{workspace}"',
                f'state_dir: "{state_dir}"',
                "log_level: WARNING",
                "max_turns: 3",
                "auto_delegate: false",
                "first_run_completed: true",
                "providers: []",
                "models: []",
                "security:",
                "  defense_mode: enforce",
                "  api_key_required: false",
                "",
            )
        ),
        encoding="utf-8",
    )
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    from js.web.auth import AuthManager

    global _LIVE_SERVER_API_KEY
    _LIVE_SERVER_API_KEY = AuthManager(state_dir).create_key("e2e-admin", role="admin")
    env = os.environ.copy()
    env.update(
        {
            "JS_CONFIG_PATH": str(config_path),
            "JS_STATE_DIR": str(state_dir),
            "JS_API_KEY_REQUIRED": "false",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "PYTHONUNBUFFERED": "1",
        }
    )
    env.pop("JS_WARM_START", None)
    env.pop("JS_ECHO_ENGINE", None)
    env.pop("JS_ALLOWED_ORIGINS", None)
    log_path = base / "server.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "js",
                "web",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        try:
            deadline = time.monotonic() + 45
            last_error = "server did not respond"
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    with _LOCAL_OPENER.open(f"{base_url}/", timeout=1) as response:
                        if response.status == 200:
                            yield base_url
                            return
                except Exception as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(0.2)
            log.flush()
            server_log = log_path.read_text(encoding="utf-8", errors="replace")[-8000:]
            pytest.fail(
                f"Browser gate server failed to start: {last_error}\n"
                f"exit={process.poll()}\n{server_log}",
                pytrace=False,
            )
        finally:
            _stop_process(process)


@pytest.fixture(scope="session")
def live_server_api_key(live_server: str) -> str:
    """Write-capable API key for the session-scoped ``live_server`` instance."""
    assert _LIVE_SERVER_API_KEY, "live_server fixture did not provision an API key"
    return _LIVE_SERVER_API_KEY


_LIVE_SERVER_API_KEY = ""
_APPSHELL_ADMIN_KEY = ""


def _write_appshell_configs(base: Path) -> tuple[Path, Path, Path, Path]:
    personal_workspace = base / "personal-workspace"
    personal_state = base / "personal-state"
    work_home = base / "work-home" / ".js-work"
    work_state = work_home / "state"
    personal_workspace.mkdir(parents=True, exist_ok=True)
    personal_state.mkdir(parents=True, exist_ok=True)
    work_home.mkdir(parents=True, exist_ok=True)
    personal_config = base / "personal.yaml"
    personal_config.write_text(
        "\n".join(
            (
                f'workspace: "{personal_workspace}"',
                f'state_dir: "{personal_state}"',
                "first_run_completed: true",
                "providers: []",
                "models: []",
                "security:",
                "  api_key_required: true",
                "",
            )
        ),
        encoding="utf-8",
    )
    work_config = base / "work.yaml"
    work_config.write_text(
        "\n".join(
            (
                f'work_home: "{work_home}"',
                f'workspace: "{work_home / "workspace"}"',
                f'state_dir: "{work_home / "state"}"',
                "first_run_completed: true",
                "providers: []",
                "models: []",
                "security:",
                "  api_key_required: true",
                "",
            )
        ),
        encoding="utf-8",
    )
    return personal_config, work_config, personal_state, work_state


def _launch_appshell(
    personal_config: Path,
    work_config: Path,
    log_path: Path,
    label: str,
) -> Iterator[str]:
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.update(
        {
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "PYTHONUNBUFFERED": "1",
        }
    )
    for name in (
        "JS_CONFIG_PATH",
        "JS_WORK_CONFIG_PATH",
        "JS_STATE_DIR",
        "JS_WORK_STATE_DIR",
        "JS_ECHO_ENGINE",
        "JS_WORK_ECHO_ENGINE",
        "JS_WARM_START",
        "JS_ALLOWED_ORIGINS",
    ):
        env.pop(name, None)
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "js",
                "appshell",
                "--personal-config",
                str(personal_config),
                "--work-config",
                str(work_config),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-browser",
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        try:
            deadline = time.monotonic() + 45
            last_error = "AppShell did not respond"
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    with _LOCAL_OPENER.open(f"{base_url}/", timeout=1) as response:
                        if response.status == 200:
                            yield base_url
                            return
                except Exception as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(0.2)
            log.flush()
            server_log = log_path.read_text(encoding="utf-8", errors="replace")[-8000:]
            pytest.fail(
                f"{label} failed to start: {last_error}\n"
                f"exit={process.poll()}\n{server_log}",
                pytrace=False,
            )
        finally:
            _stop_process(process)


@pytest.fixture(scope="session")
def appshell_live_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Start the real parent AppShell with isolated Personal and Work roots.

    Note: only the FIRST cookieless browser context can auto-bootstrap; use
    ``appshell_authed_server`` for suites that open multiple contexts.
    """
    base = tmp_path_factory.mktemp("appshell-browser-gate")
    personal_config, work_config, _personal_state, _work_state = _write_appshell_configs(base)
    yield from _launch_appshell(
        personal_config, work_config, base / "server.log", "AppShell browser gate"
    )


@pytest.fixture(scope="session")
def appshell_authed_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[str, str]]:
    """AppShell with a pre-provisioned admin key.

    Any number of browser contexts can authenticate via the production
    ``#bootstrap-api-key=`` fragment handoff.
    """
    base = tmp_path_factory.mktemp("appshell-authed-gate")
    personal_config, work_config, personal_state, work_state = _write_appshell_configs(base)
    from js.web.auth import AuthManager

    admin_key = AuthManager(personal_state).create_key("appshell-e2e-admin", role="admin")
    # Grant the same identity the Work role too (mirrors bootstrap provisioning);
    # otherwise /api/appshell/switch fails closed with work_role_required.
    AuthManager(work_state).provision_existing_key(
        admin_key, name="appshell-e2e-admin", role="admin"
    )
    for base_url in _launch_appshell(
        personal_config, work_config, base / "server.log", "Authed AppShell gate"
    ):
        yield base_url, admin_key


@pytest.fixture()
def appshell_legacy_key_server(
    tmp_path: Path,
) -> Iterator[tuple[str, Path, str]]:
    """Fresh AppShell with a Personal-only admin for legacy-key leak regression."""
    personal_workspace = tmp_path / "personal-workspace"
    personal_state = tmp_path / "personal-state"
    work_home = tmp_path / "work-home" / ".js-work"
    personal_workspace.mkdir()
    personal_state.mkdir()
    work_home.mkdir(parents=True)
    personal_config = tmp_path / "personal.yaml"
    personal_config.write_text(
        "\n".join(
            (
                f'workspace: "{personal_workspace}"',
                f'state_dir: "{personal_state}"',
                "first_run_completed: true",
                "providers: []",
                "models: []",
                "security:",
                "  api_key_required: true",
                "",
            )
        ),
        encoding="utf-8",
    )
    work_state = work_home / "state"
    work_config = tmp_path / "work.yaml"
    work_config.write_text(
        "\n".join(
            (
                f'work_home: "{work_home}"',
                f'workspace: "{work_home / "workspace"}"',
                f'state_dir: "{work_state}"',
                "first_run_completed: true",
                "providers: []",
                "models: []",
                "security:",
                "  api_key_required: true",
                "",
            )
        ),
        encoding="utf-8",
    )
    from js.web.auth import AuthManager

    legacy_key = AuthManager(personal_state).create_key("legacy-browser-admin", role="admin")
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.update(
        {
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "PYTHONUNBUFFERED": "1",
        }
    )
    for name in (
        "JS_CONFIG_PATH",
        "JS_WORK_CONFIG_PATH",
        "JS_STATE_DIR",
        "JS_WORK_STATE_DIR",
        "JS_ECHO_ENGINE",
        "JS_WORK_ECHO_ENGINE",
        "JS_WARM_START",
        "JS_ALLOWED_ORIGINS",
    ):
        env.pop(name, None)
    log_path = tmp_path / "legacy-key-server.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "js",
                "appshell",
                "--personal-config",
                str(personal_config),
                "--work-config",
                str(work_config),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-browser",
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        try:
            deadline = time.monotonic() + 45
            last_error = "AppShell did not respond"
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    with _LOCAL_OPENER.open(f"{base_url}/", timeout=1) as response:
                        if response.status == 200:
                            yield base_url, work_state, legacy_key
                            return
                except Exception as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(0.2)
            log.flush()
            server_log = log_path.read_text(encoding="utf-8", errors="replace")[-8000:]
            pytest.fail(
                f"Legacy-key AppShell failed to start: {last_error}\n"
                f"exit={process.poll()}\n{server_log}",
                pytrace=False,
            )
        finally:
            _stop_process(process)


@pytest.fixture(scope="session")
def work_live_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Start an isolated JS Agent Work server for product-bound browser checks."""

    base = tmp_path_factory.mktemp("work-browser-gate")
    config_path = base / "work-config.yaml"
    config_path.write_text(
        "\n".join(
            (
                "security:",
                "  api_key_required: false",
                "providers: []",
                "models: []",
                "",
            )
        ),
        encoding="utf-8",
    )
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.update(
        {
            "JS_WORK_CONFIG_PATH": str(config_path),
            "JS_WORK_ECHO_ENGINE": "on",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "PYTHONUNBUFFERED": "1",
        }
    )
    for name in (
        "JS_CONFIG_PATH",
        "JS_STATE_DIR",
        "JS_ECHO_ENGINE",
        "JS_WARM_START",
        "JS_ALLOWED_ORIGINS",
    ):
        env.pop(name, None)
    work_executable = Path(sys.executable).with_name("js-work")
    if not work_executable.is_file():
        pytest.fail(f"Work CLI entry point is missing: {work_executable}", pytrace=False)
    log_path = base / "work-server.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [
                str(work_executable),
                "--config",
                str(config_path),
                "--home",
                str(base),
                "--profile",
                "office",
                "web",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        try:
            deadline = time.monotonic() + 45
            last_error = "Work server did not respond"
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    with _LOCAL_OPENER.open(f"{base_url}/", timeout=1) as response:
                        if response.status == 200:
                            yield base_url
                            return
                except Exception as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(0.2)
            log.flush()
            server_log = log_path.read_text(encoding="utf-8", errors="replace")[-8000:]
            pytest.fail(
                f"Work browser gate server failed to start: {last_error}\n"
                f"exit={process.poll()}\n{server_log}",
                pytrace=False,
            )
        finally:
            _stop_process(process)


@pytest.fixture(scope="session")
def playwright_runtime() -> Iterator[Playwright]:
    """Start Playwright; missing runtime components fail instead of skipping."""

    with sync_playwright() as runtime:
        yield runtime


@pytest.fixture(scope="session")
def browser(playwright_runtime: Playwright) -> Iterator[Browser]:
    launch_args: dict[str, object] = {"headless": True}
    if SYSTEM_CHROME.is_file():
        launch_args["executable_path"] = str(SYSTEM_CHROME)
    browser = playwright_runtime.chromium.launch(**launch_args)
    try:
        yield browser
    finally:
        browser.close()


@pytest.fixture
def page(browser: Browser) -> Iterator[Page]:
    context = browser.new_context()
    context.route(
        "https://**",
        lambda route: route.fulfill(
            status=200,
            body="",
            content_type=(
                "text/css"
                if route.request.url.lower().endswith(".css")
                else "application/javascript"
            ),
        ),
    )
    context.add_init_script("localStorage.setItem('js-wizard-completed', 'true')")
    page = context.new_page()
    page.set_default_timeout(5_000)
    page.set_default_navigation_timeout(20_000)
    try:
        yield page
    finally:
        context.close()

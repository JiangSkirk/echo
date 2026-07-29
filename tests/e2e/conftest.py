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

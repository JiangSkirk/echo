from __future__ import annotations

import contextlib
import http.client
import json
import os
import selectors
import signal
import socket
import sqlite3
import subprocess
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from typing import IO, Any

import pytest
from fastapi import FastAPI

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
SOURCE_DIGEST = "ab" * 32
SOURCE_HOST_RUNNER = Path(__file__).with_name("fixtures") / "source_host_runner.py"
EMBEDDED_DIGEST_FIXTURE = (
    Path(__file__).with_name("fixtures") / "embedded_source_digest.txt"
)
ASYNC_BROWSER_PROBE = Path(__file__).with_name("fixtures") / "async_browser_probe.py"


def _host_command() -> list[str]:
    binary = os.environ.get("JS_AGENT_HOST_BINARY")
    if binary:
        return [str(Path(binary).resolve())]
    return [
        str(PYTHON),
        str(SOURCE_HOST_RUNNER),
        "--embedded-digest-file",
        str(EMBEDDED_DIGEST_FIXTURE),
    ]


def _source_host_command(embedded_digest_file: Path) -> list[str]:
    return [
        str(PYTHON),
        str(SOURCE_HOST_RUNNER),
        "--embedded-digest-file",
        str(embedded_digest_file),
    ]


def _readline_with_timeout(stream: IO[bytes], timeout: float = 20.0) -> str:
    selector = selectors.DefaultSelector()
    selector.register(stream, selectors.EVENT_READ)
    try:
        assert selector.select(timeout), "host did not emit its ready sentinel"
        line = stream.readline()
    finally:
        selector.close()
    assert line, "host exited before emitting its ready sentinel"
    return line.decode("utf-8").rstrip("\n")


def _launch_host(
    home: Path,
    *,
    token: str = "01" * 32,
    ttl_seconds: int = 60,
) -> tuple[subprocess.Popen[bytes], dict[str, Any]]:
    home.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "PYTHONPATH": str(REPO_ROOT),
        }
    )
    started_at = time.monotonic()
    process = subprocess.Popen(
        [
            *_host_command(),
            "--source-digest",
            SOURCE_DIGEST,
            "--bootstrap-ttl-seconds",
            str(ttl_seconds),
        ],
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # Production Tauri launches the externalBin in a fresh process group.
        # Mirror that boundary so the sentinel cannot accidentally report the
        # ambient test runner/Codex process-group leader.
        start_new_session=True,
    )
    assert process.stdin is not None
    process.stdin.write((token + "\n").encode("ascii"))
    process.stdin.close()
    assert process.stdout is not None
    line = _readline_with_timeout(
        process.stdout,
        timeout=75.0 if os.environ.get("JS_AGENT_HOST_BINARY") else 20.0,
    )
    ready_latency = time.monotonic() - started_at
    assert ready_latency < (50.0 if os.environ.get("JS_AGENT_HOST_BINARY") else 10.0)
    ready = json.loads(line)
    return process, ready


@contextlib.contextmanager
def _running_host(
    tmp_path: Path,
    *,
    token: str = "01" * 32,
    ttl_seconds: int = 60,
) -> Iterator[tuple[subprocess.Popen[bytes], dict[str, Any]]]:
    process, ready = _launch_host(
        tmp_path / "home",
        token=token,
        ttl_seconds=ttl_seconds,
    )
    try:
        yield process, ready
    finally:
        if process.poll() is None:
            process.terminate()
        returncode = process.wait(timeout=10)
        assert returncode in {0, -15}
        assert process.stderr is not None
        stderr = process.stderr.read().decode("utf-8", errors="replace")
        assert token not in stderr
        assert "DependencyConflict" not in stderr
        assert "Traceback" not in stderr


def _request(
    ready: dict[str, Any],
    method: str,
    path: str,
    *,
    token: str | None = None,
    cookie: str | None = None,
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any], list[tuple[str, str]]]:
    port = int(ready["port"])
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Origin": f"http://127.0.0.1:{port}"}
    body = None
    if token is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps({"token": token}, separators=(",", ":"))
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload, separators=(",", ":"))
    if cookie is not None:
        headers["Cookie"] = cookie
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = json.loads(response.read().decode("utf-8"))
    response_headers = response.getheaders()
    connection.close()
    return response.status, payload, response_headers


def _header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in headers if key.casefold() == name.casefold()]


def _run_async_browser_probe(
    ready: dict[str, Any],
    *,
    token: str,
    inject_failure: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    payload = json.dumps(
        {
            "inject_failure": inject_failure,
            "token": token,
            "url": f"http://127.0.0.1:{ready['port']}/",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    completed = subprocess.run(
        [str(PYTHON), str(ASYNC_BROWSER_PROBE)],
        cwd=REPO_ROOT,
        env={
            "HOME": os.environ.get("HOME", str(REPO_ROOT)),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(REPO_ROOT),
        },
        input=(payload + "\n").encode("ascii"),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert token.encode("ascii") not in completed.stdout
    assert token.encode("ascii") not in completed.stderr
    return completed


def _api_key_rows(home: Path) -> list[tuple[str, str, int]]:
    rows: list[tuple[str, str, int]] = []
    for database in home.rglob("api_keys.db"):
        with sqlite3.connect(database) as connection:
            rows.extend(
                (str(name), str(role), int(enabled))
                for name, role, enabled in connection.execute(
                    "SELECT name, role, enabled FROM api_keys ORDER BY name"
                )
            )
    return sorted(rows)


def _appshell_session_count(home: Path) -> int:
    total = 0
    for database in home.rglob("appshell_sessions.db"):
        with sqlite3.connect(database) as connection:
            total += int(
                connection.execute("SELECT COUNT(*) FROM appshell_sessions").fetchone()[0]
            )
    return total


def _desktop_identity_counts(home: Path) -> dict[str, int]:
    counts = {"api_keys": 0, "auth_sessions": 0, "managed_api_keys": 0}
    for database in home.rglob("api_keys.db"):
        with sqlite3.connect(database) as connection:
            for table in counts:
                counts[table] += int(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                )
    counts["appshell_sessions"] = _appshell_session_count(home)
    return counts


def _identity_test_app(personal_state: Path, work_state: Path) -> FastAPI:
    from js.appshell.principal import AppShellSessionStore

    def child(state_dir: Path) -> FastAPI:
        settings = SimpleNamespace(state_dir=state_dir)
        app = FastAPI()
        app.state.runtime_settings = settings
        return app

    parent = FastAPI()
    parent.state.personal_app = child(personal_state)
    parent.state.work_app = child(work_state)
    parent.state.appshell_session_store = AppShellSessionStore(
        personal_state / "appshell_sessions.db"
    )
    return parent


def _auth_identity_rows(state_dir: Path) -> dict[str, list[tuple[object, ...]]]:
    with sqlite3.connect(state_dir / "api_keys.db") as connection:
        return {
            "api_keys": connection.execute(
                "SELECT key_hash, name, role, created_at, last_used, enabled "
                "FROM api_keys ORDER BY key_hash"
            ).fetchall(),
            "auth_sessions": connection.execute(
                "SELECT token_hash, key_hash, created_at, expires_at "
                "FROM auth_sessions ORDER BY token_hash"
            ).fetchall(),
            "managed_api_keys": connection.execute(
                "SELECT key_hash, issuer, created_at FROM managed_api_keys "
                "ORDER BY key_hash"
            ).fetchall(),
        }


@pytest.mark.parametrize("active_parent", [False, True])
def test_desktop_startup_preserves_ordinary_same_name_keys_and_auth_sessions(
    tmp_path: Path,
    active_parent: bool,
) -> None:
    from desktop.sidecar.host import EphemeralDesktopIdentity
    from js.web.auth import AuthManager

    personal_state = tmp_path / "personal-state"
    work_state = tmp_path / "work-state"
    app = _identity_test_app(personal_state, work_state)
    shared_key = "js_" + "e" * 43
    owner: str | None = None
    for state_dir in (personal_state, work_state):
        auth = AuthManager(state_dir)
        if active_parent:
            ordinary_key = shared_key
            ordinary_identity = auth.provision_existing_key(
                ordinary_key,
                name="desktop-bootstrap-ephemeral",
                role="admin",
            )
            owner = str(ordinary_identity["key_hash"])
        else:
            ordinary_key = auth.create_key(
                "desktop-bootstrap-ephemeral",
                role="admin",
            )
        auth.create_session(ordinary_key)
    if active_parent:
        assert owner is not None
        app.state.appshell_session_store.create(
            owner=owner,
            mode_roles={"personal": "admin", "work": "admin"},
        )
    before = {
        state_dir: _auth_identity_rows(state_dir)
        for state_dir in (personal_state, work_state)
    }

    identity = EphemeralDesktopIdentity(app)
    identity.close()

    assert {
        state_dir: _auth_identity_rows(state_dir)
        for state_dir in (personal_state, work_state)
    } == before


def test_desktop_startup_purges_only_inactive_managed_crash_residue(
    tmp_path: Path,
) -> None:
    from desktop.sidecar.host import EphemeralDesktopIdentity
    from js.web.auth import AuthManager

    issuer = "js-agent-desktop-bootstrap-v1"
    personal_state = tmp_path / "personal-state"
    work_state = tmp_path / "work-state"
    app = _identity_test_app(personal_state, work_state)
    key = "js_" + "c" * 43
    for state_dir in (personal_state, work_state):
        auth = AuthManager(state_dir)
        auth.provision_managed_key(
            key,
            name="desktop-bootstrap-ephemeral",
            role="admin",
            issuer=issuer,
        )
        auth.create_session(key)

    identity = EphemeralDesktopIdentity(app)
    identity.close()

    for state_dir in (personal_state, work_state):
        assert _auth_identity_rows(state_dir) == {
            "api_keys": [],
            "auth_sessions": [],
            "managed_api_keys": [],
        }


def test_desktop_startup_revokes_managed_identity_with_active_parent_session(
    tmp_path: Path,
) -> None:
    from desktop.sidecar.host import EphemeralDesktopIdentity
    from js.web.auth import AuthManager

    issuer = "js-agent-desktop-bootstrap-v1"
    personal_state = tmp_path / "personal-state"
    work_state = tmp_path / "work-state"
    app = _identity_test_app(personal_state, work_state)
    key = "js_" + "d" * 43
    owner: str | None = None
    for state_dir in (personal_state, work_state):
        identity = AuthManager(state_dir).provision_managed_key(
            key,
            name="desktop-bootstrap-ephemeral",
            role="admin",
            issuer=issuer,
        )
        owner = str(identity["key_hash"])
    assert owner is not None
    old_token, _old_principal = app.state.appshell_session_store.create(
        owner=owner,
        mode_roles={"personal": "admin", "work": "admin"},
    )
    for state_dir in (personal_state, work_state):
        AuthManager(state_dir).create_session(key)

    identity_broker = EphemeralDesktopIdentity(app)
    identity_broker.close()

    assert app.state.appshell_session_store.resolve(old_token) is None
    for state_dir in (personal_state, work_state):
        assert _auth_identity_rows(state_dir) == {
            "api_keys": [],
            "auth_sessions": [],
            "managed_api_keys": [],
        }


def test_appshell_session_schema_adds_desktop_provenance_columns(tmp_path: Path) -> None:
    from js.appshell.principal import AppShellSessionStore

    database = tmp_path / "appshell_sessions.db"
    AppShellSessionStore(database)

    with sqlite3.connect(database) as connection:
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(appshell_sessions)")
        }
    assert {"issuer", "generation"} <= columns


def test_work_provision_failure_rolls_back_only_new_managed_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from desktop.sidecar.host import EphemeralDesktopIdentity
    from js.web.auth import AuthManager

    personal_state = tmp_path / "personal-state"
    work_state = tmp_path / "work-state"
    app = _identity_test_app(personal_state, work_state)
    for state_dir in (personal_state, work_state):
        auth = AuthManager(state_dir)
        ordinary_key = auth.create_key("desktop-bootstrap-ephemeral", role="admin")
        auth.create_session(ordinary_key)
    before = {
        state_dir: _auth_identity_rows(state_dir)
        for state_dir in (personal_state, work_state)
    }

    original_provision = AuthManager.provision_managed_key

    def fail_work_provision(
        self: AuthManager,
        key: str,
        *,
        name: str,
        role: str,
        issuer: str,
    ) -> dict[str, Any]:
        if self._db_path.parent == work_state:
            raise RuntimeError("injected Work provisioning failure")
        return original_provision(self, key, name=name, role=role, issuer=issuer)

    monkeypatch.setattr(AuthManager, "provision_managed_key", fail_work_provision)
    identity = EphemeralDesktopIdentity(app)

    with pytest.raises(RuntimeError, match="injected Work provisioning failure"):
        identity.create_parent_session()

    assert {
        state_dir: _auth_identity_rows(state_dir)
        for state_dir in (personal_state, work_state)
    } == before
    assert _appshell_session_count(tmp_path) == 0


def test_work_ordinary_key_collision_is_not_adopted_or_rolled_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from desktop.sidecar import host
    from js.web.auth import AuthManager

    personal_state = tmp_path / "personal-state"
    work_state = tmp_path / "work-state"
    app = _identity_test_app(personal_state, work_state)
    fixed_key = "js_" + "f" * 43
    work_auth = AuthManager(work_state)
    work_auth.provision_existing_key(
        fixed_key,
        name="desktop-bootstrap-ephemeral",
        role="admin",
    )
    work_auth.create_session(fixed_key)
    work_before = _auth_identity_rows(work_state)
    monkeypatch.setattr(host, "_generate_key", lambda: fixed_key)
    identity = host.EphemeralDesktopIdentity(app)

    with pytest.raises(ValueError, match="managed API key identity already exists"):
        identity.create_parent_session()

    assert _auth_identity_rows(personal_state) == {
        "api_keys": [],
        "auth_sessions": [],
        "managed_api_keys": [],
    }
    assert _auth_identity_rows(work_state) == work_before
    assert _appshell_session_count(tmp_path) == 0


def test_close_revokes_parent_session_before_keys_and_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from desktop.sidecar.host import EphemeralDesktopIdentity
    from js.web.auth import AuthManager

    personal_state = tmp_path / "personal-state"
    work_state = tmp_path / "work-state"
    app = _identity_test_app(personal_state, work_state)
    identity = EphemeralDesktopIdentity(app)
    parent_token, _principal = identity.create_parent_session()
    store = app.state.appshell_session_store
    observed_session_absence: list[bool] = []
    original_revoke = AuthManager.revoke_managed_key

    def observe_revoke(
        self: AuthManager,
        key_hash: str,
        *,
        issuer: str,
    ) -> bool:
        observed_session_absence.append(store.resolve(parent_token) is None)
        return original_revoke(self, key_hash, issuer=issuer)

    monkeypatch.setattr(AuthManager, "revoke_managed_key", observe_revoke)

    identity.close()
    identity.close()

    assert observed_session_absence == [True, True]
    assert store.resolve(parent_token) is None
    assert _appshell_session_count(tmp_path) == 0
    for state_dir in (personal_state, work_state):
        assert _auth_identity_rows(state_dir) == {
            "api_keys": [],
            "auth_sessions": [],
            "managed_api_keys": [],
        }


def test_close_preserves_session_and_both_managed_keys_when_session_revoke_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from desktop.sidecar.host import EphemeralDesktopIdentity

    personal_state = tmp_path / "personal-state"
    work_state = tmp_path / "work-state"
    app = _identity_test_app(personal_state, work_state)
    identity = EphemeralDesktopIdentity(app)
    parent_token, _principal = identity.create_parent_session()
    store = app.state.appshell_session_store
    before = {
        state_dir: _auth_identity_rows(state_dir)
        for state_dir in (personal_state, work_state)
    }

    with monkeypatch.context() as patch:
        patch.setattr(
            store,
            "revoke",
            lambda _token: (_ for _ in ()).throw(OSError("injected session revoke failure")),
        )
        identity.close()

    assert store.resolve(parent_token) is not None
    assert _appshell_session_count(tmp_path) == 1
    assert {
        state_dir: _auth_identity_rows(state_dir)
        for state_dir in (personal_state, work_state)
    } == before

    identity.close()
    assert store.resolve(parent_token) is None
    assert _appshell_session_count(tmp_path) == 0
    for state_dir in (personal_state, work_state):
        assert _auth_identity_rows(state_dir) == {
            "api_keys": [],
            "auth_sessions": [],
            "managed_api_keys": [],
        }


def test_close_preserves_keys_until_all_parent_sessions_for_owner_are_absent(
    tmp_path: Path,
) -> None:
    from desktop.sidecar.host import EphemeralDesktopIdentity

    personal_state = tmp_path / "personal-state"
    work_state = tmp_path / "work-state"
    app = _identity_test_app(personal_state, work_state)
    identity = EphemeralDesktopIdentity(app)
    parent_token, principal = identity.create_parent_session()
    store = app.state.appshell_session_store
    second_token, _second_principal = store.create(
        owner=principal.owner,
        mode_roles={"personal": "admin", "work": "admin"},
    )
    before = {
        state_dir: _auth_identity_rows(state_dir)
        for state_dir in (personal_state, work_state)
    }

    identity.close()

    assert store.resolve(parent_token) is None
    assert store.resolve(second_token) is not None
    assert _appshell_session_count(tmp_path) == 1
    assert {
        state_dir: _auth_identity_rows(state_dir)
        for state_dir in (personal_state, work_state)
    } == before

    assert store.revoke(second_token)
    identity.close()
    assert _appshell_session_count(tmp_path) == 0
    for state_dir in (personal_state, work_state):
        assert _auth_identity_rows(state_dir) == {
            "api_keys": [],
            "auth_sessions": [],
            "managed_api_keys": [],
        }


def test_close_retries_only_issuer_marked_key_residue_after_partial_key_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from desktop.sidecar.host import EphemeralDesktopIdentity
    from js.web.auth import AuthManager

    personal_state = tmp_path / "personal-state"
    work_state = tmp_path / "work-state"
    app = _identity_test_app(personal_state, work_state)
    identity = EphemeralDesktopIdentity(app)
    parent_token, _principal = identity.create_parent_session()
    store = app.state.appshell_session_store
    original_revoke = AuthManager.revoke_managed_key

    def fail_work_revoke_once(
        self: AuthManager,
        key_hash: str,
        *,
        issuer: str,
    ) -> bool:
        if self._db_path.parent == work_state:
            raise OSError("injected Work key revoke failure")
        return original_revoke(self, key_hash, issuer=issuer)

    with monkeypatch.context() as patch:
        patch.setattr(AuthManager, "revoke_managed_key", fail_work_revoke_once)
        identity.close()

    assert store.resolve(parent_token) is None
    assert _appshell_session_count(tmp_path) == 0
    assert _auth_identity_rows(personal_state) == {
        "api_keys": [],
        "auth_sessions": [],
        "managed_api_keys": [],
    }
    work_residue = _auth_identity_rows(work_state)
    assert len(work_residue["api_keys"]) == 1
    assert work_residue["auth_sessions"] == []
    assert len(work_residue["managed_api_keys"]) == 1
    assert work_residue["api_keys"][0][0] == work_residue["managed_api_keys"][0][0]

    identity.close()
    identity.close()
    assert _auth_identity_rows(work_state) == {
        "api_keys": [],
        "auth_sessions": [],
        "managed_api_keys": [],
    }


def test_ready_sentinel_is_canonical_once_and_token_stays_off_process_metadata(
    tmp_path: Path,
) -> None:
    token = "23" * 32
    with _running_host(tmp_path, token=token) as (process, ready):
        assert ready == {
            "pid": ready["pid"],
            "port": ready["port"],
            "schema": "JSAgentHostReadyV1",
            "source_digest": SOURCE_DIGEST,
        }
        assert isinstance(ready["port"], int)
        assert 0 < ready["port"] < 65536
        assert ready["port"] != 8765
        if ready["pid"] != process.pid:
            parent_pid = subprocess.check_output(
                ["/bin/ps", "-p", str(ready["pid"]), "-o", "ppid="],
                text=True,
            ).strip()
            assert int(parent_pid) == process.pid

        assert process.stdout is not None
        canonical = json.dumps(ready, sort_keys=True, separators=(",", ":"))
        # The first line already consumed by the helper must use the one
        # canonical JSON representation.
        assert canonical == (
            f'{{"pid":{ready["pid"]},"port":{ready["port"]},'
            '"schema":"JSAgentHostReadyV1",'
            f'"source_digest":"{SOURCE_DIGEST}"}}'
        )
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            assert selector.select(0.2) == []
        finally:
            selector.close()

        process_metadata = subprocess.check_output(
            [
                "/bin/ps",
                "-E",
                "-ww",
                "-p",
                f"{process.pid},{ready['pid']}",
                "-o",
                "command=",
            ],
            text=True,
        )
        assert token not in process_metadata


@pytest.mark.parametrize(
    ("case", "payload"),
    [
        ("missing", None),
        ("unreadable", None),
        ("symlink", None),
        ("fifo", None),
        ("socket", None),
        ("device", None),
        ("empty", b""),
        ("non_ascii", b"\xff" * 64),
        ("uppercase", ("AB" * 32).encode("ascii")),
        ("non_hex", b"g" * 64),
        ("short", b"a" * 63),
        ("long", b"a" * 65),
    ],
)
def test_host_rejects_missing_unreadable_or_malformed_embedded_digest_before_stdin(
    tmp_path: Path,
    case: str,
    payload: bytes | None,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    embedded = tmp_path / "embedded_source_digest.txt"
    if case == "unreadable":
        embedded.mkdir()
    elif case == "symlink":
        target = tmp_path / "valid_digest.txt"
        target.write_text(SOURCE_DIGEST, encoding="ascii")
        embedded.symlink_to(target)
    elif case == "fifo":
        os.mkfifo(embedded)
    elif case == "socket":
        embedded = Path("/tmp") / f"js-agent-{os.getpid()}-{time.time_ns()}.sock"
        unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix_socket.bind(str(embedded))
    elif case == "device":
        embedded = Path("/dev/null")
    elif payload is not None:
        embedded.write_bytes(payload)

    env = os.environ.copy()
    env.update({"HOME": str(home), "PYTHONPATH": str(REPO_ROOT)})
    process = subprocess.Popen(
        [*_source_host_command(embedded), "--source-digest", SOURCE_DIGEST],
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.wait(timeout=5) == 64, "Host blocked reading bootstrap stdin"
        assert process.stdout is not None
        assert process.stderr is not None
        assert process.stdout.read() == b""
        assert process.stderr.read() == b"desktop host provenance validation failed\n"
        assert list(home.rglob("*.db")) == []
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if case == "socket":
            unix_socket.close()
            embedded.unlink(missing_ok=True)


def test_host_rejects_fifo_even_when_writer_supplies_valid_digest_before_stdin(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    embedded = tmp_path / "embedded_source_digest.txt"
    os.mkfifo(embedded)
    writer = subprocess.Popen(
        [
            str(PYTHON),
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(('ab' * 32).encode())",
            str(embedded),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    env = os.environ.copy()
    env.update({"HOME": str(home), "PYTHONPATH": str(REPO_ROOT)})
    process = subprocess.Popen(
        [*_source_host_command(embedded), "--source-digest", SOURCE_DIGEST],
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.wait(timeout=5) == 64, "FIFO provenance reached bootstrap stdin"
        assert process.stdout is not None
        assert process.stderr is not None
        assert process.stdout.read() == b""
        assert process.stderr.read() == b"desktop host provenance validation failed\n"
        assert list(home.rglob("*.db")) == []
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if writer.poll() is None:
            writer.kill()
        writer.wait(timeout=5)


def test_embedded_digest_loader_closes_file_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from desktop import source_digest

    embedded = tmp_path / "embedded_source_digest.txt"
    embedded.write_text(SOURCE_DIGEST, encoding="ascii")
    monkeypatch.setattr(source_digest, "_EMBEDDED_DIGEST_FILE", embedded)
    before = set(os.listdir("/dev/fd"))

    for _ in range(20):
        assert source_digest.load_embedded_sidecar_digest() == SOURCE_DIGEST

    assert set(os.listdir("/dev/fd")) == before


def test_host_rejects_embedded_digest_mismatch_without_startup_effects(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    embedded = tmp_path / "embedded_source_digest.txt"
    embedded.write_text("cd" * 32, encoding="ascii")
    env = os.environ.copy()
    env.update({"HOME": str(home), "PYTHONPATH": str(REPO_ROOT)})
    process = subprocess.Popen(
        [*_source_host_command(embedded), "--source-digest", SOURCE_DIGEST],
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.wait(timeout=5) == 64, "Host blocked reading bootstrap stdin"
        assert process.stdout is not None
        assert process.stderr is not None
        assert process.stdout.read() == b""
        stderr = process.stderr.read()
        assert stderr == b"desktop host provenance validation failed\n"
        assert SOURCE_DIGEST.encode("ascii") not in stderr
        assert list(home.rglob("*.db")) == []
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_matching_host_passes_validated_embedded_digest_to_ready_serve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from desktop import source_digest
    from desktop.sidecar import host

    class EmbeddedDigest(str):
        pass

    class Listener:
        def getsockname(self) -> tuple[str, int]:
            return ("127.0.0.1", 43127)

        def close(self) -> None:
            return None

    class Identity:
        def close(self) -> None:
            return None

    embedded = EmbeddedDigest(SOURCE_DIGEST)
    observed: dict[str, object] = {}

    async def fake_serve(**kwargs: object) -> int:
        observed.update(kwargs)
        return 0

    monkeypatch.setattr(source_digest, "load_embedded_sidecar_digest", lambda: embedded)
    monkeypatch.setattr(host, "_read_bootstrap_token", lambda: "01" * 32)
    monkeypatch.setattr(host, "_bind_loopback_socket", Listener)
    monkeypatch.setattr(
        host,
        "create_desktop_host_app",
        lambda **_kwargs: (object(), Identity()),
    )
    monkeypatch.setattr(host, "_serve", fake_serve)

    assert host.main(["--source-digest", SOURCE_DIGEST]) == 0
    assert observed["source_digest"] is embedded


def test_bootstrap_token_exchanges_once_for_httponly_parent_session(
    tmp_path: Path,
) -> None:
    token = "45" * 32
    with _running_host(tmp_path, token=token) as (_process, ready):
        wrong_status, _, _ = _request(
            ready,
            "POST",
            "/api/appshell/desktop-bootstrap",
            token="67" * 32,
        )
        assert wrong_status == 401

        status, payload, headers = _request(
            ready,
            "POST",
            "/api/appshell/desktop-bootstrap",
            token=token,
        )
        assert status == 200
        assert payload["success"] is True
        cookie_header = next(value for key, value in headers if key.lower() == "set-cookie")
        assert cookie_header.startswith("js_appshell_session=")
        assert "HttpOnly" in cookie_header
        assert "samesite=strict" in cookie_header.lower()
        cookie = cookie_header.split(";", 1)[0]

        authenticated, status_payload, _ = _request(
            ready,
            "GET",
            "/api/status",
            cookie=cookie,
        )
        assert authenticated == 200
        assert status_payload["product_id"] == "js-agent"

        capabilities_status, capabilities, _ = _request(
            ready,
            "GET",
            "/api/appshell/capabilities",
            cookie=cookie,
        )
        assert capabilities_status == 200
        switch_status, switch_payload, _ = _request(
            ready,
            "POST",
            "/api/appshell/switch",
            cookie=cookie,
            payload={
                "expected_from_mode": "personal",
                "to_mode": "work",
                "session_id": None,
                "workspace_handle": capabilities["workspace_handles"]["work"],
            },
        )
        assert switch_status == 200
        assert switch_payload["to_mode"] == "work"
        work_status, work_payload, _ = _request(
            ready,
            "GET",
            "/api/status",
            cookie=cookie,
        )
        assert work_status == 200
        assert work_payload["product_id"] == "js-work"

        replay_status, replay_payload, _ = _request(
            ready,
            "POST",
            "/api/appshell/desktop-bootstrap",
            token=token,
        )
        assert replay_status == 409
        assert replay_payload["detail"]["code"] == "bootstrap_token_consumed"


def test_crash_restart_rejects_old_cookie_after_old_port_capture_attempt(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    old_bootstrap = "91" * 32
    old_process, old_ready = _launch_host(home, token=old_bootstrap)
    old_status, _old_payload, old_headers = _request(
        old_ready,
        "POST",
        "/api/appshell/desktop-bootstrap",
        token=old_bootstrap,
    )
    assert old_status == 200
    old_cookie = next(
        value.split(";", 1)[0]
        for key, value in old_headers
        if key.casefold() == "set-cookie"
        and value.startswith("js_appshell_session=")
    )
    old_port = int(old_ready["port"])

    os.killpg(old_process.pid, signal.SIGKILL)
    assert old_process.wait(timeout=10) == -signal.SIGKILL

    capture = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    capture.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    capture.bind(("127.0.0.1", old_port))
    capture.listen(1)
    try:
        def replay_to_captured_origin() -> int:
            connection = http.client.HTTPConnection("127.0.0.1", old_port, timeout=10)
            connection.request(
                "GET",
                "/api/status",
                headers={
                    "Cookie": old_cookie,
                    "Origin": f"http://127.0.0.1:{old_port}",
                },
            )
            response = connection.getresponse()
            response.read()
            connection.close()
            return response.status

        with ThreadPoolExecutor(max_workers=1) as pool:
            replay = pool.submit(replay_to_captured_origin)
            captured_connection, _peer = capture.accept()
            with captured_connection:
                captured_request = captured_connection.recv(8192)
                assert f"Cookie: {old_cookie}\r\n".encode() in captured_request
                captured_connection.sendall(
                    b"HTTP/1.1 401 Unauthorized\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n\r\n{}"
                )
            assert replay.result(timeout=10) == 401

        new_bootstrap = "92" * 32
        new_process, new_ready = _launch_host(home, token=new_bootstrap)
        try:
            assert int(new_ready["port"]) != old_port
            stale_status, _stale_payload, _stale_headers = _request(
                new_ready,
                "GET",
                "/api/status",
                cookie=old_cookie,
            )
            assert stale_status == 401

            bootstrap_status, _bootstrap_payload, new_headers = _request(
                new_ready,
                "POST",
                "/api/appshell/desktop-bootstrap",
                token=new_bootstrap,
            )
            assert bootstrap_status == 200
            new_cookie = next(
                value.split(";", 1)[0]
                for key, value in new_headers
                if key.casefold() == "set-cookie"
                and value.startswith("js_appshell_session=")
            )
            current_status, _current_payload, _current_headers = _request(
                new_ready,
                "GET",
                "/api/status",
                cookie=new_cookie,
            )
            assert current_status == 200
        finally:
            if new_process.poll() is None:
                new_process.terminate()
            assert new_process.wait(timeout=10) in {0, -signal.SIGTERM}
    finally:
        capture.close()

    assert _desktop_identity_counts(home) == {
        "api_keys": 0,
        "auth_sessions": 0,
        "managed_api_keys": 0,
        "appshell_sessions": 0,
    }


def test_desktop_host_blocks_generic_bootstrap_without_consuming_native_token(
    tmp_path: Path,
) -> None:
    token = "a1" * 32
    home = tmp_path / "home"
    with _running_host(tmp_path, token=token) as (_process, ready):
        generic_status, generic_payload, generic_headers = _request(
            ready,
            "POST",
            "/api/appshell/bootstrap",
        )
        assert {
            "status": generic_status,
            "payload": generic_payload,
            "set_cookie": any(
                key.lower() == "set-cookie" for key, _value in generic_headers
            ),
            "api_keys": _api_key_rows(home),
            "sessions": _appshell_session_count(home),
            "recovery_keys": [
                path.name for path in home.rglob("bootstrap_admin_key.txt")
            ],
        } == {
            "status": 410,
            "payload": {"detail": {"code": "desktop_bootstrap_required"}},
            "set_cookie": False,
            "api_keys": [],
            "sessions": 0,
            "recovery_keys": [],
        }

        wrong_status, _, _ = _request(
            ready,
            "POST",
            "/api/appshell/desktop-bootstrap",
            token="a2" * 32,
        )
        assert wrong_status == 401
        assert _api_key_rows(home) == []
        assert _appshell_session_count(home) == 0

        desktop_status, _, _ = _request(
            ready,
            "POST",
            "/api/appshell/desktop-bootstrap",
            token=token,
        )
        assert desktop_status == 200
        assert _appshell_session_count(home) == 1
        assert _api_key_rows(home) == [
            ("desktop-bootstrap-ephemeral", "admin", 1),
            ("desktop-bootstrap-ephemeral", "admin", 1),
        ]
        assert list(home.rglob("bootstrap_admin_key.txt")) == []

    assert _api_key_rows(home) == []
    assert list(home.rglob("bootstrap_admin_key.txt")) == []


def test_generic_bootstrap_cannot_win_concurrent_race_with_desktop_token(
    tmp_path: Path,
) -> None:
    token = "b1" * 32
    home = tmp_path / "home"
    with _running_host(tmp_path, token=token) as (_process, ready):
        wrong_status, _, _ = _request(
            ready,
            "POST",
            "/api/appshell/desktop-bootstrap",
            token="b2" * 32,
        )
        assert wrong_status == 401

        barrier = Barrier(2)

        def generic_bootstrap() -> tuple[int, dict[str, Any], list[tuple[str, str]]]:
            barrier.wait()
            return _request(ready, "POST", "/api/appshell/bootstrap")

        def desktop_bootstrap() -> tuple[int, dict[str, Any], list[tuple[str, str]]]:
            barrier.wait()
            return _request(
                ready,
                "POST",
                "/api/appshell/desktop-bootstrap",
                token=token,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            generic_future = executor.submit(generic_bootstrap)
            desktop_future = executor.submit(desktop_bootstrap)
            generic_status, generic_payload, generic_headers = generic_future.result()
            desktop_status, _, desktop_headers = desktop_future.result()

        assert generic_status == 410
        assert generic_payload == {"detail": {"code": "desktop_bootstrap_required"}}
        assert not any(key.lower() == "set-cookie" for key, _value in generic_headers)
        assert desktop_status == 200
        assert any(key.lower() == "set-cookie" for key, _value in desktop_headers)
        assert _appshell_session_count(home) == 1
        assert _api_key_rows(home) == [
            ("desktop-bootstrap-ephemeral", "admin", 1),
            ("desktop-bootstrap-ephemeral", "admin", 1),
        ]
        assert list(home.rglob("bootstrap_admin_key.txt")) == []

        replay_status, replay_payload, _ = _request(
            ready,
            "POST",
            "/api/appshell/desktop-bootstrap",
            token=token,
        )
        assert replay_status == 409
        assert replay_payload["detail"]["code"] == "bootstrap_token_consumed"

    assert _api_key_rows(home) == []
    assert list(home.rglob("bootstrap_admin_key.txt")) == []


def test_bootstrap_token_expires_and_remains_unusable(tmp_path: Path) -> None:
    token = "89" * 32
    with _running_host(tmp_path, token=token, ttl_seconds=1) as (_process, ready):
        time.sleep(1.1)
        status, payload, _ = _request(
            ready,
            "POST",
            "/api/appshell/desktop-bootstrap",
            token=token,
        )
        assert status == 410
        assert payload["detail"]["code"] == "bootstrap_token_expired"
        second_status, _, _ = _request(
            ready,
            "POST",
            "/api/appshell/desktop-bootstrap",
            token=token,
        )
        assert second_status == 410


@pytest.mark.playwright
def test_browser_clears_desktop_fragment_without_recovery_key_or_permanent_admin(
    tmp_path: Path,
) -> None:
    token = "cd" * 32
    home = tmp_path / "home"
    with _running_host(tmp_path, token=token) as (_process, ready):
        completed = _run_async_browser_probe(ready, token=token)
        assert completed.returncode == 0, completed.stderr.decode(
            "utf-8", errors="replace"
        )
        assert json.loads(completed.stdout) == {
            "cookie_http_only": True,
            "cookie_visible": False,
            "fragment_cleared": True,
            "product_id": "js-agent",
            "status": 200,
        }
        assert _appshell_session_count(home) == 1
        assert len(_api_key_rows(home)) == 2
        assert list(home.rglob("bootstrap_admin_key.txt")) == []

    assert _desktop_identity_counts(home) == {
        "api_keys": 0,
        "auth_sessions": 0,
        "managed_api_keys": 0,
        "appshell_sessions": 0,
    }
    assert list(home.rglob("bootstrap_admin_key.txt")) == []


@pytest.mark.playwright
def test_browser_probe_exception_closes_resources_and_host_identity(
    tmp_path: Path,
) -> None:
    token = "ce" * 32
    home = tmp_path / "home"
    with _running_host(tmp_path, token=token) as (_process, ready):
        completed = _run_async_browser_probe(
            ready,
            token=token,
            inject_failure=True,
        )
        assert completed.returncode == 70
        assert completed.stdout == b""
        assert completed.stderr == b"async desktop browser probe failed\n"
        assert _appshell_session_count(home) == 1
        assert len(_api_key_rows(home)) == 2

    assert _desktop_identity_counts(home) == {
        "api_keys": 0,
        "auth_sessions": 0,
        "managed_api_keys": 0,
        "appshell_sessions": 0,
    }
    assert list(home.rglob("bootstrap_admin_key.txt")) == []


def _assert_locked_response(
    response: tuple[int, dict[str, Any], list[tuple[str, str]]],
    *,
    status: int,
    payload: dict[str, Any],
) -> None:
    actual_status, actual_payload, headers = response
    assert actual_status == status
    assert actual_payload == payload
    assert _header_values(headers, "cache-control") == ["no-store"]
    assert _header_values(headers, "set-cookie") == []


@pytest.mark.parametrize("path", ["/docs", "/openapi.json", "/redoc"])
def test_desktop_docs_routes_have_exact_closed_contract(
    tmp_path: Path,
    path: str,
) -> None:
    home = tmp_path / "home"
    with _running_host(tmp_path, token="f1" * 32) as (_process, ready):
        response = _request(ready, "GET", path)
        _assert_locked_response(
            response,
            status=404,
            payload={"detail": {"code": "desktop_docs_disabled"}},
        )
        assert "openapi" not in json.dumps(response[1]).casefold()
        assert _desktop_identity_counts(home) == {
            "api_keys": 0,
            "auth_sessions": 0,
            "managed_api_keys": 0,
            "appshell_sessions": 0,
        }


def test_get_generic_bootstrap_has_exact_guest_contract(tmp_path: Path) -> None:
    home = tmp_path / "home"
    with _running_host(tmp_path, token="f2" * 32) as (_process, ready):
        _assert_locked_response(
            _request(ready, "GET", "/api/appshell/bootstrap"),
            status=405,
            payload={"detail": "Method Not Allowed"},
        )
        assert _desktop_identity_counts(home) == {
            "api_keys": 0,
            "auth_sessions": 0,
            "managed_api_keys": 0,
            "appshell_sessions": 0,
        }


def test_post_generic_session_has_exact_guest_contract(tmp_path: Path) -> None:
    home = tmp_path / "home"
    with _running_host(tmp_path, token="f3" * 32) as (_process, ready):
        _assert_locked_response(
            _request(ready, "POST", "/api/appshell/session", payload={}),
            status=401,
            payload={"detail": "AppShell session is required"},
        )
        assert _desktop_identity_counts(home) == {
            "api_keys": 0,
            "auth_sessions": 0,
            "managed_api_keys": 0,
            "appshell_sessions": 0,
        }


def test_post_generic_bootstrap_has_exact_no_side_effect_contract(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    with _running_host(tmp_path, token="f4" * 32) as (_process, ready):
        _assert_locked_response(
            _request(ready, "POST", "/api/appshell/bootstrap", payload={}),
            status=410,
            payload={"detail": {"code": "desktop_bootstrap_required"}},
        )
        assert _desktop_identity_counts(home) == {
            "api_keys": 0,
            "auth_sessions": 0,
            "managed_api_keys": 0,
            "appshell_sessions": 0,
        }


@pytest.mark.parametrize("path", ["/api/auth/setup", "/api/auth/login"])
def test_hidden_auth_routes_have_exact_guest_contract(
    tmp_path: Path,
    path: str,
) -> None:
    home = tmp_path / "home"
    with _running_host(tmp_path, token="f5" * 32) as (_process, ready):
        _assert_locked_response(
            _request(ready, "POST", path, payload={}),
            status=404,
            payload={"detail": "Not Found"},
        )
        assert _desktop_identity_counts(home) == {
            "api_keys": 0,
            "auth_sessions": 0,
            "managed_api_keys": 0,
            "appshell_sessions": 0,
        }


def test_desktop_csp_uses_precise_port_not_wildcard(tmp_path: Path) -> None:
    token = "e1" * 32
    with _running_host(tmp_path, token=token) as (_process, ready):
        port = int(ready["port"])
        status, _, headers = _request(ready, "GET", "/api/appshell/health")
        assert status == 200
        csp = next(
            value for key, value in headers if key.lower() == "content-security-policy"
        )
        assert f"ws://127.0.0.1:{port}" in csp
        assert "ws://127.0.0.1:*" not in csp
        assert "ws://127.0.0.1:0" not in csp
        other_port = 1 if port != 1 else 2
        assert f"ws://127.0.0.1:{other_port}" not in csp


@pytest.mark.parametrize("token", ["", "x" * 64, "00" * 31, "00" * 33])
def test_host_rejects_non_256_bit_lower_hex_stdin_token(
    tmp_path: Path,
    token: str,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    env = os.environ.copy()
    env.update({"HOME": str(home), "PYTHONPATH": str(REPO_ROOT)})
    started_at = time.monotonic()
    completed = subprocess.run(
        [
            *_host_command(),
            "--source-digest",
            SOURCE_DIGEST,
        ],
        cwd=REPO_ROOT,
        env=env,
        input=(token + "\n").encode("utf-8"),
        capture_output=True,
        timeout=75 if os.environ.get("JS_AGENT_HOST_BINARY") else 15,
        check=False,
    )
    assert completed.returncode == 64
    assert time.monotonic() - started_at < (
        35.0 if os.environ.get("JS_AGENT_HOST_BINARY") else 5.0
    )
    assert completed.stdout == b""
    if token:
        assert token.encode("utf-8") not in completed.stderr

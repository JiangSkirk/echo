from __future__ import annotations

import os
import plistlib
import re
import signal
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from desktop.tests.candidate_app import resolve_candidate_app as resolve_candidate_app

SIDECAR_NAME = "js-agent-host"
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _process_rows() -> dict[int, tuple[int, int, str]]:
    output = subprocess.check_output(
        ["/bin/ps", "-axo", "pid=,ppid=,pgid=,command="],
        text=True,
    )
    rows: dict[int, tuple[int, int, str]] = {}
    for raw in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(\d+)\s+(\d+)\s+(.*)", raw)
        if match:
            rows[int(match.group(1))] = (
                int(match.group(2)),
                int(match.group(3)),
                match.group(4),
            )
    return rows


def _descendants(root_pid: int, rows: dict[int, tuple[int, int, str]]) -> set[int]:
    found: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, (parent, _group, _command) in rows.items():
            if pid not in found and (parent == root_pid or parent in found):
                found.add(pid)
                changed = True
    return found


def _listeners(pids: set[int]) -> set[tuple[str, int]]:
    if not pids:
        return set()
    completed = subprocess.run(
        [
            "/usr/sbin/lsof",
            "-nP",
            "-a",
            "-p",
            ",".join(str(pid) for pid in sorted(pids)),
            "-iTCP",
            "-sTCP:LISTEN",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    listeners: set[tuple[str, int]] = set()
    for line in completed.stdout.splitlines()[1:]:
        match = re.search(r"TCP\s+([^: ]+):(\d+)\s+\(LISTEN\)", line)
        if match:
            listeners.add((match.group(1), int(match.group(2))))
    return listeners


def _http_root_ready(listener: tuple[str, int]) -> bool:
    """Require the Host HTTP stack, not merely its pre-app bound socket."""
    host, port = listener
    try:
        with _NO_PROXY_OPENER.open(f"http://{host}:{port}/", timeout=1) as response:
            return 200 <= int(response.status) < 500
    except urllib.error.HTTPError as error:
        return 400 <= int(error.code) < 500
    except (OSError, TimeoutError, urllib.error.URLError):
        return False


def _ephemeral_admin_count(home: Path) -> int:
    count = 0
    for database in home.rglob("api_keys.db"):
        with sqlite3.connect(database) as connection:
            count += int(
                connection.execute(
                    "SELECT COUNT(*) FROM api_keys WHERE name = ?",
                    ("desktop-bootstrap-ephemeral",),
                ).fetchone()[0]
            )
    return count


def _terminate_owned_process_group(process: subprocess.Popen[bytes]) -> None:
    """TERM → bounded wait → KILL → wait/reap. Never pkill/killall by name."""
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.terminate()
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=15)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def test_bundle_runs_outside_repo_with_empty_path_and_cleans_process_group(
    tmp_path: Path,
) -> None:
    """Isolated process-group smoke: unique HOME/state, no suite pollution.

    Uses start_new_session so teardown only reaps this test's process group.
    """
    app = resolve_candidate_app()
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    executable = app / "Contents/MacOS" / str(info["CFBundleExecutable"])
    # Unique nested HOME/state per test invocation to avoid cross-test races.
    home = tmp_path / f"home-{os.getpid()}-{time.time_ns()}"
    launch_dir = tmp_path / f"outside-repository-{os.getpid()}"
    home.mkdir(parents=True)
    launch_dir.mkdir(parents=True)
    env = {
        "HOME": str(home),
        "PATH": "",
        "TMPDIR": str(tmp_path / "tmp"),
        "TMP": str(tmp_path / "tmp"),
        "TEMP": str(tmp_path / "tmp"),
    }
    (tmp_path / "tmp").mkdir(exist_ok=True)
    process = subprocess.Popen(
        [str(executable)],
        cwd=launch_dir,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    observed_descendants: set[int] = set()
    listener: tuple[str, int] | None = None
    stable_ready_observations = 0
    try:
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            if process.poll() is not None:
                assert process.stderr is not None
                raise AssertionError(
                    "desktop exited before listener: "
                    + process.stderr.read().decode("utf-8", errors="replace")
                )
            rows = _process_rows()
            observed_descendants = _descendants(process.pid, rows)
            # Include the root app pid itself when scanning listeners.
            matches = _listeners(observed_descendants | {process.pid})
            if len(matches) == 1:
                candidate = next(iter(matches))
                if _http_root_ready(candidate):
                    if listener == candidate:
                        stable_ready_observations += 1
                    else:
                        listener = candidate
                        stable_ready_observations = 1
                    if stable_ready_observations >= 2:
                        break
                else:
                    listener = None
                    stable_ready_observations = 0
            time.sleep(0.25)
        assert listener is not None and stable_ready_observations >= 2, (
            "desktop did not establish one stable HTTP-ready random listener"
        )

        rows = _process_rows()
        descendants = _descendants(process.pid, rows)
        direct_sidecars = {
            pid
            for pid in descendants
            if rows[pid][0] == process.pid and SIDECAR_NAME in rows[pid][2]
        }
        assert len(direct_sidecars) == 1
        unrelated_direct_children = {
            pid
            for pid in descendants
            if rows[pid][0] == process.pid and pid not in direct_sidecars
        }
        assert unrelated_direct_children == set()
        assert listener[0] == "127.0.0.1"
        assert 0 < listener[1] < 65536
        assert listener[1] != 8765

        metadata = subprocess.check_output(
            [
                "/bin/ps",
                "-E",
                "-ww",
                "-p",
                ",".join(str(pid) for pid in sorted({process.pid, *descendants})),
                "-o",
                "command=",
            ],
            text=True,
        )
        assert "#bootstrap=" not in metadata
        assert list(home.rglob("bootstrap_admin_key.txt")) == []
        assert list(home.glob("Library/LaunchAgents/com.titan.js-agent.plist")) == []
    finally:
        _terminate_owned_process_group(process)
        # Bounded reap of any stragglers that were descendants at observation time.
        deadline = time.monotonic() + 10
        alive: set[int] = set()
        while time.monotonic() < deadline:
            rows = _process_rows()
            alive = {pid for pid in observed_descendants if pid in rows}
            if not alive:
                break
            for pid in list(alive):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            time.sleep(0.1)

    rows = _process_rows()
    alive = {pid for pid in observed_descendants if pid in rows}
    assert alive == set(), f"orphan processes remained: {alive}"
    if listener is not None:
        assert listener not in _listeners(observed_descendants | {process.pid})

    assert _ephemeral_admin_count(home) == 0
    assert list(home.rglob("bootstrap_admin_key.txt")) == []


def test_bundle_shutdown_during_sidecar_startup_is_clean(tmp_path: Path) -> None:
    """SIGTERM after sidecar spawn is cancellation, never a Tauri setup panic."""
    app = resolve_candidate_app()
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    executable = app / "Contents/MacOS" / str(info["CFBundleExecutable"])
    home = tmp_path / f"early-stop-home-{os.getpid()}-{time.time_ns()}"
    launch_dir = tmp_path / f"early-stop-outside-repository-{os.getpid()}"
    temp_dir = tmp_path / "early-stop-tmp"
    home.mkdir(parents=True)
    launch_dir.mkdir(parents=True)
    temp_dir.mkdir(parents=True)
    process = subprocess.Popen(
        [str(executable)],
        cwd=launch_dir,
        env={
            "HOME": str(home),
            "PATH": "",
            "TMPDIR": str(temp_dir),
            "TMP": str(temp_dir),
            "TEMP": str(temp_dir),
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    observed: set[int] = set()
    try:
        deadline = time.monotonic() + 60
        sidecar_observed = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            rows = _process_rows()
            descendants = _descendants(process.pid, rows)
            observed.update(descendants)
            if any(
                rows[pid][0] == process.pid and SIDECAR_NAME in rows[pid][2]
                for pid in descendants
            ):
                sidecar_observed = True
                break
            time.sleep(0.1)
        assert sidecar_observed, "desktop never entered sidecar startup"

        process.send_signal(signal.SIGTERM)
        returncode = process.wait(timeout=30)
        stdout, stderr = process.communicate(timeout=5)
        assert returncode == 0, (
            f"startup cancellation exited {returncode}; "
            f"stdout={stdout.decode(errors='replace')[-1000:]!r}; "
            f"stderr={stderr.decode(errors='replace')[-2000:]!r}"
        )
        assert b"panic" not in stderr.lower()
    finally:
        _terminate_owned_process_group(process)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            rows = _process_rows()
            alive = {pid for pid in observed if pid in rows}
            if not alive:
                break
            time.sleep(0.1)
        else:
            for pid in alive:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            raise AssertionError(f"startup cancellation left orphan processes: {alive}")

    assert _ephemeral_admin_count(home) == 0
    assert list(home.rglob("bootstrap_admin_key.txt")) == []

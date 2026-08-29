#!/usr/bin/env python3
"""Live-process multi-owner HTTP trial against a real AppShell Host.

This is an internal deployment trial, not an external audit. Container
compose is documented but not executed on hosts without Docker.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = REPO / "docs" / "security" / "staging-trial-2026-08-29.md"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _write_yaml(
    path: Path,
    workspace: Path,
    state_dir: Path,
    *,
    work_home: Path | None = None,
) -> None:
    lines = []
    if work_home is not None:
        lines.append(f'work_home: "{work_home}"')
    lines.extend(
        (
            f'workspace: "{workspace}"',
            f'state_dir: "{state_dir}"',
            "first_run_completed: true",
            "providers: []",
            "models: []",
            "security:",
            "  api_key_required: true",
            "",
        )
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def _stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=8)


class HttpClient:
    def __init__(self, base: str, origin: str) -> None:
        self.base = base
        self.origin = origin
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.ProxyHandler({}),
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        key: str | None = None,
        body: dict[str, Any] | None = None,
    ) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Origin": self.origin}
        if key:
            headers["X-API-Key"] = key
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            f"{self.base}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(req, timeout=8) as resp:
                raw = resp.read()
                payload: Any = {}
                if raw:
                    try:
                        payload = json.loads(raw.decode("utf-8"))
                    except json.JSONDecodeError:
                        payload = raw.decode("utf-8", errors="replace")
                return int(resp.status), payload
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            payload: Any = {"detail": exc.reason}
            if raw:
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    payload = raw.decode("utf-8", errors="replace")
            return int(exc.code), payload


def _wait_ready(base: str, process: subprocess.Popen[str], log_path: Path) -> None:
    deadline = time.monotonic() + 45
    last = "host did not respond"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                f"{base}/", timeout=1
            ) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(0.2)
    tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
    raise RuntimeError(f"Host failed to start: {last}\nexit={process.poll()}\n{tail}")


def _case(cases: list[dict[str, Any]], name: str, ok: bool, detail: str) -> None:
    cases.append({"name": name, "ok": ok, "detail": detail})


def _search_hits(payload: Any, needle: str) -> bool:
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return False
    return any(needle in json.dumps(item) for item in results)


def run_trial(*, output: Path, minimal: bool) -> dict[str, Any]:
    base_dir = Path(tempfile.mkdtemp(prefix="js-staging-trial-"))
    personal_ws = base_dir / "personal-ws"
    personal_state = base_dir / "personal-state"
    work_home = base_dir / "work-home" / ".js-work"
    personal_ws.mkdir()
    personal_state.mkdir()
    work_home.mkdir(parents=True)
    personal_cfg = base_dir / "personal.yaml"
    work_cfg = base_dir / "work.yaml"
    _write_yaml(personal_cfg, personal_ws, personal_state)
    _write_yaml(
        work_cfg,
        work_home / "workspace",
        work_home / "state",
        work_home=work_home,
    )
    (work_home / "workspace").mkdir()
    (work_home / "state").mkdir()

    from js.web.auth import AuthManager

    auth = AuthManager(personal_state)
    key_a = auth.create_key("owner-a", role="admin")
    key_b = auth.create_key("owner-b", role="admin")
    key_user = auth.create_key("owner-user", role="user")

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    origin = base
    log_path = base_dir / "host.log"
    env = os.environ.copy()
    env.update({"NO_PROXY": "127.0.0.1,localhost", "PYTHONUNBUFFERED": "1"})
    for name in (
        "JS_CONFIG_PATH",
        "JS_STATE_DIR",
        "JS_ALLOWED_ORIGINS",
        "JS_API_KEY_REQUIRED",
    ):
        env.pop(name, None)
    cases: list[dict[str, Any]] = []
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "js",
                "appshell",
                "--personal-config",
                str(personal_cfg),
                "--work-config",
                str(work_cfg),
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
            _wait_ready(base, process, log_path)
            anon = HttpClient(base, origin)
            alice = HttpClient(base, origin)
            bob = HttpClient(base, origin)
            user = HttpClient(base, origin)

            status, _ = anon.request("GET", "/api/status")
            _case(cases, "anon_status_401", status == 401, f"status={status}")

            status, _ = anon.request("GET", "/api/status", key=key_a)
            _case(
                cases,
                "raw_key_without_appshell_session",
                status in {401, 403},
                f"status={status}",
            )

            sa, _ = alice.request("POST", "/api/appshell/session", key=key_a)
            sb, _ = bob.request("POST", "/api/appshell/session", key=key_b)
            su, _ = user.request("POST", "/api/appshell/session", key=key_user)
            _case(
                cases, "session_exchange", sa == 200 and sb == 200 and su == 200, f"{sa}/{sb}/{su}"
            )

            sa, _ = alice.request("GET", "/api/status")
            sb, _ = bob.request("GET", "/api/status")
            _case(cases, "authed_status", sa == 200 and sb == 200, f"{sa}/{sb}")

            created, body = alice.request(
                "POST",
                "/api/memory/semantic",
                body={"key": "trial-secret", "value": "owner-a-secret-token", "category": "fact"},
            )
            _case(cases, "alice_write_memory", created == 200, f"status={created} body={body}")

            searched, payload = bob.request("GET", "/api/memory/search?q=owner-a-secret-token")
            leaked = _search_hits(payload, "owner-a-secret")
            results = payload.get("results") if isinstance(payload, dict) else None
            _case(
                cases,
                "bob_cannot_search_alice_memory",
                searched == 200 and leaked is False,
                f"status={searched} leaked={leaked} n={len(results or [])}",
            )

            audit_b, _ = bob.request("GET", "/api/audit")
            audit_u, _ = user.request("GET", "/api/audit")
            _case(
                cases,
                "non_owner_or_user_audit",
                audit_u == 403,
                f"bob={audit_b} user={audit_u}",
            )

            mixed = HttpClient(base, origin)
            mixed.request("POST", "/api/appshell/session", key=key_a)
            switch_token = "must-stay-owner-a-token"
            switched, _ = mixed.request(
                "POST",
                "/api/memory/semantic",
                key=key_b,
                body={"key": "trial-header-switch", "value": switch_token, "category": "fact"},
            )
            bob_sw, bob_payload = bob.request("GET", f"/api/memory/search?q={switch_token}")
            alice_sw, alice_payload = alice.request("GET", f"/api/memory/search?q={switch_token}")
            bob_hits = _search_hits(bob_payload, switch_token)
            alice_hits = _search_hits(alice_payload, switch_token)
            _case(
                cases,
                "foreign_api_key_cannot_switch_appshell_identity",
                switched == 200
                and bob_sw == 200
                and alice_sw == 200
                and not bob_hits
                and alice_hits,
                f"write={switched} bob_hits={bob_hits} alice_hits={alice_hits}",
            )

            if not minimal:

                def _hit(client: HttpClient) -> int:
                    code, _payload = client.request("GET", "/api/sessions")
                    return code

                with ThreadPoolExecutor(max_workers=8) as pool:
                    codes = list(pool.map(_hit, [alice, bob] * 8))
                _case(
                    cases,
                    "concurrent_session_list",
                    all(code == 200 for code in codes),
                    f"codes={codes}",
                )
        finally:
            _stop(process)

    passed = sum(1 for item in cases if item["ok"])
    summary = {
        "kind": "internal live-deployment trial, not an external audit",
        "started_utc": datetime.now(UTC).isoformat(),
        "base_url": base,
        "docker_compose_staging_ran": False,
        "docker_compose_reason": "docker is not available on this host; process-level only",
        "passed": passed,
        "total": len(cases),
        "ok": passed == len(cases) and bool(cases),
        "cases": cases,
        "work_dir": str(base_dir),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_render_report(summary), encoding="utf-8")
    return summary


def _render_report(summary: dict[str, Any]) -> str:
    rows = [
        f"| `{item['name']}` | {'PASS' if item['ok'] else 'FAIL'} | {item['detail']} |"
        for item in summary["cases"]
    ]
    return "\n".join(
        [
            "# Internal live-deployment trial (2026-08-29)",
            "",
            "This is an **internal live-deployment trial, not an external audit**.",
            "Local process HTTP cannot close `TECH_DEBT.md` ⚫ items that require",
            "people outside this tree.",
            "",
            "## Environment",
            "",
            f"- Host: `{summary['base_url']}` via `js appshell` (uvicorn loopback)",
            f"- Docker staging compose ran: `{summary['docker_compose_staging_ran']}`",
            f"- Reason: {summary['docker_compose_reason']}",
            f"- Work dir: `{summary['work_dir']}`",
            f"- Result: {summary['passed']}/{summary['total']} "
            f"{'PASS' if summary['ok'] else 'FAIL'}",
            "",
            "Reproduce:",
            "",
            "```bash",
            "uv run python scripts/staging_trial.py",
            "```",
            "",
            "Container path (not run this round):",
            "`docker compose -f docker-compose.staging.yaml up --build`",
            "",
            "## Cases",
            "",
            "| Case | Result | Detail |",
            "|------|--------|--------|",
            *rows,
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--minimal", action="store_true")
    args = parser.parse_args()
    summary = run_trial(output=args.output, minimal=args.minimal)
    print(json.dumps({"ok": summary["ok"], "passed": summary["passed"], "total": summary["total"]}))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

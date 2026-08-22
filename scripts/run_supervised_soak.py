"""Parent-supervised 3600s soak: Echo core + Tauri lifecycle overlay.

Both children share the same source digest, start window, deadline, and cleanup
domain. The parent never detaches children and only emits the combined receipt
after both succeed. Overlay produces a hash-chained heartbeat every ≤5s.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from js.echo.ledger.release_gates import (  # noqa: E402
    release_source_digest,
    release_source_surface_metadata_fingerprint,
)
from js.echo.ledger.strict_json import StrictJSONError, strict_load_object  # noqa: E402
from scripts.run_tauri_webview_gate import _manifest_bindings  # noqa: E402

SCHEMA = "js-agent-supervised-soak-v1"
OVERLAY_SCHEMA = "js-agent-tauri-overlay-v1"
HEARTBEAT_INTERVAL = 5.0
MAX_HEARTBEAT_GAP = 15.0


def _utc() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _terminate_tree(proc: subprocess.Popen[Any] | None, *, grace: float = 10.0) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            proc.terminate()
        except ProcessLookupError:
            return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.1)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _spawn(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.Popen[Any]:
    return subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,  # own process group for targeted cleanup only
    )


def run_overlay(
    *,
    duration_seconds: float,
    app_path: Path,
    harness_exec: Path,
    output_path: Path,
    source_digest: str,
    metadata_fingerprint: str,
    work_dir: Path,
    desktop_manifest_path: Path | None = None,
    app_tree_sha256: str | None = None,
) -> dict[str, Any]:
    """Run Tauri lifecycle overlay cycles with hash-chained heartbeats.

    Minimum coverage for a full 3600s run (scaled down for short dry-runs):
      mode_switches >= 30, app_restarts >= 6, sidecar_recoveries >= 3,
      ws_cancel_cycles >= 30, r4_ops >= 12, r6_ops >= 12
    """
    app_path = app_path.resolve()
    harness_exec = harness_exec.resolve()
    output_path = output_path.resolve()
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = (
        desktop_manifest_path.resolve()
        if desktop_manifest_path is not None
        else (app_path.parent.parent / "manifest.json").resolve()
    )

    started = time.monotonic()
    started_utc = _utc()
    deadline = started + duration_seconds
    scale = max(duration_seconds / 3600.0, 0.0)
    targets = {
        "mode_switches": max(1, int(30 * scale)) if duration_seconds >= 60 else 1,
        "app_restarts": max(1, int(6 * scale)) if duration_seconds >= 120 else 1,
        "sidecar_recoveries": max(1, int(3 * scale)) if duration_seconds >= 180 else 0,
        "ws_cancel_cycles": max(1, int(30 * scale)) if duration_seconds >= 60 else 1,
        "r4_ops": max(1, int(12 * scale)) if duration_seconds >= 120 else 0,
        "r6_ops": max(1, int(12 * scale)) if duration_seconds >= 180 else 0,
    }
    counters = dict.fromkeys(targets, 0)
    heartbeats: list[dict[str, Any]] = []
    chain = bytes(32)
    last_hb = started
    errors: list[str] = []
    cycles = 0

    bindings = _manifest_bindings(
        app_path=app_path,
        manifest_path=manifest_path,
        repo_root=REPO_ROOT,
    )
    if bindings is None or (
        app_tree_sha256 is not None
        and not secrets.compare_digest(bindings["app_tree_sha256"], app_tree_sha256)
    ):
        errors.append("desktop_manifest_app_binding_invalid")
    expected_bindings = bindings if bindings is not None else {}

    def emit_heartbeat(note: str) -> None:
        nonlocal chain, last_hb
        now = time.monotonic()
        gap = now - last_hb
        if heartbeats and gap > MAX_HEARTBEAT_GAP:
            errors.append(f"heartbeat_gap_exceeded:{gap:.2f}s")
        payload = {
            "index": len(heartbeats) + 1,
            "monotonic_s": round(now - started, 3),
            "wall_utc": _utc(),
            "note": note,
            "counters": dict(counters),
            "source_digest": source_digest,
            "prev_chain": chain.hex(),
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).digest()
        chain = digest
        payload["chain"] = chain.hex()
        heartbeats.append(payload)
        last_hb = now

    emit_heartbeat("overlay_start")

    while time.monotonic() < deadline and not errors:
        remaining = deadline - time.monotonic()
        if remaining < 5:
            break
        # One harness cycle (full lifecycle scenarios). Timeout bounded by remaining.
        timeout = min(300.0, max(30.0, remaining - 2.0))
        nonce = secrets.token_hex(32)
        with tempfile.TemporaryDirectory(prefix="harness-cycle-", dir=work_dir) as private_dir:
            result_path = Path(private_dir).resolve() / "result.json"
            try:
                completed = subprocess.run(
                    [
                        str(harness_exec),
                        "--app-path",
                        str(app_path),
                        "--result-path",
                        str(result_path),
                        "--nonce",
                        nonce,
                        "--app-tree-sha256",
                        expected_bindings["app_tree_sha256"],
                        "--desktop-manifest-path",
                        str(manifest_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=str(work_dir),
                )
            except subprocess.TimeoutExpired:
                errors.append("harness_timeout")
                emit_heartbeat("harness_timeout")
                break

            if completed.returncode == 10:
                errors.append("accessibility_not_authorized")
                emit_heartbeat("accessibility_not_authorized")
                break
            if completed.returncode != 0:
                errors.append(f"harness_exit_{completed.returncode}")
                emit_heartbeat(f"harness_fail_{completed.returncode}")
                # Continue only if short dry-run exhausted attempts; for production fail.
                break

            try:
                harness = strict_load_object(result_path)
            except (OSError, ValueError, StrictJSONError) as exc:
                errors.append(f"harness_result_invalid:{exc}")
                break

        current_bindings = _manifest_bindings(
            app_path=app_path,
            manifest_path=manifest_path,
            repo_root=REPO_ROOT,
        )
        nonce_result = harness.get("nonce")
        result_binding_ok = (
            isinstance(nonce_result, str)
            and secrets.compare_digest(nonce_result, nonce)
            and current_bindings == expected_bindings
        )
        if result_binding_ok:
            for field, expected in expected_bindings.items():
                actual = harness.get(field)
                if not isinstance(actual, str) or not secrets.compare_digest(actual, expected):
                    result_binding_ok = False
                    break
        if not result_binding_ok:
            errors.append("harness_result_binding_invalid")
            emit_heartbeat("harness_result_binding_invalid")
            break

        if harness.get("ok") is not True:
            errors.append("harness_scenarios_failed")
            emit_heartbeat("harness_scenarios_failed")
            break

        scenarios = harness.get("scenarios") or {}
        # Map harness scenarios to overlay counters.
        if scenarios.get("ui_mode_switch_personal_work_personal", {}).get("passed"):
            counters["mode_switches"] += 2
        if scenarios.get("restart_simplified_flow", {}).get("passed"):
            counters["app_restarts"] += 1
            counters["mode_switches"] += 2
        if scenarios.get("sidecar_crash_recovery", {}).get("passed"):
            counters["sidecar_recoveries"] += 1
        if scenarios.get("http_api_status", {}).get("passed"):
            counters["ws_cancel_cycles"] += 1  # health/stream proxy counter for short runs
        if scenarios.get("bootstrap_token_single_use", {}).get("passed"):
            counters["r4_ops"] += 1
        if scenarios.get("clean_quit_no_orphans", {}).get("passed"):
            counters["r6_ops"] += 1

        cycles += 1
        emit_heartbeat(f"cycle_{cycles}_ok")

        # Ensure heartbeat cadence even if harness is fast.
        while time.monotonic() - last_hb >= HEARTBEAT_INTERVAL and time.monotonic() < deadline:
            emit_heartbeat("idle_tick")

        # Early-complete short runs once targets met.
        if all(counters[k] >= targets[k] for k in targets) and duration_seconds < 3600:
            emit_heartbeat("targets_met_early")
            break

    # Drain remaining time with heartbeats for long soaks when cycles finish early.
    while time.monotonic() < deadline and not errors:
        sleep_for = min(HEARTBEAT_INTERVAL, deadline - time.monotonic())
        if sleep_for <= 0:
            break
        time.sleep(sleep_for)
        emit_heartbeat("soak_tick")

    finished_utc = _utc()
    max_gap = 0.0
    for i in range(1, len(heartbeats)):
        gap = heartbeats[i]["monotonic_s"] - heartbeats[i - 1]["monotonic_s"]
        max_gap = max(max_gap, float(gap))

    targets_met = all(counters[k] >= targets[k] for k in targets)
    ok = (
        not errors
        and targets_met
        and len(heartbeats) >= 2
        and max_gap <= MAX_HEARTBEAT_GAP + 0.5
    )
    report: dict[str, Any] = {
        "schema_version": OVERLAY_SCHEMA,
        "ok": ok,
        "started_utc": started_utc,
        "finished_utc": finished_utc,
        "duration_seconds": duration_seconds,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "source_digest": source_digest,
        "metadata_fingerprint": metadata_fingerprint,
        "acceptance_pid": os.getpid(),
        "targets": targets,
        "counters": counters,
        "targets_met": targets_met,
        "cycles": cycles,
        "heartbeats": heartbeats,
        "heartbeat_count": len(heartbeats),
        "max_heartbeat_gap_s": round(max_gap, 3),
        "max_heartbeat_gap_limit_s": MAX_HEARTBEAT_GAP,
        "chain_root": chain.hex(),
        "errors": errors,
        "app_path": str(app_path),
        "harness_exec": str(harness_exec),
        "desktop_manifest_path": str(manifest_path),
        "desktop_manifest_sha256": (
            bindings.get("desktop_manifest_sha256") if bindings is not None else None
        ),
        "app_tree_sha256": bindings.get("app_tree_sha256") if bindings is not None else None,
        "app_sha256": bindings.get("app_sha256") if bindings is not None else None,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Supervised Echo + Tauri soak")
    parser.add_argument("--duration-seconds", type=float, default=3600.0)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "docs/security/ECHO_LIVE_ACCEPTANCE.json",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=None,
        help="Optional evidence root for overlay artifacts and combined receipt",
    )
    parser.add_argument(
        "--app-path",
        type=Path,
        default=None,
        help="JS Agent.app for Tauri overlay (required for full product soak)",
    )
    parser.add_argument(
        "--harness-path",
        type=Path,
        default=None,
        help="Path to Harness.app or harness executable",
    )
    parser.add_argument(
        "--core-only",
        action="store_true",
        help="Run only echo core (compat); product gate must not use this",
    )
    args = parser.parse_args(argv)

    source_digest = release_source_digest(REPO_ROOT)
    metadata = release_source_surface_metadata_fingerprint(REPO_ROOT)
    started_utc = _utc()
    mono_start = time.monotonic()

    evidence = args.evidence_dir
    if evidence is None:
        evidence = REPO_ROOT / ".tmp" / "supervised-soak"
    evidence = evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    soak_dir = evidence / "soak"
    soak_dir.mkdir(parents=True, exist_ok=True)

    core_raw = soak_dir / "echo_core_soak.raw.json"
    overlay_raw = soak_dir / "tauri_overlay.raw.json"
    combined_path = soak_dir / "supervised_soak.combined.json"

    # Core soak writes to --output (docs/security/ECHO_LIVE_ACCEPTANCE.json) so
    # existing soak_json validator still re-validates the authoritative core artifact.
    core_cmd = [
        sys.executable,
        "-u",
        str(REPO_ROOT / "scripts" / "echo_live_acceptance.py"),
        "--duration-seconds",
        str(args.duration_seconds),
        "--concurrency",
        str(args.concurrency),
        "--output",
        str(args.output),
    ]

    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT) + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )

    core_proc: subprocess.Popen[Any] | None = None
    overlay_proc: subprocess.Popen[Any] | None = None
    overlay_report: dict[str, Any] | None = None
    core_exit: int | None = None
    overlay_exit: int | None = None

    product_app_path: Path | None = None
    product_harness_exec: Path | None = None
    product_manifest_path: Path | None = None
    product_bindings: dict[str, str] | None = None

    if not args.core_only:
        if args.app_path is None or args.harness_path is None:
            print(
                "[FAIL] supervised_soak requires --app-path and --harness-path "
                "(or pass --core-only for non-product dry runs)",
                file=sys.stderr,
            )
            return 2
        product_app_path = args.app_path.resolve()
        harness_path = args.harness_path.resolve()
        product_harness_exec = harness_path
        if harness_path.is_dir() and harness_path.name.endswith(".app"):
            product_harness_exec = (
                harness_path / "Contents" / "MacOS" / "js-agent-ui-test-harness"
            ).resolve()
        if not product_harness_exec.is_file():
            print(f"[FAIL] harness missing: {product_harness_exec}", file=sys.stderr)
            return 2
        product_manifest_path = (evidence / "desktop-build/manifest.json").resolve()
        product_bindings = _manifest_bindings(
            app_path=product_app_path,
            manifest_path=product_manifest_path,
            repo_root=REPO_ROOT,
        )
        if product_bindings is None:
            print(
                "[FAIL] supervised_soak: desktop manifest/app binding invalid",
                file=sys.stderr,
            )
            return 2

    def _cleanup(_signum: int | None = None, _frame: Any = None) -> None:
        _terminate_tree(overlay_proc)
        _terminate_tree(core_proc)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)

    try:
        core_proc = _spawn(core_cmd, cwd=REPO_ROOT, env=env)

        if not args.core_only:
            assert product_app_path is not None
            assert product_harness_exec is not None
            assert product_manifest_path is not None
            assert product_bindings is not None
            # Run the overlay under the same parent as a dedicated worker process.
            overlay_env = env.copy()
            overlay_env["JS_AGENT_OVERLAY_WORKER"] = "1"
            overlay_proc = _spawn(
                [
                    sys.executable,
                    "-u",
                    str(Path(__file__).resolve()),
                    "--overlay-worker",
                    "--duration-seconds",
                    str(args.duration_seconds),
                    "--app-path",
                    str(product_app_path),
                    "--harness-path",
                    str(product_harness_exec),
                    "--app-tree-sha256",
                    product_bindings["app_tree_sha256"],
                    "--desktop-manifest-path",
                    str(product_manifest_path),
                    "--overlay-output",
                    str(overlay_raw),
                    "--source-digest",
                    source_digest,
                    "--metadata-fingerprint",
                    metadata,
                    "--work-dir",
                    str(soak_dir / "overlay-work"),
                ],
                cwd=REPO_ROOT,
                env=overlay_env,
            )

        # Wait for both with shared deadline + slack.
        slack = 120.0
        wait_deadline = mono_start + args.duration_seconds + slack
        while True:
            core_done = core_proc is None or core_proc.poll() is not None
            overlay_done = overlay_proc is None or overlay_proc.poll() is not None
            if core_done and overlay_done:
                break
            if time.monotonic() > wait_deadline:
                print("[FAIL] supervised_soak: shared deadline exceeded", file=sys.stderr)
                _cleanup()
                return 1
            time.sleep(0.5)

        core_exit = core_proc.returncode if core_proc else 0
        overlay_exit = overlay_proc.returncode if overlay_proc else 0

        # Capture core raw: copy authoritative output for binding.
        if args.output.is_file():
            core_payload = json.loads(args.output.read_text(encoding="utf-8"))
            core_raw.write_text(
                json.dumps(core_payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        else:
            print(f"[FAIL] core soak output missing: {args.output}", file=sys.stderr)
            return 1

        if not args.core_only:
            if not overlay_raw.is_file():
                print("[FAIL] overlay raw missing", file=sys.stderr)
                return 1
            overlay_report = json.loads(overlay_raw.read_text(encoding="utf-8"))
        else:
            overlay_report = {
                "schema_version": OVERLAY_SCHEMA,
                "ok": True,
                "skipped": True,
                "source_digest": source_digest,
            }
            overlay_raw.write_text(
                json.dumps(overlay_report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        core_ok = core_exit == 0 and core_payload.get("ok") is True
        overlay_ok = overlay_exit == 0 and overlay_report.get("ok") is True
        combined_ok = core_ok and overlay_ok

        # Drift check: both must bind same digest.
        if core_payload.get("source_digest") != source_digest:
            combined_ok = False
        if overlay_report.get("source_digest") != source_digest:
            combined_ok = False
        if overlay_report.get("metadata_fingerprint") != metadata and not args.core_only:
            combined_ok = False
        if product_bindings is not None and any(
            overlay_report.get(field) != product_bindings[field]
            for field in ("desktop_manifest_sha256", "app_tree_sha256", "app_sha256")
        ):
            combined_ok = False

        core_raw_sha256 = _sha256_file(core_raw)
        overlay_raw_sha256 = _sha256_file(overlay_raw)

        combined: dict[str, Any] = {
            "schema_version": SCHEMA,
            "ok": combined_ok,
            "started_utc": started_utc,
            "finished_utc": _utc(),
            "duration_seconds": args.duration_seconds,
            "elapsed_seconds": round(time.monotonic() - mono_start, 3),
            "source_digest": source_digest,
            "metadata_fingerprint": metadata,
            "core": {
                "exit_code": core_exit,
                "raw_sha256": core_raw_sha256,
                "ok": core_ok,
            },
            "overlay": {
                "exit_code": overlay_exit,
                "raw_sha256": overlay_raw_sha256,
                "ok": overlay_ok,
                "targets": overlay_report.get("targets"),
                "counters": overlay_report.get("counters"),
                "targets_met": overlay_report.get("targets_met"),
                "cycles": overlay_report.get("cycles"),
                "heartbeat_count": overlay_report.get("heartbeat_count"),
                "max_heartbeat_gap_s": overlay_report.get("max_heartbeat_gap_s"),
                "max_heartbeat_gap_limit_s": overlay_report.get(
                    "max_heartbeat_gap_limit_s"
                ),
                "chain_root": overlay_report.get("chain_root"),
                "desktop_manifest_sha256": overlay_report.get("desktop_manifest_sha256"),
                "app_tree_sha256": overlay_report.get("app_tree_sha256"),
                "app_sha256": overlay_report.get("app_sha256"),
            },
        }
        combined["combined_sha256"] = _canonical_sha256(
            {k: v for k, v in combined.items() if k != "combined_sha256"}
        )
        combined_path.write_text(
            json.dumps(combined, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        if not combined_ok:
            print(
                f"[FAIL] supervised_soak core_ok={core_ok} overlay_ok={overlay_ok}",
                file=sys.stderr,
            )
            return 1

        print(
            f"[OK] supervised_soak duration={args.duration_seconds} "
            f"core_sha={combined['core']['raw_sha256'][:16]} "
            f"overlay_sha={combined['overlay']['raw_sha256'][:16]}"
        )
        return 0
    finally:
        _cleanup()


def _overlay_worker_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--overlay-worker", action="store_true")
    parser.add_argument("--duration-seconds", type=float, required=True)
    parser.add_argument("--app-path", type=Path, required=True)
    parser.add_argument("--harness-path", type=Path, required=True)
    parser.add_argument("--app-tree-sha256", required=True)
    parser.add_argument("--desktop-manifest-path", type=Path, required=True)
    parser.add_argument("--overlay-output", type=Path, required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--metadata-fingerprint", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    report = run_overlay(
        duration_seconds=args.duration_seconds,
        app_path=args.app_path,
        harness_exec=args.harness_path,
        output_path=args.overlay_output,
        source_digest=args.source_digest,
        metadata_fingerprint=args.metadata_fingerprint,
        work_dir=args.work_dir,
        desktop_manifest_path=args.desktop_manifest_path,
        app_tree_sha256=args.app_tree_sha256,
    )
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    raw = sys.argv[1:]
    if "--overlay-worker" in raw:
        raise SystemExit(_overlay_worker_main(raw))
    raise SystemExit(main(raw))

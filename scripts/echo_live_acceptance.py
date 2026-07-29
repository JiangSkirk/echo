#!/usr/bin/env python3
"""Run the Echo web boundary against local child processes only.

This deliberately keeps the fake OpenAI-compatible server outside either
product process.  The checks therefore cover the production HTTP client,
uvicorn lifecycle, authentication partitioning, websocket framing, and the
real Echo turn loop without contacting a paid or remote provider.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any

import httpx
import psutil
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from js.config import EchoLedgerConfig  # noqa: E402
from js.echo.ledger.release_gates import (  # noqa: E402
    release_source_digest,
    release_source_surface_metadata_fingerprint,
)

LOOPBACK = "127.0.0.1"
TERMINAL_FRAMES = frozenset({"done", "error"})
QUIET_DRAIN_SECONDS = 0.35
ATTACHMENT_MARKER = "live-attachment-marker-v1"
DEFAULT_MAX_STATE_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_RSS_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_RSS_GROWTH_MIB_PER_MINUTE = 0.5
DEFAULT_MAX_STATE_GROWTH_MIB_PER_MINUTE = 0.5
DEFAULT_MAX_PARTITION_GROWTH_MIB_PER_MINUTE = 0.05
RESOURCE_SAMPLE_INTERVAL_SECONDS = 5.0
# Fail-closed validator requires 2.5s <= mono interval <= 15.0s between checks.
MIN_INTEGRITY_INTERVAL_SECONDS = 2.5
RESOURCE_STABILITY_MIN_SECONDS = 600.0
RESOURCE_MAX_SAMPLE_GAP_SECONDS = 15.0
RESOURCE_MIN_SAMPLE_RATIO = 0.9
RESOURCE_MAX_PLATEAU_GROWTH_MIB = 16.0
STORAGE_MAX_PLATEAU_GROWTH_MIB = 32.0
PARTITION_MAX_PLATEAU_GROWTH_MIB = 4.0
MAX_RECORDED_SAMPLES = 40
DEFAULT_MAX_SESSION_PARTITIONS_PER_OWNER = EchoLedgerConfig().max_session_partitions_per_owner
_LIVE_IDENTITY_RE = re.compile(r"\b(?:js_agent|js_work):[a-z_]+(?::\d+)?:[0-9a-f]{32}\b")


class AcceptanceError(RuntimeError):
    """A failed externally observable acceptance condition."""

    soak_result: dict[str, Any] | None = None


class AcceptanceInterruptedError(AcceptanceError):
    """The parent received a signal and must complete child cleanup."""


def _integrity_chain_append(previous_root: str, check: dict[str, Any]) -> str:
    # Must match js.echo.ledger.release_gates._valid_echo_live_acceptance chain.
    canonical = json.dumps(
        {
            "index": check["index"],
            "metadata_fingerprint": check["metadata_fingerprint"],
            "monotonic_s": check["monotonic_s"],
            "source_digest": check["source_digest"],
            "wall_utc": check["wall_utc"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(bytes.fromhex(previous_root) + canonical).hexdigest()


def _process_snapshot(pid: int) -> dict[str, int | float]:
    process = psutil.Process(pid)
    return {
        "pid": int(process.pid),
        "ppid": int(process.ppid()),
        "create_time": float(process.create_time()),
    }


@dataclass
class ChildProcess:
    name: str
    process: subprocess.Popen[str]
    process_group: int | None
    stopped: bool = False
    stop_error: str | None = None
    forced_kill: bool = False

    def _group_alive(self) -> bool:
        if self.process_group is None or os.name != "posix":
            return self.process.poll() is None
        try:
            os.killpg(self.process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def stop(self) -> None:
        try:
            if self._group_alive():
                if self.process_group is not None and os.name == "posix":
                    os.killpg(self.process_group, signal.SIGTERM)
                elif self.process.poll() is None:
                    self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.forced_kill = True
                if self._group_alive():
                    if self.process_group is not None and os.name == "posix":
                        os.killpg(self.process_group, signal.SIGKILL)
                    elif self.process.poll() is None:
                        self.process.kill()
                self.process.wait(timeout=5)
            if self._group_alive():
                self.forced_kill = True
                if self.process_group is not None and os.name == "posix":
                    os.killpg(self.process_group, signal.SIGKILL)
                elif self.process.poll() is None:
                    self.process.kill()
        except BaseException as exc:  # noqa: BLE001 - cleanup must continue for siblings
            self.stop_error = f"{type(exc).__name__}: {exc}"
        finally:
            self.stopped = self.process.poll() is not None and not self._group_alive()


@dataclass
class Product:
    name: str
    port: int
    config: Path
    home: Path
    state_dir: Path
    owner_a: str
    owner_b: str
    checks: dict[str, bool] = field(
        default_factory=lambda: {
            "status_primary_healthy": False,
            "chat": False,
            "stream": False,
            "tool_continue": False,
            "attachment": False,
            "cross_owner_rejected": False,
            "secret_rejected": False,
            "cancel": False,
            "provider_error_single_terminal": False,
            "storage_within_limit": False,
            "session_partitions_bounded": False,
        }
    )
    latencies_ms: dict[str, float] = field(default_factory=dict)

    @property
    def base_url(self) -> str:
        return f"http://{LOOPBACK}:{self.port}"

    @property
    def ws_url(self) -> str:
        return f"ws://{LOOPBACK}:{self.port}/ws"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOOPBACK, 0))
        return int(sock.getsockname()[1])


def _local_env(home: Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        env.pop(key, None)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = "127.0.0.1,localhost"
    env["HOME"] = str(home)
    env["JS_ECHO_ENGINE"] = "on"
    return env


def _write_config(path: Path, *, workspace: Path, state_dir: Path, provider_port: int) -> None:
    config = {
        "workspace": str(workspace),
        "state_dir": str(state_dir),
        "max_turns": 4,
        "echo_engine": "on",
        "providers": [
            {
                "name": "live-local",
                "base_url": f"http://{LOOPBACK}:{provider_port}/v1",
                "api_key": "local-only",
                "timeout": 12,
                "max_retries": 1,
                "default_model": "live-local-model",
                "models": [
                    {
                        "id": "live-local-model",
                        "name": "Live local acceptance model",
                        "provider": "live-local",
                        "supports_tools": True,
                        "supports_streaming": True,
                    }
                ],
            }
        ],
        "security": {"api_key_required": True, "defense_mode": "enforce"},
    }
    import yaml

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")


def _mint_owners(state_dir: Path) -> tuple[str, str]:
    from js.web.auth import AuthManager

    manager = AuthManager(state_dir)
    return manager.create_key("live-owner-a"), manager.create_key("live-owner-b")


def _start_child(args: list[str], *, env: dict[str, str], name: str) -> ChildProcess:
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=os.name == "posix",
    )
    return ChildProcess(
        name=name,
        process=process,
        process_group=process.pid if os.name == "posix" else None,
    )


def _wait_ready(url: str, child: ChildProcess, key: str | None = None) -> None:
    headers = {"X-API-Key": key} if key else {}
    deadline = time.monotonic() + 25
    with httpx.Client(timeout=1.0, trust_env=False) as client:
        while time.monotonic() < deadline:
            if child.process.poll() is not None:
                raise AcceptanceError(f"{child.name} stopped during startup")
            try:
                response = client.get(url, headers=headers)
                if response.status_code < 500:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    raise AcceptanceError(f"{child.name} did not become ready: {url}")


def _request(
    product: Product,
    method: str,
    path: str,
    *,
    key: str,
    json_body: dict[str, Any] | None = None,
    files: dict[str, tuple[str, bytes, str]] | None = None,
    data: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> tuple[httpx.Response, float]:
    started = time.perf_counter()
    with httpx.Client(base_url=product.base_url, timeout=timeout, trust_env=False) as client:
        response = client.request(
            method,
            path,
            headers={"X-API-Key": key},
            json=json_body,
            files=files,
            data=data,
        )
    return response, (time.perf_counter() - started) * 1000


def _expect_status(response: httpx.Response, expected: int, label: str) -> None:
    if response.status_code != expected:
        raise AcceptanceError(f"{label}: HTTP {response.status_code}: {response.text[:500]}")


def _ws_frames(
    product: Product, *, key: str, payload: dict[str, Any]
) -> tuple[list[dict[str, Any]], float]:
    from websockets.sync.client import connect

    started = time.perf_counter()
    frames: list[dict[str, Any]] = []
    with connect(
        product.ws_url,
        additional_headers={"X-API-Key": key},
        open_timeout=10,
        close_timeout=2,
    ) as websocket:
        websocket.send(json.dumps(payload))
        quiet_deadline: float | None = None
        while True:
            timeout = 15.0
            if quiet_deadline is not None:
                remaining = quiet_deadline - time.monotonic()
                if remaining <= 0:
                    break
                timeout = min(remaining, 0.1)
            try:
                raw = websocket.recv(timeout=timeout)
            except TimeoutError:
                if quiet_deadline is not None:
                    continue
                raise AcceptanceError("websocket did not emit a terminal frame") from None
            frame = json.loads(raw)
            frames.append(frame)
            if frame.get("type") in TERMINAL_FRAMES:
                quiet_deadline = time.monotonic() + QUIET_DRAIN_SECONDS
    return frames, (time.perf_counter() - started) * 1000


def _provider_stats(provider_port: int) -> dict[str, Any]:
    with httpx.Client(timeout=5.0, trust_env=False) as client:
        response = client.get(f"http://{LOOPBACK}:{provider_port}/__live__/stats")
    _expect_status(response, 200, "fake provider stats")
    payload = response.json()
    if not isinstance(payload, dict):
        raise AcceptanceError("fake provider stats returned a non-object payload")
    return payload


def _provider_evidence(stats: dict[str, Any]) -> dict[str, Any]:
    identities = stats.get("identities", {})
    if not isinstance(identities, dict):
        identities = {}
    primary_identities = stats.get("primary_identities", {})
    if not isinstance(primary_identities, dict):
        primary_identities = {}
    distribution: dict[str, int] = {}
    for calls in identities.values():
        key = str(calls)
        distribution[key] = distribution.get(key, 0) + 1
    primary_distribution: dict[str, int] = {}
    for calls in primary_identities.values():
        key = str(calls)
        primary_distribution[key] = primary_distribution.get(key, 0) + 1
    background_identity_calls = sum(
        max(0, int(identities.get(identity, 0)) - int(primary_calls))
        for identity, primary_calls in primary_identities.items()
    )
    chat_calls = int(stats.get("chat_calls", 0) or 0)
    interactive_calls = int(stats.get("interactive_calls", 0) or 0)
    background_calls = int(stats.get("background_calls", 0) or 0)
    scenarios = stats.get("scenarios", {})
    return {
        "chat_calls": chat_calls,
        "interactive_model_calls": interactive_calls,
        "background_model_calls": background_calls,
        "classification_complete": interactive_calls + background_calls == chat_calls,
        "scenarios": dict(scenarios) if isinstance(scenarios, dict) else {},
        "identity_count": len(identities),
        "identity_call_distribution": dict(sorted(distribution.items())),
        "primary_identity_count": len(primary_identities),
        "primary_identity_call_distribution": dict(sorted(primary_distribution.items())),
        "background_identity_calls": background_identity_calls,
    }


def _state_storage_evidence(state_dir: Path) -> dict[str, Any]:
    files: list[tuple[str, int]] = []
    suffix_bytes: dict[str, int] = {}
    if state_dir.exists():
        for path in state_dir.rglob("*"):
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                size = path.stat().st_size
            except OSError:
                continue
            relative = path.relative_to(state_dir).as_posix()
            files.append((relative, size))
            suffix = path.suffix.lower() or "<none>"
            suffix_bytes[suffix] = suffix_bytes.get(suffix, 0) + size
    largest = sorted(files, key=lambda item: (-item[1], item[0]))[:10]
    partition_files = [
        (relative, size)
        for relative, size in files
        if relative.startswith("echo/ledger/partitions/")
    ]
    partition_counts: dict[str, int] = {}
    retired_session_count = 0
    retention_checkpoint_bytes = 0
    retention_checkpoint_errors: list[str] = []
    incomplete_retirements: list[str] = []
    incomplete_retirement_markers: list[str] = []
    partitions_root = state_dir / "echo" / "ledger" / "partitions"
    if partitions_root.is_dir() and not partitions_root.is_symlink():
        for owner_root in sorted(partitions_root.glob("*/*")):
            if owner_root.is_symlink() or not owner_root.is_dir():
                retention_checkpoint_errors.append(
                    f"invalid_owner_root:{owner_root.relative_to(state_dir).as_posix()}"
                )
                continue
            owner_ref = owner_root.relative_to(partitions_root).as_posix()
            partition_counts[owner_ref] = sum(
                1
                for path in owner_root.glob("session_*")
                if path.is_dir() and not path.is_symlink()
            )
            retiring = owner_root / ".retiring"
            if retiring.exists() or retiring.is_symlink():
                incomplete_retirements.append(owner_ref)
                try:
                    metadata = retiring.lstat()
                    incomplete_retirement_markers.append(
                        f"{owner_ref}|{metadata.st_dev}:{metadata.st_ino}:{metadata.st_ctime_ns}"
                    )
                except OSError:
                    incomplete_retirement_markers.append(f"{owner_ref}|unknown")
            checkpoint = owner_root / "retired-sessions.json"
            if not checkpoint.exists():
                continue
            try:
                if checkpoint.is_symlink() or not checkpoint.is_file():
                    raise ValueError("not_regular")
                retention_checkpoint_bytes += checkpoint.stat().st_size
                row = json.loads(checkpoint.read_text(encoding="utf-8"))
                count = row.get("retired_count")
                if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                    raise ValueError("retired_count")
                retired_session_count += count
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                retention_checkpoint_errors.append(f"{owner_ref}:{exc.__class__.__name__}:{exc}")
    component_names = (
        "audit",
        "compression_feedback",
        "learning",
        "lifecycle",
        "memory_enhanced",
        "metacognition",
        "prompt_optimization",
        "quality",
        "review_capsules",
        "token_stats",
    )
    component_bytes = dict.fromkeys(component_names, 0)
    component_bytes.update({"echo_partitions": 0, "events": 0, "other": 0})
    for relative, size in files:
        if relative.startswith("echo/ledger/partitions/"):
            component = "echo_partitions"
        elif relative.startswith("events/"):
            component = "events"
        else:
            component = next(
                (
                    name
                    for name in component_names
                    if relative == f"{name}.db" or relative.startswith(f"{name}.db-")
                ),
                "other",
            )
        component_bytes[component] += size
    return {
        "total_bytes": sum(size for _path, size in files),
        "file_count": len(files),
        "bytes_by_suffix": dict(sorted(suffix_bytes.items())),
        "largest_files": [{"path": relative, "bytes": size} for relative, size in largest],
        "partition_storage_bytes": sum(size for _path, size in partition_files),
        "partition_file_count": len(partition_files),
        "session_partition_counts": dict(sorted(partition_counts.items())),
        "max_active_session_partitions_per_owner": max(partition_counts.values(), default=0),
        "retired_session_partition_count": retired_session_count,
        "retention_checkpoint_bytes": retention_checkpoint_bytes,
        "retention_checkpoint_errors": retention_checkpoint_errors,
        "incomplete_retirements": incomplete_retirements,
        "incomplete_retirement_markers": incomplete_retirement_markers,
        "component_bytes": dict(sorted(component_bytes.items())),
    }


def _sample_process_resources(
    processes: dict[str, subprocess.Popen[str]],
    *,
    elapsed_seconds: float,
) -> dict[str, Any]:
    rss_bytes: dict[str, int] = {}
    process_counts: dict[str, int] = {}
    for name, process in processes.items():
        if process.poll() is not None:
            continue
        try:
            root = psutil.Process(process.pid)
            members = [root, *root.children(recursive=True)]
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
        total_rss = 0
        sampled = 0
        for member in members:
            try:
                total_rss += int(member.memory_info().rss)
                sampled += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
        if sampled:
            rss_bytes[name] = total_rss
            process_counts[name] = sampled
    return {
        "elapsed_seconds": round(elapsed_seconds, 3),
        "rss_bytes": rss_bytes,
        "process_counts": process_counts,
    }


def _rss_growth_mib_per_minute(points: list[tuple[float, int]]) -> float:
    if len(points) < 2:
        return 0.0
    mean_x = sum(point[0] for point in points) / len(points)
    mean_y = sum(point[1] for point in points) / len(points)
    denominator = sum((point[0] - mean_x) ** 2 for point in points)
    if denominator <= 0:
        return 0.0
    bytes_per_second = (
        sum((elapsed - mean_x) * (rss - mean_y) for elapsed, rss in points) / denominator
    )
    return round(bytes_per_second * 60 / (1024 * 1024), 3)


def _minute_medians(points: list[tuple[float, int]], *, start: float) -> list[tuple[float, int]]:
    buckets: dict[int, list[int]] = {}
    for elapsed, rss in points:
        if elapsed < start:
            continue
        minute = int(elapsed // 60)
        buckets.setdefault(minute, []).append(rss)
    return [
        (minute * 60.0 + 30.0, int(median(values))) for minute, values in sorted(buckets.items())
    ]


def _theil_sen_growth_mib_per_minute(points: list[tuple[float, int]]) -> float:
    slopes: list[float] = []
    for index, (left_elapsed, left_rss) in enumerate(points):
        for right_elapsed, right_rss in points[index + 1 :]:
            elapsed = right_elapsed - left_elapsed
            if elapsed <= 0:
                continue
            slopes.append((right_rss - left_rss) / elapsed)
    if not slopes:
        return 0.0
    return round(float(median(slopes)) * 60 / (1024 * 1024), 3)


def _summarize_resource_samples(
    samples: list[dict[str, Any]],
    *,
    duration_seconds: float,
    max_rss_bytes: int,
    max_growth_mib_per_minute: float,
    required_processes: tuple[str, ...] = (),
) -> dict[str, Any]:
    observed_names = {str(name) for sample in samples for name in sample.get("rss_bytes", {})}
    names = sorted(observed_names | set(required_processes))
    stability_enforced = duration_seconds >= RESOURCE_STABILITY_MIN_SECONDS
    process_reports: dict[str, dict[str, Any]] = {}
    for name in names:
        points = [
            (float(sample["elapsed_seconds"]), int(sample["rss_bytes"][name]))
            for sample in samples
            if name in sample.get("rss_bytes", {})
        ]
        expected_samples = max(
            2,
            math.ceil(
                max(0.0, duration_seconds)
                / RESOURCE_SAMPLE_INTERVAL_SECONDS
                * RESOURCE_MIN_SAMPLE_RATIO
            ),
        )
        coverage = points[-1][0] - points[0][0] if len(points) >= 2 else 0.0
        max_gap = max(
            (right[0] - left[0] for left, right in zip(points, points[1:], strict=False)),
            default=math.inf,
        )
        minimum_coverage = max(0.0, duration_seconds - RESOURCE_MAX_SAMPLE_GAP_SECONDS)
        sample_integrity_ok = bool(
            len(points) >= expected_samples
            and coverage >= minimum_coverage
            and max_gap <= RESOURCE_MAX_SAMPLE_GAP_SECONDS
        )

        warmup_seconds = 900.0 if duration_seconds >= 3600.0 else duration_seconds * 0.5
        minute_medians = _minute_medians(points, start=0.0)
        stable_points = _minute_medians(points, start=warmup_seconds)
        growth = _theil_sen_growth_mib_per_minute(stable_points)
        tail_points = stable_points[-3:]
        tail_growth = _theil_sen_growth_mib_per_minute(tail_points)
        reference_start = max(warmup_seconds, duration_seconds * 0.5)
        reference_end = min(duration_seconds - 60.0, reference_start + 300.0)
        reference_values = [
            rss for elapsed, rss in points if reference_start <= elapsed <= reference_end
        ]
        final_values = [
            rss for elapsed, rss in points if elapsed >= max(0.0, duration_seconds - 60.0)
        ]
        plateau_growth = (
            (float(median(final_values)) - float(median(reference_values))) / (1024 * 1024)
            if reference_values and final_values
            else math.inf
        )
        peak = max((rss for _elapsed, rss in points), default=0)
        start = points[0][1] if points else 0
        final = points[-1][1] if points else 0
        peak_ok = peak <= max_rss_bytes
        growth_ok = not stability_enforced or (
            growth <= max_growth_mib_per_minute
            and plateau_growth <= RESOURCE_MAX_PLATEAU_GROWTH_MIB
        )
        process_reports[name] = {
            "sample_count": len(points),
            "required_sample_count": expected_samples,
            "sample_coverage_seconds": round(coverage, 3),
            "max_sample_gap_seconds": (round(max_gap, 3) if math.isfinite(max_gap) else None),
            "sample_integrity_ok": sample_integrity_ok,
            "start_rss_mib": round(start / (1024 * 1024), 3),
            "final_rss_mib": round(final / (1024 * 1024), 3),
            "peak_rss_mib": round(peak / (1024 * 1024), 3),
            "growth_mib_per_minute": growth,
            "tail_growth_mib_per_minute": tail_growth,
            "plateau_growth_mib": (
                round(plateau_growth, 3) if math.isfinite(plateau_growth) else None
            ),
            "stability_window_start_seconds": round(warmup_seconds, 3),
            "minute_medians": [
                {
                    "elapsed_seconds": round(elapsed, 3),
                    "rss_mib": round(rss / (1024 * 1024), 3),
                }
                for elapsed, rss in minute_medians
            ],
            "peak_within_limit": peak_ok,
            "growth_within_limit": growth_ok,
            "ok": peak_ok and growth_ok and (sample_integrity_ok or not stability_enforced),
        }
    recorded_samples = list(samples)
    return {
        "ok": bool(process_reports) and all(report["ok"] for report in process_reports.values()),
        "stability_enforced": stability_enforced,
        "max_rss_bytes": max_rss_bytes,
        "max_growth_mib_per_minute": max_growth_mib_per_minute,
        "max_plateau_growth_mib": RESOURCE_MAX_PLATEAU_GROWTH_MIB,
        "sample_interval_seconds": RESOURCE_SAMPLE_INTERVAL_SECONDS,
        "max_sample_gap_seconds": RESOURCE_MAX_SAMPLE_GAP_SECONDS,
        "min_sample_ratio": RESOURCE_MIN_SAMPLE_RATIO,
        "stability_min_seconds": RESOURCE_STABILITY_MIN_SECONDS,
        "processes": process_reports,
        "samples_truncated": len(recorded_samples) < len(samples),
        "recorded_sample_count": len(recorded_samples),
        "omitted_sample_count": len(samples) - len(recorded_samples),
        "samples": recorded_samples,
    }


def _storage_plateau_growth_mib(
    points: list[tuple[float, int]],
    *,
    duration_seconds: float,
    warmup_seconds: float,
) -> float:
    reference_start = max(warmup_seconds, duration_seconds * 0.5)
    reference_end = min(duration_seconds - 60.0, reference_start + 300.0)
    reference_values = [
        value for elapsed, value in points if reference_start <= elapsed <= reference_end
    ]
    final_values = [
        value for elapsed, value in points if elapsed >= max(0.0, duration_seconds - 60.0)
    ]
    if not reference_values or not final_values:
        return math.inf
    return (float(median(final_values)) - float(median(reference_values))) / (1024 * 1024)


def _summarize_storage_samples(
    samples: list[dict[str, Any]],
    *,
    duration_seconds: float,
    max_state_bytes: int,
    required_products: tuple[str, ...],
) -> dict[str, Any]:
    stability_enforced = duration_seconds >= RESOURCE_STABILITY_MIN_SECONDS
    product_reports: dict[str, dict[str, Any]] = {}
    expected_samples = max(
        2,
        math.ceil(
            max(0.0, duration_seconds)
            / RESOURCE_SAMPLE_INTERVAL_SECONDS
            * RESOURCE_MIN_SAMPLE_RATIO
        ),
    )
    for name in required_products:
        points = [
            (float(sample["elapsed_seconds"]), dict(sample["storage"][name]))
            for sample in samples
            if name in sample.get("storage", {})
        ]
        elapsed_points = [elapsed for elapsed, _evidence in points]
        coverage = elapsed_points[-1] - elapsed_points[0] if len(elapsed_points) >= 2 else 0.0
        max_gap = max(
            (right - left for left, right in zip(elapsed_points, elapsed_points[1:], strict=False)),
            default=math.inf,
        )
        minimum_coverage = max(0.0, duration_seconds - RESOURCE_MAX_SAMPLE_GAP_SECONDS)
        sample_integrity_ok = bool(
            len(points) >= expected_samples
            and coverage >= minimum_coverage
            and max_gap <= RESOURCE_MAX_SAMPLE_GAP_SECONDS
        )
        total_points = [(elapsed, int(evidence["total_bytes"])) for elapsed, evidence in points]
        partition_points = [
            (elapsed, int(evidence["partition_storage_bytes"])) for elapsed, evidence in points
        ]
        warmup_seconds = 900.0 if duration_seconds >= 3600.0 else duration_seconds * 0.5
        total_growth = _theil_sen_growth_mib_per_minute(
            _minute_medians(total_points, start=warmup_seconds)
        )
        partition_growth = _theil_sen_growth_mib_per_minute(
            _minute_medians(partition_points, start=warmup_seconds)
        )
        total_plateau = _storage_plateau_growth_mib(
            total_points,
            duration_seconds=duration_seconds,
            warmup_seconds=warmup_seconds,
        )
        partition_plateau = _storage_plateau_growth_mib(
            partition_points,
            duration_seconds=duration_seconds,
            warmup_seconds=warmup_seconds,
        )
        peak_total = max((value for _elapsed, value in total_points), default=0)
        max_session_partitions = max(
            (
                int(evidence["max_active_session_partitions_per_owner"])
                for _elapsed, evidence in points
            ),
            default=0,
        )
        retention_errors = sorted(
            {
                str(error)
                for _elapsed, evidence in points
                for error in evidence.get("retention_checkpoint_errors", [])
            }
        )
        retirement_observations = [
            {str(owner) for owner in evidence.get("incomplete_retirements", [])}
            for _elapsed, evidence in points
        ]
        transient_retirement_observations = sorted(
            set().union(*retirement_observations) if retirement_observations else set()
        )
        retirement_marker_observations = [
            {
                str(marker)
                for marker in (
                    evidence.get("incomplete_retirement_markers")
                    or evidence.get("incomplete_retirements")
                    or []
                )
            }
            for _elapsed, evidence in points
        ]
        stale_retirement_markers: set[str] = set(
            retirement_marker_observations[-1] if retirement_marker_observations else set()
        )
        for previous, current in zip(
            retirement_marker_observations,
            retirement_marker_observations[1:],
            strict=False,
        ):
            stale_retirement_markers.update(previous & current)
        incomplete_retirements = sorted(
            {marker.split("|", 1)[0] for marker in stale_retirement_markers}
        )
        component_names = sorted(
            {
                str(component)
                for _elapsed, evidence in points
                for component in evidence.get("component_bytes", {})
            }
        )
        component_growth: dict[str, dict[str, Any]] = {}
        for component in component_names:
            component_points = [
                (elapsed, int(evidence.get("component_bytes", {}).get(component, 0)))
                for elapsed, evidence in points
            ]
            component_plateau = _storage_plateau_growth_mib(
                component_points,
                duration_seconds=duration_seconds,
                warmup_seconds=warmup_seconds,
            )
            component_growth[component] = {
                "start_mib": round(component_points[0][1] / (1024 * 1024), 3),
                "final_mib": round(component_points[-1][1] / (1024 * 1024), 3),
                "growth_mib_per_minute": _theil_sen_growth_mib_per_minute(
                    _minute_medians(component_points, start=warmup_seconds)
                ),
                "plateau_growth_mib": (
                    round(component_plateau, 3) if math.isfinite(component_plateau) else None
                ),
            }
        bounds_ok = bool(
            peak_total <= max_state_bytes
            and max_session_partitions <= DEFAULT_MAX_SESSION_PARTITIONS_PER_OWNER
            and not retention_errors
            and not incomplete_retirements
        )
        growth_ok = not stability_enforced or bool(
            total_growth <= DEFAULT_MAX_STATE_GROWTH_MIB_PER_MINUTE
            and partition_growth <= DEFAULT_MAX_PARTITION_GROWTH_MIB_PER_MINUTE
            and total_plateau <= STORAGE_MAX_PLATEAU_GROWTH_MIB
            and partition_plateau <= PARTITION_MAX_PLATEAU_GROWTH_MIB
        )
        product_reports[name] = {
            "sample_count": len(points),
            "required_sample_count": expected_samples,
            "sample_coverage_seconds": round(coverage, 3),
            "max_sample_gap_seconds": (round(max_gap, 3) if math.isfinite(max_gap) else None),
            "sample_integrity_ok": sample_integrity_ok,
            "start_total_mib": (
                round(total_points[0][1] / (1024 * 1024), 3) if total_points else 0.0
            ),
            "final_total_mib": (
                round(total_points[-1][1] / (1024 * 1024), 3) if total_points else 0.0
            ),
            "peak_total_mib": round(peak_total / (1024 * 1024), 3),
            "total_growth_mib_per_minute": total_growth,
            "partition_growth_mib_per_minute": partition_growth,
            "total_plateau_growth_mib": (
                round(total_plateau, 3) if math.isfinite(total_plateau) else None
            ),
            "partition_plateau_growth_mib": (
                round(partition_plateau, 3) if math.isfinite(partition_plateau) else None
            ),
            "max_active_session_partitions_per_owner": max_session_partitions,
            "retention_checkpoint_errors": retention_errors,
            "transient_retirement_observations": transient_retirement_observations,
            "stale_incomplete_retirement_markers": sorted(stale_retirement_markers),
            "stale_incomplete_retirements": incomplete_retirements,
            "incomplete_retirements": incomplete_retirements,
            "component_growth": component_growth,
            "bounds_within_limit": bounds_ok,
            "growth_within_limit": growth_ok,
            "ok": sample_integrity_ok and bounds_ok and growth_ok,
        }
    recorded = list(samples)
    return {
        "ok": bool(product_reports) and all(report["ok"] for report in product_reports.values()),
        "stability_enforced": stability_enforced,
        "max_state_bytes": max_state_bytes,
        "max_total_growth_mib_per_minute": DEFAULT_MAX_STATE_GROWTH_MIB_PER_MINUTE,
        "max_partition_growth_mib_per_minute": (DEFAULT_MAX_PARTITION_GROWTH_MIB_PER_MINUTE),
        "max_total_plateau_growth_mib": STORAGE_MAX_PLATEAU_GROWTH_MIB,
        "max_partition_plateau_growth_mib": PARTITION_MAX_PLATEAU_GROWTH_MIB,
        "max_active_session_partitions_per_owner": (
            DEFAULT_MAX_SESSION_PARTITIONS_PER_OWNER
        ),
        "sample_interval_seconds": RESOURCE_SAMPLE_INTERVAL_SECONDS,
        "max_sample_gap_seconds": RESOURCE_MAX_SAMPLE_GAP_SECONDS,
        "min_sample_ratio": RESOURCE_MIN_SAMPLE_RATIO,
        "stability_min_seconds": RESOURCE_STABILITY_MIN_SECONDS,
        "products": product_reports,
        "samples_truncated": len(recorded) < len(samples),
        "recorded_sample_count": len(recorded),
        "omitted_sample_count": len(samples) - len(recorded),
        "samples": recorded,
    }


def _identity(product: Product, phase: str, index: int | None = None) -> str:
    suffix = f":{index}" if index is not None else ""
    return f"{product.name}:{phase}{suffix}:{uuid.uuid4().hex}"


def _latest_user_text(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""
    for message in reversed(messages):
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content", "")
        if isinstance(content, str):
            return content
        return json.dumps(content, ensure_ascii=True, sort_keys=True)
    return ""


def _has_product_system_boundary(messages: Any) -> bool:
    """Require the normal product prompt, not a background summarizer prompt."""
    if not isinstance(messages, list):
        return False
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "system":
            continue
        content = message.get("content")
        return isinstance(content, str) and content.lstrip().startswith("You are JS,")
    return False


def _is_primary_soak_call(messages: Any) -> bool:
    """Separate foreground soak turns from background work that quotes them."""
    if not _has_product_system_boundary(messages):
        return False
    text = _latest_user_text(messages)
    marker = r"__live_soak(?:_stream)?__\s+__live_id__="
    stripped = text.lstrip()
    if re.match(rf"^{marker}", stripped):
        return True
    return stripped.startswith("工作模式：") and bool(
        re.search(rf"\n\n用户任务：\s*{marker}", stripped)
    )


def _is_interactive_acceptance_call(messages: Any) -> bool:
    """Classify foreground harness work without counting background transcripts."""
    if not _has_product_system_boundary(messages):
        return False
    text = _latest_user_text(messages)
    marker = r"__live_[a-z_]+__"
    stripped = text.lstrip()
    if re.match(rf"^{marker}(?:\s|$)", stripped):
        return True
    return stripped.startswith("工作模式：") and bool(
        re.search(rf"\n\n用户任务：\s*{marker}(?:\s|$)", stripped)
    )


def _identity_in_text(text: str, expected: str) -> str | None:
    if expected in text:
        return expected
    match = _LIVE_IDENTITY_RE.search(text)
    return match.group(0) if match is not None else None


def _stream_evidence(frames: list[dict[str, Any]], expected_identity: str) -> dict[str, Any]:
    error_frames: list[dict[str, Any]] = []
    for frame in frames:
        if frame.get("type") != "error":
            continue
        diagnostic: dict[str, Any] = {
            "type": "error",
            "content": str(frame.get("content", ""))[:500],
        }
        if isinstance(frame.get("turns"), int):
            diagnostic["turns"] = frame["turns"]
        error_frames.append(diagnostic)
    return {
        "ws_identity": _identity_in_text(
            "".join(
                str(frame.get("content", "")) for frame in frames if frame.get("type") == "token"
            ),
            expected_identity,
        ),
        "terminal_frames": [
            frame.get("type") for frame in frames if frame.get("type") in TERMINAL_FRAMES
        ],
        "ws_errors": sum(1 for frame in frames if frame.get("type") == "error"),
        "ws_error_frames": error_frames,
    }


def _soak_failure_reasons(sample: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    expected = sample.get("expected_identity")
    product = sample.get("product")
    request_id = sample.get("request_id")
    if sample.get("exception"):
        reasons.append("exception")
    if sample.get("http_status") != 200:
        reasons.append("http_status")
    if (
        not isinstance(expected, str)
        or not isinstance(product, str)
        or not isinstance(request_id, str)
    ):
        reasons.append("missing_identity")
    elif expected != f"{product}:{request_id}":
        reasons.append("invalid_expected_identity")
    if sample.get("http_identity") != expected:
        reasons.append("http_identity")
    if sample.get("ws_identity") != expected:
        reasons.append("ws_identity")
    if sample.get("terminal_frames") != ["done"]:
        reasons.append("terminal_frames")
    if sample.get("ws_errors") != 0:
        reasons.append("ws_errors")
    if sample.get("provider_identity_calls") != 2:
        reasons.append("provider_identity_calls")
    return reasons


def _summarize_soak(samples: list[dict[str, Any]]) -> dict[str, Any]:
    failures = 0
    crosstalk = 0
    identities: set[str] = set()
    terminals: list[str] = []
    reason_counts: dict[str, int] = {}
    failure_samples: list[dict[str, Any]] = []
    for sample in samples:
        reasons = _soak_failure_reasons(sample)
        expected = sample.get("expected_identity")
        observed_identities = (sample.get("http_identity"), sample.get("ws_identity"))
        identity_fault = isinstance(expected, str) and any(
            isinstance(observed, str) and observed != expected for observed in observed_identities
        )
        if isinstance(expected, str) and expected in identities:
            reasons.append("duplicate_identity")
            identity_fault = True
        if isinstance(expected, str):
            identities.add(expected)
        sample["failure_reasons"] = reasons
        if reasons:
            failures += 1
            failure_samples.append(sample)
            for reason in reasons:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1
        if identity_fault:
            crosstalk += 1
        terminals.extend(str(value) for value in sample.get("terminal_frames", []))
    representative_samples = _representative_samples(samples)
    return {
        "sample_count": len(samples),
        "success": len(samples) - failures,
        "failures": failures,
        "crosstalk": crosstalk,
        "http_5xx": sum(1 for sample in samples if int(sample.get("http_status", 0)) >= 500),
        "terminal": {"done": terminals.count("done"), "error": terminals.count("error")},
        "failure_reasons": dict(sorted(reason_counts.items())),
        "failure_samples": _representative_samples(failure_samples),
        "latency_ms": {
            "http": _latency_summary(samples, "http_ms"),
            "ws": _latency_summary(samples, "ws_ms"),
        },
        "samples": representative_samples,
    }


def _representative_samples(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(samples) <= MAX_RECORDED_SAMPLES:
        return samples
    half = MAX_RECORDED_SAMPLES // 2
    return [*samples[:half], *samples[-half:]]


def _latency_summary(samples: list[dict[str, Any]], field: str) -> dict[str, int | float]:
    values = sorted(
        float(sample[field]) for sample in samples if isinstance(sample.get(field), int | float)
    )
    if not values:
        return {"count": 0}

    def percentile(fraction: float) -> float:
        index = max(0, math.ceil(len(values) * fraction) - 1)
        return round(values[index], 2)

    return {
        "count": len(values),
        "min": round(values[0], 2),
        "p50": percentile(0.5),
        "p95": percentile(0.95),
        "max": round(values[-1], 2),
        "mean": round(sum(values) / len(values), 2),
    }


def _soak_failure_message(soak: dict[str, Any]) -> str:
    return (
        "soak failed: "
        f"failures={int(soak.get('failures', 0))}, "
        f"crosstalk={int(soak.get('crosstalk', 0))}, "
        f"http_5xx={int(soak.get('http_5xx', 0))}, "
        f"reasons={soak.get('failure_reasons', {})}"
    )


def _overall_ok(
    products: dict[str, dict[str, Any]],
    soak: dict[str, Any],
    *,
    cleanup_ok: bool,
    resources: dict[str, Any] | None = None,
    storage_resources: dict[str, Any] | None = None,
) -> bool:
    product_checks_ok = bool(products) and all(
        all(value for value in checks.values() if isinstance(value, bool))
        for checks in products.values()
    )
    return bool(
        cleanup_ok
        and product_checks_ok
        and (resources is None or resources.get("ok") is True)
        and (storage_resources is None or storage_resources.get("ok") is True)
        and soak.get("success", 0) >= len(products)
        and soak.get("failures", 0) == 0
        and soak.get("crosstalk", 0) == 0
        and soak.get("http_5xx", 0) == 0
    )


def _run_product_checks(product: Product, provider_port: int) -> None:
    response, latency = _request(product, "GET", "/api/status", key=product.owner_a)
    _expect_status(response, 200, f"{product.name} status")
    body = response.json()
    product.checks["status_primary_healthy"] = (
        body.get("echo", {}).get("architecture_state") == "primary_healthy"
        and body.get("degraded") is False
    )
    if not product.checks["status_primary_healthy"]:
        raise AcceptanceError(f"{product.name} did not report a healthy Echo primary")
    product.latencies_ms["status"] = round(latency, 2)

    session = f"live-chat-{product.name}"
    response, latency = _request(
        product,
        "POST",
        "/api/chat",
        key=product.owner_a,
        json_body={"message": f"__live_chat__ {product.name}", "session_id": session},
    )
    _expect_status(response, 200, f"{product.name} chat")
    if response.json().get("status") != "completed":
        raise AcceptanceError(f"{product.name} chat did not complete")
    product.checks["chat"] = True
    product.latencies_ms["chat"] = round(latency, 2)

    stream_identity = _identity(product, "stream")
    frames, latency = _ws_frames(
        product,
        key=product.owner_a,
        payload={
            "type": "stream",
            "content": f"__live_stream__ __live_id__={stream_identity}",
            "session_id": f"live-stream-{product.name}",
            "enable_tools": False,
        },
    )
    stream = _stream_evidence(frames, stream_identity)
    if (
        stream["terminal_frames"] != ["done"]
        or stream["ws_errors"] != 0
        or stream["ws_identity"] != stream_identity
    ):
        raise AcceptanceError(f"{product.name} stream frames were not incremental: {frames!r}")
    product.checks["stream"] = True
    product.latencies_ms["stream"] = round(latency, 2)

    before_tools = _provider_stats(provider_port).get("chat_calls", 0)
    response, latency = _request(
        product,
        "POST",
        "/api/chat",
        key=product.owner_a,
        json_body={"message": "__live_tool__", "session_id": f"live-tool-{product.name}"},
    )
    _expect_status(response, 200, f"{product.name} tool continuation")
    after_tools = _provider_stats(provider_port).get("chat_calls", 0)
    if (
        "tool continuation complete" not in response.json().get("response", "")
        or after_tools < before_tools + 2
    ):
        raise AcceptanceError(f"{product.name} did not continue after a real tool execution")
    product.checks["tool_continue"] = True
    product.latencies_ms["tool_continue"] = round(latency, 2)

    attachment_session = f"live-attachment-{product.name}"
    response, latency = _request(
        product,
        "POST",
        "/api/upload",
        key=product.owner_a,
        files={"file": ("note.txt", ATTACHMENT_MARKER.encode(), "text/plain")},
        data={"session_id": attachment_session},
    )
    _expect_status(response, 200, f"{product.name} upload")
    attachment_path = response.json().get("path")
    if not isinstance(attachment_path, str) or not attachment_path:
        raise AcceptanceError(f"{product.name} upload returned no attachment path")
    response, attachment_latency = _request(
        product,
        "POST",
        "/api/chat",
        key=product.owner_a,
        json_body={
            "message": "__live_attachment__ summarize the note",
            "session_id": attachment_session,
            "attachments": [attachment_path],
        },
    )
    _expect_status(response, 200, f"{product.name} attachment chat")
    if f"attachment acknowledged: {ATTACHMENT_MARKER}" not in response.json().get("response", ""):
        raise AcceptanceError(f"{product.name} provider did not acknowledge the attachment marker")
    product.checks["attachment"] = True
    product.latencies_ms["attachment"] = round(latency + attachment_latency, 2)

    before_cross_owner = _provider_stats(provider_port).get("chat_calls", 0)
    response, _ = _request(
        product,
        "POST",
        "/api/chat",
        key=product.owner_b,
        json_body={
            "message": "cross owner attachment must fail",
            "session_id": attachment_session,
            "attachments": [attachment_path],
        },
    )
    after_cross_owner = _provider_stats(provider_port).get("chat_calls", 0)
    if (
        response.status_code != 403
        or response.json().get("detail") != "Upload access denied"
        or after_cross_owner != before_cross_owner
    ):
        raise AcceptanceError(
            f"{product.name} cross-owner upload denial was not ownership-specific"
        )
    product.checks["cross_owner_rejected"] = True

    before_secret = _provider_stats(provider_port).get("chat_calls", 0)
    response, _ = _request(
        product,
        "POST",
        "/api/chat",
        key=product.owner_a,
        json_body={
            "message": "secret = sk-test-1234567890abcdef",
            "session_id": f"live-secret-{product.name}",
        },
    )
    after_secret = _provider_stats(provider_port).get("chat_calls", 0)
    if response.status_code != 400 or after_secret != before_secret:
        raise AcceptanceError(f"{product.name} secret did not stop before the provider")
    product.checks["secret_rejected"] = True

    cancel_session = f"live-cancel-{product.name}"
    cancel_identity = _identity(product, "cancel")
    before_cancel = _provider_stats(provider_port).get("identities", {}).get(cancel_identity, 0)
    result: dict[str, Any] = {}

    def _slow_chat() -> None:
        try:
            result["response"], result["latency"] = _request(
                product,
                "POST",
                "/api/chat",
                key=product.owner_a,
                json_body={
                    "message": f"__live_slow__ __live_id__={cancel_identity}",
                    "session_id": cancel_session,
                },
                timeout=18.0,
            )
        except BaseException as exc:  # pragma: no cover - surfaced below
            result["error"] = repr(exc)

    worker = threading.Thread(target=_slow_chat, daemon=True)
    worker.start()
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        slow_count = _provider_stats(provider_port).get("identities", {}).get(cancel_identity, 0)
        if slow_count == before_cancel + 1:
            break
        time.sleep(0.05)
    else:
        raise AcceptanceError(f"{product.name} slow request never reached the fake provider")
    response, latency = _request(
        product,
        "POST",
        f"/api/cancel/{cancel_session}",
        key=product.owner_a,
    )
    _expect_status(response, 200, f"{product.name} cancel request")
    worker.join(timeout=10)
    cancelled_response = result.get("response")
    if worker.is_alive() or not isinstance(cancelled_response, httpx.Response):
        raise AcceptanceError(f"{product.name} cancelled request did not finish: {result!r}")
    if cancelled_response.status_code != 409:
        raise AcceptanceError(
            f"{product.name} cancellation returned {cancelled_response.status_code}: "
            f"{cancelled_response.text[:300]}"
        )
    product.checks["cancel"] = True
    product.latencies_ms["cancel"] = round(latency, 2)

    frames, latency = _ws_frames(
        product,
        key=product.owner_a,
        payload={
            "type": "stream",
            "content": "__live_provider_error__",
            "session_id": f"live-error-{product.name}",
            "enable_tools": False,
        },
    )
    terminal = [frame.get("type") for frame in frames if frame.get("type") in TERMINAL_FRAMES]
    if terminal != ["error"]:
        raise AcceptanceError(
            f"{product.name} provider error emitted bad terminal frames: {frames!r}"
        )
    product.checks["provider_error_single_terminal"] = True
    product.latencies_ms["provider_error"] = round(latency, 2)


def _soak_one(product: Product, index: int, provider_port: int) -> dict[str, Any]:
    del provider_port
    request_id = f"soak:{index}:{uuid.uuid4().hex}"
    expected_identity = f"{product.name}:{request_id}"
    sample: dict[str, Any] = {
        "product": product.name,
        "request_id": request_id,
        "expected_identity": expected_identity,
        "http_status": None,
        "http_identity": None,
        "ws_identity": None,
        "terminal_frames": [],
        "ws_errors": 0,
    }
    session = f"soak-{product.name}-{index}-{uuid.uuid4().hex[:8]}"
    try:
        response, http_ms = _request(
            product,
            "POST",
            "/api/chat",
            key=product.owner_a,
            json_body={
                "message": f"__live_soak__ __live_id__={expected_identity}",
                "session_id": session,
            },
        )
        sample["http_status"] = response.status_code
        sample["http_ms"] = round(http_ms, 2)
        sample["http_identity"] = _identity_in_text(response.text, expected_identity)
        frames, ws_ms = _ws_frames(
            product,
            key=product.owner_a,
            payload={
                "type": "stream",
                "content": f"__live_soak_stream__ __live_id__={expected_identity}",
                "session_id": f"{session}-ws",
                "enable_tools": False,
            },
        )
        sample["ws_ms"] = round(ws_ms, 2)
        sample.update(_stream_evidence(frames, expected_identity))
    except BaseException as exc:  # noqa: BLE001 - strict soak records every failed sample
        sample["exception"] = f"{type(exc).__name__}: {exc}"
    return sample


def _run_soak(
    products: list[Product],
    *,
    provider_port: int,
    duration_seconds: float,
    concurrency: int,
    processes: dict[str, subprocess.Popen[str]] | None = None,
    max_state_bytes: int = DEFAULT_MAX_STATE_BYTES,
    max_rss_bytes: int = DEFAULT_MAX_RSS_BYTES,
    max_growth_mib_per_minute: float = DEFAULT_MAX_RSS_GROWTH_MIB_PER_MINUTE,
) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    resource_samples: list[dict[str, Any]] = []
    monitored_processes = processes or {}
    wall_started = time.time()
    active_started = time.monotonic()
    deadline = time.monotonic() + duration_seconds
    index = 0
    resource_stop = threading.Event()
    resource_lock = threading.Lock()
    integrity_lock = threading.Lock()
    expected_digest = release_source_digest(REPO_ROOT)
    expected_metadata = release_source_surface_metadata_fingerprint(REPO_ROOT)
    source_integrity: dict[str, Any] = {
        "ok": True,
        "drifted": False,
        "check_count": 0,
        "expected_digest": expected_digest,
        "final_digest": expected_digest,
        "expected_metadata_fingerprint": expected_metadata,
        "final_metadata_fingerprint": expected_metadata,
        "failure_message": None,
        "checks": [],
        "chain_root": "0" * 64,
    }
    integrity_failure: list[AcceptanceError] = []
    storage_products = [
        product
        for product in products
        if isinstance(getattr(product, "state_dir", None), Path)
        and isinstance(getattr(product, "name", None), str)
    ]

    def _mark_integrity_failure(message: str) -> None:
        with integrity_lock:
            source_integrity["ok"] = False
            source_integrity["drifted"] = True
            source_integrity["failure_message"] = message
            if not integrity_failure:
                integrity_failure.append(AcceptanceError(message))
        resource_stop.set()

    def _record_integrity_drift(metadata: str, digest: str) -> bool:
        """Update finals and mark drift. Returns True when a failure was recorded."""
        source_integrity["final_metadata_fingerprint"] = metadata
        source_integrity["final_digest"] = digest
        if source_integrity["drifted"]:
            return True
        if metadata != expected_metadata:
            source_integrity["ok"] = False
            source_integrity["drifted"] = True
            source_integrity["failure_message"] = "release-surface metadata drift during soak"
            if not integrity_failure:
                integrity_failure.append(
                    AcceptanceError("release-surface metadata drift during soak")
                )
            resource_stop.set()
            return True
        if digest != expected_digest:
            source_integrity["ok"] = False
            source_integrity["drifted"] = True
            source_integrity["failure_message"] = "source digest drift during soak"
            if not integrity_failure:
                integrity_failure.append(AcceptanceError("source digest drift during soak"))
            resource_stop.set()
            return True
        return False

    def check_source_integrity() -> None:
        with integrity_lock:
            if source_integrity["drifted"]:
                return
        try:
            metadata = release_source_surface_metadata_fingerprint(REPO_ROOT)
            digest = release_source_digest(REPO_ROOT)
        except BaseException as exc:  # noqa: BLE001 - fail closed on probe errors
            _mark_integrity_failure(f"source integrity probe failed: {type(exc).__name__}: {exc}")
            return
        with integrity_lock:
            checks = source_integrity["checks"]
            monotonic_s = round(time.monotonic() - active_started, 6)
            if checks:
                prior = checks[-1].get("monotonic_s")
                if (
                    isinstance(prior, int | float)
                    and not isinstance(prior, bool)
                    and (monotonic_s - float(prior)) < MIN_INTEGRITY_INTERVAL_SECONDS
                    and metadata == expected_metadata
                    and digest == expected_digest
                ):
                    # Skip underspaced samples when the release surface is still
                    # stable (e.g. final flush right after the last tick). Drift
                    # probes always append so abort evidence remains durable.
                    _record_integrity_drift(metadata, digest)
                    return
            check = {
                "index": len(checks) + 1,
                "source_digest": digest,
                "metadata_fingerprint": metadata,
                "monotonic_s": monotonic_s,
                "wall_utc": datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            }
            checks.append(check)
            source_integrity["check_count"] = len(checks)
            source_integrity["chain_root"] = _integrity_chain_append(
                str(source_integrity["chain_root"]),
                check,
            )
            _record_integrity_drift(metadata, digest)

    def capture_resources() -> None:
        check_source_integrity()
        now = time.monotonic()
        sample = _sample_process_resources(
            monitored_processes,
            elapsed_seconds=now - active_started,
        )
        sample["storage"] = {}
        for product in storage_products:
            evidence = _state_storage_evidence(product.state_dir)
            sample["storage"][product.name] = {
                key: evidence[key]
                for key in (
                    "total_bytes",
                    "file_count",
                    "partition_storage_bytes",
                    "partition_file_count",
                    "max_active_session_partitions_per_owner",
                    "retired_session_partition_count",
                    "retention_checkpoint_bytes",
                    "retention_checkpoint_errors",
                    "incomplete_retirements",
                    "incomplete_retirement_markers",
                    "component_bytes",
                )
            }
        with resource_lock:
            resource_samples.append(sample)

    def resource_sampler() -> None:
        next_due = time.monotonic()
        while not resource_stop.is_set():
            capture_resources()
            if integrity_failure:
                break
            next_due += RESOURCE_SAMPLE_INTERVAL_SECONDS
            delay = next_due - time.monotonic()
            if delay > 0 and resource_stop.wait(delay):
                break
            if delay <= 0:
                # Probe overran the interval; schedule from now to avoid burst catch-up.
                next_due = time.monotonic()

    resource_thread = threading.Thread(
        target=resource_sampler,
        name="echo-live-resource-sampler",
        daemon=True,
    )
    resource_thread.start()

    soak_error: BaseException | None = None
    try:
        # Seed both products so a one-second, single-worker run still proves the
        # isolated deployments independently before the timed loop adds pressure.
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
            for sample in executor.map(
                lambda item: _soak_one(*item),
                ((product, index, provider_port) for index, product in enumerate(products)),
            ):
                samples.append(sample)
            while time.monotonic() < deadline:
                if integrity_failure:
                    break
                batch = [
                    (products[(index + offset) % len(products)], index + offset, provider_port)
                    for offset in range(concurrency)
                ]
                index += len(batch)
                for sample in executor.map(lambda item: _soak_one(*item), batch):
                    samples.append(sample)
                    if integrity_failure:
                        break
    except BaseException as exc:  # noqa: BLE001 - preserve for summary attachment
        soak_error = exc
    finally:
        resource_stop.set()
        resource_thread.join(timeout=RESOURCE_SAMPLE_INTERVAL_SECONDS + 1)
        if not integrity_failure:
            capture_resources()

    provider_stats = _provider_stats(provider_port)
    primary_identities = provider_stats.get("primary_identities", {})
    if not isinstance(primary_identities, dict):
        raise AcceptanceError("fake provider stats primary_identities must be an object")
    for sample in samples:
        sample["provider_identity_calls"] = primary_identities.get(
            sample.get("expected_identity"), 0
        )

    summary = _summarize_soak(samples)
    summary["provider_snapshot"] = _provider_evidence(provider_stats)
    summary["requested_seconds"] = duration_seconds
    summary["active_elapsed_seconds"] = round(time.monotonic() - active_started, 3)
    summary["wall_elapsed_seconds"] = round(time.time() - wall_started, 3)
    resources = _summarize_resource_samples(
        resource_samples,
        duration_seconds=duration_seconds,
        max_rss_bytes=max_rss_bytes,
        max_growth_mib_per_minute=max_growth_mib_per_minute,
        required_processes=tuple(sorted(monitored_processes)),
    )
    for name, process in monitored_processes.items():
        process_report = resources["processes"].get(name)
        if isinstance(process_report, dict) and process.pid is not None:
            process_report["pid"] = int(process.pid)
    summary["resources"] = resources
    storage_resources = _summarize_storage_samples(
        resource_samples,
        duration_seconds=duration_seconds,
        max_state_bytes=max_state_bytes,
        required_products=tuple(sorted(product.name for product in storage_products)),
    )
    summary["storage_resources"] = storage_resources
    with integrity_lock:
        # Deterministic hash-chain consistency binder (public fixed seed).
        # This is NOT an unforgeable authenticity signature: anyone can derive the
        # same key. Third-party authenticity is out of scope here.
        private_seed = hashlib.sha256(b"js-agent-round87-soak-integrity-signing-key-v1").digest()
        private_key = Ed25519PrivateKey.from_private_bytes(private_seed)
        public_raw = private_key.public_key().public_bytes_raw()
        source_check_chain_root = str(source_integrity["chain_root"])
        resource_sample_payload = json.dumps(
            resources["samples"],
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        storage_sample_payload = json.dumps(
            storage_resources["samples"],
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        resource_sample_root = hashlib.sha256(resource_sample_payload).hexdigest()
        storage_sample_root = hashlib.sha256(storage_sample_payload).hexdigest()
        chain_binding = "echo-live-resource-samples-v1"
        binding_payload = {
            "binding_version": chain_binding,
            "resource_sample_count": len(resources["samples"]),
            "resource_sample_root": resource_sample_root,
            "storage_sample_count": len(storage_resources["samples"]),
            "storage_sample_root": storage_sample_root,
        }
        binding_json = json.dumps(
            binding_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        chain_root = hashlib.sha256(bytes.fromhex(source_check_chain_root) + binding_json).hexdigest()
        source_integrity.update(
            {
                "source_check_chain_root": source_check_chain_root,
                "resource_sample_count": binding_payload["resource_sample_count"],
                "resource_sample_root": resource_sample_root,
                "storage_sample_count": binding_payload["storage_sample_count"],
                "storage_sample_root": storage_sample_root,
                "chain_root": chain_root,
                "chain_binding": chain_binding,
            }
        )
        source_integrity["chain_root_signature_b64"] = base64.b64encode(
            private_key.sign(chain_root.encode("ascii"))
        ).decode()
        source_integrity["pubkey_fingerprint"] = hashlib.sha256(public_raw).hexdigest()
        summary["source_integrity"] = dict(source_integrity)
    if soak_error is not None:
        raise soak_error
    if integrity_failure:
        error = integrity_failure[0]
        error.soak_result = summary
        raise error
    return summary


def _run_parent(args: argparse.Namespace) -> int:
    if args.duration_seconds <= 0:
        raise AcceptanceError("--duration-seconds must be positive")
    if args.concurrency <= 0:
        raise AcceptanceError("--concurrency must be positive")
    if args.max_state_bytes <= 0:
        raise AcceptanceError("--max-state-bytes must be positive")
    if args.max_rss_bytes <= 0:
        raise AcceptanceError("--max-rss-bytes must be positive")
    if args.max_rss_growth_mib_per_minute < 0:
        raise AcceptanceError("--max-rss-growth-mib-per-minute must be non-negative")

    initial_digest = release_source_digest(REPO_ROOT)
    initial_metadata = release_source_surface_metadata_fingerprint(REPO_ROOT)
    report: dict[str, Any] = {
        "schema_version": "echo-live-acceptance-v4",
        "started_utc": datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "source_digest": initial_digest,
        "acceptance_pid": os.getpid(),
        "ok": False,
        "duration_seconds": args.duration_seconds,
        "concurrency": args.concurrency,
        "max_state_bytes": args.max_state_bytes,
        "max_session_partitions_per_owner": DEFAULT_MAX_SESSION_PARTITIONS_PER_OWNER,
        "max_rss_bytes": args.max_rss_bytes,
        "max_rss_growth_mib_per_minute": args.max_rss_growth_mib_per_minute,
        "network": "local-only",
        "products": {},
        "storage": {},
        "soak": {
            "sample_count": 0,
            "success": 0,
            "failures": 0,
            "crosstalk": 0,
            "http_5xx": 0,
            "terminal": {"done": 0, "error": 0},
            "failure_reasons": {},
            "failure_samples": [],
            "latency_ms": {"http": {"count": 0}, "ws": {"count": 0}},
            "provider_snapshot": {},
            "samples": [],
        },
        "resources": {
            "ok": False,
            "stability_enforced": False,
            "processes": {},
            "samples": [],
        },
        "storage_stability": {
            "ok": False,
            "stability_enforced": False,
            "products": {},
            "samples": [],
        },
        "source_integrity": {
            "ok": True,
            "drifted": False,
            "check_count": 0,
            "expected_digest": initial_digest,
            "final_digest": initial_digest,
            "expected_metadata_fingerprint": initial_metadata,
            "final_metadata_fingerprint": initial_metadata,
            "failure_message": None,
            "checks": [],
            "chain_root": "0" * 64,
        },
        "process_tree": {
            "wrapper": _process_snapshot(os.getppid()),
            "acceptance": _process_snapshot(os.getpid()),
            "children": {},
        },
        "provider": {},
        "runtime_memory": {},
        "cleanup": {
            "all_processes_stopped": False,
            "graceful": False,
            "children": {},
        },
    }
    children: list[ChildProcess] = []
    products: list[Product] = []
    provider_port: int | None = None
    failure: BaseException | None = None
    signal_state: dict[str, str | None] = {"name": None}
    previous_handlers: dict[int, Any] = {}

    def _signal_handler(signum: int, _frame: Any) -> None:
        signal_state["name"] = signal.Signals(signum).name
        raise AcceptanceInterruptedError(f"received {signal_state['name']}")

    for handled_signal in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[handled_signal] = signal.signal(handled_signal, _signal_handler)
    try:
        with tempfile.TemporaryDirectory(prefix="echo-live-acceptance-") as raw_tmp:
            root = Path(raw_tmp)
            provider_port = _free_port()
            provider_env = _local_env(root / "provider-home")
            provider = _start_child(
                ["--child-component", "fake-provider", "--port", str(provider_port)],
                env=provider_env,
                name="fake-provider",
            )
            children.append(provider)
            _wait_ready(f"http://{LOOPBACK}:{provider_port}/v1/models", provider)

            for product_name in ("js_agent", "js_work"):
                product_root = root / product_name
                home = product_root / "home"
                product_home = home / ".js-work" if product_name == "js_work" else product_root
                state_dir = product_home / "state"
                config = product_root / "config.yaml"
                _write_config(
                    config,
                    workspace=product_home / "workspace",
                    state_dir=state_dir,
                    provider_port=provider_port,
                )
                owner_a, owner_b = _mint_owners(state_dir)
                product = Product(
                    name=product_name,
                    port=_free_port(),
                    config=config,
                    home=home,
                    state_dir=state_dir,
                    owner_a=owner_a,
                    owner_b=owner_b,
                )
                env = _local_env(product.home)
                if product_name == "js_agent":
                    env["JS_CONFIG_PATH"] = str(config)
                else:
                    env["JS_WORK_CONFIG_PATH"] = str(config)
                child = _start_child(
                    [
                        "--child-component",
                        "web-app",
                        "--product",
                        product_name,
                        "--config",
                        str(config),
                        "--home",
                        str(product.home),
                        "--port",
                        str(product.port),
                    ],
                    env=env,
                    name=product_name,
                )
                children.append(child)
                _wait_ready(f"{product.base_url}/api/status", child, product.owner_a)
                products.append(product)

            report["process_tree"]["children"] = {
                child.name: _process_snapshot(child.process.pid) for child in children
            }
            if args.ready_file:
                ready_file = Path(args.ready_file)
                ready_file.parent.mkdir(parents=True, exist_ok=True)
                ready_file.write_text(
                    json.dumps(
                        {
                            "children": [
                                {
                                    "name": child.name,
                                    "pid": child.process.pid,
                                    "process_group": child.process_group,
                                }
                                for child in children
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
            for product in products:
                _run_product_checks(product, provider_port)
            try:
                report["soak"] = _run_soak(
                    products,
                    provider_port=provider_port,
                    duration_seconds=args.duration_seconds,
                    concurrency=args.concurrency,
                    processes={
                        child.name: child.process
                        for child in children
                        if child.name in {product.name for product in products}
                    },
                    max_state_bytes=args.max_state_bytes,
                    max_rss_bytes=args.max_rss_bytes,
                    max_growth_mib_per_minute=args.max_rss_growth_mib_per_minute,
                )
            except AcceptanceError as soak_exc:
                soak_result = getattr(soak_exc, "soak_result", None)
                if isinstance(soak_result, dict):
                    report["soak"] = {
                        key: value
                        for key, value in soak_result.items()
                        if key not in {"resources", "storage_resources", "source_integrity"}
                    }
                    if "resources" in soak_result:
                        report["resources"] = soak_result["resources"]
                    if "storage_resources" in soak_result:
                        report["storage_stability"] = soak_result["storage_resources"]
                    if "source_integrity" in soak_result:
                        report["source_integrity"] = soak_result["source_integrity"]
                    if "provider_snapshot" in soak_result:
                        report["provider"] = soak_result["provider_snapshot"]
                raise
            report["resources"] = report["soak"].pop("resources")
            report["storage_stability"] = report["soak"].pop("storage_resources")
            report["source_integrity"] = report["soak"].pop("source_integrity")
            report["provider"] = report["soak"]["provider_snapshot"]
            report["storage"] = {
                product.name: _state_storage_evidence(product.state_dir) for product in products
            }
            for product in products:
                response, _latency = _request(
                    product,
                    "GET",
                    "/__live__/memory",
                    key=product.owner_a,
                )
                _expect_status(response, 200, f"{product.name} runtime memory evidence")
                report["runtime_memory"][product.name] = response.json()
            for product in products:
                product.checks["storage_within_limit"] = (
                    report["storage"][product.name]["total_bytes"] <= args.max_state_bytes
                )
                storage = report["storage"][product.name]
                product.checks["session_partitions_bounded"] = bool(
                    storage["max_active_session_partitions_per_owner"]
                    <= DEFAULT_MAX_SESSION_PARTITIONS_PER_OWNER
                    and not storage["retention_checkpoint_errors"]
                    and not storage["incomplete_retirements"]
                )
            if report["soak"]["failures"] or report["soak"]["crosstalk"]:
                raise AcceptanceError(_soak_failure_message(report["soak"]))
            if not report["resources"]["ok"]:
                failed_resources = [
                    name
                    for name, evidence in report["resources"]["processes"].items()
                    if not evidence.get("ok")
                ]
                raise AcceptanceError(
                    "resource stability limit exceeded: " + ", ".join(failed_resources)
                )
            if not report["storage_stability"]["ok"]:
                failed_storage = [
                    name
                    for name, evidence in report["storage_stability"]["products"].items()
                    if not evidence.get("ok")
                ]
                raise AcceptanceError(
                    "storage stability limit exceeded: " + ", ".join(failed_storage)
                )
            oversized_products = [
                name
                for name, evidence in report["storage"].items()
                if evidence["total_bytes"] > args.max_state_bytes
            ]
            if oversized_products:
                raise AcceptanceError(
                    "state storage limit exceeded: " + ", ".join(oversized_products)
                )
            unbounded_partition_products = [
                name
                for name, evidence in report["storage"].items()
                if evidence["max_active_session_partitions_per_owner"]
                > DEFAULT_MAX_SESSION_PARTITIONS_PER_OWNER
                or evidence["retention_checkpoint_errors"]
                or evidence["incomplete_retirements"]
            ]
            if unbounded_partition_products:
                raise AcceptanceError(
                    "session partition retention failed: " + ", ".join(unbounded_partition_products)
                )
    except BaseException as exc:  # noqa: BLE001 - report failures for operators
        failure = exc
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for handled_signal in (signal.SIGINT, signal.SIGTERM):
            signal.signal(handled_signal, signal.SIG_IGN)
        if provider_port is not None and not report["provider"]:
            try:
                report["provider"] = _provider_evidence(_provider_stats(provider_port))
            except BaseException as exc:  # noqa: BLE001 - preserve the primary failure
                report["provider_capture_error"] = f"{type(exc).__name__}: {exc}"
        cleanup_errors: list[str] = []
        for child in reversed(children):
            try:
                child.stop()
            except BaseException as exc:  # pragma: no cover - ChildProcess records its own failure
                cleanup_errors.append(f"{child.name}: {type(exc).__name__}: {exc}")
            if child.stop_error:
                cleanup_errors.append(f"{child.name}: {child.stop_error}")
        report["products"] = {
            product.name: {**product.checks, "latencies_ms": product.latencies_ms}
            for product in products
        }
        all_processes_stopped = bool(children) and all(child.stopped for child in children)
        graceful_cleanup = (
            all_processes_stopped
            and not cleanup_errors
            and all(not child.forced_kill for child in children)
        )
        report["cleanup"] = {
            "all_processes_stopped": all_processes_stopped,
            "graceful": graceful_cleanup,
            "signal": signal_state["name"],
            "errors": cleanup_errors,
            "children": {
                child.name: {
                    "pid": child.process.pid,
                    "process_group": child.process_group,
                    "returncode": child.process.returncode,
                    "stopped": child.stopped,
                    "forced_kill": child.forced_kill,
                    "stop_error": child.stop_error,
                }
                for child in children
            },
        }
        integrity = report.get("source_integrity")
        if not isinstance(integrity, dict):
            integrity = {
                "ok": False,
                "drifted": True,
                "check_count": 0,
                "expected_digest": report.get("source_digest"),
                "final_digest": None,
                "expected_metadata_fingerprint": None,
                "final_metadata_fingerprint": None,
                "failure_message": "source_integrity missing",
            }
            report["source_integrity"] = integrity
        final_digest: str | None
        final_metadata: str | None
        try:
            final_digest = release_source_digest(REPO_ROOT)
            final_metadata = release_source_surface_metadata_fingerprint(REPO_ROOT)
        except BaseException as exc:  # noqa: BLE001 - fail closed before write
            final_digest = None
            final_metadata = None
            integrity["ok"] = False
            integrity["drifted"] = True
            integrity["failure_message"] = (
                f"source integrity final probe failed: {type(exc).__name__}: {exc}"
            )
        else:
            integrity["final_digest"] = final_digest
            integrity["final_metadata_fingerprint"] = final_metadata
            expected_digest = integrity.get("expected_digest", report.get("source_digest"))
            expected_metadata = integrity.get("expected_metadata_fingerprint")
            if final_digest != expected_digest:
                integrity["ok"] = False
                integrity["drifted"] = True
                integrity["failure_message"] = "source digest drift during soak"
            elif not isinstance(expected_metadata, str) or final_metadata != expected_metadata:
                integrity["ok"] = False
                integrity["drifted"] = True
                integrity["failure_message"] = "release-surface metadata drift during soak"
        report["source_integrity"] = integrity
        if integrity.get("ok") is not True and failure is None:
            failure = AcceptanceError(
                str(integrity.get("failure_message") or "source digest drift during soak")
            )
            report["error"] = str(failure)

        report["ok"] = (
            failure is None
            and integrity.get("ok") is True
            and _overall_ok(
                report["products"],
                report["soak"],
                cleanup_ok=report["cleanup"]["graceful"],
                resources=report["resources"],
                storage_resources=report["storage_stability"],
            )
        )
        if not report["ok"] and failure is None:
            failure = AcceptanceError("aggregate acceptance criteria failed after cleanup")
            report["error"] = str(failure)
        for restore_signal, previous in previous_handlers.items():
            signal.signal(restore_signal, previous)
        output = Path(args.output)
        report["finished_utc"] = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if failure is not None:
        print(report["error"], file=sys.stderr)
        return 1
    return 0


def _run_fake_provider(port: int) -> None:
    import uvicorn
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse, StreamingResponse

    app = FastAPI()
    state: dict[str, Any] = {
        "chat_calls": 0,
        "interactive_calls": 0,
        "background_calls": 0,
        "scenarios": {},
        "identities": {},
        "primary_identities": {},
    }

    def _scenario(text: str) -> str:
        for marker, name in (
            ("__live_attachment__", "attachment"),
            ("__live_slow__", "slow"),
            ("__live_tool__", "tool"),
            ("__live_provider_error__", "provider_error"),
            ("__live_stream__", "stream"),
            ("__live_soak", "soak"),
        ):
            if marker in text:
                return name
        return "chat"

    @app.get("/v1/models")
    async def models() -> dict[str, Any]:
        return {"object": "list", "data": [{"id": "live-local-model", "object": "model"}]}

    @app.get("/__live__/stats")
    async def stats() -> dict[str, Any]:
        return state

    @app.post("/v1/chat/completions")
    async def completions(body: dict[str, Any]) -> Any:
        messages = body.get("messages", [])
        text = _latest_user_text(messages)
        scenario = _scenario(text)
        identity_match = re.search(r"__live_id__=([A-Za-z0-9:_-]+)", text)
        identity = identity_match.group(1) if identity_match else ""
        state["chat_calls"] += 1
        if _is_interactive_acceptance_call(messages):
            state["interactive_calls"] += 1
        else:
            state["background_calls"] += 1
        state["scenarios"][scenario] = state["scenarios"].get(scenario, 0) + 1
        if identity:
            state["identities"][identity] = state["identities"].get(identity, 0) + 1
            if _is_primary_soak_call(messages):
                state["primary_identities"][identity] = (
                    state["primary_identities"].get(identity, 0) + 1
                )
        if scenario == "provider_error":
            return JSONResponse(
                status_code=500, content={"error": {"message": "local provider error"}}
            )
        if scenario == "slow":
            await asyncio.sleep(10)

        if body.get("stream"):

            async def events() -> Any:
                for token in ("live ", f"stream {identity}"):
                    chunk = {
                        "id": "live-stream",
                        "object": "chat.completion.chunk",
                        "model": "live-local-model",
                        "choices": [
                            {"index": 0, "delta": {"content": token}, "finish_reason": None}
                        ],
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
                    await asyncio.sleep(0.01)
                final = {
                    "id": "live-stream",
                    "object": "chat.completion.chunk",
                    "model": "live-local-model",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
                }
                yield f"data: {json.dumps(final)}\n\n"
                yield "data: [DONE]\n\n"

            return StreamingResponse(events(), media_type="text/event-stream")

        has_tool_result = any(
            isinstance(message, dict) and message.get("role") == "tool" for message in messages
        )
        if scenario == "tool" and not has_tool_result:
            message: dict[str, Any] = {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "live-tool-call",
                        "type": "function",
                        "function": {"name": "file_list", "arguments": "{}"},
                    }
                ],
            }
            finish_reason = "tool_calls"
        elif has_tool_result:
            message = {"role": "assistant", "content": "tool continuation complete"}
            finish_reason = "stop"
        elif scenario == "attachment" and ATTACHMENT_MARKER in text:
            message = {
                "role": "assistant",
                "content": f"attachment acknowledged: {ATTACHMENT_MARKER}",
            }
            finish_reason = "stop"
        else:
            message = {
                "role": "assistant",
                "content": f"local acceptance complete {identity}".strip(),
            }
            finish_reason = "stop"
        return {
            "id": "live-completion",
            "object": "chat.completion",
            "created": 0,
            "model": "live-local-model",
            "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        }

    uvicorn.run(app, host=LOOPBACK, port=port, log_level="error", access_log=False)


def _run_web_app(args: argparse.Namespace) -> None:
    import gc

    import uvicorn

    if args.product == "js_agent":
        os.environ["JS_CONFIG_PATH"] = args.config
        from js.web.server import create_app

        app = create_app()
    elif args.product == "js_work":
        os.environ["JS_WORK_CONFIG_PATH"] = args.config
        from js_work.tools import WorkToolProfile
        from js_work.web import create_work_web_app

        app = create_work_web_app(
            config=args.config,
            home=Path(args.home),
            profile=WorkToolProfile.EXECUTE,
            host=LOOPBACK,
            port=args.port,
        )
    else:  # pragma: no cover - argparse constrains this path
        raise AcceptanceError(f"unknown product: {args.product}")

    @app.get("/__live__/memory")
    async def runtime_memory() -> dict[str, Any]:
        from js.echo.runtime import get_pulse_runtime

        partition_id = "js-agent" if args.product == "js_agent" else "js-work"
        runtime = getattr(app.state, "web_runtime", None)
        agent = getattr(runtime, "agent", None)
        memory = getattr(agent, "memory", None)
        enhanced_memory = getattr(memory, "enhanced", None)
        echo_service = getattr(agent, "echo_safety_service", None)
        caches = {
            "active_runs": len(getattr(agent, "_active_run_tasks", {})),
            "cancel_tokens": len(getattr(agent, "_cancel_tokens", {})),
            "echo_tenant_states": len(getattr(echo_service, "_tenant_states", {})),
            "routing": len(getattr(getattr(agent, "router", None), "_routing_cache", {})),
            "system_prompt": len(getattr(agent, "_system_message_cache", {})),
            "tool_results": len(getattr(getattr(agent, "registry", None), "_result_cache", {})),
            "working_memory": len(getattr(enhanced_memory, "_working_cache", {})),
        }
        type_counts = Counter(
            f"{type(item).__module__}.{type(item).__qualname__}" for item in gc.get_objects()
        )
        return {
            "cache_sizes": caches,
            "pulse": get_pulse_runtime(partition_id).snapshot(),
            "tracked_object_count": sum(type_counts.values()),
            "top_tracked_types": dict(type_counts.most_common(30)),
            "gc_counts": list(gc.get_count()),
        }

    uvicorn.run(app, host=LOOPBACK, port=args.port, log_level="error", access_log=False)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local Echo live acceptance checks.")
    parser.add_argument("--duration-seconds", type=float, default=10.0)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--max-state-bytes", type=int, default=DEFAULT_MAX_STATE_BYTES)
    parser.add_argument("--max-rss-bytes", type=int, default=DEFAULT_MAX_RSS_BYTES)
    parser.add_argument(
        "--max-rss-growth-mib-per-minute",
        type=float,
        default=DEFAULT_MAX_RSS_GROWTH_MIB_PER_MINUTE,
    )
    parser.add_argument(
        "--output", type=Path, default=REPO_ROOT / ".tmp" / "echo-live-acceptance.json"
    )
    parser.add_argument("--ready-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--child-component", choices=("fake-provider", "web-app"))
    parser.add_argument("--product", choices=("js_agent", "js_work"))
    parser.add_argument("--config")
    parser.add_argument("--home")
    parser.add_argument("--port", type=int)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.child_component == "fake-provider":
        if not args.port:
            raise AcceptanceError("fake provider requires --port")
        _run_fake_provider(args.port)
        return 0
    if args.child_component == "web-app":
        if not (args.product and args.config and args.home and args.port):
            raise AcceptanceError("web app child requires product, config, home, and port")
        _run_web_app(args)
        return 0
    return _run_parent(args)


if __name__ == "__main__":
    raise SystemExit(main())

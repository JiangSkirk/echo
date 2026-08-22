from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from scripts import run_supervised_soak as soak

if TYPE_CHECKING:
    import pytest


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _product_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, dict[str, str]]:
    evidence = (tmp_path / "evidence").resolve()
    app = evidence / "desktop-build/artifacts/JS Agent.app"
    executable = app / "Contents/MacOS/js-agent-desktop"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"fresh-app")
    manifest = evidence / "desktop-build/manifest.json"
    manifest.write_text('{"fixture":true}\n', encoding="utf-8")
    harness = evidence / "harness/JS Agent UI Test Harness.app/Contents/MacOS/harness"
    harness.parent.mkdir(parents=True)
    harness.write_bytes(b"harness")
    harness.chmod(0o755)
    bindings = {
        "app_sha256": _sha256(executable),
        "app_tree_sha256": "b" * 64,
        "desktop_manifest_sha256": _sha256(manifest),
        "bundle_identifier": "com.titan.js-agent",
    }
    return evidence, app, harness, manifest, bindings


def _passing_scenarios() -> dict[str, dict[str, bool]]:
    return {
        "ui_mode_switch_personal_work_personal": {"passed": True},
        "restart_simplified_flow": {"passed": True},
        "http_api_status": {"passed": True},
    }


def test_overlay_harness_argv_carries_fresh_binding_and_nonce_without_leaking_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, app, harness, manifest, bindings = _product_fixture(tmp_path)
    work_dir = (tmp_path / "overlay-work").resolve()
    work_dir.mkdir()
    output = tmp_path / "overlay.json"
    binding_calls: list[tuple[Path, Path, Path]] = []
    harness_commands: list[list[str]] = []
    rejected_missing: list[str] = []
    issued_nonces: list[str] = []

    def fake_bindings(*, app_path: Path, manifest_path: Path, repo_root: Path) -> dict[str, str]:
        binding_calls.append((app_path, manifest_path, repo_root))
        return dict(bindings)

    monkeypatch.setattr(soak, "_manifest_bindings", fake_bindings, raising=False)

    def fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        harness_commands.append(cmd)
        required = ("--nonce", "--app-tree-sha256", "--desktop-manifest-path")
        missing = [flag for flag in required if flag not in cmd]
        if missing:
            rejected_missing.extend(missing)
            return SimpleNamespace(returncode=64, stdout="", stderr="usage")

        nonce = cmd[cmd.index("--nonce") + 1]
        issued_nonces.append(nonce)
        result_path = Path(cmd[cmd.index("--result-path") + 1])
        result_path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "nonce": nonce,
                    "app_sha256": bindings["app_sha256"],
                    "app_tree_sha256": bindings["app_tree_sha256"],
                    "desktop_manifest_sha256": bindings["desktop_manifest_sha256"],
                    "bundle_identifier": bindings["bundle_identifier"],
                    "scenarios": _passing_scenarios(),
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    report = soak.run_overlay(
        duration_seconds=6,
        app_path=app,
        harness_exec=harness,
        output_path=output,
        source_digest="a" * 64,
        metadata_fingerprint="c" * 64,
        work_dir=work_dir,
    )

    assert report["ok"] is True
    assert rejected_missing == []
    assert len(harness_commands) == 1
    assert len(issued_nonces) == 1
    nonce = issued_nonces[0]
    assert re.fullmatch(r"[0-9a-f]{64}", nonce)
    command = harness_commands[0]
    assert command[command.index("--app-path") + 1] == str(app.resolve())
    assert command[command.index("--app-tree-sha256") + 1] == bindings["app_tree_sha256"]
    assert command[command.index("--desktop-manifest-path") + 1] == str(manifest.resolve())
    assert Path(command[command.index("--result-path") + 1]).is_absolute()
    assert binding_calls
    assert all(call[0].is_absolute() and call[1].is_absolute() for call in binding_calls)
    assert nonce not in json.dumps(report, sort_keys=True)
    assert nonce not in output.read_text(encoding="utf-8")
    assert not (work_dir / "overlay_harness_result.json").exists()


def test_overlay_rejects_app_without_strict_desktop_manifest_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, app, harness, _, _ = _product_fixture(tmp_path)
    work_dir = (tmp_path / "overlay-work").resolve()
    work_dir.mkdir()
    monkeypatch.setattr(soak, "_manifest_bindings", lambda **_kwargs: None, raising=False)

    def unexpected_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        raise AssertionError("unbound app must be rejected before the harness starts")

    monkeypatch.setattr(subprocess, "run", unexpected_run)

    report = soak.run_overlay(
        duration_seconds=6,
        app_path=app,
        harness_exec=harness,
        output_path=tmp_path / "overlay.json",
        source_digest="a" * 64,
        metadata_fingerprint="c" * 64,
        work_dir=work_dir,
    )

    assert report["ok"] is False
    assert report["errors"] == ["desktop_manifest_app_binding_invalid"]


def test_product_soak_rejects_app_not_bound_to_same_evidence_before_core_starts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence, app, harness, manifest, _ = _product_fixture(tmp_path)
    binding_calls: list[tuple[Path, Path, Path]] = []

    def reject_bindings(*, app_path: Path, manifest_path: Path, repo_root: Path) -> None:
        binding_calls.append((app_path, manifest_path, repo_root))
        return None

    def unexpected_spawn(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("invalid product provenance must fail before the core child starts")

    monkeypatch.setattr(soak, "release_source_digest", lambda _root: "d" * 64)
    monkeypatch.setattr(
        soak, "release_source_surface_metadata_fingerprint", lambda _root: "e" * 64
    )
    monkeypatch.setattr(soak, "_manifest_bindings", reject_bindings)
    monkeypatch.setattr(soak, "_spawn", unexpected_spawn)

    rc = soak.main(
        [
            "--duration-seconds",
            "0",
            "--output",
            str(tmp_path / "core.json"),
            "--evidence-dir",
            str(evidence),
            "--app-path",
            str(app),
            "--harness-path",
            str(harness),
        ]
    )

    assert rc == 2
    assert binding_calls == [(app.resolve(), manifest.resolve(), soak.REPO_ROOT)]


def test_product_main_writes_closed_sanitized_combined_and_forwards_worker_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence, app, harness, _, bindings = _product_fixture(tmp_path)
    output = (tmp_path / "core.json").resolve()
    source_digest = "d" * 64
    metadata_fingerprint = "e" * 64
    spawned: list[list[str]] = []

    class FinishedChild:
        returncode = 0

        def __init__(self, pid: int) -> None:
            self.pid = pid

        @staticmethod
        def poll() -> int:
            return 0

    def fake_spawn(cmd: list[str], **_kwargs: object) -> FinishedChild:
        spawned.append(cmd)
        if "--overlay-worker" not in cmd:
            Path(cmd[cmd.index("--output") + 1]).write_text(
                json.dumps({"ok": True, "source_digest": source_digest}),
                encoding="utf-8",
            )
            return FinishedChild(111)
        overlay_output = Path(cmd[cmd.index("--overlay-output") + 1])
        overlay_output.write_text(
            json.dumps(
                {
                    "ok": True,
                    "source_digest": source_digest,
                    "metadata_fingerprint": metadata_fingerprint,
                    "targets": dict.fromkeys(_passing_scenarios(), 1),
                    "counters": dict.fromkeys(_passing_scenarios(), 1),
                    "targets_met": True,
                    "cycles": 1,
                    "heartbeat_count": 2,
                    "max_heartbeat_gap_s": 5.0,
                    "max_heartbeat_gap_limit_s": 15.0,
                    "chain_root": "f" * 64,
                    "desktop_manifest_sha256": bindings["desktop_manifest_sha256"],
                    "app_tree_sha256": bindings["app_tree_sha256"],
                    "app_sha256": bindings["app_sha256"],
                }
            ),
            encoding="utf-8",
        )
        return FinishedChild(222)

    monkeypatch.setattr(soak, "release_source_digest", lambda _root: source_digest)
    monkeypatch.setattr(
        soak,
        "release_source_surface_metadata_fingerprint",
        lambda _root: metadata_fingerprint,
    )
    monkeypatch.setattr(soak, "_manifest_bindings", lambda **_kwargs: dict(bindings))
    monkeypatch.setattr(soak, "_spawn", fake_spawn)

    rc = soak.main(
        [
            "--duration-seconds",
            "0",
            "--output",
            str(output),
            "--evidence-dir",
            str(evidence),
            "--app-path",
            str(app),
            "--harness-path",
            str(harness),
        ]
    )

    assert rc == 0
    worker = next(cmd for cmd in spawned if "--overlay-worker" in cmd)
    assert worker[worker.index("--app-tree-sha256") + 1] == bindings["app_tree_sha256"]
    assert worker[worker.index("--desktop-manifest-path") + 1] == str(
        (evidence / "desktop-build/manifest.json").resolve()
    )
    combined_path = evidence / "soak/supervised_soak.combined.json"
    combined = json.loads(combined_path.read_text(encoding="utf-8"))
    assert set(combined) == {
        "schema_version",
        "ok",
        "started_utc",
        "finished_utc",
        "duration_seconds",
        "elapsed_seconds",
        "source_digest",
        "metadata_fingerprint",
        "core",
        "overlay",
        "combined_sha256",
    }
    assert set(combined["core"]) == {"exit_code", "raw_sha256", "ok"}
    assert set(combined["overlay"]) == {
        "exit_code",
        "raw_sha256",
        "ok",
        "targets",
        "counters",
        "targets_met",
        "cycles",
        "heartbeat_count",
        "max_heartbeat_gap_s",
        "max_heartbeat_gap_limit_s",
        "chain_root",
        "desktop_manifest_sha256",
        "app_tree_sha256",
        "app_sha256",
    }
    serialized = combined_path.read_text(encoding="utf-8")
    assert str(tmp_path) not in serialized
    assert "nonce" not in serialized.lower()
    assert "pid" not in serialized.lower()
    assert combined["combined_sha256"] == soak._canonical_sha256(
        {key: value for key, value in combined.items() if key != "combined_sha256"}
    )


def test_core_only_diagnostic_does_not_require_desktop_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output = (tmp_path / "core.json").resolve()
    evidence = (tmp_path / "evidence").resolve()
    source_digest = "d" * 64

    class FinishedCore:
        pid = 4321
        returncode = 0

        @staticmethod
        def poll() -> int:
            return 0

    def fake_spawn(cmd: list[str], **_kwargs: object) -> FinishedCore:
        output_arg = Path(cmd[cmd.index("--output") + 1])
        output_arg.write_text(
            json.dumps({"ok": True, "source_digest": source_digest}), encoding="utf-8"
        )
        return FinishedCore()

    def unexpected_bindings(**_kwargs: object) -> None:
        raise AssertionError("core-only diagnostics must not load desktop provenance")

    monkeypatch.setattr(soak, "release_source_digest", lambda _root: source_digest)
    monkeypatch.setattr(
        soak, "release_source_surface_metadata_fingerprint", lambda _root: "e" * 64
    )
    monkeypatch.setattr(soak, "_manifest_bindings", unexpected_bindings, raising=False)
    monkeypatch.setattr(soak, "_spawn", fake_spawn)

    rc = soak.main(
        [
            "--core-only",
            "--duration-seconds",
            "0",
            "--output",
            str(output),
            "--evidence-dir",
            str(evidence),
        ]
    )

    assert rc == 0
    overlay = json.loads((evidence / "soak/tauri_overlay.raw.json").read_text())
    assert overlay["skipped"] is True

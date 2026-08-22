from __future__ import annotations

import hashlib
import json
import plistlib
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from js.echo.ledger.release_gates import (
    _valid_local_gate_receipt,
    format_release_result_line,
    parse_gate_stdout,
    release_source_digest,
    validate_final_local_gate_evidence,
    write_toolchain_lock,
)
from scripts import run_tauri_webview_gate as gate
from tests.test_local_gate_receipt_round85 import (
    _ensure_repo_toolchain,
    _valid_receipt_payload,
    _write_capture,
)

ResultMutation = Callable[[dict[str, object], list[str]], object]
SetupMutation = Callable[[Path], object]
FormalMutation = Callable[[dict[str, object], Path], object]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    evidence = tmp_path / "evidence"
    app = evidence / "desktop-build/artifacts/JS Agent.app"
    executable = app / "Contents/MacOS/js-agent-desktop"
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(b"app-v1")
    info = app / "Contents/Info.plist"
    info.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.titan.js-agent</string>
<key>CFBundleExecutable</key><string>js-agent-desktop</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>2026081101</string>
</dict></plist>
""",
        encoding="utf-8",
    )
    harness = (
        evidence / "harness/JS Agent UI Test Harness.app/Contents/MacOS/js-agent-ui-test-harness"
    )
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_bytes(b"harness-v1")
    harness.chmod(0o755)
    harness_contents = harness.parent.parent
    (harness_contents / "Info.plist").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>local.js-agent.ui-test-harness</string>
<key>CFBundleExecutable</key><string>js-agent-ui-test-harness</string>
</dict></plist>
""",
        encoding="utf-8",
    )
    source = (
        Path(__file__).resolve().parents[1] / "desktop/tests/harness/tauri_webview_harness.swift"
    )
    harness_manifest = evidence / "harness/manifest.json"
    harness_manifest.write_text(
        json.dumps(
            {
                "schema_version": "JSAgentTauriHarnessProvenanceV1",
                "source_path": "desktop/tests/harness/tauri_webview_harness.swift",
                "source_sha256": _sha256(source),
                "executable_path": (
                    "JS Agent UI Test Harness.app/Contents/MacOS/js-agent-ui-test-harness"
                ),
                "executable_sha256": _sha256(harness),
                "bundle_identifier": "local.js-agent.ui-test-harness",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    from desktop.build_driver import _sha256_tree

    manifest = evidence / "desktop-build/manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "JSAgentDesktopProvenanceV4",
                "source_digest": "a" * 64,
                "arch": "aarch64-apple-darwin",
                "product_version": "0.1.0",
                "build_number": "2026081101",
                "artifacts": {
                    "rust_main": {
                        "path": "artifacts/JS Agent.app/Contents/MacOS/js-agent-desktop",
                        "sha256": _sha256(executable),
                    },
                    "app_tree": {
                        "path": "artifacts/JS Agent.app",
                        "sha256": _sha256_tree(app),
                    },
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return evidence, app, harness.parent.parent.parent, manifest


def _valid_result(
    *,
    nonce: str,
    app: Path,
    harness_exec: Path,
    manifest: Path,
    started: datetime | None = None,
) -> dict[str, object]:
    from desktop.build_driver import _sha256_tree

    started_at = started or datetime.now(tz=UTC)
    scenarios = {
        name: {
            "passed": True,
            "status": "passed",
            "detail": "fixture",
            "duration_ms": 1.0,
            "error_code": None,
        }
        for name in gate.REQUIRED_SCENARIOS
    }
    return {
        "schema_version": gate.RESULT_SCHEMA_VERSION,
        "ok": True,
        "status": "passed",
        "nonce": nonce,
        "scenarios": scenarios,
        "app_sha256": _sha256(app / "Contents/MacOS/js-agent-desktop"),
        "app_tree_sha256": _sha256_tree(app),
        "harness_sha256": _sha256(harness_exec),
        "desktop_manifest_sha256": _sha256(manifest),
        "bundle_identifier": "com.titan.js-agent",
        "accessibility_authorized": True,
        "target_pid": 123,
        "started_utc": started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finished_utc": (started_at + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    mutate: ResultMutation | None = None,
    setup_mutate: SetupMutation | None = None,
    returncode: int = 0,
) -> tuple[int, Path, Path, Path]:
    evidence, app, harness_bundle, manifest = _fixture(tmp_path)
    if setup_mutate is not None:
        setup_mutate(evidence)
    harness_exec = harness_bundle / "Contents/MacOS/js-agent-ui-test-harness"
    monkeypatch.setattr("desktop.build_driver.verify_manifest", lambda *_a, **_kw: [])

    def fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        nonce = cmd[cmd.index("--nonce") + 1]
        result_path = Path(cmd[cmd.index("--result-path") + 1])
        payload = _valid_result(
            nonce=nonce,
            app=app,
            harness_exec=harness_exec,
            manifest=manifest,
        )
        if mutate is not None:
            mutate(payload, cmd)
        result_path.write_text(json.dumps(payload), encoding="utf-8")
        return SimpleNamespace(returncode=returncode, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc = gate.main(
        [
            "--evidence-dir",
            str(evidence),
            "--app-path",
            str(app),
            "--harness-path",
            str(harness_bundle),
        ]
    )
    return rc, evidence, app, manifest


def test_wrapper_ignores_stale_fixed_result_and_publishes_current_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence, _, _, _ = _fixture(tmp_path)
    stale = evidence / "tauri-webview/result.json"
    stale.parent.mkdir(parents=True)
    stale.write_text('{"ok":true,"scenarios":{}}', encoding="utf-8")

    rc, evidence, _, _ = _run(monkeypatch, tmp_path)

    assert rc == 0
    published = json.loads((evidence / "tauri-webview/result.json").read_text())
    assert published["schema_version"] == gate.RESULT_SCHEMA_VERSION
    assert published["nonce"]
    assert set(published["scenarios"]) == gate.REQUIRED_SCENARIOS


@pytest.mark.parametrize(
    "mutation",
    [
        lambda result, _cmd: result.update(scenarios={}),
        lambda result, _cmd: result["scenarios"].pop(next(iter(gate.REQUIRED_SCENARIOS))),
        lambda result, _cmd: result["scenarios"].update(
            {"unexpected_scenario": dict(next(iter(result["scenarios"].values())))}
        ),
        lambda result, _cmd: result.update(nonce="wrong-nonce"),
        lambda result, _cmd: result.update(
            started_utc="2020-01-01T00:00:00Z", finished_utc="2020-01-01T00:00:01Z"
        ),
        lambda result, _cmd: result.update(app_sha256="0" * 64),
        lambda result, _cmd: result.update(app_tree_sha256="0" * 64),
        lambda result, _cmd: result.update(harness_sha256="0" * 64),
        lambda result, _cmd: result.update(bundle_identifier="local.js-agent.ui-test-harness"),
        lambda result, _cmd: result.update(desktop_manifest_sha256="0" * 64),
        lambda result, _cmd: result.update(accessibility_authorized=False),
        lambda result, _cmd: result.update(unexpected=True),
        lambda result, _cmd: next(iter(result["scenarios"].values())).update(status="failed"),
    ],
    ids=[
        "empty-scenarios",
        "missing-scenario",
        "extra-scenario",
        "wrong-nonce",
        "stale-time",
        "wrong-app-executable",
        "wrong-app-tree",
        "wrong-harness",
        "wrong-bundle",
        "wrong-manifest",
        "accessibility-not-authorized",
        "extra-result-field",
        "scenario-status-not-passed",
    ],
)
def test_wrapper_rejects_forged_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: ResultMutation,
) -> None:
    rc, _, _, _ = _run(monkeypatch, tmp_path, mutate=mutation)
    assert rc == 1


def test_wrapper_rejects_replaced_app_after_manifest_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def replace_app(result: dict[str, object], cmd: list[str]) -> None:
        app = Path(cmd[cmd.index("--app-path") + 1])
        (app / "Contents/MacOS/js-agent-desktop").write_bytes(b"replaced")

    rc, _, _, _ = _run(monkeypatch, tmp_path, mutate=replace_app)
    assert rc == 1


def test_wrapper_rejects_harness_not_bound_to_current_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def tamper(evidence: Path) -> None:
        path = evidence / "harness/manifest.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["source_sha256"] = "0" * 64
        path.write_text(json.dumps(payload), encoding="utf-8")

    rc, _, _, _ = _run(monkeypatch, tmp_path, setup_mutate=tamper)
    assert rc == 1


def test_swift_harness_contract_has_real_replay_mode_readback_and_term_first() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "desktop/tests/harness/tauri_webview_harness.swift"
    ).read_text(encoding="utf-8")

    assert '"--nonce"' in source
    assert '"/api/appshell/desktop-bootstrap"' in source
    assert "409" in source
    assert '"/api/appshell/capabilities"' in source
    assert '"active_mode"' in source
    assert "SELECT epoch FROM appshell_sessions" in source
    assert "pressedWork && pressedPersonal" in source
    assert 'Data("JSAgentTreeDigestV2\\0".utf8)' in source
    assert "posixPermissions" in source
    assert 'entryType: "directory"' in source
    clean_quit = source.index('scenario("clean_quit_no_orphans"')
    restart = source.index('scenario("restart_simplified_flow"')
    clean_block = source[clean_quit:restart]
    assert "SIGKILL" not in clean_block
    assert "terminateOwned" not in clean_block


def _artifact_bindings(
    *, evidence: Path, app: Path, harness_bundle: Path, manifest: Path, tauri: bool
) -> dict[str, str]:
    from desktop.build_driver import _sha256_tree

    bindings = {
        "desktop_manifest_sha256": _sha256(manifest),
        "app_tree_sha256": _sha256_tree(app),
        "app_sha256": _sha256(app / "Contents/MacOS/js-agent-desktop"),
    }
    if tauri:
        bindings.update(
            {
                "result_sha256": _sha256(evidence / "tauri-webview/result.json"),
                "harness_sha256": _sha256(
                    harness_bundle / "Contents/MacOS/js-agent-ui-test-harness"
                ),
            }
        )
    return bindings


def _bound_receipt(
    tmp_path: Path,
    *,
    gate_name: str,
    manifest_mutation: FormalMutation | None = None,
) -> tuple[dict[str, object], Path, Path]:
    from desktop import build_driver
    from desktop.tests.test_build_driver import (
        BUILD_NUMBER,
        _offline_build_inputs,
        _write_info_plist,
        _write_release_inputs,
        _write_zip_from_app,
    )

    root = tmp_path / "repo"
    root.mkdir()
    _write_release_inputs(root)
    harness_source = (
        Path(__file__).resolve().parents[1] / "desktop/tests/harness/tauri_webview_harness.swift"
    )
    root_harness_source = root / "desktop/tests/harness/tauri_webview_harness.swift"
    root_harness_source.parent.mkdir(parents=True)
    root_harness_source.write_bytes(harness_source.read_bytes())
    evidence, _old_app, harness_bundle, _old_manifest = _fixture(tmp_path)
    shutil.rmtree(evidence / "desktop-build")
    run = build_driver.prepare_build_run(
        output_dir=evidence / "desktop-build",
        repo_root=root,
    )
    artifacts = run.root / "artifacts"
    app = artifacts / "JS Agent.app"
    executable = app / "Contents/MacOS/js-agent-desktop"
    bundled_sidecar = app / "Contents/MacOS/js-agent-host"
    standalone = artifacts / build_driver.SIDECAR_NAME
    for path, content in (
        (executable, b"app-v1"),
        (bundled_sidecar, b"sidecar-v1"),
        (standalone, b"sidecar-v1"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    _write_info_plist(app / "Contents/Info.plist", build_number=BUILD_NUMBER)
    build_driver.normalize_app_bundle_permissions(app)
    standalone.chmod(0o755)
    source_digest = release_source_digest(root)
    zip_path = artifacts / (
        f"JS-Agent-0.1.0-macos-arm64-unsigned-{source_digest[:16]}.zip"
    )
    _write_zip_from_app(app, zip_path)
    manifest = build_driver.generate_manifest(
        source_digest=source_digest,
        build_number=BUILD_NUMBER,
        sidecar_path=standalone,
        app_path=app,
        zip_path=zip_path,
        run=run,
        repo_root=root,
        offline_inputs=_offline_build_inputs(tmp_path / "formal-inputs"),
    )
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    if manifest_mutation is not None:
        manifest_mutation(manifest_payload, app)
    manifest.write_text(json.dumps(manifest_payload, sort_keys=True), encoding="utf-8")
    harness_exec = harness_bundle / "Contents/MacOS/js-agent-ui-test-harness"
    result_dir = evidence / "tauri-webview"
    result_dir.mkdir()
    result = _valid_result(
        nonce="1" * 64,
        app=app,
        harness_exec=harness_exec,
        manifest=manifest,
    )
    (result_dir / "result.json").write_text(json.dumps(result), encoding="utf-8")
    bindings = _artifact_bindings(
        evidence=evidence,
        app=app,
        harness_bundle=harness_bundle,
        manifest=manifest,
        tauri=gate_name == "tauri_webview_lifecycle",
    )
    stdout = evidence / "gates" / f"{gate_name}.stdout.txt"
    stderr = evidence / "gates" / f"{gate_name}.stderr.txt"
    stdout_sha = _write_capture(
        stdout,
        "[OK] fixture\n"
        + format_release_result_line(gate=gate_name, ok=True, bindings=bindings)
        + "\n",
    )
    stderr_sha = _write_capture(stderr, "")
    _ensure_repo_toolchain(root)
    write_toolchain_lock(evidence, root)
    receipt = _valid_receipt_payload(
        root=root,
        evidence_dir=evidence,
        gate_name=gate_name,
        stdout_path=stdout,
        stderr_path=stderr,
        stdout_sha256=stdout_sha,
        stderr_sha256=stderr_sha,
    )
    return receipt, root, evidence


@pytest.mark.parametrize("gate_name", ["desktop_build", "tauri_webview_lifecycle"])
def test_success_marker_requires_exact_artifact_bindings(gate_name: str) -> None:
    fields = {
        "desktop_manifest_sha256": "1" * 64,
        "app_tree_sha256": "2" * 64,
        "app_sha256": "3" * 64,
    }
    if gate_name == "tauri_webview_lifecycle":
        fields.update(result_sha256="4" * 64, harness_sha256="5" * 64)
    line = format_release_result_line(gate=gate_name, ok=True, bindings=fields)
    assert all(value in line for value in fields.values())
    unbound = format_release_result_line(gate=gate_name, ok=True)
    assert not parse_gate_stdout(
        "release_markers",
        unbound,
        exit_code=0,
        require_exit_code_zero=True,
        expected_gate=gate_name,
    )["ok"]


def test_tauri_receipt_fails_after_result_replacement(tmp_path: Path) -> None:
    receipt, root, evidence = _bound_receipt(tmp_path, gate_name="tauri_webview_lifecycle")
    digest = release_source_digest(root)
    assert _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )
    final_dir = evidence / "final"
    final_dir.mkdir()
    (final_dir / "tauri_webview_lifecycle.receipt.json").write_text(
        json.dumps(receipt), encoding="utf-8"
    )
    before = validate_final_local_gate_evidence(
        root,
        final_dir=final_dir,
        evidence_dir=evidence,
        expected_source_digest=digest,
    )
    assert "tauri_webview_lifecycle" in before.passed_gates
    (evidence / "tauri-webview/result.json").write_text("{}", encoding="utf-8")
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )
    after = validate_final_local_gate_evidence(
        root,
        final_dir=final_dir,
        evidence_dir=evidence,
        expected_source_digest=digest,
    )
    assert "tauri_webview_lifecycle" not in after.passed_gates
    assert "tauri_webview_lifecycle:invalid_receipt" in after.blockers


def test_desktop_receipt_fails_after_app_replacement(tmp_path: Path) -> None:
    receipt, root, evidence = _bound_receipt(tmp_path, gate_name="desktop_build")
    digest = release_source_digest(root)
    assert _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )
    app_exec = evidence / "desktop-build/artifacts/JS Agent.app/Contents/MacOS/js-agent-desktop"
    app_exec.write_bytes(b"replacement")
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )


def test_desktop_receipt_fails_after_executable_permission_drift(tmp_path: Path) -> None:
    receipt, root, evidence = _bound_receipt(tmp_path, gate_name="desktop_build")
    digest = release_source_digest(root)
    assert _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )
    app_exec = evidence / "desktop-build/artifacts/JS Agent.app/Contents/MacOS/js-agent-desktop"
    app_exec.chmod(0o600)

    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )


def test_desktop_receipt_fails_after_zip_replacement(tmp_path: Path) -> None:
    receipt, root, evidence = _bound_receipt(tmp_path, gate_name="desktop_build")
    digest = release_source_digest(root)
    assert _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )
    manifest = json.loads(
        (evidence / "desktop-build/manifest.json").read_text(encoding="utf-8")
    )
    zip_relative = manifest["artifacts"]["zip"]["path"]
    zip_path = evidence / "desktop-build" / zip_relative
    zip_path.write_bytes(zip_path.read_bytes() + b"forged-zip-suffix")

    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )


def _mutate_formal_manifest_schema(payload: dict[str, object], _app: Path) -> None:
    payload["schema"] = "forged-schema"


def _mutate_formal_product_version(payload: dict[str, object], _app: Path) -> None:
    payload["product_version"] = "9.9.9"


def _mutate_formal_build_number(payload: dict[str, object], _app: Path) -> None:
    payload["build_number"] = "2026081102"


def _mutate_formal_plist_version(payload: dict[str, object], app: Path) -> None:
    from desktop.build_driver import _sha256_tree

    info_path = app / "Contents/Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["CFBundleVersion"] = "2026081102"
    info_path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True))
    artifacts = payload["artifacts"]
    assert isinstance(artifacts, dict)
    app_tree = artifacts["app_tree"]
    assert isinstance(app_tree, dict)
    app_tree["sha256"] = _sha256_tree(app)


@pytest.mark.parametrize(
    "mutation",
    [
        _mutate_formal_manifest_schema,
        _mutate_formal_product_version,
        _mutate_formal_build_number,
        _mutate_formal_plist_version,
    ],
    ids=["schema", "product-version", "build-number", "plist-version"],
)
def test_formal_desktop_receipt_rejects_self_consistent_invalid_manifest(
    tmp_path: Path,
    mutation: FormalMutation,
) -> None:
    receipt, root, evidence = _bound_receipt(
        tmp_path,
        gate_name="desktop_build",
        manifest_mutation=mutation,
    )

    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )

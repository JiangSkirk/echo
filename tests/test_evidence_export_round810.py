from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from js.echo.ledger.evidence_export import (
    ENVELOPE_NAME,
    EXPORT_DIR_NAME,
    MANIFEST_NAME,
    PrivacyHit,
    format_privacy_hits,
    redact_text,
    verify_manifest_v2,
)

DIGEST = "c" * 64


@pytest.fixture(autouse=True)
def _formal_validator_for_export_mechanics(monkeypatch: pytest.MonkeyPatch) -> None:
    import js.echo.ledger.release_gates as release_gates

    report = release_gates.FinalLocalGateEvidenceReport(
        all_local_gates_passed=False,
        passed_gates=("ruff", "mypy"),
        blockers=("remaining_required_gates_not_seeded",),
        product_internal_ready=False,
    )
    monkeypatch.setattr(release_gates, "release_source_digest", lambda _root: DIGEST)
    monkeypatch.setattr(
        release_gates, "validate_final_local_gate_evidence", lambda *_a, **_k: report
    )


def _snapshot_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _hidden_export_staging_roots(out_root: Path) -> list[Path]:
    return sorted(out_root.glob(f".{EXPORT_DIR_NAME}.staging-*"))


def _seed(evidence: Path, repo: Path) -> None:
    (evidence / "final").mkdir(parents=True)
    (evidence / "gates").mkdir(parents=True)
    for gate, body, parser, parse_result in (
        (
            "ruff",
            "All checks passed!\n",
            "ruff",
            {"parser": "ruff", "ok": True},
        ),
        (
            "mypy",
            "Success: no issues found in 1 source file\n",
            "mypy",
            {
                "parser": "mypy",
                "ok": True,
                "success_text": True,
                "silent_failure_pattern": False,
            },
        ),
    ):
        stdout = evidence / "gates" / f"{gate}.stdout.txt"
        stderr = evidence / "gates" / f"{gate}.stderr.txt"
        stdout.write_text(body, encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        receipt = {
            "schema_version": "js-agent-local-gate-receipt-v4",
            "gate_name": gate,
            "stdout_path": f"<EVIDENCE_ROOT>/gates/{gate}.stdout.txt",
            "stderr_path": f"<EVIDENCE_ROOT>/gates/{gate}.stderr.txt",
            "stdout_sha256": __import__("hashlib").sha256(body.encode()).hexdigest(),
            "stderr_sha256": __import__("hashlib").sha256(b"").hexdigest(),
            "source_digest_before": DIGEST,
            "source_digest_after": DIGEST,
            "exit_code": 0,
            "output_parse": {
                "parser": parser,
                "require_exit_code_zero": True,
                "stderr_must_be_empty": False,
            },
            "parse_result": parse_result,
            "passed": True,
        }
        # Minimal receipt for path closure tests (full validator not required here).
        (evidence / "final" / f"{gate}.receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
    (evidence / "TOOLCHAIN.lock.json").write_text("{}\n", encoding="utf-8")
    (evidence / "FROZEN_DIGEST.txt").write_text(DIGEST + "\n", encoding="utf-8")
    artifacts = evidence / "e2e" / "artifacts"
    artifacts.mkdir(parents=True)
    whl = artifacts / "demo-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as archive:
        archive.writestr("demo/__init__.py", "x=1\n")
    sdist = artifacts / "demo-0.0.1.tar.gz"
    sdist_content = b"x=1\n"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        info = tarfile.TarInfo("demo/__init__.py")
        info.size = len(sdist_content)
        archive.addfile(info, io.BytesIO(sdist_content))
    sdist.write_bytes(stream.getvalue())
    wheel_payload = whl.read_bytes()
    sdist_payload = sdist.read_bytes()
    (evidence / "e2e" / "ECHO_ISOLATED_VENV_E2E.json").write_text(
        json.dumps(
            {
                "ok": True,
                "artifacts": {
                    "wheel": {
                        "path": "e2e/artifacts/demo-0.0.1-py3-none-any.whl",
                        "sha256": hashlib.sha256(wheel_payload).hexdigest(),
                        "bytes": len(wheel_payload),
                    },
                    "sdist": {
                        "path": "e2e/artifacts/demo-0.0.1.tar.gz",
                        "sha256": hashlib.sha256(sdist_payload).hexdigest(),
                        "bytes": len(sdist_payload),
                    },
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def test_privacy_hit_has_no_excerpt() -> None:
    hit = PrivacyHit(rule_id="absolute_home_path", relative_path="x.txt", count=2)
    rendered = format_privacy_hits([hit])
    assert "Users" not in rendered
    assert "excerpt" not in rendered
    assert hit.rule_id in rendered


def test_redact_uses_runtime_home_not_hardcoded_user(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    home = tmp_path / "example-user"
    repo.mkdir()
    evidence.mkdir()
    home.mkdir()
    raw = f"home={home}/secret cwd={repo}"
    cleaned = redact_text(raw, repo_root=repo, evidence_root=evidence, home=home)
    assert str(home) not in cleaned
    assert "<HOME>" in cleaned
    assert "jiangxuanzhen" not in Path("js/echo/ledger/evidence_export.py").read_text(
        encoding="utf-8"
    )


def test_manifest_mode_and_schema_and_count_strict(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed(evidence, repo)
    # Build without receipt closure (closure needs 17 receipts) — use build_manifest only path
    from js.echo.ledger.evidence_export import (
        EXPORT_DIR_NAME,
        _copy_redacted,
        _iter_allowlisted,
        build_manifest_v2,
    )

    export = evidence / EXPORT_DIR_NAME
    export.mkdir()
    for src in _iter_allowlisted(evidence):
        _copy_redacted(
            src, export / src.relative_to(evidence), repo_root=repo, evidence_root=evidence
        )
    manifest, count, _total = build_manifest_v2(export)
    verify_manifest_v2(export)

    # chmod attack
    target = next(p for p in export.rglob("*") if p.is_file() and p.name != MANIFEST_NAME)
    os.chmod(target, 0o600)
    with pytest.raises(RuntimeError, match="mode mismatch"):
        verify_manifest_v2(export)
    os.chmod(target, 0o644)

    # schema bogus
    text = manifest.read_text(encoding="utf-8")
    manifest.write_text(text.replace("js-agent-evidence-manifest-v2", "bogus"), encoding="utf-8")
    with pytest.raises(RuntimeError, match="schema"):
        verify_manifest_v2(export)
    manifest.write_text(text, encoding="utf-8")

    # entry_count wrong
    bad = text.replace(f"entry_count={count}", "entry_count=999")
    manifest.write_text(bad, encoding="utf-8")
    with pytest.raises(RuntimeError, match="entry_count"):
        verify_manifest_v2(export)
    manifest.write_text(text, encoding="utf-8")

    # duplicate relative path
    lines = text.splitlines(keepends=True)
    body_lines = [line for line in lines if line and not line.startswith("#")]
    assert body_lines
    dup = "".join(lines) + body_lines[0]
    if not dup.endswith("\n"):
        dup += "\n"
    manifest.write_text(dup, encoding="utf-8")
    with pytest.raises(RuntimeError, match="duplicate"):
        verify_manifest_v2(export)
    manifest.write_text(text, encoding="utf-8")

    # delete a tracked file
    victim = next(p for p in export.rglob("*") if p.is_file() and p.name != MANIFEST_NAME)
    victim.unlink()
    with pytest.raises(RuntimeError, match="missing|set|mismatch"):
        verify_manifest_v2(export)


def test_export_log_closure_tamper_and_missing(tmp_path: Path) -> None:
    from js.echo.ledger.evidence_export import build_sanitized_export

    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed(evidence, repo)
    result = build_sanitized_export(
        evidence_root=evidence,
        repo_root=repo,
        source_digest=DIGEST,
        out_root=evidence,
        required_gates=("ruff", "mypy"),
    )
    log = result.export_dir / "gates" / "ruff.stdout.txt"
    log.write_text(log.read_text(encoding="utf-8") + "x", encoding="utf-8")
    with pytest.raises(RuntimeError, match="sha mismatch"):
        from js.echo.ledger.evidence_export import verify_export_receipt_log_closure

        verify_export_receipt_log_closure(
            export_dir=result.export_dir,
            expected_source_digest=DIGEST,
            required_gates=("ruff", "mypy"),
        )


def test_desktop_v4_exports_closed_sanitized_descriptor_without_private_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import desktop.build_driver as build_driver
    import js.echo.ledger.evidence_export as evidence_export
    import js.echo.ledger.release_gates as release_gates

    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed(evidence, repo)

    artifacts = {
        "rust_main": {
            "path": "artifacts/JS Agent.app/Contents/MacOS/js-agent-desktop",
            "sha256": "1" * 64,
        },
        "sidecar": {
            "path": "artifacts/JS Agent.app/Contents/MacOS/js-agent-host",
            "sha256": "2" * 64,
        },
        "sidecar_standalone": {
            "path": "artifacts/js-agent-host-aarch64-apple-darwin",
            "sha256": "2" * 64,
        },
        "app_tree": {
            "path": "artifacts/JS Agent.app",
            "sha256": "3" * 64,
        },
        "zip": {
            "path": f"artifacts/JS-Agent-0.1.0-macos-arm64-unsigned-{DIGEST[:16]}.zip",
            "sha256": "4" * 64,
        },
    }
    original_manifest = {
        "schema": "JSAgentDesktopProvenanceV4",
        "source_digest": DIGEST,
        "arch": "aarch64-apple-darwin",
        "product_version": "0.1.0",
        "build_number": "2026081101",
        "artifacts": artifacts,
        "build_inputs": {
            name: {"path": f"desktop/{name}.lock", "sha256": "5" * 64}
            for name in ("cargo_lock", "pnpm_lock", "python_build_reqs", "build_driver")
        },
        "build_environment": {
            "schema": "JSAgentDesktopBuildEnvironmentV1",
            "run_owner_marker_sha256": "6" * 64,
            "python": {"path": "/Users/private-builder/.venv/bin/python", "sha256": "7" * 64},
            "pnpm": {"path": "/opt/private-tools/pnpm", "sha256": "8" * 64},
            "cargo": {"path": "/Users/private-builder/.cargo/bin/cargo", "sha256": "9" * 64},
            "node": {"path": "/opt/private-tools/node", "sha256": "a" * 64},
            "ditto": {"path": "/usr/bin/ditto", "sha256": "b" * 64},
            "cargo_home": {
                "path": "/Users/private-builder/.cargo",
                "tree_sha256": "c" * 64,
            },
            "pnpm_store": {
                "path": "/Users/private-builder/Library/pnpm/store",
                "tree_sha256": "d" * 64,
            },
        },
    }
    source_manifest = evidence / "desktop-build/manifest.json"
    source_manifest.parent.mkdir(parents=True)
    source_manifest.write_text(
        json.dumps(original_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    source_manifest_bytes = source_manifest.read_bytes()
    original_manifest_sha = hashlib.sha256(source_manifest_bytes).hexdigest()
    desktop_bindings = {
        "desktop_manifest_sha256": original_manifest_sha,
        "app_tree_sha256": str(artifacts["app_tree"]["sha256"]),
        "app_sha256": str(artifacts["rust_main"]["sha256"]),
    }

    def write_release_marker_receipt(gate_name: str, marker_bindings: dict[str, str]) -> None:
        stdout_text = (
            f"[OK] {gate_name}\n"
            + release_gates.format_release_result_line(
                gate=gate_name,
                ok=True,
                bindings=marker_bindings,
            )
            + "\n"
        )
        (evidence / "gates" / f"{gate_name}.stdout.txt").write_text(
            stdout_text,
            encoding="utf-8",
        )
        (evidence / "gates" / f"{gate_name}.stderr.txt").write_text("", encoding="utf-8")
        parsed = release_gates.parse_gate_stdout(
            "release_markers",
            stdout_text,
            exit_code=0,
            require_exit_code_zero=True,
            expected_gate=gate_name,
        )
        (evidence / "final" / f"{gate_name}.receipt.json").write_text(
            json.dumps(
                {
                    "schema_version": "js-agent-local-gate-receipt-v4",
                    "gate_name": gate_name,
                    "stdout_path": f"<EVIDENCE_ROOT>/gates/{gate_name}.stdout.txt",
                    "stderr_path": f"<EVIDENCE_ROOT>/gates/{gate_name}.stderr.txt",
                    "stdout_sha256": hashlib.sha256(stdout_text.encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                    "source_digest_before": DIGEST,
                    "source_digest_after": DIGEST,
                    "exit_code": 0,
                    "output_parse": {
                        "parser": "release_markers",
                        "require_exit_code_zero": True,
                        "stderr_must_be_empty": False,
                    },
                    "parse_result": parsed,
                    "passed": True,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    write_release_marker_receipt("desktop_build", desktop_bindings)
    write_release_marker_receipt(
        "tauri_webview_lifecycle",
        {
            **desktop_bindings,
            "result_sha256": "e" * 64,
            "harness_sha256": "f" * 64,
        },
    )
    targets = {
        "mode_switches": 30,
        "app_restarts": 6,
        "sidecar_recoveries": 3,
        "ws_cancel_cycles": 30,
        "r4_ops": 12,
        "r6_ops": 12,
    }
    combined: dict[str, object] = {
        "schema_version": "js-agent-supervised-soak-v1",
        "ok": True,
        "started_utc": "2026-08-11T00:00:00Z",
        "finished_utc": "2026-08-11T01:00:00Z",
        "duration_seconds": 3600.0,
        "elapsed_seconds": 3600.0,
        "source_digest": DIGEST,
        "metadata_fingerprint": "0" * 64,
        "core": {"exit_code": 0, "raw_sha256": "a" * 64, "ok": True},
        "overlay": {
            "exit_code": 0,
            "raw_sha256": "b" * 64,
            "ok": True,
            "targets": targets,
            "counters": targets,
            "targets_met": True,
            "cycles": 1,
            "heartbeat_count": 721,
            "max_heartbeat_gap_s": 5.0,
            "max_heartbeat_gap_limit_s": 15.0,
            "chain_root": "c" * 64,
            "desktop_manifest_sha256": original_manifest_sha,
            "app_tree_sha256": "3" * 64,
            "app_sha256": "1" * 64,
        },
    }
    combined["combined_sha256"] = hashlib.sha256(
        json.dumps(combined, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    combined_path = evidence / "soak/supervised_soak.combined.json"
    combined_path.parent.mkdir()
    combined_path.write_text(
        json.dumps(combined, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    combined_artifact_sha = hashlib.sha256(combined_path.read_bytes()).hexdigest()
    soak_stdout = "[OK] supervised_soak\n"
    soak_parse = release_gates.parse_gate_stdout(
        "soak_json",
        soak_stdout,
        exit_code=0,
        require_exit_code_zero=True,
        expected_gate="soak_3600",
    )
    (evidence / "gates/soak_3600.stdout.txt").write_text(soak_stdout, encoding="utf-8")
    (evidence / "gates/soak_3600.stderr.txt").write_text("", encoding="utf-8")
    (evidence / "final/soak_3600.receipt.json").write_text(
        json.dumps(
            {
                "schema_version": "js-agent-local-gate-receipt-v4",
                "gate_name": "soak_3600",
                "stdout_path": "<EVIDENCE_ROOT>/gates/soak_3600.stdout.txt",
                "stderr_path": "<EVIDENCE_ROOT>/gates/soak_3600.stderr.txt",
                "stdout_sha256": hashlib.sha256(soak_stdout.encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "source_digest_before": DIGEST,
                "source_digest_after": DIGEST,
                "exit_code": 0,
                "output_parse": {
                    "parser": "soak_json",
                    "require_exit_code_zero": True,
                    "stderr_must_be_empty": True,
                },
                "parse_result": soak_parse,
                "artifact_sha256": combined_artifact_sha,
                "passed": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    pack_summary = evidence / "pack/JS_AGENT_FINAL_EVIDENCE.json"
    pack_summary.parent.mkdir()
    pack_summary.write_text(
        json.dumps(
            {
                "schema_version": "js-agent-final-evidence-v2",
                "desktop_manifest_digest": original_manifest_sha,
                "gate_receipts": {
                    "soak_3600": {"artifact_sha256": combined_artifact_sha}
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    report = release_gates.FinalLocalGateEvidenceReport(
        all_local_gates_passed=False,
        passed_gates=(
            "ruff",
            "mypy",
            "soak_3600",
            "desktop_build",
            "tauri_webview_lifecycle",
        ),
        blockers=("remaining_required_gates_not_seeded",),
        product_internal_ready=False,
    )
    monkeypatch.setattr(
        release_gates, "validate_final_local_gate_evidence", lambda *_a, **_k: report
    )
    verified_source_bytes: list[bytes] = []

    def verify_original(path: Path, *_a: object, **_k: object) -> list[str]:
        verified_source_bytes.append(path.read_bytes())
        return []

    monkeypatch.setattr(build_driver, "verify_manifest", verify_original)

    result = evidence_export.build_sanitized_export(
        evidence_root=evidence,
        repo_root=repo,
        source_digest=DIGEST,
        out_root=evidence,
    )

    descriptor_path = result.export_dir / "desktop-build/sanitized-descriptor.json"
    assert verified_source_bytes == [source_manifest_bytes]
    assert source_manifest.read_bytes() == source_manifest_bytes
    assert not (result.export_dir / "desktop-build/manifest.json").exists()
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    assert descriptor == {
        "schema_version": "js-agent-sanitized-desktop-descriptor-v1",
        "original_manifest_schema": "JSAgentDesktopProvenanceV4",
        "original_manifest_sha256": original_manifest_sha,
        "source_digest": DIGEST,
        "arch": "aarch64-apple-darwin",
        "product_version": "0.1.0",
        "build_number": "2026081101",
        "app_tree": artifacts["app_tree"],
        "app_binary": artifacts["rust_main"],
        "zip": artifacts["zip"],
    }
    exported_bytes = b"\n".join(
        path.read_bytes() for path in result.export_dir.rglob("*") if path.is_file()
    )
    assert b"/Users/private-builder" not in exported_bytes
    assert b"/opt/private-tools" not in exported_bytes
    assert b"build_environment" not in descriptor_path.read_bytes()

    descriptor_sha = hashlib.sha256(descriptor_path.read_bytes()).hexdigest()
    expected_summary_binding = {
        "schema_version": "js-agent-sanitized-desktop-summary-binding-v1",
        "descriptor_relative_path": "desktop-build/sanitized-descriptor.json",
        "descriptor_sha256": descriptor_sha,
        "original_manifest_sha256": original_manifest_sha,
        "app_tree_sha256": "3" * 64,
        "app_sha256": "1" * 64,
        "zip_sha256": "4" * 64,
    }
    summary = json.loads((result.export_dir / "gate_run_summary.json").read_text())
    validator = json.loads(
        (result.export_dir / "final_validator.receipt.json").read_text()
    )
    assert summary["desktop_binding"] == expected_summary_binding
    assert validator["desktop_binding"] == expected_summary_binding
    exported_combined = result.export_dir / "soak/supervised_soak.combined.json"
    assert exported_combined.read_bytes() == combined_path.read_bytes()
    assert not (result.export_dir / "soak/echo_core_soak.raw.json").exists()
    assert not (result.export_dir / "soak/tauri_overlay.raw.json").exists()
    expected_soak_binding = {
        "schema_version": "js-agent-sanitized-supervised-soak-summary-binding-v1",
        "combined_relative_path": "soak/supervised_soak.combined.json",
        "artifact_sha256": combined_artifact_sha,
        "combined_sha256": combined["combined_sha256"],
        "core_raw_sha256": "a" * 64,
        "overlay_raw_sha256": "b" * 64,
        "metadata_fingerprint": "0" * 64,
        "overlay_chain_root": "c" * 64,
        "desktop_manifest_sha256": original_manifest_sha,
        "app_tree_sha256": "3" * 64,
        "app_sha256": "1" * 64,
    }
    assert summary["supervised_soak_binding"] == expected_soak_binding
    assert validator["supervised_soak_binding"] == expected_soak_binding
    assert (
        json.loads(
            (result.export_dir / "pack/JS_AGENT_FINAL_EVIDENCE.json").read_text()
        )["desktop_manifest_digest"]
        == original_manifest_sha
    )
    evidence_export.verify_export_validator_binding(
        result.export_dir,
        expected_source_digest=DIGEST,
        report=report,
    )

    descriptor_bytes = descriptor_path.read_bytes()
    descriptor["original_manifest_sha256"] = "0" * 64
    descriptor_path.write_text(json.dumps(descriptor, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="desktop"):
        evidence_export.verify_export_validator_binding(
            result.export_dir,
            expected_source_digest=DIGEST,
            report=report,
        )
    descriptor_path.write_bytes(descriptor_bytes)

    descriptor["original_manifest_sha256"] = original_manifest_sha
    descriptor["build_number"] = "2026023001"
    descriptor_path.write_text(json.dumps(descriptor, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="desktop descriptor identity"):
        evidence_export.verify_export_validator_binding(
            result.export_dir,
            expected_source_digest=DIGEST,
            report=report,
        )
    descriptor_path.write_bytes(descriptor_bytes)

    tauri_receipt_path = result.export_dir / "final/tauri_webview_lifecycle.receipt.json"
    tauri_receipt_bytes = tauri_receipt_path.read_bytes()
    tauri_receipt = json.loads(tauri_receipt_bytes)
    tauri_receipt["parse_result"]["payload"]["bindings"]["desktop_manifest_sha256"] = (
        "0" * 64
    )
    tauri_receipt_path.write_text(
        json.dumps(tauri_receipt, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="Tauri receipt"):
        evidence_export.verify_export_validator_binding(
            result.export_dir,
            expected_source_digest=DIGEST,
            report=report,
        )
    tauri_receipt_path.write_bytes(tauri_receipt_bytes)

    combined_bytes = exported_combined.read_bytes()
    soak_receipt_path = result.export_dir / "final/soak_3600.receipt.json"
    soak_receipt_bytes = soak_receipt_path.read_bytes()
    forged_combined = json.loads(combined_bytes)
    forged_combined["overlay"]["desktop_manifest_sha256"] = "0" * 64
    forged_combined["combined_sha256"] = hashlib.sha256(
        json.dumps(
            {
                key: value
                for key, value in forged_combined.items()
                if key != "combined_sha256"
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    exported_combined.write_text(
        json.dumps(forged_combined, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    forged_receipt = json.loads(soak_receipt_bytes)
    forged_receipt["artifact_sha256"] = hashlib.sha256(
        exported_combined.read_bytes()
    ).hexdigest()
    soak_receipt_path.write_text(
        json.dumps(forged_receipt, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="soak/desktop descriptor"):
        evidence_export.verify_export_validator_binding(
            result.export_dir,
            expected_source_digest=DIGEST,
            report=report,
        )
    exported_combined.write_bytes(combined_bytes)
    soak_receipt_path.write_bytes(soak_receipt_bytes)

    exported_combined.write_bytes(combined_bytes + b" ")
    with pytest.raises(RuntimeError, match="artifact sha mismatch for soak_3600"):
        evidence_export.verify_export_receipt_log_closure(
            export_dir=result.export_dir,
            expected_source_digest=DIGEST,
            required_gates=result.passed_gates,
        )
    exported_combined.write_bytes(combined_bytes)

    private_raw = result.export_dir / "soak/tauri_overlay.raw.json"
    private_raw.write_text("{}\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="raw artifact"):
        evidence_export.verify_export_validator_binding(
            result.export_dir,
            expected_source_digest=DIGEST,
            report=report,
        )
    private_raw.unlink()

    exported_pack_path = result.export_dir / "pack/JS_AGENT_FINAL_EVIDENCE.json"
    exported_pack_bytes = exported_pack_path.read_bytes()
    exported_pack = json.loads(exported_pack_bytes)
    exported_pack["desktop_manifest_digest"] = "0" * 64
    exported_pack_path.write_text(
        json.dumps(exported_pack, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="final desktop summary"):
        evidence_export.verify_export_validator_binding(
            result.export_dir,
            expected_source_digest=DIGEST,
            report=report,
        )
    exported_pack_path.write_bytes(exported_pack_bytes)

    exported_pack.pop("desktop_manifest_digest")
    exported_pack_path.write_text(
        json.dumps(exported_pack, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="summary binding missing"):
        evidence_export.verify_export_validator_binding(
            result.export_dir,
            expected_source_digest=DIGEST,
            report=report,
        )
    exported_pack_path.write_bytes(exported_pack_bytes)

    validator_path = result.export_dir / "final_validator.receipt.json"
    validator_bytes = validator_path.read_bytes()
    validator["desktop_binding"]["descriptor_sha256"] = "0" * 64
    validator_path.write_text(json.dumps(validator, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="desktop receipt binding"):
        evidence_export.verify_export_validator_binding(
            result.export_dir,
            expected_source_digest=DIGEST,
            report=report,
        )
    validator_path.write_bytes(validator_bytes)


def test_failed_build_preserves_final_artifacts_and_cleans_same_fs_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import js.echo.ledger.evidence_export as evidence_export

    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed(evidence, repo)

    final_export = evidence / EXPORT_DIR_NAME
    final_export.mkdir()
    (final_export / "prior.txt").write_text("previous export\n", encoding="utf-8")
    final_envelope = evidence / ENVELOPE_NAME
    final_envelope.write_text("previous envelope\n", encoding="utf-8")
    prior_export = _snapshot_files(final_export)
    prior_envelope = final_envelope.read_bytes()
    observed: dict[str, object] = {}

    def reject_during_privacy_scan(candidate: Path) -> list[PrivacyHit]:
        observed["hidden_parent"] = candidate.parent.name.startswith(
            f".{EXPORT_DIR_NAME}.staging-"
        )
        observed["same_device"] = candidate.stat().st_dev == evidence.stat().st_dev
        raise RuntimeError("injected privacy failure")

    monkeypatch.setattr(evidence_export, "privacy_scan", reject_during_privacy_scan)

    with pytest.raises(RuntimeError, match="injected privacy failure"):
        evidence_export.build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff", "mypy"),
        )

    assert _snapshot_files(final_export) == prior_export
    assert final_envelope.read_bytes() == prior_envelope
    assert observed == {"hidden_parent": True, "same_device": True}
    assert _hidden_export_staging_roots(evidence) == []


def test_baseexception_during_staging_preserves_previous_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import js.echo.ledger.evidence_export as evidence_export

    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed(evidence, repo)
    final_export = evidence / EXPORT_DIR_NAME
    final_export.mkdir()
    (final_export / "old.txt").write_text("old\n", encoding="utf-8")
    final_envelope = evidence / ENVELOPE_NAME
    final_envelope.write_text('{"old": true}\n', encoding="utf-8")
    prior_export = _snapshot_files(final_export)
    prior_envelope = final_envelope.read_bytes()

    monkeypatch.setattr(
        evidence_export,
        "privacy_scan",
        lambda _root: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        evidence_export.build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff", "mypy"),
        )

    assert _snapshot_files(final_export) == prior_export
    assert final_envelope.read_bytes() == prior_envelope
    assert _hidden_export_staging_roots(evidence) == []


def test_publish_failure_rolls_back_prior_export_and_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import js.echo.ledger.evidence_export as evidence_export

    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed(evidence, repo)

    final_export = evidence / EXPORT_DIR_NAME
    final_export.mkdir()
    (final_export / "prior.txt").write_text("previous export\n", encoding="utf-8")
    final_envelope = evidence / ENVELOPE_NAME
    final_envelope.write_text("previous envelope\n", encoding="utf-8")
    prior_export = _snapshot_files(final_export)
    prior_envelope = final_envelope.read_bytes()

    real_replace = os.replace
    injected = False

    def fail_first_envelope_publish(src: os.PathLike[str], dst: os.PathLike[str]) -> None:
        nonlocal injected
        if Path(dst) == final_envelope and not injected:
            injected = True
            raise OSError("injected envelope publish failure")
        real_replace(src, dst)

    monkeypatch.setattr(evidence_export.os, "replace", fail_first_envelope_publish)

    with pytest.raises(OSError, match="injected envelope publish failure"):
        evidence_export.build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff", "mypy"),
        )

    assert injected is True
    assert _snapshot_files(final_export) == prior_export
    assert final_envelope.read_bytes() == prior_envelope
    assert _hidden_export_staging_roots(evidence) == []


def test_rollback_failure_retains_recovery_backup_without_leaking_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import js.echo.ledger.evidence_export as evidence_export

    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed(evidence, repo)

    final_export = evidence / EXPORT_DIR_NAME
    final_export.mkdir()
    (final_export / "prior.txt").write_text("previous export\n", encoding="utf-8")
    final_envelope = evidence / ENVELOPE_NAME
    final_envelope.write_text("previous envelope\n", encoding="utf-8")
    prior_envelope = final_envelope.read_bytes()

    real_replace = os.replace
    publish_failed = False

    def fail_publish_and_export_restore(
        src: os.PathLike[str], dst: os.PathLike[str]
    ) -> None:
        nonlocal publish_failed
        source = Path(src)
        destination = Path(dst)
        if destination == final_envelope and source.name == ENVELOPE_NAME:
            publish_failed = True
            raise OSError("injected envelope publish failure")
        if destination == final_export and source.name == f".previous-{EXPORT_DIR_NAME}":
            raise OSError("injected export rollback failure")
        real_replace(src, dst)

    monkeypatch.setattr(evidence_export.os, "replace", fail_publish_and_export_restore)

    with pytest.raises(RuntimeError, match="sanitized export rollback failed") as caught:
        evidence_export.build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff", "mypy"),
        )

    assert publish_failed is True
    assert str(evidence) not in str(caught.value)
    assert final_envelope.read_bytes() == prior_envelope
    staging_roots = _hidden_export_staging_roots(evidence)
    assert len(staging_roots) == 1
    recovery_export = staging_roots[0] / f".previous-{EXPORT_DIR_NAME}"
    assert (recovery_export / "prior.txt").read_text(encoding="utf-8") == "previous export\n"


def test_archive_current_home_rejected(tmp_path: Path) -> None:
    import zipfile

    from js.echo.ledger.evidence_export import scan_archive_members

    home = str(Path.home())
    whl = tmp_path / "leak.whl"
    with zipfile.ZipFile(whl, "w") as archive:
        archive.writestr("pkg/data.txt", f"path={home}/secret\n")
    hits = scan_archive_members(whl, current_home=home)
    assert any(hit.rule_id == "archive_current_home" for hit in hits)
    rendered = format_privacy_hits(hits)
    assert home not in rendered


def test_privacy_format_never_echoes_secret(tmp_path: Path) -> None:
    from js.echo.ledger.evidence_export import privacy_scan

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    secret = f"{Path.home()}/.ssh/id_rsa"
    (evidence / "leak.txt").write_text(f"token=Bearer abcdefghijklmnop path={secret}\n")
    hits = privacy_scan(evidence)
    assert hits
    rendered = format_privacy_hits(hits)
    assert "Bearer" not in rendered
    assert "abcdefghijklmnop" not in rendered
    assert str(Path.home()) not in rendered
    for hit in hits:
        assert not hasattr(hit, "excerpt")

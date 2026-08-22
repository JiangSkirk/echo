"""Phase E.1 tests: desktop gates in product readiness.

Verifies that removing desktop_build or tauri_webview_lifecycle receipts
causes product_internal_ready to be false, and that the gates are in
REQUIRED_FINAL_LOCAL_GATES.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from js.echo.ledger.release_gates import (
    _INDEPENDENT_GATE_RECEIPTS,
    REQUIRED_FINAL_LOCAL_GATES,
    get_local_gate_spec,
    validate_final_local_gate_evidence,
)
from scripts import run_desktop_build_gate
from tests.test_local_gate_receipt_round85 import (
    _seed_final_receipts,
)


def test_desktop_gates_in_required() -> None:
    assert "desktop_build" in REQUIRED_FINAL_LOCAL_GATES
    assert "tauri_webview_lifecycle" in REQUIRED_FINAL_LOCAL_GATES


def test_desktop_gates_in_independent() -> None:
    assert "desktop_build" in _INDEPENDENT_GATE_RECEIPTS
    assert "tauri_webview_lifecycle" in _INDEPENDENT_GATE_RECEIPTS


def test_desktop_gate_specs_exist() -> None:
    spec = get_local_gate_spec("desktop_build", evidence_dir=Path("/tmp/e"))
    assert spec is not None
    assert spec.gate_name == "desktop_build"
    spec = get_local_gate_spec("tauri_webview_lifecycle", evidence_dir=Path("/tmp/e"))
    assert spec is not None
    assert spec.gate_name == "tauri_webview_lifecycle"


def test_removing_desktop_receipt_blocks_product_ready(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    final_dir = evidence / "final"
    root.mkdir()
    final_dir.mkdir(parents=True)

    _seed_final_receipts(final_dir, evidence, root)

    # Remove desktop_build receipt
    (final_dir / "desktop_build.receipt.json").unlink()
    report = validate_final_local_gate_evidence(
        root,
        final_dir=final_dir,
        evidence_dir=evidence,
    )
    assert not report.all_local_gates_passed
    assert not report.product_internal_ready
    assert "desktop_build:receipt_missing" in report.blockers


def test_removing_tauri_receipt_blocks_product_ready(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    final_dir = evidence / "final"
    root.mkdir()
    final_dir.mkdir(parents=True)

    _seed_final_receipts(final_dir, evidence, root)

    # Remove tauri_webview_lifecycle receipt
    (final_dir / "tauri_webview_lifecycle.receipt.json").unlink()
    report = validate_final_local_gate_evidence(
        root,
        final_dir=final_dir,
        evidence_dir=evidence,
    )
    assert not report.all_local_gates_passed
    assert not report.product_internal_ready
    assert "tauri_webview_lifecycle:receipt_missing" in report.blockers


def _set_desktop_build_gate_tool_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    for name in (
        "PNPM_EXECUTABLE",
        "CARGO_EXECUTABLE",
        "NODE_EXECUTABLE",
        "DITTO_EXECUTABLE",
    ):
        path = tmp_path / name.lower()
        path.write_bytes(b"fixture")
        path.chmod(0o755)
        monkeypatch.setenv(f"JS_AGENT_{name}", str(path))
    for name in ("CARGO_HOME", "PNPM_STORE"):
        path = tmp_path / name.lower()
        path.mkdir()
        monkeypatch.setenv(f"JS_AGENT_{name}", str(path))


@pytest.mark.parametrize("value", [None, "", "2026081100", "not-a-build"])
def test_desktop_build_gate_requires_valid_explicit_environment_build_number(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    value: str | None,
) -> None:
    if value is None:
        monkeypatch.delenv("JS_AGENT_BUILD_NUMBER", raising=False)
    else:
        monkeypatch.setenv("JS_AGENT_BUILD_NUMBER", value)

    assert (
        run_desktop_build_gate.main(
            ["--evidence-dir", str(tmp_path), "--output-dir", str(tmp_path / "out")]
        )
        == 1
    )


def test_desktop_build_gate_passes_valid_environment_build_number_explicitly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    build_number = "2026081101"
    captured: dict[str, object] = {}
    _set_desktop_build_gate_tool_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("JS_AGENT_BUILD_NUMBER", build_number)

    def fake_build_desktop(**kwargs: object) -> Path:
        captured.update(kwargs)
        output = Path(kwargs["output_dir"])
        output.mkdir(parents=True)
        manifest = output / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "source_digest": "a" * 64,
                    "build_number": build_number,
                    "artifacts": {
                        "rust_main": {"sha256": "b" * 64},
                        "app_tree": {"sha256": "c" * 64},
                    },
                }
            ),
            encoding="utf-8",
        )
        return manifest

    monkeypatch.setattr("desktop.build_driver.build_desktop", fake_build_desktop)
    monkeypatch.setattr("desktop.build_driver.verify_manifest", lambda *_a, **_k: [])

    assert (
        run_desktop_build_gate.main(
            ["--evidence-dir", str(tmp_path), "--output-dir", str(tmp_path / "out")]
        )
        == 0
    )
    assert captured["build_number"] == build_number


def test_desktop_build_gate_rejects_cached_manifest_for_other_build_number(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _set_desktop_build_gate_tool_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("JS_AGENT_BUILD_NUMBER", "2026081102")
    output = tmp_path / "out"
    (output / "artifacts/JS Agent.app").mkdir(parents=True)
    (output / "manifest.json").write_text(
        json.dumps(
            {
                "source_digest": "a" * 64,
                "build_number": "2026081101",
                "artifacts": {
                    "rust_main": {"sha256": "b" * 64},
                    "app_tree": {"sha256": "c" * 64},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("desktop.build_driver.verify_manifest", lambda *_a, **_k: [])

    assert (
        run_desktop_build_gate.main(
            ["--evidence-dir", str(tmp_path), "--output-dir", str(output)]
        )
        == 1
    )

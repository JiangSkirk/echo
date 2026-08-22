"""M1: final evidence nested-field extraction, audit artifact SHA, ordering.

Fail-closed tests for the Round 8.15 evidence-summary bugs:
- nested soak counters extracted from the wrong level / wrong key names
- slo_ok read from a non-existent top-level ``ok`` field
- echo_full_audit receipt bound only to stdout markers (no audit artifact SHA)
- audit gate ordered before soak, producing a stale Internal-ready=False report
- sanitized export omit of the audit markdown
- readonly validator must not mutate inputs while rejecting those defects
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

import js.echo.ledger.evidence_export as evidence_export
import js.echo.ledger.final_evidence as final_evidence
import js.echo.ledger.release_gates as rg


def _nested_soak_acceptance(*, sample_count: int = 42) -> dict[str, Any]:
    return {
        "schema_version": "echo-live-acceptance-v4",
        "ok": True,
        "duration_seconds": 3600.0,
        "source_digest": "a" * 64,
        "resources": {"recorded_sample_count": 7},
        "soak": {
            "sample_count": sample_count,
            "success": sample_count,
            "failures": 0,
            "crosstalk": 0,
            "http_5xx": 0,
            "requested_seconds": 3600.0,
            "active_elapsed_seconds": 3600.0,
        },
    }


def _slo_without_top_level_ok(*, digest: str = "a" * 64) -> dict[str, Any]:
    # Mirrors production ECHO_SLO_BENCHMARK.json: no top-level ``ok``.
    return {
        "source_digest": digest,
        "metadata": {"source_digest": digest, "runs": 5},
        "security_matrix": {"ok": True, "passed": 25, "total": 25},
        "aggregate": {"group_count": 5},
    }


def _tree_fingerprint(root: Path) -> dict[str, tuple[int, str, int]]:
    out: dict[str, tuple[int, str, int]] = {}
    if not root.exists():
        return out
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        data = path.read_bytes()
        st = path.stat()
        out[rel] = (len(data), hashlib.sha256(data).hexdigest(), st.st_mtime_ns)
    return out


def _stub_formal_state(
    monkeypatch: Any,
    *,
    receipts: dict[str, dict[str, Any]] | None = None,
    digest: str = "a" * 64,
    passed_gates: tuple[str, ...] | None = None,
) -> None:
    bound = receipts or {}
    monkeypatch.setattr(
        final_evidence,
        "_derive_formal_state",
        lambda **_kwargs: {
            "source_digest": digest,
            "passed_gates": passed_gates or tuple(bound),
            "blockers": (),
            "validation_ok": True,
            "internal_ready": True,
            "product_internal_ready": False,
            "desktop_manifest_digest": None,
            "gate_receipts": bound,
        },
    )


def test_extract_soak_summary_reads_nested_counters_not_top_level_aliases() -> None:
    acceptance = _nested_soak_acceptance(sample_count=14394)
    summary = final_evidence.extract_soak_summary(acceptance)

    assert summary["sample_count"] == 14394
    assert summary["success_count"] == 14394
    assert summary["failure_count"] == 0
    assert summary["crosstalk_count"] == 0
    assert summary["http_5xx_count"] == 0
    assert summary["ok"] is True
    assert summary["duration_seconds"] == 3600.0
    assert summary["source_digest"] == "a" * 64


def test_legacy_buggy_top_level_extraction_leaves_nulls() -> None:
    """Document the Round 8.15 bug shape so the fix cannot regress to it."""
    acceptance = _nested_soak_acceptance(sample_count=99)
    resources = acceptance.get("resources") if isinstance(acceptance.get("resources"), dict) else {}
    buggy = {
        "sample_count": acceptance.get("sample_count") or resources.get("sample_count"),
        "success_count": acceptance.get("success_count"),
        "failure_count": acceptance.get("failure_count"),
        "crosstalk_count": acceptance.get("crosstalk_count"),
        "http_5xx_count": acceptance.get("http_5xx_count") or acceptance.get("status_5xx_count"),
    }
    assert buggy["sample_count"] is None
    assert buggy["success_count"] is None
    assert buggy["failure_count"] is None
    assert buggy["crosstalk_count"] is None
    assert buggy["http_5xx_count"] is None


def test_build_final_evidence_fills_slo_ok_without_top_level_ok(
    tmp_path: Path, monkeypatch: Any
) -> None:
    root = tmp_path / "repo"
    (root / "docs" / "security").mkdir(parents=True)
    acceptance = _nested_soak_acceptance()
    slo = _slo_without_top_level_ok()
    (root / "docs/security/ECHO_LIVE_ACCEPTANCE.json").write_text(
        json.dumps(acceptance) + "\n", encoding="utf-8"
    )
    (root / "docs/security/ECHO_SLO_BENCHMARK.json").write_text(
        json.dumps(slo) + "\n", encoding="utf-8"
    )
    (root / "docs/security/ECHO_ISOLATED_VENV_E2E.json").write_text(
        json.dumps({"ok": True}) + "\n", encoding="utf-8"
    )

    monkeypatch.setattr(
        final_evidence,
        "slo_artifact_ok",
        lambda _path, *, root=None: True,  # noqa: ARG005
    )
    receipts = {
        "echo_full_audit": {
            "passed": True,
            "exit_code": 0,
            "duration_seconds": 1.0,
            "start_utc": "2026-07-29T00:00:00Z",
            "end_utc": "2026-07-29T00:00:01Z",
            "artifact_sha256": "c" * 64,
        }
    }
    _stub_formal_state(
        monkeypatch,
        receipts=receipts,
        passed_gates=tuple(f"slo_run_{index}" for index in range(1, 6)),
    )

    payload = final_evidence.build_final_evidence_payload(
        root=root,
        evidence_dir=tmp_path / "evidence",
        branch="feature/echo-runtime",
        head="b" * 40,
        evidence_root_relative=".task-tmp/evidence/demo",
        soak_path=root / "docs/security/ECHO_LIVE_ACCEPTANCE.json",
        e2e_path=root / "docs/security/ECHO_ISOLATED_VENV_E2E.json",
        generated_utc="2026-07-29T00:00:02Z",
    )

    assert payload["slo_ok"] is True
    assert payload["soak"]["sample_count"] == 42
    assert payload["soak"]["success_count"] == 42
    assert payload["soak"]["failure_count"] == 0
    assert payload["e2e_ok"] is False
    assert payload["gate_receipts"]["echo_full_audit"]["artifact_sha256"] == "c" * 64


def test_readonly_validator_rejects_null_soak_and_slo_summary(
    tmp_path: Path, monkeypatch: Any
) -> None:
    acceptance = _nested_soak_acceptance(sample_count=10)
    slo = _slo_without_top_level_ok()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    soak_path = evidence / "soak.json"
    slo_path = evidence / "slo.json"
    soak_path.write_text(json.dumps(acceptance) + "\n", encoding="utf-8")
    slo_path.write_text(json.dumps(slo) + "\n", encoding="utf-8")

    bad_payload = {
        "schema_version": "js-agent-final-evidence-v2",
        "slo_ok": None,
        "soak": {
            "duration_seconds": 3600.0,
            "ok": True,
            "source_digest": "a" * 64,
            "sample_count": None,
            "success_count": None,
            "failure_count": None,
            "crosstalk_count": None,
            "http_5xx_count": None,
        },
        "gate_receipts": {
            "echo_full_audit": {
                "passed": True,
                "exit_code": 0,
                "artifact_sha256": None,
            }
        },
    }
    before = _tree_fingerprint(evidence)
    time.sleep(0.02)
    _stub_formal_state(monkeypatch)
    errors = final_evidence.validate_final_evidence_document(
        bad_payload,
        soak_path=soak_path,
        slo_path=slo_path,
        root=tmp_path,
        evidence_dir=evidence,
        require_audit_artifact_sha=True,
    )
    after = _tree_fingerprint(evidence)

    assert before == after
    assert any("sample_count" in err for err in errors)
    assert any("slo_ok" in err for err in errors)
    assert any("echo_full_audit" in err and "artifact_sha256" in err for err in errors)


def test_echo_full_audit_gate_binds_audit_markdown_artifact(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    root = tmp_path / "repo"
    audit = root / "docs" / "echo" / "ECHO_10_ROUND_AUDIT.md"
    audit.parent.mkdir(parents=True)
    audit.write_text("# Echo 10 Round Audit\n", encoding="utf-8")

    spec = rg.get_local_gate_spec("echo_full_audit", evidence_dir=evidence)
    assert spec is not None
    path = rg._artifact_path_from_argv(
        spec.argv,
        spec,
        root=root,
        evidence_dir=evidence,
        source_digest="a" * 64,
    )
    assert path is not None
    assert path.resolve() == audit.resolve()


def test_echo_full_audit_ordered_after_soak_and_before_strict_readiness() -> None:
    gates = list(rg.REQUIRED_FINAL_LOCAL_GATES)
    assert gates.index("soak_3600") < gates.index("echo_full_audit")
    assert gates.index("isolated_venv_e2e") < gates.index("release_smoke")
    assert gates.index("release_smoke") < gates.index("echo_full_audit")
    assert gates.index("echo_full_audit") < gates.index("strict_readiness")


def test_sanitized_export_allowlist_includes_audit_artifacts() -> None:
    joined = "\n".join(evidence_export._ALLOWLIST_GLOBS)
    assert "pack/ECHO_10_ROUND_AUDIT.md" in joined
    assert "pack/ECHO_FINAL_REPLACEMENT_REPORT.md" in joined


def test_receipt_validation_requires_echo_full_audit_artifact_sha(
    tmp_path: Path, monkeypatch: Any
) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    final = evidence / "final"
    gates = evidence / "gates"
    final.mkdir(parents=True)
    gates.mkdir(parents=True)
    audit = root / "docs/echo/ECHO_10_ROUND_AUDIT.md"
    audit.parent.mkdir(parents=True)
    audit.write_text("# Echo 10 Round Audit\n- Internal release ready: `True`\n", encoding="utf-8")
    digest = "a" * 64
    monkeypatch.setattr(rg, "release_source_digest", lambda _root: digest)
    monkeypatch.setattr(rg, "build_frozen_toolchain_lock", lambda _root: {"schema_version": "x"})

    # Minimal path: unit-check the helper that decides artifact binding policy.
    assert final_evidence.gate_requires_audit_artifact_sha("echo_full_audit") is True
    assert final_evidence.gate_requires_audit_artifact_sha("release_smoke") is False
    assert final_evidence.gate_requires_audit_artifact_sha("ruff") is False


def test_buggy_publisher_pattern_produces_nulls_that_validator_rejects(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The Round 8.15 continue_gates inline extractor must not be used again."""
    acceptance = _nested_soak_acceptance(sample_count=14394)
    slo = _slo_without_top_level_ok()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    soak_path = evidence / "soak.json"
    slo_path = evidence / "slo.json"
    soak_path.write_text(json.dumps(acceptance) + "\n", encoding="utf-8")
    slo_path.write_text(json.dumps(slo) + "\n", encoding="utf-8")

    buggy_payload = {
        "schema_version": "js-agent-final-evidence-v2",
        "slo_ok": final_evidence.buggy_slo_ok_from_top_level(slo),
        "soak": final_evidence.buggy_top_level_soak_extraction(acceptance),
        "gate_receipts": {
            "echo_full_audit": {
                "passed": True,
                "exit_code": 0,
                "artifact_sha256": None,
            }
        },
    }
    assert buggy_payload["slo_ok"] is None
    assert buggy_payload["soak"]["sample_count"] is None

    monkeypatch.setattr(
        final_evidence,
        "slo_artifact_ok",
        lambda _path, *, root=None: True,  # noqa: ARG005
    )
    _stub_formal_state(monkeypatch)
    before = _tree_fingerprint(evidence)
    errors = final_evidence.validate_final_evidence_document(
        buggy_payload,
        soak_path=soak_path,
        slo_path=slo_path,
        root=tmp_path,
        evidence_dir=evidence,
        require_audit_artifact_sha=True,
    )
    after = _tree_fingerprint(evidence)
    assert before == after
    assert any("sample_count" in err for err in errors)
    assert any("slo_ok" in err for err in errors)
    assert any("artifact_sha256" in err for err in errors)


def test_publisher_helpers_bind_audit_sha_and_pass_validator(
    tmp_path: Path, monkeypatch: Any
) -> None:
    root = tmp_path / "repo"
    final = tmp_path / "final"
    final.mkdir(parents=True)
    (root / "docs" / "security").mkdir(parents=True)
    (root / "docs" / "echo").mkdir(parents=True)
    acceptance = _nested_soak_acceptance(sample_count=77)
    slo = _slo_without_top_level_ok()
    soak_path = root / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    slo_path = root / "docs/security/ECHO_SLO_BENCHMARK.json"
    e2e_path = root / "docs/security/ECHO_ISOLATED_VENV_E2E.json"
    soak_path.write_text(json.dumps(acceptance) + "\n", encoding="utf-8")
    slo_path.write_text(json.dumps(slo) + "\n", encoding="utf-8")
    e2e_path.write_text(json.dumps({"ok": True}) + "\n", encoding="utf-8")
    audit = root / "docs/echo/ECHO_10_ROUND_AUDIT.md"
    audit.write_text("# Echo 10 Round Audit\n- Internal release ready: `True`\n", encoding="utf-8")

    # Marker-only historical receipt (Round 8.15 shape) — summary must still bind SHA.
    (final / "echo_full_audit.receipt.json").write_text(
        json.dumps(
            {
                "passed": True,
                "exit_code": 0,
                "duration_seconds": 1.0,
                "start_utc": "2026-07-29T00:00:00Z",
                "end_utc": "2026-07-29T00:00:01Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        final_evidence,
        "slo_artifact_ok",
        lambda _path, *, root=None: True,  # noqa: ARG005
    )

    raw = final_evidence.load_gate_receipt_summaries(final)
    assert raw["echo_full_audit"].get("artifact_sha256") is None
    receipts = final_evidence.bind_audit_artifact_sha(raw, root=root)
    assert receipts["echo_full_audit"]["artifact_sha256"] == final_evidence.sha256_file(audit)
    _stub_formal_state(monkeypatch, receipts=receipts)

    payload = final_evidence.build_final_evidence_payload(
        root=root,
        evidence_dir=tmp_path,
        branch="feature/echo-runtime",
        head="b" * 40,
        evidence_root_relative=".task-tmp/evidence/demo",
        soak_path=soak_path,
        slo_path=slo_path,
        e2e_path=e2e_path,
        generated_utc="2026-07-29T00:00:02Z",
    )
    out = tmp_path / "JS_AGENT_FINAL_EVIDENCE.json"
    final_evidence.write_final_evidence_json(out, payload)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    errors = final_evidence.validate_final_evidence_document(
        loaded,
        soak_path=soak_path,
        slo_path=slo_path,
        root=root,
        evidence_dir=tmp_path,
        e2e_path=e2e_path,
        require_audit_artifact_sha=True,
    )
    assert errors == []
    assert loaded["soak"]["sample_count"] == 77
    assert loaded["slo_ok"] is False


def test_final_summary_keyboard_interrupt_preserves_old_output_and_cleans_temp(
    tmp_path: Path, monkeypatch: Any
) -> None:
    output = tmp_path / "JS_AGENT_FINAL_EVIDENCE.json"
    output.write_text('{"old": true}\n', encoding="utf-8")
    before = output.read_bytes()
    real_replace = os.replace

    def interrupt_replace(source: str | Path, destination: str | Path) -> None:
        if Path(destination) == output:
            raise KeyboardInterrupt
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", interrupt_replace)

    with pytest.raises(KeyboardInterrupt):
        final_evidence.write_final_evidence_json(output, {"new": True})

    assert output.read_bytes() == before
    assert list(tmp_path.glob(f".{output.name}.*.tmp")) == []


def test_marker_only_echo_full_audit_receipt_fails_gate_validator(tmp_path: Path) -> None:
    """Round 8.15 marker-only audit receipts must fail under current fail-closed rules."""
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    gates = evidence / "gates"
    gates.mkdir(parents=True)
    (root / "docs" / "echo").mkdir(parents=True)
    audit = root / "docs/echo/ECHO_10_ROUND_AUDIT.md"
    audit.write_text("# Echo 10 Round Audit\n", encoding="utf-8")
    stdout = gates / "echo_full_audit.stdout.txt"
    stderr = gates / "echo_full_audit.stderr.txt"
    marker = rg.format_release_result_line(gate="echo_full_audit", ok=True)
    stdout.write_text(marker + "\n", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")

    digest = "a" * 64
    receipt = {
        "schema_version": rg.LOCAL_GATE_RECEIPT_SCHEMA_VERSION,
        "gate_spec_version": rg.LOCAL_GATE_SPEC_VERSION,
        "gate_name": "echo_full_audit",
        "argv": [".venv/bin/python", "scripts/echo_full_audit.py"],
        "normalized_argv": [
            ".venv/bin/python",
            "{repo_root}/scripts/echo_full_audit.py",
        ],
        "coverage_scope": ["scripts/echo_full_audit.py", "js/echo/"],
        "output_parse": {
            "parser": "release_markers",
            "require_exit_code_zero": True,
            "stderr_must_be_empty": True,
        },
        "toolchain": {},
        "toolchain_lock_sha256": "c" * 64,
        "toolchain_before": {"schema_version": "js-agent-toolchain-lock-v1", "tools": {}},
        "toolchain_after": {"schema_version": "js-agent-toolchain-lock-v1", "tools": {}},
        "parse_result": {
            "parser": "release_markers",
            "ok": True,
            "ok_markers": 1,
            "json_ok": True,
            "expected_gate": "echo_full_audit",
            "payload": {
                "schema_version": "js-agent-release-result-v1",
                "gate": "echo_full_audit",
                "ok": True,
            },
        },
        "cwd": "<REPO_ROOT>",
        "evidence_dir": "<EVIDENCE_ROOT>",
        "start_utc": "2026-07-28T15:56:21Z",
        "end_utc": "2026-07-28T15:56:27Z",
        "duration_seconds": 5.0,
        "source_digest_before": digest,
        "source_digest_after": digest,
        "exit_code": 0,
        "stdout_path": "<EVIDENCE_ROOT>/gates/echo_full_audit.stdout.txt",
        "stderr_path": "<EVIDENCE_ROOT>/gates/echo_full_audit.stderr.txt",
        "stdout_sha256": hashlib.sha256(stdout.read_bytes()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.read_bytes()).hexdigest(),
        "passed": True,
        # Intentionally omit artifact_sha256 — Round 8.15 marker-only shape.
    }

    assert (
        rg._valid_local_gate_receipt(
            receipt,
            root=root,
            evidence_dir=evidence,
            expected_source_digest=digest,
        )
        is False
    )

"""Final evidence summary builder and read-only validator (M1 closure).

Correctly extracts nested soak counters and SLO readiness from authoritative
artifacts. Validators are strictly read-only: they never rewrite inputs.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from js.echo.ledger.strict_json import StrictJSONError, strict_load_path

FINAL_EVIDENCE_SCHEMA_VERSION = "js-agent-final-evidence-v2"
_AUDIT_GATES_REQUIRING_ARTIFACT_SHA: frozenset[str] = frozenset({"echo_full_audit"})
_DEFAULT_AUDIT_OUTPUT = Path("docs/echo/ECHO_10_ROUND_AUDIT.md")
_DEFAULT_FINAL_REPORT_OUTPUT = Path("docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md")


def gate_requires_audit_artifact_sha(gate_name: str) -> bool:
    return gate_name in _AUDIT_GATES_REQUIRING_ARTIFACT_SHA


def default_echo_full_audit_artifact(root: Path) -> Path:
    return (root / _DEFAULT_AUDIT_OUTPUT).resolve()


def default_echo_final_report_artifact(root: Path) -> Path:
    return (root / _DEFAULT_FINAL_REPORT_OUTPUT).resolve()


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _non_bool_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def extract_soak_summary(acceptance: Mapping[str, Any]) -> dict[str, Any]:
    """Pull soak counters from the nested ``soak`` object used by live acceptance."""
    nested = _as_dict(acceptance.get("soak"))
    sample_count = _non_bool_int(nested.get("sample_count"))
    success = _non_bool_int(nested.get("success"))
    failures = _non_bool_int(nested.get("failures"))
    crosstalk = _non_bool_int(nested.get("crosstalk"))
    http_5xx = _non_bool_int(nested.get("http_5xx"))
    if http_5xx is None:
        http_5xx = _non_bool_int(nested.get("http_5xx_count"))
    if http_5xx is None:
        http_5xx = _non_bool_int(acceptance.get("status_5xx_count"))

    return {
        "duration_seconds": acceptance.get("duration_seconds"),
        "ok": acceptance.get("ok"),
        "source_digest": acceptance.get("source_digest"),
        "sample_count": sample_count,
        "success_count": success
        if success is not None
        else _non_bool_int(nested.get("success_count")),
        "failure_count": failures
        if failures is not None
        else _non_bool_int(nested.get("failure_count")),
        "crosstalk_count": crosstalk
        if crosstalk is not None
        else _non_bool_int(nested.get("crosstalk_count")),
        "http_5xx_count": http_5xx,
    }


def slo_artifact_ok(path: Path, *, root: Path | None = None) -> bool:
    """Return whether a SLO benchmark artifact is valid for the current tree."""
    from js.echo.ledger.release_gates import _valid_echo_slo_benchmark

    return _valid_echo_slo_benchmark(path, root=root)


def _load_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = strict_load_path(path)
    except (OSError, StrictJSONError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def build_final_evidence_payload(
    *,
    root: Path,
    digest: str,
    branch: str,
    head: str,
    evidence_root_relative: str,
    gate_receipts: Mapping[str, object],
    internal_ready: bool,
    validation_ok: bool,
    generated_utc: str | None = None,
    round_label: str = "8.15",
    pre_key_diagnostic_digest: str | None = None,
    notes: str | None = None,
    soak_path: Path | None = None,
    slo_path: Path | None = None,
    e2e_path: Path | None = None,
) -> dict[str, Any]:
    resolved = root.resolve()
    soak_doc = _load_object(soak_path or resolved / "docs/security/ECHO_LIVE_ACCEPTANCE.json")
    slo_doc_path = slo_path or resolved / "docs/security/ECHO_SLO_BENCHMARK.json"
    e2e_doc = _load_object(e2e_path or resolved / "docs/security/ECHO_ISOLATED_VENV_E2E.json")
    soak_summary = extract_soak_summary(soak_doc)
    slo_ok: bool | None
    if slo_doc_path.is_file():
        slo_ok = bool(slo_artifact_ok(slo_doc_path, root=resolved))
    else:
        slo_ok = None

    payload: dict[str, Any] = {
        "schema_version": FINAL_EVIDENCE_SCHEMA_VERSION,
        "round": round_label,
        "branch": branch,
        "HEAD": head,
        "frozen_source_digest": digest,
        "generated_utc": generated_utc or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_root_relative": evidence_root_relative,
        "stable_ready": False,
        "internal_ready": bool(internal_ready),
        "not_a_third_party_signature": True,
        "classification": {
            "passed": [
                "bulk_truncation_recovery",
                "release_source_integrity_preflight",
                "echo_model_and_tool_authorization_fail_closed",
                "work_owner_session_snapshot_and_descriptor_output",
                "atomic_context_compression_and_verified_token_accounting",
                "external_old_baseline_provenance_v2",
                "required_local_gates",
                "real_3600_soak",
            ],
            "failed": [],
            "partial": [],
            "not_tested": ["real_office_business_files"],
            "external_pending": [
                "legal_fto_review_pending",
                "clean_room_reviewer_pending",
                "external_security_audit_missing",
                "redteam_report_missing",
            ],
        },
        "gate_receipts": dict(gate_receipts),
        "soak": soak_summary,
        "e2e_ok": e2e_doc.get("ok"),
        "slo_ok": slo_ok,
        "validation_ok": bool(validation_ok),
        "notes": notes
        or (
            "Final evidence summary binds nested soak counters and SLO validity from "
            "authoritative artifacts. This establishes an internal production candidate "
            "only; external legal and independent security evidence remains pending."
        ),
    }
    if pre_key_diagnostic_digest is not None:
        payload["pre_key_diagnostic_digest"] = pre_key_diagnostic_digest
    return payload


def validate_final_evidence_document(
    payload: Mapping[str, Any],
    *,
    soak_path: Path,
    slo_path: Path,
    root: Path,
    require_audit_artifact_sha: bool = True,
) -> list[str]:
    """Read-only validation of a final-evidence summary against raw artifacts.

    Never creates, rewrites, or deletes files under ``soak_path`` / ``slo_path`` /
    ``root``. Returns a list of human-readable errors (empty means ok).
    """
    errors: list[str] = []
    if payload.get("schema_version") != FINAL_EVIDENCE_SCHEMA_VERSION:
        errors.append("schema_version must be js-agent-final-evidence-v2")

    soak_doc = _load_object(soak_path)
    expected_soak = extract_soak_summary(soak_doc) if soak_doc else {}
    soak = _as_dict(payload.get("soak"))
    for field in (
        "sample_count",
        "success_count",
        "failure_count",
        "crosstalk_count",
        "http_5xx_count",
    ):
        expected = expected_soak.get(field)
        actual = soak.get(field)
        if expected is not None and actual != expected:
            errors.append(f"soak.{field} expected {expected!r}, got {actual!r}")
        if expected is not None and actual is None:
            errors.append(f"soak.{field} is null while raw acceptance has {expected!r}")

    if slo_path.is_file():
        expected_slo_ok = bool(slo_artifact_ok(slo_path, root=root))
        actual_slo_ok = payload.get("slo_ok")
        if actual_slo_ok is None:
            errors.append("slo_ok is null while SLO artifact is present")
        elif actual_slo_ok is not expected_slo_ok:
            errors.append(f"slo_ok expected {expected_slo_ok!r}, got {actual_slo_ok!r}")

    if require_audit_artifact_sha:
        receipts = _as_dict(payload.get("gate_receipts"))
        audit_receipt = _as_dict(receipts.get("echo_full_audit"))
        artifact_sha = audit_receipt.get("artifact_sha256")
        if not isinstance(artifact_sha, str) or len(artifact_sha) != 64:
            errors.append(
                "gate_receipts.echo_full_audit.artifact_sha256 must bind the "
                "final audit markdown SHA-256"
            )

    return errors


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_gate_receipt_summaries(final_dir: Path) -> dict[str, dict[str, Any]]:
    """Load compact gate receipts from ``final/*.receipt.json`` for the summary doc."""
    from js.echo.ledger.strict_json import StrictJSONError, strict_load_path

    summaries: dict[str, dict[str, Any]] = {}
    if not final_dir.is_dir():
        return summaries
    for receipt_path in sorted(final_dir.glob("*.receipt.json")):
        try:
            data = strict_load_path(receipt_path)
        except (OSError, StrictJSONError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        gate_name = receipt_path.name.removesuffix(".receipt.json")
        entry: dict[str, Any] = {
            "passed": data.get("passed"),
            "exit_code": data.get("exit_code"),
            "duration_seconds": data.get("duration_seconds"),
            "start_utc": data.get("start_utc"),
            "end_utc": data.get("end_utc"),
            "artifact_sha256": data.get("artifact_sha256"),
        }
        summaries[gate_name] = entry
    return summaries


def bind_audit_artifact_sha(
    receipts: Mapping[str, object],
    *,
    root: Path,
) -> dict[str, dict[str, Any]]:
    """Return a copy of receipts with ``echo_full_audit.artifact_sha256`` bound to markdown."""
    out: dict[str, dict[str, Any]] = {}
    for name, raw in receipts.items():
        out[name] = dict(_as_dict(raw))
    audit_path = default_echo_full_audit_artifact(root)
    if not audit_path.is_file():
        return out
    digest = sha256_file(audit_path)
    audit_receipt = dict(_as_dict(out.get("echo_full_audit")))
    audit_receipt["artifact_sha256"] = digest
    out["echo_full_audit"] = audit_receipt
    return out


def buggy_top_level_soak_extraction(acceptance: Mapping[str, Any]) -> dict[str, Any]:
    """Reproduce the Round 8.15 summary bug (top-level / wrong key names).

    Kept for regression tests only — never use in publishers.
    """
    resources = _as_dict(acceptance.get("resources"))
    return {
        "duration_seconds": acceptance.get("duration_seconds"),
        "ok": acceptance.get("ok"),
        "source_digest": acceptance.get("source_digest"),
        "sample_count": acceptance.get("sample_count") or resources.get("sample_count"),
        "success_count": acceptance.get("success_count"),
        "failure_count": acceptance.get("failure_count"),
        "crosstalk_count": acceptance.get("crosstalk_count"),
        "http_5xx_count": acceptance.get("http_5xx_count") or acceptance.get("status_5xx_count"),
    }


def buggy_slo_ok_from_top_level(slo_doc: Mapping[str, Any]) -> bool | None:
    """Reproduce the Round 8.15 ``slo.get('ok')`` bug — always null for real SLO artifacts."""
    if not slo_doc:
        return None
    value = slo_doc.get("ok")
    return bool(value) if value is not None else None


def write_final_evidence_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Atomically write a final-evidence summary JSON document."""
    import json
    import os
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(dict(payload), indent=2, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def promote_audit_artifacts_to_pack(*, root: Path, pack_dir: Path) -> list[Path]:
    """Copy audit markdown into pack/ for sanitized-export allowlist closure."""
    import shutil

    pack_dir.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for source in (
        default_echo_full_audit_artifact(root),
        default_echo_final_report_artifact(root),
    ):
        if not source.is_file():
            continue
        destination = pack_dir / source.name
        shutil.copy2(source, destination)
        copied.append(destination)
    return copied

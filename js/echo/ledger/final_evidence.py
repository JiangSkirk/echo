"""Final evidence summary builder and read-only validator (M1 closure).

Correctly extracts nested soak counters and SLO readiness from authoritative
artifacts. Validators are strictly read-only: they never rewrite inputs.
"""

from __future__ import annotations

import hashlib
import re
import stat
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


def _read_frozen_digest(evidence_dir: Path) -> str:
    path = evidence_dir / "FROZEN_DIGEST.txt"
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("FROZEN_DIGEST.txt missing or unreadable") from exc
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("FROZEN_DIGEST.txt must contain one lowercase SHA-256 digest")
    return value


def _desktop_manifest_binding(
    *,
    root: Path,
    evidence_dir: Path,
    expected_source_digest: str,
) -> tuple[str | None, list[str]]:
    manifest_path = evidence_dir / "desktop-build" / "manifest.json"
    try:
        manifest_stat = manifest_path.lstat()
    except OSError:
        return None, ["desktop_manifest_missing"]
    if stat.S_ISLNK(manifest_stat.st_mode) or not stat.S_ISREG(manifest_stat.st_mode):
        return None, ["desktop_manifest_not_regular"]
    manifest = _load_object(manifest_path)
    if not manifest:
        return None, ["desktop_manifest_invalid_json"]
    errors: list[str] = []
    if manifest.get("source_digest") != expected_source_digest:
        errors.append("desktop_manifest_source_digest_mismatch")
    try:
        from desktop.build_driver import verify_manifest

        verify_errors = verify_manifest(manifest_path, repo_root=root)
    except (ImportError, OSError, RuntimeError, ValueError, TypeError):
        verify_errors = ["desktop manifest verifier failed"]
    if verify_errors:
        errors.append("desktop_manifest_verification_failed")
    return sha256_file(manifest_path), errors


def _derive_formal_state(*, root: Path, evidence_dir: Path) -> dict[str, Any]:
    from js.echo.ledger.release_gates import (
        REQUIRED_FINAL_LOCAL_GATES,
        release_source_digest,
        validate_final_local_gate_evidence,
        verify_release_readiness,
    )

    resolved_root = root.resolve()
    resolved_evidence = evidence_dir.resolve()
    current_digest = release_source_digest(resolved_root)
    frozen_digest = _read_frozen_digest(resolved_evidence)
    if frozen_digest != current_digest:
        raise ValueError("frozen source digest does not match current source digest")
    report = validate_final_local_gate_evidence(
        resolved_root,
        final_dir=resolved_evidence / "final",
        evidence_dir=resolved_evidence,
        expected_source_digest=current_digest,
    )
    passed = tuple(report.passed_gates)
    if any(gate not in REQUIRED_FINAL_LOCAL_GATES for gate in passed):
        raise ValueError("formal validator returned unknown passed gate")
    expected_all = all(gate in passed for gate in REQUIRED_FINAL_LOCAL_GATES) and not report.blockers
    if report.all_local_gates_passed is not expected_all:
        raise ValueError("formal validator gate closure is inconsistent")
    readiness = verify_release_readiness(
        resolved_root,
        require_audit_reports=False,
        require_live_acceptance=False,
    )
    internal_ready = bool(readiness.internal_ready)
    desktop_digest, desktop_errors = _desktop_manifest_binding(
        root=resolved_root,
        evidence_dir=resolved_evidence,
        expected_source_digest=current_digest,
    )
    product_ready = bool(
        report.product_internal_ready
        and report.all_local_gates_passed
        and internal_ready
        and desktop_digest is not None
        and not desktop_errors
    )
    blockers = list(report.blockers)
    if report.product_internal_ready or "desktop_build" in passed:
        blockers.extend(desktop_errors)
    raw_receipts = load_gate_receipt_summaries(resolved_evidence / "final")
    receipts = {
        gate: raw_receipts[gate]
        for gate in REQUIRED_FINAL_LOCAL_GATES
        if gate in passed and gate in raw_receipts
    }
    if set(receipts) != set(passed):
        raise ValueError("formal validator passed_gates receipt summary closure mismatch")
    return {
        "source_digest": current_digest,
        "report": report,
        "passed_gates": passed,
        "blockers": tuple(dict.fromkeys(blockers)),
        "validation_ok": bool(report.all_local_gates_passed),
        "internal_ready": internal_ready,
        "product_internal_ready": product_ready,
        "desktop_manifest_digest": desktop_digest,
        "gate_receipts": receipts,
    }


def _artifact_is_formally_bound(
    formal: Mapping[str, Any],
    *,
    gate_name: str,
    path: Path,
) -> bool:
    passed = formal.get("passed_gates")
    if not isinstance(passed, tuple) or gate_name not in passed or not path.is_file():
        return False
    receipts = _as_dict(formal.get("gate_receipts"))
    receipt = _as_dict(receipts.get(gate_name))
    expected = receipt.get("artifact_sha256")
    return bool(
        isinstance(expected, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected)
        and sha256_file(path) == expected
    )


def _derive_summary_artifacts(
    *,
    root: Path,
    formal: Mapping[str, Any],
    soak_path: Path,
    slo_path: Path,
    e2e_path: Path,
) -> tuple[dict[str, Any], bool | None, bool]:
    passed_obj = formal.get("passed_gates")
    passed = set(passed_obj) if isinstance(passed_obj, tuple) else set()

    soak_doc = _load_object(soak_path)
    soak_summary = extract_soak_summary(soak_doc)
    soak_bound = _artifact_is_formally_bound(formal, gate_name="soak_3600", path=soak_path)
    if "soak_3600" in passed and not soak_bound:
        raise ValueError("selected soak artifact is not bound by formal gate receipt")
    soak_summary["validated_by_gate"] = soak_bound

    raw_slo_ok = bool(slo_artifact_ok(slo_path, root=root)) if slo_path.is_file() else None
    slo_gates = {f"slo_run_{index}" for index in range(1, 6)}
    slo_bound = slo_gates.issubset(passed)
    if slo_bound and raw_slo_ok is not True:
        raise ValueError("selected SLO artifact is not valid for formal passed gates")
    slo_ok = raw_slo_ok if slo_bound else (False if raw_slo_ok is not None else None)

    e2e_doc = _load_object(e2e_path)
    e2e_bound = _artifact_is_formally_bound(
        formal,
        gate_name="isolated_venv_e2e",
        path=e2e_path,
    )
    if "isolated_venv_e2e" in passed and (not e2e_bound or e2e_doc.get("ok") is not True):
        raise ValueError("selected E2E artifact is not bound by formal gate receipt")
    e2e_ok = bool(e2e_bound and e2e_doc.get("ok") is True)
    return soak_summary, slo_ok, e2e_ok


def build_final_evidence_payload(
    *,
    root: Path,
    evidence_dir: Path,
    branch: str,
    head: str,
    evidence_root_relative: str,
    generated_utc: str | None = None,
    round_label: str = "8.15",
    pre_key_diagnostic_digest: str | None = None,
    notes: str | None = None,
    soak_path: Path | None = None,
    slo_path: Path | None = None,
    e2e_path: Path | None = None,
) -> dict[str, Any]:
    resolved = root.resolve()
    formal = _derive_formal_state(root=resolved, evidence_dir=evidence_dir)
    digest = str(formal["source_digest"])
    gate_receipts = _as_dict(formal["gate_receipts"])
    internal_ready = bool(formal["internal_ready"])
    validation_ok = bool(formal["validation_ok"])
    product_internal_ready = bool(formal["product_internal_ready"])
    desktop_manifest_digest = formal["desktop_manifest_digest"]
    resolved_evidence = evidence_dir.resolve()
    soak_doc_path = soak_path or resolved_evidence / "soak" / "ECHO_LIVE_ACCEPTANCE.json"
    slo_doc_path = slo_path or resolved / "docs/security/ECHO_SLO_BENCHMARK.json"
    e2e_doc_path = e2e_path or resolved_evidence / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
    soak_summary, slo_ok, e2e_ok = _derive_summary_artifacts(
        root=resolved,
        formal=formal,
        soak_path=soak_doc_path,
        slo_path=slo_doc_path,
        e2e_path=e2e_doc_path,
    )

    payload: dict[str, Any] = {
        "schema_version": FINAL_EVIDENCE_SCHEMA_VERSION,
        "round": round_label,
        "branch": branch,
        "HEAD": head,
        "frozen_source_digest": digest,
        "current_source_digest": digest,
        "generated_utc": generated_utc or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_root_relative": evidence_root_relative,
        "stable_ready": False,
        "internal_ready": bool(internal_ready),
        "product_internal_ready": bool(product_internal_ready),
        "desktop_manifest_digest": desktop_manifest_digest,
        "validation_blockers": list(formal["blockers"]),
        "not_a_third_party_signature": True,
        "classification": _build_classification(
            validation_ok=bool(validation_ok),
            product_internal_ready=bool(product_internal_ready),
            internal_ready=bool(internal_ready),
            gate_receipts=gate_receipts,
            soak_summary=soak_summary,
            slo_ok=slo_ok,
            e2e_ok=e2e_ok,
        ),
        "gate_receipts": dict(gate_receipts),
        "soak": soak_summary,
        "e2e_ok": e2e_ok,
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


def _build_classification(
    *,
    validation_ok: bool,
    product_internal_ready: bool,
    internal_ready: bool,
    gate_receipts: Mapping[str, object],
    soak_summary: Mapping[str, object] | None,
    slo_ok: bool | None,
    e2e_ok: object,
) -> dict[str, list[str]]:
    """Classify evidence buckets with accurate gate-readiness semantics.

    ``required_local_gates`` is only listed under ``passed`` when every required
    local gate has passed (``validation_ok`` / product-ready path). An 18/19
    partial result must land in ``partial``/``blocked``, never ``passed``.
    """
    # Every passed item below is derived from the formal gate report and bound
    # artifacts. Historical prose labels are not evidence and must not be
    # pre-populated as green.
    passed: list[str] = []
    failed: list[str] = []
    partial: list[str] = []

    receipt_map = dict(gate_receipts) if isinstance(gate_receipts, Mapping) else {}
    if validation_ok and product_internal_ready:
        passed.append("required_local_gates")
        passed.append("desktop_product_internal_ready")
    elif validation_ok:
        # Local gates green but product readiness still blocked (should be rare).
        passed.append("required_local_gates")
        partial.append("product_internal_ready_blocked")
    else:
        # Count how many gate receipts claim passed for partial signaling.
        passed_count = 0
        for value in receipt_map.values():
            if value is True or (
                isinstance(value, Mapping) and value.get("passed") is True
            ):
                passed_count += 1
        if passed_count > 0:
            partial.append("required_local_gates")
        else:
            failed.append("required_local_gates")

    soak_ok = False
    if isinstance(soak_summary, Mapping):
        soak_ok = (
            soak_summary.get("ok") is True
            and soak_summary.get("validated_by_gate") is True
        )
    if soak_ok and validation_ok:
        passed.append("real_3600_soak")
    elif soak_ok:
        partial.append("real_3600_soak")
    else:
        # Keep soak out of passed when validation is incomplete.
        if soak_summary:
            partial.append("real_3600_soak")

    if slo_ok is True:
        passed.append("slo_contract")
    elif slo_ok is False:
        failed.append("slo_contract")

    if e2e_ok is True:
        passed.append("isolated_venv_e2e")
    elif e2e_ok is False:
        failed.append("isolated_venv_e2e")

    if internal_ready and not product_internal_ready:
        partial.append("echo_internal_ready_without_desktop_product")

    return {
        "passed": passed,
        "failed": failed,
        "partial": partial,
        "not_tested": ["real_office_business_files"],
        "external_pending": [
            "legal_fto_review_pending",
            "clean_room_reviewer_pending",
            "external_security_audit_missing",
            "redteam_report_missing",
            "developer_id_and_notarization",
            "automatic_update_channel",
        ],
    }


def validate_final_evidence_document(
    payload: Mapping[str, Any],
    *,
    soak_path: Path,
    slo_path: Path,
    root: Path,
    evidence_dir: Path,
    e2e_path: Path | None = None,
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

    if require_audit_artifact_sha:
        receipts = _as_dict(payload.get("gate_receipts"))
        audit_receipt = _as_dict(receipts.get("echo_full_audit"))
        artifact_sha = audit_receipt.get("artifact_sha256")
        if not isinstance(artifact_sha, str) or len(artifact_sha) != 64:
            errors.append(
                "gate_receipts.echo_full_audit.artifact_sha256 must bind the "
                "final audit markdown SHA-256"
            )

    try:
        formal = _derive_formal_state(root=root, evidence_dir=evidence_dir)
    except ValueError as exc:
        errors.append(str(exc))
        return errors

    resolved_e2e_path = e2e_path or evidence_dir / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
    try:
        expected_soak, expected_slo_ok, expected_e2e_ok = _derive_summary_artifacts(
            root=root,
            formal=formal,
            soak_path=soak_path,
            slo_path=slo_path,
            e2e_path=resolved_e2e_path,
        )
    except ValueError as exc:
        errors.append(str(exc))
        return errors

    expected_digest = formal["source_digest"]
    for field in ("frozen_source_digest", "current_source_digest"):
        if payload.get(field) != expected_digest:
            errors.append(f"{field} does not match current/frozen source digest")
    expected_scalars = {
        "validation_ok": formal["validation_ok"],
        "internal_ready": formal["internal_ready"],
        "product_internal_ready": formal["product_internal_ready"],
        "desktop_manifest_digest": formal["desktop_manifest_digest"],
        "validation_blockers": list(formal["blockers"]),
        "slo_ok": expected_slo_ok,
        "e2e_ok": expected_e2e_ok,
    }
    for field, expected in expected_scalars.items():
        if payload.get(field) != expected:
            errors.append(f"{field} expected {expected!r}, got {payload.get(field)!r}")
    if _as_dict(payload.get("gate_receipts")) != formal["gate_receipts"]:
        errors.append("gate_receipts do not match formal validator passed_gates")
    if _as_dict(payload.get("soak")) != expected_soak:
        errors.append("soak summary does not match formally bound artifact")

    expected_classification = _build_classification(
        validation_ok=bool(formal["validation_ok"]),
        product_internal_ready=bool(formal["product_internal_ready"]),
        internal_ready=bool(formal["internal_ready"]),
        gate_receipts=_as_dict(formal["gate_receipts"]),
        soak_summary=expected_soak,
        slo_ok=expected_slo_ok,
        e2e_ok=expected_e2e_ok,
    )
    if payload.get("classification") != expected_classification:
        errors.append("classification does not match formal validator/readiness state")

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
    except BaseException:
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

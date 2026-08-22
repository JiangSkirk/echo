#!/usr/bin/env python3
"""Build a final-evidence summary from nested soak/SLO artifacts and gate receipts.

Uses ``js.echo.ledger.final_evidence`` so publishers cannot regress to the Round 8.15
top-level ``sample_count`` / ``slo.get('ok')`` extraction bugs. Validators remain
read-only: this script never mutates soak/SLO inputs.

Example::

    .venv/bin/python scripts/build_final_evidence_summary.py \\
        --evidence-dir .task-tmp/evidence/round8_15_final/20260728T153945Z \\
        --output .task-tmp/evidence/m1_closure/out/JS_AGENT_FINAL_EVIDENCE.json \\
        --soak-path .task-tmp/evidence/round8_15_final/20260728T153945Z/soak/ECHO_LIVE_ACCEPTANCE.json \\
        --slo-path .task-tmp/evidence/round8_15_final/20260728T153945Z/docs_promoted/ECHO_SLO_BENCHMARK.json
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

from js.echo.ledger.final_evidence import (  # noqa: E402
    build_final_evidence_payload,
    promote_audit_artifacts_to_pack,
    validate_final_evidence_document,
    write_final_evidence_json,
)


def _git_text(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--soak-path", type=Path, default=None)
    parser.add_argument("--slo-path", type=Path, default=None)
    parser.add_argument("--e2e-path", type=Path, default=None)
    parser.add_argument("--digest", type=str, default=None)
    parser.add_argument("--branch", type=str, default=None)
    parser.add_argument("--head", type=str, default=None)
    parser.add_argument("--round", type=str, default="8.15")
    parser.add_argument("--promote-audit-to-pack", action="store_true")
    parser.add_argument(
        "--allow-validation-errors",
        action="store_true",
        help="Write output even when read-only validation reports errors (diagnostic only).",
    )
    parser.add_argument("--notes", type=str, default=None)
    parser.add_argument("--pre-key-diagnostic-digest", type=str, default=None)
    args = parser.parse_args(argv)

    evidence_dir = args.evidence_dir
    if not evidence_dir.is_absolute():
        evidence_dir = (REPO_ROOT / evidence_dir).resolve()
    else:
        evidence_dir = evidence_dir.resolve()

    branch = args.branch or _git_text("branch", "--show-current")
    head = args.head or _git_text("rev-parse", "HEAD")
    digest = args.digest
    if digest is None:
        from js.echo.ledger.release_gates import release_source_digest

        digest = release_source_digest(REPO_ROOT)

    soak_path = args.soak_path
    if soak_path is None:
        soak_path = evidence_dir / "soak" / "ECHO_LIVE_ACCEPTANCE.json"
    elif not soak_path.is_absolute():
        soak_path = (REPO_ROOT / soak_path).resolve()

    slo_path = args.slo_path
    if slo_path is None:
        slo_path = REPO_ROOT / "docs/security/ECHO_SLO_BENCHMARK.json"
    elif not slo_path.is_absolute():
        slo_path = (REPO_ROOT / slo_path).resolve()

    e2e_path = args.e2e_path
    if e2e_path is None:
        candidate = evidence_dir / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
        e2e_path = (
            candidate
            if candidate.is_file()
            else REPO_ROOT / "docs/security/ECHO_ISOLATED_VENV_E2E.json"
        )
    elif not e2e_path.is_absolute():
        e2e_path = (REPO_ROOT / e2e_path).resolve()

    if args.promote_audit_to_pack:
        promote_audit_artifacts_to_pack(root=REPO_ROOT, pack_dir=evidence_dir / "pack")

    try:
        evidence_root_relative = str(evidence_dir.relative_to(REPO_ROOT))
    except ValueError:
        evidence_root_relative = str(evidence_dir)

    try:
        payload = build_final_evidence_payload(
            root=REPO_ROOT,
            evidence_dir=evidence_dir,
            branch=branch,
            head=head,
            evidence_root_relative=evidence_root_relative,
            round_label=args.round,
            soak_path=soak_path,
            slo_path=slo_path,
            e2e_path=e2e_path,
            notes=args.notes,
            pre_key_diagnostic_digest=args.pre_key_diagnostic_digest,
        )
    except ValueError as exc:
        print(f"formal evidence validation failed: {exc}", file=sys.stderr)
        return 1
    if digest != payload.get("current_source_digest"):
        print("requested digest does not match formal current source digest", file=sys.stderr)
        return 1

    errors = validate_final_evidence_document(
        payload,
        soak_path=soak_path,
        slo_path=slo_path,
        root=REPO_ROOT,
        evidence_dir=evidence_dir,
        e2e_path=e2e_path,
        require_audit_artifact_sha=True,
    )
    output = args.output if args.output.is_absolute() else (REPO_ROOT / args.output).resolve()
    if errors and not args.allow_validation_errors:
        print("validation errors:", file=sys.stderr)
        for err in errors:
            print(f" - {err}", file=sys.stderr)
        return 1

    write_final_evidence_json(output, payload)
    print(f"wrote {output}")
    print(f"slo_ok={payload.get('slo_ok')}")
    raw_soak = payload.get("soak")
    soak: dict[str, object] = raw_soak if isinstance(raw_soak, dict) else {}
    print(
        "soak counters:",
        {
            "sample_count": soak.get("sample_count"),
            "success_count": soak.get("success_count"),
            "failure_count": soak.get("failure_count"),
            "crosstalk_count": soak.get("crosstalk_count"),
            "http_5xx_count": soak.get("http_5xx_count"),
        },
    )
    if errors:
        print("wrote with validation errors (diagnostic mode)", file=sys.stderr)
        for err in errors:
            print(f" - {err}", file=sys.stderr)
        return 2
    if payload.get("validation_ok") is not True or payload.get("product_internal_ready") is not True:
        print("wrote partial formal evidence; product is not internally ready", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

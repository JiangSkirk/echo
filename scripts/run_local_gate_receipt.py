#!/usr/bin/env python3
"""Run one local quality gate and atomically write a versioned receipt.

Receipts use schema ``js-agent-local-gate-receipt-v4``. Commands are executed
via argv arrays (never ``shell=True``). If ``release_source_digest`` drifts
between start and finish, ``passed`` is forced false, ``source_drift`` is set,
and the runner exits non-zero — such receipts must not be copied into ``final/``.

Evidence layout::

    final/          # success receipts only (passed=true, no source_drift)
    pre_fix/        # failing runs captured before a fix lands
    historical/     # archived stale or superseded gate logs

Do **not** leave failing stdout/stderr under ``final/`` while claiming
``failed=[]`` in a summary report.

Usage::

    .venv/bin/python scripts/run_local_gate_receipt.py \\
        --gate-name ruff \\
        --evidence-dir .task-tmp/evidence/round8_6/<ts> \\
        --receipt .task-tmp/evidence/round8_6/<ts>/final/ruff.receipt.json \\
        -- .venv/bin/ruff check js/ js_work/ tests/

Exit code is non-zero when the wrapped command fails or source drift is detected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

from js.echo.ledger.release_gates import (  # noqa: E402
    LOCAL_GATE_RECEIPT_SCHEMA_VERSION,
    LOCAL_GATE_SPEC_VERSION,
    _artifact_path_from_argv,
    argv_matches_gate_spec,
    build_frozen_toolchain_lock,
    build_receipt_toolchain_for_argv,
    canonical_gate_capture_paths,
    get_local_gate_spec,
    normalize_gate_argv,
    parse_gate_stdout,
    release_source_digest,
    validate_release_source_integrity,
    write_toolchain_lock,
)
from js.echo.ledger.strict_json import StrictJSONError, strict_load_path  # noqa: E402


def _utc_now() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    _atomic_write_bytes(path, body.encode("utf-8"))


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def run_local_gate_receipt(
    *,
    gate_name: str,
    argv: list[str],
    receipt_path: Path,
    repo_root: Path,
    evidence_dir: Path,
    cwd: Path | None = None,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
) -> dict[str, Any]:
    """Execute ``argv`` and atomically publish a local gate receipt."""
    if not gate_name.strip():
        raise ValueError("gate_name must be non-empty")
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must be a non-empty list of non-empty strings")

    resolved_receipt = receipt_path.resolve()
    resolved_root = repo_root.resolve()
    resolved_evidence = evidence_dir.resolve()
    expected_filename = f"{gate_name}.receipt.json"
    if resolved_receipt.name != expected_filename:
        raise ValueError(
            f"receipt filename must be {expected_filename!r}, got {resolved_receipt.name!r}"
        )
    spec = get_local_gate_spec(gate_name, evidence_dir=resolved_evidence)
    if spec is None:
        raise ValueError(f"unknown gate_name {gate_name!r}")

    run_cwd = (cwd or resolved_root).resolve()
    if run_cwd != resolved_root:
        raise ValueError("cwd must resolve to the authoritative repository root")

    canonical_stdout, canonical_stderr = canonical_gate_capture_paths(
        gate_name,
        resolved_evidence,
    )
    if stdout_path is not None and stdout_path.resolve() != canonical_stdout.resolve():
        raise ValueError(
            f"stdout path must be the canonical gate capture path {canonical_stdout!r}"
        )
    if stderr_path is not None and stderr_path.resolve() != canonical_stderr.resolve():
        raise ValueError(
            f"stderr path must be the canonical gate capture path {canonical_stderr!r}"
        )
    stdout_target = canonical_stdout
    stderr_target = canonical_stderr

    validate_release_source_integrity(resolved_root)
    digest_before = release_source_digest(resolved_root)
    if not argv_matches_gate_spec(
        argv,
        spec,
        root=resolved_root,
        evidence_dir=resolved_evidence,
        source_digest=digest_before,
    ):
        raise ValueError(f"argv does not match gate spec for {gate_name!r}")

    lock_path = resolved_evidence / "TOOLCHAIN.lock.json"
    if lock_path.is_file():
        try:
            frozen_lock = strict_load_path(lock_path)
            if not isinstance(frozen_lock, dict):
                raise ValueError("invalid frozen toolchain lock")
        except (OSError, ValueError, StrictJSONError) as exc:
            raise ValueError("invalid frozen toolchain lock") from exc
    else:
        frozen_lock = write_toolchain_lock(resolved_evidence, resolved_root)
    toolchain_before = build_frozen_toolchain_lock(resolved_root)
    if toolchain_before != frozen_lock:
        raise ValueError("live toolchain does not match frozen toolchain lock")
    lock_sha256 = _sha256_file(lock_path)
    if lock_sha256 is None:
        raise ValueError("frozen toolchain lock is unreadable")

    start_utc = _utc_now()
    start_mono = time.monotonic()

    gate_env = os.environ.copy()
    # Fail-closed parsers bind plain text; disable tool colorization in captures.
    gate_env.setdefault("NO_COLOR", "1")
    gate_env.setdefault("TERM", "dumb")
    result = subprocess.run(
        argv,
        cwd=run_cwd,
        check=False,
        capture_output=True,
        text=False,
        env=gate_env,
    )

    end_mono = time.monotonic()
    end_utc = _utc_now()
    duration_seconds = round(end_mono - start_mono, 6)

    # Normalize absolute paths BEFORE writing logs and hashing — export must not
    # change bytes after receipt digests are sealed.
    from js.echo.ledger.evidence_export import redact_text

    stdout_text_raw = result.stdout.decode("utf-8", errors="replace")
    stderr_text_raw = result.stderr.decode("utf-8", errors="replace")
    stdout_text = redact_text(
        stdout_text_raw, repo_root=resolved_root, evidence_root=resolved_evidence
    )
    stderr_text = redact_text(
        stderr_text_raw, repo_root=resolved_root, evidence_root=resolved_evidence
    )
    stdout_bytes = stdout_text.encode("utf-8")
    stderr_bytes = stderr_text.encode("utf-8")
    _atomic_write_bytes(stdout_target, stdout_bytes)
    _atomic_write_bytes(stderr_target, stderr_bytes)

    digest_after = release_source_digest(resolved_root)
    source_drift = not hmac_compare(digest_before, digest_after)
    toolchain_after = build_frozen_toolchain_lock(resolved_root)
    toolchain_drift = toolchain_after != toolchain_before or toolchain_after != frozen_lock
    parse_result = parse_gate_stdout(
        spec.output_parse.parser,
        stdout_text,
        exit_code=result.returncode,
        require_exit_code_zero=spec.output_parse.require_exit_code_zero,
        expected_gate=spec.gate_name,
    )
    passed = (
        result.returncode == 0
        and parse_result.get("ok") is True
        and not source_drift
        and not toolchain_drift
    )
    normalized = normalize_gate_argv(
        argv,
        root=resolved_root,
        evidence_dir=resolved_evidence,
        source_digest=digest_before,
    )
    toolchain = build_receipt_toolchain_for_argv(resolved_root, argv)
    artifact_path = _artifact_path_from_argv(
        argv,
        spec,
        root=resolved_root,
        evidence_dir=resolved_evidence,
        source_digest=digest_before,
    )
    artifact_sha256 = _sha256_file(artifact_path) if artifact_path is not None else None

    def _redact_structure(value: Any) -> Any:
        if isinstance(value, str):
            return redact_text(value, repo_root=resolved_root, evidence_root=resolved_evidence)
        if isinstance(value, dict):
            return {str(key): _redact_structure(item) for key, item in value.items()}
        if isinstance(value, list):
            return [_redact_structure(item) for item in value]
        return value

    # Store capture paths as evidence-relative tokens for privacy + independent verify.
    stdout_rel = f"<EVIDENCE_ROOT>/gates/{stdout_target.name}"
    stderr_rel = f"<EVIDENCE_ROOT>/gates/{stderr_target.name}"

    receipt: dict[str, Any] = {
        "schema_version": LOCAL_GATE_RECEIPT_SCHEMA_VERSION,
        "gate_spec_version": LOCAL_GATE_SPEC_VERSION,
        "gate_name": gate_name,
        "argv": argv,
        "normalized_argv": list(normalized),
        "coverage_scope": list(spec.coverage_scope),
        "output_parse": {
            "parser": spec.output_parse.parser,
            "require_exit_code_zero": spec.output_parse.require_exit_code_zero,
            "stderr_must_be_empty": spec.output_parse.stderr_must_be_empty,
        },
        "toolchain": _redact_structure(toolchain),
        "toolchain_lock_sha256": lock_sha256,
        "toolchain_before": _redact_structure(toolchain_before),
        "toolchain_after": _redact_structure(toolchain_after),
        "parse_result": parse_result,
        "cwd": "<REPO_ROOT>",
        "evidence_dir": "<EVIDENCE_ROOT>",
        "start_utc": start_utc,
        "end_utc": end_utc,
        "duration_seconds": duration_seconds,
        "source_digest_before": digest_before,
        "source_digest_after": digest_after,
        "exit_code": result.returncode,
        "stdout_path": stdout_rel,
        "stderr_path": stderr_rel,
        "stdout_sha256": _sha256_bytes(stdout_bytes),
        "stderr_sha256": _sha256_bytes(stderr_bytes),
        "passed": passed,
    }
    if artifact_sha256 is not None:
        receipt["artifact_sha256"] = artifact_sha256
    if source_drift:
        receipt["source_drift"] = True
    if toolchain_drift:
        receipt["toolchain_drift"] = True

    _atomic_write_json(resolved_receipt, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a local gate and write a js-agent-local-gate-receipt-v4 artifact.",
        epilog=(
            "Evidence directories: put successful receipts under final/; archive failing "
            "or pre-fix logs under pre_fix/ or historical/. Never store fail logs in final/."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--gate-name", required=True, help="Stable gate identifier")
    parser.add_argument(
        "--evidence-dir",
        required=True,
        type=Path,
        help="Evidence bundle root; stdout/stderr captures must live under this directory",
    )
    parser.add_argument(
        "--receipt",
        required=True,
        type=Path,
        help="Output receipt JSON path (must be <gate_name>.receipt.json)",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root for release_source_digest binding",
    )
    parser.add_argument(
        "--cwd",
        type=Path,
        default=None,
        help="Working directory for the wrapped command (must equal repo root)",
    )
    parser.add_argument(
        "--stdout",
        type=Path,
        default=None,
        help="Stdout capture path (must equal <evidence-dir>/gates/<gate>.stdout.txt)",
    )
    parser.add_argument(
        "--stderr",
        type=Path,
        default=None,
        help="Stderr capture path (must equal <evidence-dir>/gates/<gate>.stderr.txt)",
    )
    parser.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        help="Command argv after '--' (required)",
    )
    args = parser.parse_args()
    argv = list(args.argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        parser.error("missing command argv after '--'")

    receipt = run_local_gate_receipt(
        gate_name=args.gate_name,
        argv=argv,
        receipt_path=args.receipt,
        repo_root=args.repo_root,
        evidence_dir=args.evidence_dir,
        cwd=args.cwd,
        stdout_path=args.stdout,
        stderr_path=args.stderr,
    )
    if receipt.get("source_drift"):
        print(
            f"source drift detected for gate {args.gate_name!r}; receipt marked passed=false",
            file=sys.stderr,
        )
        return 2
    return int(receipt["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())

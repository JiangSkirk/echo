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
    MANIFEST_NAME,
    PrivacyHit,
    format_privacy_hits,
    redact_text,
    verify_manifest_v2,
)

DIGEST = "c" * 64


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
    with tarfile.open(sdist, "w:gz") as archive:
        info = tarfile.TarInfo("demo/__init__.py")
        info.size = len(sdist_content)
        archive.addfile(info, io.BytesIO(sdist_content))
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

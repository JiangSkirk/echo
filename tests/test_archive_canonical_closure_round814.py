from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import traceback
import zipfile
from pathlib import Path

import pytest

from js.echo.ledger.evidence_export import (
    ARCHIVE_SCAN_RECEIPT_NAME,
    ARCHIVE_SCAN_RULE_VERSION,
    build_sanitized_export,
    scan_archive_members,
    verify_archive_scan_receipt,
    write_archive_scan_receipt,
)

DIGEST = "d" * 64


@pytest.fixture(autouse=True)
def _formal_validator_for_export_mechanics(monkeypatch: pytest.MonkeyPatch) -> None:
    import js.echo.ledger.release_gates as release_gates

    report = release_gates.FinalLocalGateEvidenceReport(
        all_local_gates_passed=False,
        passed_gates=("ruff",),
        blockers=("remaining_required_gates_not_seeded",),
        product_internal_ready=False,
    )
    monkeypatch.setattr(release_gates, "release_source_digest", lambda _root: DIGEST)
    monkeypatch.setattr(
        release_gates, "validate_final_local_gate_evidence", lambda *_a, **_k: report
    )


def _make_archive(path: Path, *, content: str = "clean\n") -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.name.lower().endswith(".whl"):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("demo/data.txt", content)
    else:
        payload = content.encode("utf-8")
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo("demo/data.txt")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        path.write_bytes(stream.getvalue())
    return path.read_bytes()


def _write_e2e(path: Path, artifacts: dict[str, bytes]) -> Path:
    declared = {
        ("wheel" if relative.endswith(".whl") else "sdist"): {
            "path": relative,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        for relative, payload in sorted(artifacts.items())
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"ok": True, "artifacts": declared}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _forge_zero_hit_receipt(export: Path, artifacts: dict[str, bytes]) -> None:
    payload = {
        "schema_version": "js-agent-archive-scan-receipt-v1",
        "rule_version": ARCHIVE_SCAN_RULE_VERSION,
        "source_digest": DIGEST,
        "artifacts": [
            {
                "relative_path": relative,
                "filename": Path(relative).name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for relative, data in sorted(artifacts.items())
        ],
        "hit_count": 0,
        "hits": [],
        "ok": True,
        "generated_utc": "2026-07-26T00:00:00Z",
    }
    (export / ARCHIVE_SCAN_RECEIPT_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _exception_tree_text(exc: BaseException) -> str:
    rendered: list[str] = []
    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        rendered.append(
            "".join(traceback.format_exception(type(current), current, current.__traceback__))
        )
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return "\n".join(rendered)


def _seed_final_gate(evidence: Path) -> None:
    (evidence / "final").mkdir(parents=True)
    (evidence / "gates").mkdir(parents=True)
    body = "All checks passed!\n"
    (evidence / "gates" / "ruff.stdout.txt").write_text(body, encoding="utf-8")
    (evidence / "gates" / "ruff.stderr.txt").write_text("", encoding="utf-8")
    receipt = {
        "gate_name": "ruff",
        "stdout_path": "<EVIDENCE_ROOT>/gates/ruff.stdout.txt",
        "stderr_path": "<EVIDENCE_ROOT>/gates/ruff.stderr.txt",
        "stdout_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "source_digest_before": DIGEST,
        "source_digest_after": DIGEST,
        "exit_code": 0,
        "output_parse": {
            "parser": "ruff",
            "require_exit_code_zero": True,
            "stderr_must_be_empty": False,
        },
        "parse_result": {"parser": "ruff", "ok": True},
        "passed": True,
    }
    (evidence / "final" / "ruff.receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence / "TOOLCHAIN.lock.json").write_text("{}\n", encoding="utf-8")


@pytest.mark.parametrize("name", ["leaky.WHL", "leaky.TAR.GZ", "clean.WhL", "clean.Tar.Gz"])
def test_mixed_case_suspect_archive_never_scans_as_clean(tmp_path: Path, name: str) -> None:
    private_home = "/Users/round814-private-home"
    archive = tmp_path / name
    _make_archive(archive, content=f"home={private_home}\n")

    with pytest.raises(RuntimeError, match="canonical|lowercase") as caught:
        scan_archive_members(archive, current_home=private_home)

    message = str(caught.value)
    assert private_home not in message
    assert str(tmp_path) not in message


def test_receipt_builder_rejects_mixed_case_archive(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _make_archive(export / "e2e" / "artifacts" / "clean.WhL")

    with pytest.raises(RuntimeError, match="canonical|lowercase"):
        write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])


def test_verifier_rejects_mixed_case_archive_with_matching_receipt(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    relative = "e2e/artifacts/clean.Tar.Gz"
    payload = _make_archive(export / relative)
    artifacts = {relative: payload}
    _forge_zero_hit_receipt(export, artifacts)
    e2e = _write_e2e(export / "e2e" / "ECHO_ISOLATED_VENV_E2E.json", artifacts)

    with pytest.raises(RuntimeError, match="canonical|lowercase"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


@pytest.mark.parametrize("name", ["broken.whl", "broken.tar.gz"])
def test_corrupted_canonical_archive_fails_closed(tmp_path: Path, name: str) -> None:
    export = tmp_path / "sanitized-export"
    relative = f"e2e/artifacts/{name}"
    archive = export / relative
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"not-an-archive")
    counterpart = (
        "e2e/artifacts/valid.tar.gz" if name.endswith(".whl") else "e2e/artifacts/valid.whl"
    )
    artifacts = {
        relative: archive.read_bytes(),
        counterpart: _make_archive(export / counterpart),
    }
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    e2e = _write_e2e(export / "e2e" / "ECHO_ISOLATED_VENV_E2E.json", artifacts)

    with pytest.raises(RuntimeError, match="archive scan|unreadable|hit"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


@pytest.mark.parametrize("invalid_kind", ["missing", "directory", "symlink"])
def test_explicit_nonregular_e2e_path_cannot_disable_closure(
    tmp_path: Path, invalid_kind: str
) -> None:
    export = tmp_path / "sanitized-export"
    relative = "e2e/artifacts/demo.whl"
    payload = _make_archive(export / relative)
    artifacts = {relative: payload}
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])

    private_dir = tmp_path / "round814-private-path-marker"
    private_dir.mkdir()
    e2e = private_dir / "ECHO_ISOLATED_VENV_E2E.json"
    if invalid_kind == "directory":
        e2e.mkdir()
    elif invalid_kind == "symlink":
        target = _write_e2e(private_dir / "target.json", artifacts)
        os.symlink(target, e2e)

    with pytest.raises(RuntimeError, match="e2e artifact JSON") as caught:
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)

    assert str(private_dir) not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not-json\n",
        b"{}\n",
        b'{"artifacts": {}}\n',
        b'{"ok": false, "artifacts": {}}\n',
        b'{"ok": true}\n',
        b'{"ok": true, "artifacts": {}}\n',
        b'{"ok": true, "artifacts": null}\n',
        b'{"ok": true, "artifacts": []}\n',
    ],
)
def test_invalid_or_empty_e2e_declaration_fails_closed(tmp_path: Path, content: bytes) -> None:
    export = tmp_path / "sanitized-export"
    export.mkdir()
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    e2e = tmp_path / "ECHO_ISOLATED_VENV_E2E.json"
    e2e.write_bytes(content)

    with pytest.raises(RuntimeError, match="e2e artifact JSON|declaration"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_e2e_declaration_requires_wheel_and_sdist_roles(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    relative = "e2e/artifacts/demo.whl"
    payload = _make_archive(export / relative)
    artifacts = {relative: payload}
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    e2e = _write_e2e(export / "e2e" / "ECHO_ISOLATED_VENV_E2E.json", artifacts)

    with pytest.raises(RuntimeError, match="declaration|artifact"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


@pytest.mark.parametrize(
    "declared_path",
    [
        "/Users/round814-private-declaration/demo.whl",
        "e2e/artifacts/../round814-private-declaration/demo.whl",
        "round814-private-declaration/demo.whl",
    ],
)
def test_untrusted_e2e_artifact_path_never_leaks(
    tmp_path: Path, declared_path: str, capsys
) -> None:
    export = tmp_path / "sanitized-export"
    wheel_relative = "e2e/artifacts/demo.whl"
    sdist_relative = "e2e/artifacts/demo.tar.gz"
    wheel = _make_archive(export / wheel_relative)
    sdist = _make_archive(export / sdist_relative)
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    e2e = export / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
    e2e.write_text(
        json.dumps(
            {
                "ok": True,
                "artifacts": {
                    "wheel": {
                        "path": declared_path,
                        "bytes": len(wheel),
                        "sha256": hashlib.sha256(wheel).hexdigest(),
                    },
                    "sdist": {
                        "path": sdist_relative,
                        "bytes": len(sdist),
                        "sha256": hashlib.sha256(sdist).hexdigest(),
                    },
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="declaration|closure") as caught:
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)

    private_marker = "round814-private-declaration"
    assert private_marker not in _exception_tree_text(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    captured = capsys.readouterr()
    assert private_marker not in captured.out
    assert private_marker not in captured.err
    assert private_marker not in (export / ARCHIVE_SCAN_RECEIPT_NAME).read_text(encoding="utf-8")


def test_final_builder_rejects_missing_artifacts_declaration(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_final_gate(evidence)
    (evidence / "e2e").mkdir()
    (evidence / "e2e" / "ECHO_ISOLATED_VENV_E2E.json").write_text(
        json.dumps({"ok": True}) + "\n", encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="declaration|artifact"):
        build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff",),
        )


def test_exact_lowercase_wheel_and_sdist_declaration_passes(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    artifacts = {
        "e2e/artifacts/demo.whl": _make_archive(export / "e2e/artifacts/demo.whl"),
        "e2e/artifacts/demo.tar.gz": _make_archive(export / "e2e/artifacts/demo.tar.gz"),
    }
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    e2e = _write_e2e(export / "e2e" / "ECHO_ISOLATED_VENV_E2E.json", artifacts)

    verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)

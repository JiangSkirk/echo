from __future__ import annotations

import errno
import hashlib
import io
import json
import multiprocessing
import os
import socket
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

import js.echo.ledger.evidence_export as evidence_export
from js.echo.ledger.evidence_export import (
    MANIFEST_NAME,
    build_sanitized_export,
    verify_manifest_v2,
)

DIGEST = "e" * 64


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


def _open_fd_count() -> int:
    fd_root = "/proc/self/fd" if Path("/proc/self/fd").is_dir() else "/dev/fd"
    return len(os.listdir(fd_root))


def _canonical_json_sha256(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _seed_evidence(root: Path) -> None:
    (root / "final").mkdir(parents=True)
    (root / "gates").mkdir(parents=True)
    stdout = "All checks passed!\n"
    (root / "gates" / "ruff.stdout.txt").write_text(stdout, encoding="utf-8")
    (root / "gates" / "ruff.stderr.txt").write_text("", encoding="utf-8")
    receipt = {
        "gate_name": "ruff",
        "passed": True,
        "stdout_path": "<EVIDENCE_ROOT>/gates/ruff.stdout.txt",
        "stderr_path": "<EVIDENCE_ROOT>/gates/ruff.stderr.txt",
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
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
    }
    (root / "final" / "ruff.receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    artifacts_dir = root / "e2e" / "artifacts"
    artifacts_dir.mkdir(parents=True)
    wheel = artifacts_dir / "demo-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "x = 1\n")
    sdist = artifacts_dir / "demo-0.0.1.tar.gz"
    sdist_contents = b"x = 1\n"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        info = tarfile.TarInfo("demo/__init__.py")
        info.size = len(sdist_contents)
        archive.addfile(info, io.BytesIO(sdist_contents))
    sdist.write_bytes(stream.getvalue())
    wheel_bytes = wheel.read_bytes()
    sdist_bytes = sdist.read_bytes()
    (root / "e2e" / "ECHO_ISOLATED_VENV_E2E.json").write_text(
        json.dumps(
            {
                "ok": True,
                "artifacts": {
                    "wheel": {
                        "path": "e2e/artifacts/demo-0.0.1-py3-none-any.whl",
                        "bytes": len(wheel_bytes),
                        "sha256": hashlib.sha256(wheel_bytes).hexdigest(),
                    },
                    "sdist": {
                        "path": "e2e/artifacts/demo-0.0.1.tar.gz",
                        "bytes": len(sdist_bytes),
                        "sha256": hashlib.sha256(sdist_bytes).hexdigest(),
                    },
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    inputs = {
        "schema_version": "js-agent-final-gate-inputs-v1",
        "artifacts": {
            "tokenizer_digest": {
                "path": "validator_inputs/tokenizer.digest.json",
                "present": True,
            },
        },
    }
    inputs_dir = root / "validator_inputs"
    inputs_dir.mkdir()
    (inputs_dir / "tokenizer.digest.json").write_text(
        json.dumps(
            {
                "schema_version": "js-agent-tokenizer-digest-evidence-v1",
                "digest_version": "v1",
                "tokenizer_resource_sha256": DIGEST,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    summary = {
        "schema_version": "js-agent-gate-run-summary-v2",
        "generated_utc": "2026-07-26T00:00:00Z",
        "source_digest": DIGEST,
        "required_gates": ["ruff"],
        "passed_gates": ["ruff"],
        "blockers": [],
        "all_local_gates_passed": True,
        "validator_inputs": inputs,
    }
    validator = {
        "schema_version": "js-agent-final-validator-receipt-v1",
        "generated_utc": "2026-07-26T00:00:00Z",
        "validator": "validate_final_local_gate_evidence",
        "writer": "generate_final_local_gate_summary",
        "source_digest": DIGEST,
        "gate_run_summary_sha256": _canonical_json_sha256(summary),
        "ok": True,
        "blockers": [],
        "validator_inputs_sha256": _canonical_json_sha256(inputs),
    }
    (root / "gate_run_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "final_validator.receipt.json").write_text(
        json.dumps(validator, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _post_enumeration_fifo_worker(evidence_text: str, repo_text: str, result_queue: object) -> None:
    evidence = Path(evidence_text)
    repo = Path(repo_text)
    member = evidence / "final_validator.receipt.json"
    original_iter = evidence_export._iter_allowlisted_sources

    def enumerate_then_swap(*args: object, **kwargs: object) -> object:
        sources = original_iter(*args, **kwargs)
        member.replace(member.with_name(member.name + ".before-fifo"))
        os.mkfifo(member)
        return sources

    evidence_export._iter_allowlisted_sources = enumerate_then_swap
    try:
        build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff",),
        )
    except RuntimeError as exc:
        result_queue.put(("error", str(exc), exc.__cause__, exc.__context__))
    else:
        result_queue.put(("success", "", None, None))


def test_sanitized_export_manifest_binds_canonical_validator_closure(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_evidence(evidence)

    result = build_sanitized_export(
        evidence_root=evidence,
        repo_root=repo,
        source_digest=DIGEST,
        out_root=evidence,
        required_gates=("ruff",),
    )

    expected = {
        "gate_run_summary.json",
        "final_validator.receipt.json",
        "validator_inputs/tokenizer.digest.json",
    }
    manifest_entries = {
        line.split()[-1]
        for line in (result.export_dir / MANIFEST_NAME).read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    assert expected <= manifest_entries
    assert all((result.export_dir / relative).is_file() for relative in expected)
    verify_manifest_v2(result.export_dir)

    (result.export_dir / "final_validator.receipt.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="sha256|size"):
        verify_manifest_v2(result.export_dir)


@pytest.mark.parametrize(
    "relative",
    [
        "gate_run_summary.json",
        "final_validator.receipt.json",
        "validator_inputs/tokenizer.digest.json",
    ],
)
@pytest.mark.parametrize("target_scope", ["in_tree", "out_of_tree"])
def test_canonical_validator_members_reject_symlink_sources(
    tmp_path: Path, relative: str, target_scope: str
) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_evidence(evidence)
    member = evidence / relative
    member.unlink()
    if target_scope == "in_tree":
        target = evidence / "non_allowlisted_private_target.json"
    else:
        target = tmp_path / "outside-private-target.json"
    target.write_text("not an allowlisted validator artifact\n", encoding="utf-8")
    member.symlink_to(target)

    with pytest.raises(RuntimeError, match="symlink|allowlisted") as caught:
        build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff",),
        )

    assert str(target) not in str(caught.value)
    assert not (evidence / "sanitized-export" / relative).exists()


@pytest.mark.parametrize(
    "relative",
    [
        "gate_run_summary.json",
        "final_validator.receipt.json",
        "validator_inputs/tokenizer.digest.json",
    ],
)
def test_canonical_validator_members_reject_fifo_sources(tmp_path: Path, relative: str) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_evidence(evidence)
    member = evidence / relative
    member.unlink()
    os.mkfifo(member)

    with pytest.raises(RuntimeError, match="non-regular|allowlisted"):
        build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff",),
        )


def test_validator_inputs_directory_symlink_and_socket_reject_without_target_leak(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with tempfile.TemporaryDirectory(prefix="r814-", dir="/tmp") as evidence_dir:
        evidence = Path(evidence_dir)
        _seed_evidence(evidence)
        private_target_dir = tmp_path / "outside-private-validator-inputs"
        private_target_dir.mkdir()
        (evidence / "validator_inputs" / "linked-dir").symlink_to(
            private_target_dir, target_is_directory=True
        )

        with pytest.raises(RuntimeError, match="symlink|allowlisted") as caught:
            build_sanitized_export(
                evidence_root=evidence,
                repo_root=repo,
                source_digest=DIGEST,
                out_root=evidence,
                required_gates=("ruff",),
            )

        assert str(private_target_dir) not in str(caught.value)

        (evidence / "validator_inputs" / "linked-dir").unlink()
        socket_path = evidence / "validator_inputs" / "validator.socket"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(socket_path))
            with pytest.raises(RuntimeError, match="non-regular|allowlisted"):
                build_sanitized_export(
                    evidence_root=evidence,
                    repo_root=repo,
                    source_digest=DIGEST,
                    out_root=evidence,
                    required_gates=("ruff",),
                )
        finally:
            server.close()
            socket_path.unlink(missing_ok=True)


def test_canonical_validator_member_rejects_source_hardlink(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_evidence(evidence)
    member = evidence / "gate_run_summary.json"
    source = evidence / "non_allowlisted_validator_summary.json"
    member.replace(source)
    os.link(source, member)

    with pytest.raises(RuntimeError, match="hardlink|allowlisted"):
        build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff",),
        )


@pytest.mark.parametrize("kind", ["empty_directory_symlink", "regular_file"])
def test_empty_validator_inputs_ancestor_must_be_a_real_directory(
    tmp_path: Path, kind: str
) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_evidence(evidence)
    inputs = evidence / "validator_inputs"
    (inputs / "tokenizer.digest.json").unlink()
    inputs.rmdir()
    private_target = tmp_path / "outside-private-empty-inputs"
    if kind == "empty_directory_symlink":
        private_target.mkdir()
        inputs.symlink_to(private_target, target_is_directory=True)
    else:
        inputs.write_text("not a validator inputs directory\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="validator_inputs|allowlisted|directory") as caught:
        build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff",),
        )

    assert str(private_target) not in str(caught.value)


@pytest.mark.parametrize(
    "relative",
    ["final_validator.receipt.json", "validator_inputs/tokenizer.digest.json"],
)
@pytest.mark.parametrize("replacement", ["symlink", "regular_file"])
def test_allowlisted_copy_rejects_post_enumeration_source_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str, replacement: str
) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_evidence(evidence)
    member = evidence / relative
    private_target = tmp_path / "outside-private-swap.json"
    marker = "round814-private-source-swap-marker"
    private_target.write_text(marker + "\n", encoding="utf-8")
    original_iter = evidence_export._iter_allowlisted_sources
    swapped = False

    def enumerate_then_swap(*args: object, **kwargs: object) -> object:
        nonlocal swapped
        result = original_iter(*args, **kwargs)
        if not swapped:
            swapped = True
            member.replace(member.with_name(member.name + ".before-swap"))
            if replacement == "symlink":
                member.symlink_to(private_target)
            else:
                private_target.replace(member)
        return result

    monkeypatch.setattr(evidence_export, "_iter_allowlisted_sources", enumerate_then_swap)

    with pytest.raises(RuntimeError, match="identity|source|unreadable|symlink") as caught:
        build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff",),
        )

    assert marker not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    export = evidence / "sanitized-export"
    assert all(
        marker.encode("utf-8") not in path.read_bytes()
        for path in export.rglob("*")
        if path.is_file()
    )


@pytest.mark.parametrize("replacement", ["empty_symlink", "empty_directory"])
def test_validator_inputs_swap_after_validation_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str
) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_evidence(evidence)
    inputs = evidence / "validator_inputs"
    private_target = tmp_path / "outside-private-replacement-inputs"
    original_validate = evidence_export._validate_validator_inputs_ancestor
    original_dup = evidence_export.os.dup
    original_close = evidence_export.os.close
    held_validator_inputs_fd: int | None = None
    duplicated_parent_fds: list[int] = []
    duplicate_close_counts: dict[int, int] = {}

    def tracking_dup(fd: int) -> int:
        duplicated = original_dup(fd)
        if fd == held_validator_inputs_fd:
            duplicated_parent_fds.append(duplicated)
        return duplicated

    def tracking_close(fd: int) -> None:
        if fd in duplicated_parent_fds:
            duplicate_close_counts[fd] = duplicate_close_counts.get(fd, 0) + 1
        original_close(fd)

    def validate_then_replace(root_fd: int) -> tuple[int, tuple[int, int]] | None:
        nonlocal held_validator_inputs_fd
        result = original_validate(root_fd)
        assert result is not None
        held_validator_inputs_fd = result[0]
        inputs.replace(inputs.with_name("validator_inputs.before-replacement"))
        private_target.mkdir()
        if replacement == "empty_symlink":
            inputs.symlink_to(private_target, target_is_directory=True)
        else:
            private_target.replace(inputs)
        return result

    monkeypatch.setattr(
        evidence_export, "_validate_validator_inputs_ancestor", validate_then_replace
    )
    monkeypatch.setattr(evidence_export.os, "dup", tracking_dup)
    monkeypatch.setattr(evidence_export.os, "close", tracking_close)

    baseline_fd_count = _open_fd_count()
    with pytest.raises(RuntimeError, match="validator_inputs|identity|source|unreadable") as caught:
        build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=DIGEST,
            out_root=evidence,
            required_gates=("ruff",),
        )

    assert len(duplicated_parent_fds) == 1
    duplicated_parent_fd = duplicated_parent_fds[0]
    assert duplicate_close_counts.get(duplicated_parent_fd, 0) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(duplicated_parent_fd)
    assert closed.value.errno == errno.EBADF
    assert _open_fd_count() == baseline_fd_count
    assert str(private_target) not in str(caught.value)
    assert not (
        evidence / "sanitized-export" / "validator_inputs" / "tokenizer.digest.json"
    ).exists()


def test_post_enumeration_fifo_source_swap_fails_without_blocking(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_evidence(evidence)
    context = multiprocessing.get_context("fork")
    result_queue = context.Queue()
    process = context.Process(
        target=_post_enumeration_fifo_worker,
        args=(str(evidence), str(repo), result_queue),
    )
    process.start()
    process.join(timeout=5)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
        pytest.fail("allowlisted FIFO replacement blocked the export")
    assert process.exitcode == 0
    status, message, cause, context_error = result_queue.get(timeout=1)
    assert status == "error"
    assert "fifo" not in message.lower()
    assert cause is None
    assert context_error is None
    assert not (evidence / "sanitized-export" / "final_validator.receipt.json").exists()

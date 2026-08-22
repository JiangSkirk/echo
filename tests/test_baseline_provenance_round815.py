"""PT-006 baseline provenance must be measured from a clean detached export."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks import old_architecture_baseline as baseline

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_baseline_disables_project_bytecode_writes_before_measurement() -> None:
    """Importing the measured export must not make its own release surface dirty."""
    assert baseline.sys.dont_write_bytecode is True


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _clean_detached_archive_export(tmp_path: Path) -> tuple[Path, str]:
    """Create a detached committed-tree export without adding current harness bytes."""
    archive = tmp_path / "baseline.tar"
    with archive.open("wb") as stream:
        subprocess.run(
            ["git", "archive", "--format=tar", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            stdout=stream,
        )
    export = tmp_path / "export"
    export.mkdir()
    with tarfile.open(archive) as contents:
        contents.extractall(export, filter="data")

    _git(export, "init", "--quiet")
    _git(export, "config", "user.email", "baseline-provenance@example.invalid")
    _git(export, "config", "user.name", "Baseline Provenance Test")
    _git(export, "add", "--all", "--force")
    _git(export, "commit", "--quiet", "-m", "clean archive export")
    commit = _git(export, "rev-parse", "--verify", "HEAD^{commit}")
    # Detach without a checkout: the working tree already contains this commit.
    _git(export, "update-ref", "--no-deref", "HEAD", commit)
    assert (
        subprocess.run(
            ["git", "symbolic-ref", "--quiet", "HEAD"], cwd=export, check=False
        ).returncode
        != 0
    )
    return export, commit


def _detached_clone_at_old_commit(tmp_path: Path) -> tuple[Path, str]:
    """Clone the old commit into a temp worktree; never mutate the live checkout."""
    measured = tmp_path / "measured-old"
    subprocess.run(
        ["git", "clone", "--no-local", "--quiet", str(REPO_ROOT), str(measured)],
        check=True,
    )
    commit = _git(
        measured,
        "rev-parse",
        "--verify",
        "65cc545e3ec893f5bab62d356514643f14456a58^{commit}",
    )
    # Materialize the old tree so worktree bytes match HEAD^{tree}.
    _git(measured, "checkout", "--quiet", "--detach", commit)
    assert (
        subprocess.run(
            ["git", "symbolic-ref", "--quiet", "HEAD"], cwd=measured, check=False
        ).returncode
        != 0
    )
    return measured, commit


def test_free_form_commit_label_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A caller must not be able to record an arbitrary revision as the baseline commit."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "old_architecture_baseline.py",
            "--commit",
            "f" * 40,
            "--output",
            str(tmp_path / "baseline.json"),
        ],
    )

    with pytest.raises(SystemExit) as rejected:
        baseline.parse_args()

    assert rejected.value.code == 2


def test_external_harness_measures_untouched_old_commit_without_copying_itself(
    tmp_path: Path,
) -> None:
    """The trusted current harness must execute against the unchanged detached old tree."""
    measured, commit = _detached_clone_at_old_commit(tmp_path)
    output = tmp_path / "old-baseline.json"
    harness = REPO_ROOT / "benchmarks" / "old_architecture_baseline.py"
    assert not (measured / "benchmarks" / "old_architecture_baseline.py").exists()
    assert not (measured / "resources" / "tokenizer").exists()

    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [
            sys.executable,
            str(harness),
            "--measured-root",
            str(measured),
            "--expected-commit",
            commit,
            "--iterations",
            "1",
            "--warmup",
            "0",
            "--runs",
            "1",
            "--output",
            str(output),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    receipt = json.loads(output.read_text(encoding="utf-8"))
    assert receipt["commit"] == commit
    assert receipt["tree"] == _git(measured, "rev-parse", "--verify", "HEAD^{tree}")
    assert receipt["import_root"] == str((measured / "js" / "__init__.py").resolve())
    assert receipt["provenance"]["measured_root"] == str(measured.resolve())
    assert receipt["provenance"]["harness_root"] == str(REPO_ROOT.resolve())
    assert receipt["provenance"]["workload"]["history_message_count"] == 40
    assert (
        receipt["run_summaries"][0]["long_provider_payload_evidence"][0]["history_marker_count"]
        == 40
    )
    assert receipt["failures"] == []


def test_measured_provenance_rejects_dirty_untracked_release_surface(tmp_path: Path) -> None:
    """An untracked Python file in ``js/`` must block a baseline measurement."""
    export, commit = _clean_detached_archive_export(tmp_path)
    (export / "js" / "untracked_release_surface.py").write_text("VALUE = 1\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="untracked.*js/untracked_release_surface.py"):
        baseline.measured_export_provenance(export, expected_commit=commit)


def test_measured_provenance_rejects_untracked_file_outside_release_surfaces(
    tmp_path: Path,
) -> None:
    """Clean means the entire measured tree, not only the current release-surface list."""
    export, commit = _clean_detached_archive_export(tmp_path)
    (export / "private-note.txt").write_text("untracked\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="untracked.*private-note.txt"):
        baseline.measured_export_provenance(export, expected_commit=commit)


def test_measured_provenance_rejects_clean_tracked_symlink(tmp_path: Path) -> None:
    """A symlink in the measured Git tree must fail even when status is clean."""
    export, _commit = _clean_detached_archive_export(tmp_path)
    (export / "uv-link").symlink_to("uv.lock")
    _git(export, "add", "uv-link")
    _git(export, "commit", "--quiet", "-m", "add symlink")
    commit = _git(export, "rev-parse", "--verify", "HEAD^{commit}")

    with pytest.raises(RuntimeError, match="symlink.*uv-link"):
        baseline.measured_export_provenance(export, expected_commit=commit)


def test_measured_provenance_records_actual_tree_source_and_runtime_inputs(tmp_path: Path) -> None:
    """The receipt must bind the measured tree, bytes, tokenizer, and runtime identity."""
    export, commit = _clean_detached_archive_export(tmp_path)

    receipt = baseline.measured_export_provenance(export, expected_commit=commit)

    assert receipt["commit"] == commit
    assert receipt["tree"] == _git(export, "rev-parse", "--verify", "HEAD^{tree}")
    assert receipt["source_digest"] == baseline.release_source_digest(export)
    assert (
        receipt["uv_lock_sha256"] == hashlib.sha256((export / "uv.lock").read_bytes()).hexdigest()
    )
    assert (
        receipt["baseline_script_sha256"]
        == hashlib.sha256(
            (REPO_ROOT / "benchmarks" / "old_architecture_baseline.py").read_bytes()
        ).hexdigest()
    )
    assert receipt["measured_root"] == str(export.resolve())
    assert receipt["harness_root"] == str(REPO_ROOT.resolve())
    assert receipt["workload"]["history_message_count"] == 40
    assert receipt["workload"]["corpus_sha256"]
    assert receipt["tokenizer"]["method"] == baseline.TOKENIZER_METHOD
    assert receipt["tokenizer"]["resource_tree_sha256"] == baseline.tokenizer_resource_digest(
        REPO_ROOT
    )
    assert receipt["interpreter"]["implementation"]
    assert receipt["interpreter"]["executable_sha256"]
    assert receipt["platform"]["identity"]
    assert receipt["platform"]["identity_sha256"]


def test_measured_provenance_rejects_a_different_expected_commit(tmp_path: Path) -> None:
    """The optional expected revision is a check, never a label."""
    export, _commit = _clean_detached_archive_export(tmp_path)

    with pytest.raises(RuntimeError, match="expected commit"):
        baseline.measured_export_provenance(export, expected_commit="0" * 40)


def test_import_origin_check_rejects_any_measured_js_module_escape(tmp_path: Path) -> None:
    """One escaped ``js.*`` module invalidates the measured runtime provenance."""
    measured = tmp_path / "measured"
    (measured / "js").mkdir(parents=True)
    (measured / "js" / "__init__.py").write_text("", encoding="utf-8")
    inside = SimpleNamespace(__name__="js", __file__=str(measured / "js" / "__init__.py"))
    escaped = SimpleNamespace(__name__="js.config", __file__=str(REPO_ROOT / "js/config.py"))

    with pytest.raises(RuntimeError, match="import escaped measured root.*js.config"):
        baseline.require_measured_module_origins(measured, [inside, escaped])

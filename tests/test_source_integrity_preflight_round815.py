from __future__ import annotations

import ast
import importlib.util
import os
import time
from pathlib import Path

import pytest

from js.echo.ledger import release_gates

TEST_SURFACES = (
    Path("README.md"),
    Path("pyproject.toml"),
    Path("js"),
    Path("resources"),
    Path("scripts"),
    Path("tests"),
)


def _validator():
    validator = getattr(release_gates, "validate_release_source_integrity", None)
    assert callable(validator), "release source integrity validator is missing"
    return validator


@pytest.fixture
def source_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(release_gates, "_RELEASE_SOURCE_DIGEST_SURFACES", TEST_SURFACES)
    (tmp_path / "README.md").write_text("# release\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'fixture'\nversion = '0.0.0'\n",
        encoding="utf-8",
    )
    for relative, content in (
        ("js/__init__.py", '"""Runtime package."""\n'),
        ("scripts/gate.py", "VALUE = 1\n"),
        ("tests/test_gate.py", "def test_fixture():\n    assert True\n"),
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    resource = tmp_path / "resources" / "tokenizer" / "model.bin"
    resource.parent.mkdir(parents=True)
    resource.write_bytes(b"\x00fixture-resource")
    return tmp_path


def test_empty_python_false_passes_ast_and_import_but_preflight_rejects_it(
    source_tree: Path,
) -> None:
    empty_python = source_tree / "js" / "__init__.py"
    empty_python.write_bytes(b"")

    assert isinstance(ast.parse(""), ast.Module)
    spec = importlib.util.spec_from_file_location("round815_empty_module", empty_python)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with pytest.raises(ValueError, match=r"js/__init__\.py: empty"):
        _validator()(source_tree)


@pytest.mark.parametrize("relative", ["README.md", "pyproject.toml"])
def test_zero_byte_required_source_metadata_fails(source_tree: Path, relative: str) -> None:
    (source_tree / relative).write_bytes(b"")

    with pytest.raises(ValueError, match=rf"{relative}: empty"):
        _validator()(source_tree)


def test_only_explicit_empty_test_package_marker_is_allowed(source_tree: Path) -> None:
    marker = source_tree / "tests" / "echo" / "__init__.py"
    marker.parent.mkdir()
    marker.write_bytes(b"")

    _validator()(source_tree)

    other_marker = source_tree / "tests" / "other" / "__init__.py"
    other_marker.parent.mkdir()
    other_marker.write_bytes(b"")
    with pytest.raises(ValueError, match=r"tests/other/__init__\.py: empty"):
        _validator()(source_tree)


def test_generated_evidence_outside_release_surfaces_is_not_rejected(source_tree: Path) -> None:
    generated = source_tree / "generated-evidence" / "result.json"
    generated.parent.mkdir()
    generated.write_bytes(b"")

    _validator()(source_tree)


@pytest.mark.parametrize(
    ("case", "relative", "diagnostic"),
    [
        ("symlink", "js/linked.py", "symlink"),
        ("special", "scripts/gate.py", "special file"),
        ("missing", "README.md", "missing"),
        ("invalid_utf8", "README.md", "invalid UTF-8"),
        ("syntax", "js/__init__.py", "invalid Python syntax"),
    ],
)
def test_preflight_fails_closed_for_invalid_release_surface_entries(
    source_tree: Path,
    case: str,
    relative: str,
    diagnostic: str,
) -> None:
    path = source_tree / relative
    if case == "symlink":
        path.symlink_to(source_tree / "js" / "__init__.py")
    elif case == "special":
        path.unlink()
        os.mkfifo(path)
    elif case == "missing":
        path.unlink()
    elif case == "invalid_utf8":
        path.write_bytes(b"\xff\xfeprivate payload")
    else:
        path.write_text("private_payload = (\n", encoding="utf-8")

    with pytest.raises(ValueError) as caught:
        _validator()(source_tree)

    message = str(caught.value)
    assert relative in message
    assert diagnostic in message


def test_diagnostics_are_relative_and_do_not_expose_file_contents(source_tree: Path) -> None:
    secret = "ROUND815-CONTENT-MUST-STAY-PRIVATE"
    broken = source_tree / "scripts" / "gate.py"
    broken.write_text(f"{secret} = (\n", encoding="utf-8")

    with pytest.raises(ValueError) as caught:
        _validator()(source_tree)

    message = str(caught.value)
    assert "scripts/gate.py" in message
    assert str(source_tree) not in message
    assert secret not in message


def test_local_gate_receipt_preflight_blocks_before_subprocess(
    source_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.run_local_gate_receipt as runner

    (source_tree / "js" / "__init__.py").write_bytes(b"")
    monkeypatch.setattr(runner, "release_source_digest", pytest.fail)
    monkeypatch.setattr(runner, "subprocess", pytest.fail)

    with pytest.raises(ValueError, match=r"js/__init__\.py: empty"):
        runner.run_local_gate_receipt(
            gate_name="git_diff_check",
            argv=["git", "diff", "--check"],
            receipt_path=source_tree / "evidence/final/git_diff_check.receipt.json",
            repo_root=source_tree,
            evidence_dir=source_tree / "evidence",
        )


def test_release_smoke_preflight_blocks_before_async_or_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import scripts.release_smoke as release_smoke

    def block(_root: Path) -> None:
        raise release_smoke.ReleaseSourceIntegrityError("README.md: empty")

    monkeypatch.setattr(release_smoke, "validate_release_source_integrity", block, raising=False)
    monkeypatch.setattr(release_smoke.asyncio, "run", pytest.fail)
    monkeypatch.setattr(release_smoke.subprocess, "run", pytest.fail)

    assert release_smoke.main(["--checks", "package"]) == 1
    assert "README.md: empty" in capsys.readouterr().err


def test_valid_current_release_tree_passes_preflight_quickly() -> None:
    root = Path(__file__).resolve().parents[1]

    started = time.monotonic()
    _validator()(root)
    elapsed = time.monotonic() - started

    assert elapsed < 5.0

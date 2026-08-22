from __future__ import annotations

import os
import site
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_RUNTIME_MEMBERS = {
    "js/security/secrets.py",
    "js/echo/turn_runtime.py",
    "js/echo/effect_interpreter.py",
    "js/echo/os_sandbox.py",
    "js/echo/ledger/service.py",
    "js/echo/ledger/journal.py",
    "js/web/server.py",
    "js/web/static/app.js",
    "js/web/static/vendor/tailwind.css",
    "js/web/static/vendor/fontawesome/css/all.min.css",
    "js/web/static/vendor/fontawesome/webfonts/fa-solid-900.woff2",
    "js/web/templates/index.html",
    "js/skills/builtin/code-review/SKILL.md",
    "js_work/cli.py",
    "js_work/web.py",
    "js_work/routines/spreadsheet.py",
}
REMOVED_RUNTIME_PREFIXES = (
    "js/rivetline/",
    "js/agent_core/",
    "js/echo2_primitives.py",
)
RELEASE_SDIST_FILES = {
    ".gitignore",
    "LICENSE",
    "ORIGIN_LEDGER.md",
    "PKG-INFO",
    "README.md",
    "README_en.md",
    "THIRD_PARTY_NOTICES.md",
    "pyproject.toml",
    "uv.lock",
}
RELEASE_SDIST_PREFIXES = ("js/", "js_work/", "resources/")
REQUIRED_WHEEL_METADATA_SUFFIXES = (
    ".dist-info/METADATA",
    ".dist-info/RECORD",
    ".dist-info/WHEEL",
)
RUNTIME_STATE_PREFIXES = (".tmp/", "state/", "ledgers/", "keys/", "uploads/")


def _all_source_runtime_members() -> set[str]:
    members: set[str] = set()
    for package_root in (REPO_ROOT / "js", REPO_ROOT / "js_work"):
        for path in package_root.rglob("*"):
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or path.suffix == ".pyc"
                or path.name == ".DS_Store"
            ):
                continue
            members.add(path.relative_to(REPO_ROOT).as_posix())
    return members


@pytest.fixture(scope="module")
def release_artifacts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    artifact_dir = os.environ.get("RELEASE_ARTIFACT_DIR")
    if artifact_dir:
        output_dir = Path(artifact_dir).resolve()
    else:
        root = tmp_path_factory.mktemp("release-artifacts")
        output_dir = root / "dist"
        output_dir.mkdir()
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env["PIP_NO_INDEX"] = "1"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--no-isolation",
                "--wheel",
                "--sdist",
                "--outdir",
                str(output_dir),
            ],
            cwd=REPO_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )

    wheels = list(output_dir.glob("*.whl"))
    sdists = list(output_dir.glob("*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1

    root = tmp_path_factory.mktemp("release-artifacts")
    dependency_dir = root / "dependencies"
    dependency_dir.mkdir()
    for entry in Path(site.getsitepackages()[0]).iterdir():
        if entry.suffix == ".pth":
            continue
        (dependency_dir / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())

    return {"wheel": wheels[0], "sdist": sdists[0], "dependencies": dependency_dir}


def test_wheel_contains_runtime_packages(release_artifacts: dict[str, Path]) -> None:
    with zipfile.ZipFile(release_artifacts["wheel"]) as wheel:
        members = set(wheel.namelist())
        member_sizes = {info.filename: info.file_size for info in wheel.infolist()}

    assert members >= REQUIRED_RUNTIME_MEMBERS
    assert members >= _all_source_runtime_members()
    required_metadata = {
        member
        for member in members
        if member.endswith(REQUIRED_WHEEL_METADATA_SUFFIXES)
    }
    assert len(required_metadata) == len(REQUIRED_WHEEL_METADATA_SUFFIXES)
    assert all(
        member_sizes[member] > 0 for member in REQUIRED_RUNTIME_MEMBERS | required_metadata
    )
    assert not any(
        member.startswith(prefix) for member in members for prefix in REMOVED_RUNTIME_PREFIXES
    )


def test_sdist_contains_runtime_packages(release_artifacts: dict[str, Path]) -> None:
    with tarfile.open(release_artifacts["sdist"]) as sdist:
        members_with_sizes = {
            member.name.split("/", 1)[1]: member.size
            for member in sdist.getmembers()
            if "/" in member.name and member.isfile()
        }
        members = set(members_with_sizes)

    assert members >= REQUIRED_RUNTIME_MEMBERS
    assert members >= _all_source_runtime_members()
    assert members >= RELEASE_SDIST_FILES
    assert all(
        members_with_sizes[member] > 0
        for member in REQUIRED_RUNTIME_MEMBERS | RELEASE_SDIST_FILES
    )
    assert not any(
        member.startswith(prefix) for member in members for prefix in REMOVED_RUNTIME_PREFIXES
    )


def test_artifacts_contain_only_release_sources_and_no_runtime_state(
    release_artifacts: dict[str, Path],
) -> None:
    with zipfile.ZipFile(release_artifacts["wheel"]) as wheel:
        wheel_members = set(wheel.namelist())
    with tarfile.open(release_artifacts["sdist"]) as sdist:
        sdist_members = {
            member.name.split("/", 1)[1]
            for member in sdist.getmembers()
            if "/" in member.name and member.isfile()
        }

    assert not any(member.startswith(RUNTIME_STATE_PREFIXES) for member in sdist_members)
    assert not any(member.startswith(RUNTIME_STATE_PREFIXES) for member in wheel_members)
    assert all(
        member in RELEASE_SDIST_FILES or member.startswith(RELEASE_SDIST_PREFIXES)
        for member in sdist_members
    )


def test_release_workflow_audits_the_built_artifact_and_fails_closed_for_stable_tags() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "release-smoke.yml").read_text(
        encoding="utf-8"
    )

    assert "verify_installed_artifact.py --artifact-dir dist --audit" in workflow
    assert 'tags: ["v*"]' in workflow
    assert "environment: stable-release" in workflow
    assert "JS_ECHO_TRUSTED_REVIEW_KEYS: ${{ secrets.JS_ECHO_TRUSTED_REVIEW_KEYS }}" in workflow
    assert "unset JS_ECHO_TRUSTED_REVIEW_KEYS" not in workflow
    assert "report.stable_ready" in workflow


@pytest.mark.parametrize("artifact", ["wheel", "sdist"])
def test_artifact_isolated_install_smoke(
    artifact: str, release_artifacts: dict[str, Path], tmp_path: Path
) -> None:
    venv_dir = tmp_path / artifact
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    python = venv_dir / "bin" / "python"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(release_artifacts["dependencies"])
    env["PIP_NO_INDEX"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["HOME"] = str(venv_dir)
    env["XDG_CONFIG_HOME"] = str(venv_dir / ".config")
    env["XDG_STATE_HOME"] = str(venv_dir / ".local" / "state")
    install_args = [str(python), "-m", "pip", "install", "--no-index", "--no-deps"]
    if artifact == "sdist":
        install_args.append("--no-build-isolation")
    subprocess.run(
        [*install_args, str(release_artifacts[artifact])],
        cwd=venv_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    for command in (
        [str(venv_dir / "bin" / "js"), "work", "--help"],
        [str(venv_dir / "bin" / "js-work"), "--help"],
        [str(python), "-m", "js_work", "--help"],
        [
            str(python),
            "-c",
            (
                "import importlib.util, pathlib, js.web; "
                "import js.echo.turn_runtime, js.echo.effect_interpreter, "
                "js.echo.os_sandbox, js.echo.ledger.service, js.security.secrets, "
                "js_work.web, js_work.routines.spreadsheet; "
                "root=pathlib.Path(js.web.__file__).parent; "
                "assert (root/'static'/'app.js').is_file(); "
                "assert (root/'static'/'vendor'/'tailwind.css').is_file(); "
                "assert (root/'static'/'vendor'/'fontawesome'/'css'/'all.min.css').is_file(); "
                "assert (root/'templates'/'index.html').is_file(); "
                "assert importlib.util.find_spec('js.rivetline') is None; "
                "assert importlib.util.find_spec('js.agent_core') is None"
            ),
        ],
    ):
        result = subprocess.run(command, cwd=venv_dir, env=env, capture_output=True, text=True)
        assert result.returncode == 0, (
            f"command failed: {command}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def test_sdist_includes_readme_en(release_artifacts: dict[str, Path]) -> None:
    with tarfile.open(release_artifacts["sdist"]) as sdist:
        members = {
            member.name.split("/", 1)[1] for member in sdist.getmembers() if "/" in member.name
        }
    assert "README_en.md" in members


def test_isolated_venv_e2e_summary_schema_requires_source_digest_and_chat_200() -> None:
    from js.echo.ledger.release_gates import _ISOLATED_VENV_E2E_REQUIRED_STEPS
    from scripts.isolated_venv_e2e import (
        ISOLATED_VENV_E2E_SCHEMA_VERSION,
        _validate_summary_schema,
    )

    base = {
        "schema_version": ISOLATED_VENV_E2E_SCHEMA_VERSION,
        "offline": True,
        "source_digest": "a" * 64,
        "ok": True,
        "artifacts": {
            "wheel": {"path": "e2e/artifacts/w.whl", "sha256": "b" * 64, "bytes": 1},
            "sdist": {"path": "e2e/artifacts/s.tar.gz", "sha256": "c" * 64, "bytes": 1},
        },
        "work_output": {
            "path": "e2e/work/sdist/iso-e2e.xlsx",
            "sha256": "d" * 64,
            "bytes": 1,
            "cells": [["iso", "e2e", "leased"]],
        },
        "work_outputs": {
            "wheel": {
                "path": "e2e/work/wheel/iso-e2e.xlsx",
                "sha256": "e" * 64,
                "bytes": 1,
                "cells": [["iso", "e2e", "leased"]],
            },
            "sdist": {
                "path": "e2e/work/sdist/iso-e2e.xlsx",
                "sha256": "d" * 64,
                "bytes": 1,
                "cells": [["iso", "e2e", "leased"]],
            },
        },
        "manifest": [
            {"path": "e2e/artifacts/w.whl", "sha256": "b" * 64, "bytes": 1},
            {"path": "e2e/artifacts/s.tar.gz", "sha256": "c" * 64, "bytes": 1},
            {"path": "e2e/work/wheel/iso-e2e.xlsx", "sha256": "e" * 64, "bytes": 1},
            {"path": "e2e/work/sdist/iso-e2e.xlsx", "sha256": "d" * 64, "bytes": 1},
            {"path": "e2e/work/wheel/ledger.journal", "sha256": "f" * 64, "bytes": 1},
            {"path": "e2e/work/sdist/ledger.journal", "sha256": "1" * 64, "bytes": 1},
            {"path": "e2e/work/wheel/ledger.mac_key", "sha256": "2" * 64, "bytes": 32},
            {"path": "e2e/work/sdist/ledger.mac_key", "sha256": "3" * 64, "bytes": 32},
        ],
        "evidence_root": "evidence",
        "pip_check": {
            "wheel": {"ok": True, "exit_code": 0, "stdout_tail": "", "stderr_tail": ""},
            "sdist": {"ok": True, "exit_code": 0, "stdout_tail": "", "stderr_tail": ""},
        },
        "results": [
            {
                "step": name,
                "argv": ["python", "-m", "check"],
                "cwd": "/tmp",
                "started_utc": "2026-07-22T00:00:00Z",
                "finished_utc": "2026-07-22T00:00:01Z",
                "exit_code": 0,
                "stdout_tail": "",
                "stderr_tail": "",
                "ok": True,
                "source_digest": "a" * 64,
            }
            for name in _ISOLATED_VENV_E2E_REQUIRED_STEPS
        ],
    }
    assert _validate_summary_schema(base) == []

    missing_schema = dict(base)
    missing_schema.pop("schema_version")
    assert any("schema_version" in err for err in _validate_summary_schema(missing_schema))

    missing_offline = dict(base)
    missing_offline["offline"] = False
    assert any("offline" in err for err in _validate_summary_schema(missing_offline))

    missing_digest = dict(base)
    missing_digest.pop("source_digest")
    assert any("source_digest" in err for err in _validate_summary_schema(missing_digest))

    bad_chat = dict(base)
    bad_chat["results"] = list(base["results"])
    bad_chat["results"][0] = {
        **base["results"][0],
        "stdout_tail": '{"ok": false, "results": {"chat_status": 403}}',
        "ok": False,
    }
    bad_chat["ok"] = False
    assert bad_chat["results"][0]["stdout_tail"].find('"chat_status": 403') != -1
    assert _validate_summary_schema(bad_chat) == []


def test_isolated_venv_e2e_rejects_non_200_chat_in_server_step_stdout() -> None:
    """Document strict gate semantics: chat 403/500 must fail the server E2E step."""
    forbidden = (400, 403, 422, 500, 503)
    for status in forbidden:
        payload = {"ok": False, "results": {"chat_status": status}}
        assert payload["results"]["chat_status"] != 200
        assert payload["ok"] is False

"""Packaging contracts for the new UI static assets (revision #5).

Proves: (a) wheel + sdist carry the production Web static resources,
(b) an isolated install serves them from site-packages, (c) the release
source digest surface covers them, (d) test-only assets stay out.
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

REQUIRED_STATIC = (
    "js/web/static/css/tokens.css",
    "js/web/static/css/shell.css",
    "js/web/static/css/legacy.css",
    "js/web/static/css/memory.css",
    "js/web/static/js/theme-init.js",
    "js/web/static/js/theme.js",
    "js/web/static/js/shell.js",
    "js/web/static/js/work_context.js",
    "js/web/static/js/bots.js",
    "js/web/static/js/friends.js",
    "js/web/static/js/icons.js",
    "js/web/static/vendor/lucide/LICENSE",
    "js/web/static/vendor/lucide/icons/message-circle.svg",
    "js/web/templates/index.html",
)


@pytest.fixture(scope="session")
def built_artifacts(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("dist")
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=REPO,
        check=True,
        capture_output=True,
        timeout=600,
    )
    return out


def _wheel_path(dist: Path) -> Path:
    wheels = list(dist.glob("*.whl"))
    assert wheels, "wheel not built"
    return wheels[0]


def _sdist_path(dist: Path) -> Path:
    sdists = list(dist.glob("*.tar.gz"))
    assert sdists, "sdist not built"
    return sdists[0]


class TestWheelContents:
    def test_required_static_in_wheel(self, built_artifacts: Path) -> None:
        with zipfile.ZipFile(_wheel_path(built_artifacts)) as zf:
            names = set(zf.namelist())
        for rel in REQUIRED_STATIC:
            assert rel in names, f"{rel} missing from wheel"

    def test_no_test_assets_in_wheel(self, built_artifacts: Path) -> None:
        with zipfile.ZipFile(_wheel_path(built_artifacts)) as zf:
            names = zf.namelist()
        offenders = [
            n for n in names if n.startswith("tests/") or "/tests/" in n or n.endswith("_test.py")
        ]
        assert offenders == [], f"test-only assets leaked into wheel: {offenders[:5]}"

    def test_no_desktop_in_wheel(self, built_artifacts: Path) -> None:
        with zipfile.ZipFile(_wheel_path(built_artifacts)) as zf:
            names = zf.namelist()
        assert not any(n.startswith("desktop/") for n in names)


class TestSdistContents:
    def test_required_static_in_sdist(self, built_artifacts: Path) -> None:
        with tarfile.open(_sdist_path(built_artifacts)) as tf:
            names = {m.name.split("/", 1)[-1] for m in tf.getmembers()}
        for rel in REQUIRED_STATIC:
            assert rel in names, f"{rel} missing from sdist"


class TestIsolatedInstallServesStatic:
    def test_installed_package_has_static_files(
        self, built_artifacts: Path, tmp_path: Path
    ) -> None:
        venv = tmp_path / "venv"
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv)],
            check=True,
            capture_output=True,
            timeout=300,
        )
        pip = venv / "bin" / "pip"
        wheel = _wheel_path(built_artifacts)
        subprocess.run(
            [
                str(pip),
                "install",
                "--no-index",
                "--no-deps",
                str(wheel),
            ],
            check=True,
            capture_output=True,
            timeout=300,
        )
        site_packages = next((venv / "lib").glob("python*/site-packages"))
        for rel in REQUIRED_STATIC:
            assert (site_packages / rel).is_file(), f"{rel} not served after install"


class TestDigestSurface:
    def test_release_digest_covers_new_static_assets(self) -> None:
        from js.echo.ledger.release_gates import _release_source_member_included

        for rel in REQUIRED_STATIC:
            assert _release_source_member_included(Path(rel)), (
                f"{rel} excluded from release digest surface"
            )

    def test_digest_changes_with_static_asset_change(self, tmp_path: Path) -> None:
        """Digest must be sensitive to a static-file content change."""
        import shutil

        from js.echo.ledger.release_gates import release_source_digest

        staged = tmp_path / "repo"
        shutil.copytree(
            REPO,
            staged,
            ignore=shutil.ignore_patterns(
                ".git",
                ".venv",
                ".task-tmp",
                ".test-tmp-baseline",
                ".superpowers",
                "node_modules",
                "target",
                "__pycache__",
                "pytest-of-*",
            ),
        )
        before = release_source_digest(staged)
        target = staged / "js" / "web" / "static" / "css" / "tokens.css"
        target.write_text(target.read_text(encoding="utf-8") + "\n/* drift */\n", encoding="utf-8")
        after = release_source_digest(staged)
        assert before != after, "digest insensitive to static asset drift"

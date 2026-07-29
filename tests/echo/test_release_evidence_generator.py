from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.generate_release_evidence as release_evidence
from scripts.generate_release_evidence import (
    PackageEvidence,
    _existing_generated_at,
    _license_metadata,
    _normalize_command_output,
    _spdx_license_value,
    render_license_scan,
)


def _package(name: str, license_text: str) -> PackageEvidence:
    return PackageEvidence(
        name=name,
        version="1.0",
        source="registry",
        license_text=license_text,
        classifiers=(),
        hashes=(),
    )


def test_license_scan_separates_strong_weak_and_unknown_licenses() -> None:
    report = render_license_scan(
        [
            _package("strong", "AGPL-3.0-only"),
            _package("weak", "LGPL-3.0-only"),
            _package("file-level", "MPL-2.0"),
            _package("unknown", "NOASSERTION"),
        ],
        "2026-07-11T00:00:00Z",
    )

    assert "Strong copyleft markers: strong (AGPL-3.0-only)" in report
    assert "Weak/file-level reciprocal markers:" in report
    assert "weak (LGPL-3.0-only)" in report
    assert "file-level (MPL-2.0)" in report
    assert "Unknown license metadata: `unknown`" in report


def test_check_mode_reuses_the_existing_sbom_timestamp(tmp_path: Path) -> None:
    sbom = tmp_path / "SBOM.spdx.json"
    sbom.write_text(
        json.dumps({"creationInfo": {"created": "2026-07-11T00:00:00Z"}}),
        encoding="utf-8",
    )

    assert _existing_generated_at(sbom) == "2026-07-11T00:00:00Z"


def test_release_smoke_evidence_removes_nondeterministic_log_noise() -> None:
    raw = "\n".join(
        [
            "临时测试目录: /tmp/titan-release-smoke-random",
            "[检查] package",
            "  [OK] package",
            "2026-07-11 20:43:50 [info] random runtime log",
            "  [OK] web/model",
            "发布烟测通过。",
        ]
    )

    normalized = _normalize_command_output("release_smoke", raw)

    assert "random runtime log" not in normalized
    assert "titan-release-smoke-random" not in normalized
    assert normalized.splitlines() == [
        "[检查] package",
        "[OK] package",
        "[OK] web/model",
        "发布烟测通过。",
    ]


def test_command_evidence_uses_a_temporary_ledger_outside_the_repository(
    monkeypatch,
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(command: list[str], *, evidence_name: str = "") -> str:
        captured[evidence_name] = command
        return "$ fake\nexit=0\nok"

    monkeypatch.setattr(release_evidence, "_run_capture", fake_run)

    release_evidence.collect_command_evidence()

    command = captured["echo_ledger_smoke"]
    state_dir = Path(command[command.index("--state-dir") + 1]).resolve()
    assert not state_dir.is_relative_to(release_evidence.ROOT.resolve())


def test_spdx_value_maps_known_license_classifiers() -> None:
    assert _spdx_license_value("License :: OSI Approved :: MIT License") == "MIT"
    assert (
        _spdx_license_value("License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)")
        == "MPL-2.0"
    )


def test_license_metadata_rejects_an_installed_version_that_differs_from_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = SimpleNamespace(
        version="2.0",
        metadata={"License-Expression": "MIT"},
    )
    monkeypatch.setattr(release_evidence.metadata, "distribution", lambda _name: installed)

    assert _license_metadata("example", "1.0") == ("NOASSERTION", ())


def test_lockfile_evidence_rejects_an_empty_package_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text("version = 1\n", encoding="utf-8")
    monkeypatch.setattr(release_evidence, "LOCKFILE", lockfile)

    with pytest.raises(ValueError, match="no packages"):
        release_evidence.read_lock_packages()


def test_lockfile_evidence_accepts_any_complete_nonempty_package_graph(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text(
        '[[package]]\nname = "example-root"\nversion = "1.0"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(release_evidence, "LOCKFILE", lockfile)

    packages = release_evidence.read_lock_packages()

    assert [(package.name, package.version) for package in packages] == [
        ("example-root", "1.0")
    ]


def test_lockfile_evidence_rejects_a_missing_declared_dependency(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text(
        '[[package]]\nname = "js-agent"\nversion = "0.1.5"\n'
        'dependencies = [{ name = "missing-transitive" }]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(release_evidence, "LOCKFILE", lockfile)

    with pytest.raises(ValueError, match="missing-transitive"):
        release_evidence.read_lock_packages()

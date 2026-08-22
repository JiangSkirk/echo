from __future__ import annotations

import hashlib
import json
import os
import plistlib
import stat
import struct
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from desktop import build_driver
from js.echo.ledger.release_gates import release_source_digest

DIGEST = "ab" * 32
OTHER_DIGEST = "cd" * 32
BUILD_NUMBER = "2026081101"
_BUILD_INPUT_RELATIVES = (
    "desktop/src-tauri/Cargo.lock",
    "desktop/pnpm-lock.yaml",
    "desktop/requirements-build.txt",
    "desktop/build_driver.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_info_plist(path: Path, *, build_number: str = BUILD_NUMBER) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        plistlib.dumps(
            {
                "CFBundleExecutable": "js-agent-desktop",
                "CFBundleIdentifier": "com.titan.js-agent",
                "CFBundleShortVersionString": "0.1.0",
                "CFBundleVersion": build_number,
            },
            fmt=plistlib.FMT_XML,
            sort_keys=True,
        )
    )


def _thin_macho64() -> bytes:
    return struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        0,
        0,
        0,
        0,
    )


def _fat_macho64() -> bytes:
    thin = _thin_macho64()
    header_size = 40
    return (
        bytes.fromhex("cafebabf")
        + struct.pack(">I", 1)
        + struct.pack(
            ">IIQQII",
            0x0100000C,
            0,
            header_size,
            len(thin),
            2,
            0,
        )
        + thin
    )


def _zip_member(name: str, *, file_type: int, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (file_type | mode) << 16
    return info


def _write_release_inputs(repo_root: Path) -> None:
    files = {
        "desktop/build_driver.py": "BUILD_DRIVER_VERSION = 2\n",
        "desktop/package.json": '{"private":true}\n',
        "desktop/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "desktop/requirements-build.txt": (
            "pyinstaller==6.21.0\npyinstaller-hooks-contrib==2026.6\n"
        ),
        "desktop/sidecar/host.py": "HOST_VERSION = 1\n",
        "desktop/source_digest.py": "SOURCE_DIGEST_VERSION = 1\n",
        "desktop/src-tauri/Cargo.lock": "version = 4\n",
        "desktop/src-tauri/Cargo.toml": "[package]\nname = 'fixture'\n",
        "desktop/src-tauri/src/main.rs": "fn main() {}\n",
    }
    for relative, content in files.items():
        path = repo_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _write_zip_from_app(app_path: Path, zip_path: Path) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w") as archive:
        for path in [app_path, *sorted(app_path.rglob("*"))]:
            if path.is_symlink():
                continue
            archive.write(
                path,
                (
                    Path(app_path.name)
                    if path == app_path
                    else Path(app_path.name) / path.relative_to(app_path)
                ).as_posix(),
            )


@pytest.fixture
def manifest_tree(tmp_path: Path) -> dict[str, Any]:
    repo_root = tmp_path / "repo"
    output_dir = tmp_path / "output"
    _write_release_inputs(repo_root)
    run = build_driver.prepare_build_run(output_dir=output_dir, repo_root=repo_root)
    inputs = _offline_build_inputs(tmp_path / "manifest-inputs")
    artifacts = run.root / "artifacts"
    app_path = artifacts / "JS Agent.app"
    main_binary = app_path / "Contents/MacOS/js-agent-desktop"
    bundled_sidecar = app_path / "Contents/MacOS/js-agent-host"
    standalone = artifacts / "js-agent-host-aarch64-apple-darwin"
    for path, payload in (
        (main_binary, b"rust-main"),
        (bundled_sidecar, b"sidecar-binary"),
        (standalone, b"sidecar-binary"),
        (app_path / "Contents/Info.plist", b"placeholder"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    _write_info_plist(app_path / "Contents/Info.plist")
    main_binary.chmod(0o755)
    bundled_sidecar.chmod(0o755)
    standalone.chmod(0o755)
    source_digest = release_source_digest(repo_root)
    zip_path = artifacts / (
        f"JS-Agent-0.1.0-macos-arm64-unsigned-{source_digest[:16]}.zip"
    )
    _write_zip_from_app(app_path, zip_path)
    manifest_path = build_driver.generate_manifest(
        source_digest=source_digest,
        build_number=BUILD_NUMBER,
        sidecar_path=standalone,
        app_path=app_path,
        zip_path=zip_path,
        run=run,
        repo_root=repo_root,
        offline_inputs=inputs,
    )
    return {
        "repo_root": repo_root,
        "output_dir": output_dir,
        "app_path": app_path,
        "main_binary": main_binary,
        "bundled_sidecar": bundled_sidecar,
        "standalone": standalone,
        "zip_path": zip_path,
        "manifest_path": manifest_path,
        "source_digest": source_digest,
    }


def test_stage_and_build_commands_are_source_stable_locked_and_offline(
    tmp_path: Path,
) -> None:
    repo_root = tmp_path / "repo"
    output_dir = tmp_path / "output"
    _write_release_inputs(repo_root)
    run = build_driver.prepare_build_run(output_dir=output_dir, repo_root=repo_root)
    inputs = _offline_build_inputs(tmp_path / "inputs")
    source_digest = release_source_digest(repo_root)
    before = release_source_digest(repo_root)
    calls: list[dict[str, Any]] = []

    def fake_runner(
        cmd: list[str],
        *,
        cwd: Path,
        env: dict[str, str] | None = None,
        timeout: int = 600,
    ) -> tuple[int, str, str]:
        calls.append({"cmd": cmd, "cwd": cwd, "env": env, "timeout": timeout})
        if "PyInstaller" in cmd:
            dist = Path(cmd[cmd.index("--distpath") + 1])
            name = cmd[cmd.index("--name") + 1]
            dist.mkdir(parents=True, exist_ok=True)
            (dist / name).write_bytes(b"sidecar")
        return 0, "", ""

    stage_root = build_driver.stage_release_sources(
        source_digest,
        run=run,
        repo_root=repo_root,
    )
    tauri = stage_root / "desktop/node_modules/.bin/tauri"
    tauri.parent.mkdir(parents=True)
    tauri.write_text("fixture", encoding="utf-8")
    tauri.chmod(0o700)
    app_path = (
        run.root
        / "stage/cargo-target/aarch64-apple-darwin/release/bundle/macos/JS Agent.app"
    )
    app_path.mkdir(parents=True)
    _write_info_plist(app_path / "Contents/Info.plist", build_number="0")

    build_driver.install_desktop_dependencies(
        stage_root,
        run=run,
        offline_inputs=inputs,
        runner=fake_runner,
    )
    sidecar = build_driver.build_sidecar(
        source_digest,
        run=run,
        stage_root=stage_root,
        offline_inputs=inputs,
        runner=fake_runner,
    )
    built_app = build_driver.build_tauri_app(
        source_digest,
        build_number=BUILD_NUMBER,
        run=run,
        stage_root=stage_root,
        offline_inputs=inputs,
        runner=fake_runner,
    )

    assert sidecar == run.root / "artifacts/js-agent-host-aarch64-apple-darwin"
    assert built_app == app_path
    built_info = plistlib.loads((built_app / "Contents/Info.plist").read_bytes())
    assert built_info["CFBundleShortVersionString"] == "0.1.0"
    assert built_info["CFBundleVersion"] == BUILD_NUMBER
    assert not (repo_root / "desktop/.embedded_source_digest").exists()
    assert not (repo_root / "desktop/src-tauri/binaries").exists()
    assert not (repo_root / "desktop/src-tauri/target").exists()
    assert (stage_root / "desktop/.embedded_source_digest").read_text(encoding="ascii") == (
        source_digest
    )
    assert release_source_digest(repo_root) == before

    pnpm_call, pyinstaller_call, tauri_call = calls
    assert pnpm_call["cmd"] == [
        str(inputs.pnpm_executable.resolve()),
        "install",
        "--frozen-lockfile",
        "--offline",
        "--ignore-scripts",
        "--store-dir",
        str(inputs.pnpm_store.resolve()),
    ]
    assert pnpm_call["env"]["PIP_NO_INDEX"] == "1"
    assert pnpm_call["env"]["UV_OFFLINE"] == "1"
    assert pyinstaller_call["env"]["PIP_NO_INDEX"] == "1"
    assert pyinstaller_call["env"]["UV_OFFLINE"] == "1"
    assert pyinstaller_call["env"]["PYTHONPATH"] == str(stage_root)
    assert str(repo_root / "desktop/.embedded_source_digest") not in pyinstaller_call["cmd"]
    assert tauri_call["cmd"] == [
        str(tauri.resolve()),
        "build",
        "--runner",
        str(inputs.cargo_executable.resolve()),
        "--target",
        "aarch64-apple-darwin",
        "--no-sign",
        "--bundles",
        "app",
        "--",
        "--locked",
        "--offline",
    ]
    assert tauri_call["env"]["JS_AGENT_DESKTOP_SOURCE_DIGEST"] == source_digest
    assert tauri_call["env"]["CARGO_NET_OFFLINE"] == "true"
    assert tauri_call["env"]["PIP_NO_INDEX"] == "1"
    assert tauri_call["env"]["UV_OFFLINE"] == "1"


def test_python_build_versions_must_match_exact_offline_pins(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements-build.txt"
    requirements.write_text(
        "pyinstaller==6.21.0\npyinstaller-hooks-contrib==2026.6\n",
        encoding="utf-8",
    )
    installed = {
        "pyinstaller": "6.21.0",
        "pyinstaller-hooks-contrib": "2026.6",
    }

    build_driver.verify_python_build_requirements(
        requirements,
        version_resolver=installed.__getitem__,
    )

    installed["pyinstaller"] = "6.20.0"
    with pytest.raises(RuntimeError, match="Python build requirement mismatch"):
        build_driver.verify_python_build_requirements(
            requirements,
            version_resolver=installed.__getitem__,
        )


def test_cargo_cache_preservation_restores_nonempty_bytes_and_absence(
    tmp_path: Path,
) -> None:
    cargo_home = tmp_path / "cargo-home"
    cargo_home.mkdir()
    global_cache = cargo_home / ".global-cache"
    mutate_cache = cargo_home / ".package-cache-mutate"
    package_cache = cargo_home / ".package-cache"
    global_cache.write_bytes(b"preexisting-nonempty-cache")

    with build_driver._preserve_cargo_home_caches(cargo_home):
        global_cache.write_bytes(b"cargo-mutated-cache")
        mutate_cache.write_bytes(b"created-during-build")
        package_cache.write_bytes(b"created-during-build")

    assert global_cache.read_bytes() == b"preexisting-nonempty-cache"
    assert not mutate_cache.exists()
    assert not package_cache.exists()


def test_cargo_cache_preservation_restores_preexisting_package_cache_bytes(
    tmp_path: Path,
) -> None:
    cargo_home = tmp_path / "cargo-home"
    cargo_home.mkdir()
    package_cache = cargo_home / ".package-cache"
    package_cache.write_bytes(b"preexisting-nonempty-package-cache")

    with build_driver._preserve_cargo_home_caches(cargo_home):
        package_cache.write_bytes(b"cargo-mutated-package-cache")

    assert package_cache.read_bytes() == b"preexisting-nonempty-package-cache"


def test_digest_drift_retains_failed_run_and_marks_manifest_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "output"
    inputs = _offline_build_inputs(tmp_path / "inputs")
    digests = iter((DIGEST, OTHER_DIGEST))

    def stage(*_args: object, **_kwargs: object) -> Path:
        staged = output_dir / "stage/source"
        staged.mkdir(parents=True)
        return staged

    def sidecar(*_args: object, **_kwargs: object) -> Path:
        path = output_dir / "artifacts/js-agent-host-aarch64-apple-darwin"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"sidecar")
        return path

    def app(*_args: object, **_kwargs: object) -> Path:
        path = output_dir / "stage/cargo-target/fixture/JS Agent.app"
        path.mkdir(parents=True)
        return path

    def archive(*_args: object, **_kwargs: object) -> Path:
        path = output_dir / "artifacts/build.zip"
        path.write_bytes(b"zip")
        return path

    monkeypatch.setattr(build_driver, "compute_source_digest", lambda *_args: next(digests))
    monkeypatch.setattr(build_driver, "stage_release_sources", stage)
    monkeypatch.setattr(build_driver, "verify_python_build_requirements", lambda *_a, **_k: None)
    monkeypatch.setattr(build_driver, "install_desktop_dependencies", lambda *_a, **_k: None)
    monkeypatch.setattr(build_driver, "build_sidecar", sidecar)
    monkeypatch.setattr(build_driver, "build_tauri_app", app)
    monkeypatch.setattr(build_driver, "create_zip", archive)
    monkeypatch.setattr(build_driver, "generate_manifest", pytest.fail)

    with pytest.raises(RuntimeError, match="source digest drift"):
        build_driver.build_desktop(
            output_dir=output_dir,
            build_number=BUILD_NUMBER,
            offline_inputs=inputs,
        )

    assert output_dir.is_dir()
    assert (output_dir / ".js-agent-build-invalid-manual-cleanup").is_file()
    assert (output_dir / "artifacts/build.zip").read_bytes() == b"zip"
    assert (
        output_dir / "artifacts/js-agent-host-aarch64-apple-darwin"
    ).read_bytes() == b"sidecar"
    assert not (output_dir / "manifest.json").exists()


def test_manifest_accepts_exact_closed_artifact_set(manifest_tree: dict[str, Any]) -> None:
    assert build_driver.verify_manifest(
        manifest_tree["manifest_path"],
        repo_root=manifest_tree["repo_root"],
    ) == []


def test_build_number_is_explicit_and_bound_to_manifest_and_bundle(
    manifest_tree: dict[str, Any],
) -> None:
    payload = json.loads(manifest_tree["manifest_path"].read_text(encoding="utf-8"))
    info = plistlib.loads(
        (manifest_tree["app_path"] / "Contents/Info.plist").read_bytes()
    )

    assert payload["product_version"] == "0.1.0"
    assert payload["build_number"] == BUILD_NUMBER
    assert info["CFBundleShortVersionString"] == payload["product_version"]
    assert info["CFBundleVersion"] == payload["build_number"]


@pytest.mark.parametrize(
    "value",
    ["", "20260811", "2026081100", "2026130101", "2026023001", "20260811001"],
)
def test_build_number_rejects_invalid_or_ambiguous_values(value: str) -> None:
    with pytest.raises(RuntimeError, match="build number"):
        build_driver.validate_build_number(value)


def test_artifact_zip_name_uses_product_version_constant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(build_driver, "PRODUCT_VERSION", "9.8.7")

    paths = build_driver._artifact_paths("a" * 64)

    assert paths["zip"] == (
        "artifacts/JS-Agent-9.8.7-macos-arm64-unsigned-aaaaaaaaaaaaaaaa.zip"
    )


def test_manifest_rejects_build_number_or_bundle_version_drift(
    manifest_tree: dict[str, Any],
) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        payload["build_number"] = "2026081102"

    _rewrite_manifest(manifest_tree, mutate)
    errors = build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )
    assert any("build number" in error for error in errors)

    payload = json.loads(manifest_tree["manifest_path"].read_text(encoding="utf-8"))
    payload["build_number"] = BUILD_NUMBER
    manifest_tree["manifest_path"].write_text(json.dumps(payload), encoding="utf-8")
    _write_info_plist(
        manifest_tree["app_path"] / "Contents/Info.plist",
        build_number="2026081102",
    )
    errors = build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )
    assert any("CFBundleVersion" in error for error in errors)


def test_normalize_app_bundle_permissions_is_content_and_path_deterministic(
    tmp_path: Path,
) -> None:
    app = tmp_path / "JS Agent.app"
    main = app / "Contents/MacOS/js-agent-desktop"
    script = app / "Contents/Resources/tool.sh"
    dylib = app / "Contents/Frameworks/helper.dylib"
    resource = app / "Contents/Resources/payload.json"
    main.parent.mkdir(parents=True)
    script.parent.mkdir(parents=True)
    dylib.parent.mkdir(parents=True)
    main.write_bytes(b"not-real-mach-o")
    script.write_bytes(b"#!/bin/sh\nexit 0\n")
    dylib.write_bytes(_thin_macho64())
    resource.write_bytes(b"{}")
    main.chmod(0o600)
    script.chmod(0o600)
    dylib.chmod(0o600)
    resource.chmod(0o777)
    app.chmod(0o700)
    (app / "Contents/Resources").chmod(0o700)

    build_driver.normalize_app_bundle_permissions(app)

    assert stat.S_IMODE(app.stat().st_mode) == 0o755
    assert stat.S_IMODE((app / "Contents/Resources").stat().st_mode) == 0o755
    assert stat.S_IMODE(main.stat().st_mode) == 0o755
    assert stat.S_IMODE(script.stat().st_mode) == 0o755
    assert stat.S_IMODE(dylib.stat().st_mode) == 0o755
    assert stat.S_IMODE(resource.stat().st_mode) == 0o644


@pytest.mark.parametrize("case", ["symlink", "fifo"])
def test_normalize_app_bundle_permissions_rejects_links_and_special_nodes(
    tmp_path: Path,
    case: str,
) -> None:
    app = tmp_path / "JS Agent.app"
    resources = app / "Contents/Resources"
    resources.mkdir(parents=True)
    injected = resources / "injected"
    if case == "symlink":
        target = tmp_path / "outside"
        target.write_bytes(b"outside")
        injected.symlink_to(target)
    else:
        os.mkfifo(injected)

    with pytest.raises(RuntimeError, match="symlink|special file"):
        build_driver.normalize_app_bundle_permissions(app)


def test_manifest_rejects_bundle_permission_drift(
    manifest_tree: dict[str, Any],
) -> None:
    resource = manifest_tree["app_path"] / "Contents/Info.plist"
    resource.chmod(0o755)

    errors = build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )
    assert any("permission" in error for error in errors)


def test_tree_digest_binds_file_and_directory_permissions(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    nested = tree / "nested"
    payload = nested / "payload"
    nested.mkdir(parents=True)
    payload.write_bytes(b"same-content")
    tree.chmod(0o755)
    nested.chmod(0o755)
    payload.chmod(0o644)
    baseline = build_driver._sha256_tree(tree)

    payload.chmod(0o600)
    with pytest.raises(RuntimeError, match="permission"):
        build_driver._sha256_tree(tree)
    payload.chmod(0o644)
    nested.chmod(0o700)
    with pytest.raises(RuntimeError, match="permission"):
        build_driver._sha256_tree(tree)
    nested.chmod(0o755)
    assert build_driver._sha256_tree(tree) == baseline


def test_java_class_magic_is_not_treated_as_fat_macho(tmp_path: Path) -> None:
    app = tmp_path / "JS Agent.app"
    java_class = app / "Contents/Resources/Foo.class"
    real_macho = app / "Contents/Frameworks/helper.dylib"
    real_fat_macho = app / "Contents/Frameworks/universal.dylib"
    java_class.parent.mkdir(parents=True)
    real_macho.parent.mkdir(parents=True)
    java_class.write_bytes(
        bytes.fromhex("cafebabe0000003d0011") + b"java-constant-pool-fixture"
    )
    real_macho.write_bytes(_thin_macho64())
    real_fat_macho.write_bytes(_fat_macho64())
    java_class.chmod(0o755)
    real_macho.chmod(0o600)
    real_fat_macho.chmod(0o600)

    build_driver.normalize_app_bundle_permissions(app)

    assert stat.S_IMODE(java_class.stat().st_mode) == 0o644
    assert stat.S_IMODE(real_macho.stat().st_mode) == 0o755
    assert stat.S_IMODE(real_fat_macho.stat().st_mode) == 0o755


def test_zip_requires_explicit_declared_app_root(tmp_path: Path) -> None:
    zip_path = tmp_path / "missing-root.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(
            _zip_member(
                "JS Agent.app/Contents/MacOS/js-agent-desktop",
                file_type=stat.S_IFREG,
                mode=0o755,
            ),
            b"main",
        )

    with pytest.raises(RuntimeError, match="root"):
        build_driver._zip_app_entries(zip_path, "JS Agent.app")


@pytest.mark.parametrize(
    "directory_name,file_type,mode",
    [
        ("Unexpected.app/", stat.S_IFDIR, 0o755),
        ("JS Agent.app/", stat.S_IFDIR, 0o700),
        ("JS Agent.app/", stat.S_IFIFO, 0o755),
    ],
    ids=["extra-top-level-directory", "wrong-directory-mode", "directory-special-type"],
)
def test_zip_rejects_unclosed_or_invalid_directory_metadata(
    tmp_path: Path,
    directory_name: str,
    file_type: int,
    mode: int,
) -> None:
    zip_path = tmp_path / "directory-attack.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(
            _zip_member(directory_name, file_type=file_type, mode=mode),
            b"",
        )
        if directory_name != "JS Agent.app/":
            archive.writestr(
                _zip_member("JS Agent.app/", file_type=stat.S_IFDIR, mode=0o755),
                b"",
            )
        archive.writestr(
            _zip_member(
                "JS Agent.app/Contents/MacOS/js-agent-desktop",
                file_type=stat.S_IFREG,
                mode=0o755,
            ),
            b"main",
        )

    with pytest.raises(RuntimeError, match="directory|root|top-level|special"):
        build_driver._zip_app_entries(zip_path, "JS Agent.app")


@pytest.mark.parametrize(
    "relative",
    [
        "desktop/src-tauri/Cargo.lock",
        "desktop/pnpm-lock.yaml",
        "desktop/requirements-build.txt",
        "desktop/build_driver.py",
    ],
)
def test_manifest_rejects_every_build_input_mutation(
    manifest_tree: dict[str, Any],
    relative: str,
) -> None:
    path = manifest_tree["repo_root"] / relative
    path.write_bytes(path.read_bytes() + b"tampered")

    assert build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )


@pytest.mark.parametrize(
    "artifact",
    ["main_binary", "bundled_sidecar", "standalone", "zip_path"],
)
def test_manifest_rejects_every_artifact_mutation(
    manifest_tree: dict[str, Any],
    artifact: str,
) -> None:
    path = manifest_tree[artifact]
    path.write_bytes(path.read_bytes() + b"tampered")

    assert build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )


def test_manifest_rejects_app_tree_mutation(manifest_tree: dict[str, Any]) -> None:
    extra = manifest_tree["app_path"] / "Contents/Resources/injected"
    extra.parent.mkdir(parents=True)
    extra.write_bytes(b"tampered")

    assert build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )


def _rewrite_manifest(
    tree: dict[str, Any],
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    path = tree["manifest_path"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")


@pytest.mark.parametrize(
    "case",
    [
        "bogus_schema",
        "wrong_source_digest",
        "empty_artifacts",
        "missing_artifact",
        "extra_artifact",
        "unknown_top_field",
        "null_hash",
        "absolute_path",
        "traversal_path",
    ],
)
def test_manifest_rejects_open_schema_or_unsafe_paths(
    manifest_tree: dict[str, Any],
    case: str,
) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        if case == "bogus_schema":
            payload["schema"] = "bogus"
        elif case == "wrong_source_digest":
            payload["source_digest"] = OTHER_DIGEST
        elif case == "empty_artifacts":
            payload["artifacts"] = {}
        elif case == "missing_artifact":
            payload["artifacts"].pop("zip")
        elif case == "extra_artifact":
            payload["artifacts"]["extra"] = {
                "path": "artifacts/extra",
                "sha256": DIGEST,
            }
        elif case == "unknown_top_field":
            payload["unexpected"] = True
        elif case == "null_hash":
            payload["artifacts"]["rust_main"]["sha256"] = None
        elif case == "absolute_path":
            payload["artifacts"]["zip"]["path"] = "/tmp/escape.zip"
        else:
            payload["artifacts"]["zip"]["path"] = "artifacts/../escape.zip"

    _rewrite_manifest(manifest_tree, mutate)

    assert build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )


def test_manifest_rejects_sidecars_that_are_individually_hashed_but_differ(
    manifest_tree: dict[str, Any],
) -> None:
    standalone = manifest_tree["standalone"]
    standalone.write_bytes(b"different-valid-standalone")

    def mutate(payload: dict[str, Any]) -> None:
        payload["artifacts"]["sidecar_standalone"]["sha256"] = _sha256(standalone)

    _rewrite_manifest(manifest_tree, mutate)

    errors = build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )
    assert any("sidecar" in error for error in errors)


def test_zip_forbidden_members_detects_appledouble(tmp_path: Path) -> None:
    """Injected AppleDouble / __MACOSX / .DS_Store members must fail closed."""
    zip_path = tmp_path / "poison.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(
            _zip_member("JS Agent.app/", file_type=stat.S_IFDIR, mode=0o755), b""
        )
        archive.writestr(
            _zip_member("JS Agent.app/Contents/", file_type=stat.S_IFDIR, mode=0o755),
            b"",
        )
        for name, payload in (
            ("JS Agent.app/Contents/Info.plist", b"<plist/>"),
            ("JS Agent.app/Contents/._Info.plist", b"appledouble"),
            ("__MACOSX/JS Agent.app/._Contents", b"junk"),
            ("JS Agent.app/Contents/.DS_Store", b"ds"),
        ):
            archive.writestr(
                _zip_member(name, file_type=stat.S_IFREG, mode=0o644), payload
            )
    bad = build_driver._zip_forbidden_members(zip_path)
    assert any("._" in name for name in bad)
    assert any("__MACOSX" in name for name in bad)
    assert any(".DS_Store" in name for name in bad)

    # _zip_app_entries must also raise rather than silently skip.
    with pytest.raises(RuntimeError, match="AppleDouble"):
        build_driver._zip_app_entries(zip_path, "JS Agent.app")


@pytest.mark.parametrize(
    "case",
    ["traversal", "symlink", "missing", "extra", "noncanonical"],
)
def test_manifest_rejects_unsafe_or_nonreproducing_zip_closure(
    manifest_tree: dict[str, Any],
    case: str,
) -> None:
    zip_path = manifest_tree["zip_path"]
    app_path = manifest_tree["app_path"]
    with zipfile.ZipFile(zip_path, "w") as archive:
        files = [
            path
            for path in sorted(app_path.rglob("*"))
            if path.is_file() and not path.is_symlink()
        ]
        if case == "missing":
            files = files[:-1]
        for index, path in enumerate(files):
            member_name = (Path(app_path.name) / path.relative_to(app_path)).as_posix()
            if case == "noncanonical" and index == 0:
                member_name = member_name.replace("/", "/./", 1)
                archive.writestr(member_name, path.read_bytes())
            else:
                archive.write(path, member_name)
        if case == "traversal":
            archive.writestr("../escape", b"escape")
        elif case == "symlink":
            info = zipfile.ZipInfo(f"{app_path.name}/Contents/Resources/link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "../../outside")
        elif case == "extra":
            archive.writestr(f"{app_path.name}/Contents/Resources/extra", b"extra")

    def mutate(payload: dict[str, Any]) -> None:
        payload["artifacts"]["zip"]["sha256"] = _sha256(zip_path)

    _rewrite_manifest(manifest_tree, mutate)

    assert build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )


def test_manifest_rejects_symlink_in_app_tree(manifest_tree: dict[str, Any]) -> None:
    link = manifest_tree["app_path"] / "Contents/Resources/link"
    link.parent.mkdir(parents=True)
    link.symlink_to(manifest_tree["main_binary"])

    assert build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )


def test_manifest_rejects_top_level_artifact_symlink_even_when_target_is_contained(
    manifest_tree: dict[str, Any],
) -> None:
    standalone = manifest_tree["standalone"]
    standalone.unlink()
    standalone.symlink_to(manifest_tree["bundled_sidecar"])

    assert build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )


def _offline_build_inputs(tmp_path: Path) -> Any:
    inputs_type = getattr(build_driver, "OfflineBuildInputs", None)
    assert inputs_type is not None, "OfflineBuildInputs is missing"
    tools = tmp_path / "controlled-tools"
    cargo_home = tmp_path / "controlled-cargo-home"
    pnpm_store = tmp_path / "controlled-pnpm-store"
    for name in ("pnpm", "cargo", "node", "ditto"):
        executable = tools / name
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_text(f"{name}-tool\n", encoding="utf-8")
        executable.chmod(0o700)
    for path, payload in (
        (cargo_home / "registry/cache.marker", b"cargo-cache"),
        (pnpm_store / "v3/files/store.marker", b"pnpm-store"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return inputs_type(
        pnpm_executable=tools / "pnpm",
        cargo_executable=tools / "cargo",
        node_executable=tools / "node",
        ditto_executable=tools / "ditto",
        cargo_home=cargo_home,
        pnpm_store=pnpm_store,
    )


def test_prepare_build_run_rejects_existing_output_without_touching_user_files(
    tmp_path: Path,
) -> None:
    prepare = getattr(build_driver, "prepare_build_run", None)
    assert callable(prepare), "prepare_build_run is missing"
    repo_root = tmp_path / "repo"
    output_dir = tmp_path / "user-output"
    user_files = {
        "manifest.json": b"user-manifest",
        "artifacts/user.bin": b"user-artifact",
        "stage/user.txt": b"user-stage",
    }
    for relative, payload in user_files.items():
        path = output_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    with pytest.raises(RuntimeError, match="already exists"):
        prepare(output_dir=output_dir, repo_root=repo_root)

    assert {
        relative: (output_dir / relative).read_bytes()
        for relative in user_files
    } == user_files


def test_prepare_build_run_rejects_every_repository_subpath_before_write(
    tmp_path: Path,
) -> None:
    prepare = getattr(build_driver, "prepare_build_run", None)
    assert callable(prepare), "prepare_build_run is missing"
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    for relative in (
        ".task-tmp/node_modules",
        "desktop/node_modules/build",
        "outside-looking",
    ):
        output = repo_root / relative
        with pytest.raises(RuntimeError, match="outside the repository"):
            prepare(output_dir=output, repo_root=repo_root)
        assert not output.exists()


def test_owned_run_cleanup_requires_live_secret_and_preserves_siblings(
    tmp_path: Path,
) -> None:
    prepare = getattr(build_driver, "prepare_build_run", None)
    cleanup = getattr(build_driver, "cleanup_build_run", None)
    assert callable(prepare), "prepare_build_run is missing"
    assert callable(cleanup), "cleanup_build_run is missing"
    repo_root = tmp_path / "repo"
    output = tmp_path / "owned-run"
    sibling = tmp_path / "user-sibling.txt"
    sibling.write_bytes(b"preserve")
    run = prepare(output_dir=output, repo_root=repo_root)
    (run.root / "artifacts/result").parent.mkdir(parents=True)
    (run.root / "artifacts/result").write_bytes(b"owned")

    marker = run.root / ".js-agent-build-owner"
    original_marker = marker.read_bytes()
    marker.write_bytes(b"forged-owner")
    assert cleanup(run) is False
    assert (run.root / "artifacts/result").read_bytes() == b"owned"
    assert sibling.read_bytes() == b"preserve"

    marker.write_bytes(original_marker)
    assert cleanup(run) is False
    assert (run.root / "artifacts/result").read_bytes() == b"owned"
    assert (run.root / ".js-agent-build-invalid-manual-cleanup").is_file()
    assert sibling.read_bytes() == b"preserve"


def test_owned_run_cleanup_rejects_replaced_directory_with_replayed_marker(
    tmp_path: Path,
) -> None:
    repo_root = tmp_path / "repo"
    run = build_driver.prepare_build_run(
        output_dir=tmp_path / "owned-run",
        repo_root=repo_root,
    )
    marker_payload = (run.root / ".js-agent-build-owner").read_bytes()
    original = tmp_path / "original-owned-run"
    run.root.rename(original)
    run.root.mkdir(mode=0o700)
    (run.root / ".js-agent-build-owner").write_bytes(marker_payload)
    replacement = run.root / "user-file"
    replacement.write_bytes(b"preserve")

    assert build_driver.cleanup_build_run(run) is False
    assert replacement.read_bytes() == b"preserve"
    assert original.is_dir()


def test_cleanup_preserves_restored_marker_inode_and_concurrent_unknown_file(
    tmp_path: Path,
) -> None:
    run = build_driver.prepare_build_run(
        output_dir=tmp_path / "owned-run",
        repo_root=tmp_path / "repo",
    )
    marker = run.root / ".js-agent-build-owner"
    original_marker = marker.read_bytes()
    original_inode = marker.stat().st_ino
    marker.write_bytes(b"same-inode-tamper")
    marker.write_bytes(original_marker)
    concurrent = run.root / "concurrent-user-file"
    concurrent.write_bytes(b"must-survive-byte-for-byte")

    assert marker.stat().st_ino == original_inode
    assert build_driver.cleanup_build_run(run) is False
    assert run.root.is_dir()
    assert marker.read_bytes() == original_marker
    assert concurrent.read_bytes() == b"must-survive-byte-for-byte"
    assert (run.root / ".js-agent-build-invalid-manual-cleanup").is_file()


def test_default_build_run_is_unique_owned_and_outside_repository(tmp_path: Path) -> None:
    prepare = getattr(build_driver, "prepare_build_run", None)
    cleanup = getattr(build_driver, "cleanup_build_run", None)
    assert callable(prepare), "prepare_build_run is missing"
    assert callable(cleanup), "cleanup_build_run is missing"
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    external = tmp_path / "external"
    external.mkdir()

    first = prepare(output_dir=None, repo_root=repo_root, temporary_parent=external)
    second = prepare(output_dir=None, repo_root=repo_root, temporary_parent=external)

    assert first.root != second.root
    assert first.root.parent == external
    assert second.root.parent == external
    assert (first.root / ".js-agent-build-owner").is_file()
    assert (second.root / ".js-agent-build-owner").is_file()
    assert cleanup(first) is True
    assert cleanup(second) is True


def test_default_build_run_uses_canonical_system_temporary_directory(
    tmp_path: Path,
) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    run = build_driver.prepare_build_run(output_dir=None, repo_root=repo_root)

    assert run.root.parent == Path(os.path.realpath(os.getenv("TMPDIR", "/tmp")))
    assert not run.root.is_relative_to(repo_root.resolve())
    assert build_driver.cleanup_build_run(run) is True


def test_explicit_output_accepts_symlinked_parent_but_uses_canonical_directory(
    tmp_path: Path,
) -> None:
    canonical_parent = tmp_path / "private-tmp"
    canonical_parent.mkdir()
    lexical_parent = tmp_path / "var-tmp"
    lexical_parent.symlink_to(canonical_parent, target_is_directory=True)
    output = lexical_parent / "explicit-run"

    run = build_driver.prepare_build_run(
        output_dir=output,
        repo_root=tmp_path / "repo",
    )

    assert run.root == canonical_parent.resolve() / "explicit-run"
    assert not output.is_symlink()
    assert (run.root / ".js-agent-build-owner").is_file()
    assert build_driver.cleanup_build_run(run) is True


def test_controlled_subprocess_environment_drops_ambient_build_injection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepare = getattr(build_driver, "prepare_build_run", None)
    environment = getattr(build_driver, "controlled_build_environment", None)
    assert callable(prepare), "prepare_build_run is missing"
    assert callable(environment), "controlled_build_environment is missing"
    poison = {
        "NODE_OPTIONS": "--require=/tmp/inject.js",
        "RUSTC_WRAPPER": "/tmp/wrapper",
        "RUSTFLAGS": "--cfg injected",
        "PYTHONPATH": "/tmp/python-inject",
        "PYTHONHOME": "/tmp/python-home",
        "PYINSTALLER_CONFIG_DIR": "/tmp/pyinstaller-inject",
        "PIP_INDEX_URL": "https://invalid.example/simple",
        "PIP_EXTRA_INDEX_URL": "https://invalid.example/extra",
        "PIP_CONFIG_FILE": "/tmp/pip.conf",
        "CARGO_HOME": "/tmp/ambient-cargo",
        "HOME": "/tmp/ambient-home",
        "HTTP_PROXY": "http://invalid.example",
        "HTTPS_PROXY": "http://invalid.example",
    }
    for key, value in poison.items():
        monkeypatch.setenv(key, value)
    repo_root = tmp_path / "repo"
    run = prepare(output_dir=tmp_path / "run", repo_root=repo_root)
    inputs = _offline_build_inputs(tmp_path)

    env = environment(run, inputs)

    assert env["HOME"] == str(run.root / "home")
    assert env["CARGO_HOME"] == str(inputs.cargo_home.resolve())
    assert env["PYINSTALLER_CONFIG_DIR"] == str(run.root / "cache/pyinstaller")
    assert env["PIP_NO_INDEX"] == "1"
    assert env["UV_OFFLINE"] == "1"
    for key, value in poison.items():
        if key not in {"HOME", "CARGO_HOME", "PYINSTALLER_CONFIG_DIR"}:
            assert env.get(key) != value


@pytest.mark.parametrize(
    "target",
    ["manifest_path", "main_binary", "bundled_sidecar", "standalone", "zip_path"],
)
def test_manifest_rejects_external_hardlink_to_manifest_or_artifact(
    manifest_tree: dict[str, Any],
    tmp_path: Path,
    target: str,
) -> None:
    path = manifest_tree[target]
    outside = tmp_path / f"outside-{target}"
    os.link(path, outside)

    errors = build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )
    assert any("link" in error for error in errors)


@pytest.mark.parametrize("relative", list(_BUILD_INPUT_RELATIVES))
def test_manifest_rejects_external_hardlink_to_lock_or_driver(
    manifest_tree: dict[str, Any],
    tmp_path: Path,
    relative: str,
) -> None:
    path = manifest_tree["repo_root"] / relative
    outside = tmp_path / f"outside-{path.name}"
    os.link(path, outside)

    errors = build_driver.verify_manifest(
        manifest_tree["manifest_path"], repo_root=manifest_tree["repo_root"]
    )
    assert any("link" in error for error in errors)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("Contents/Readme.txt", "contents/readme.txt"),
        ("Contents/Caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt", "Contents/Cafe\N{COMBINING ACUTE ACCENT}.txt"),
    ],
)
def test_zip_rejects_casefold_or_unicode_normalization_collision(
    tmp_path: Path,
    first: str,
    second: str,
) -> None:
    zip_path = tmp_path / "collision.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(
            _zip_member("JS Agent.app/", file_type=stat.S_IFDIR, mode=0o755), b""
        )
        archive.writestr(
            _zip_member("JS Agent.app/Contents/", file_type=stat.S_IFDIR, mode=0o755),
            b"",
        )
        archive.writestr(
            _zip_member(
                f"JS Agent.app/{first}", file_type=stat.S_IFREG, mode=0o644
            ),
            b"first",
        )
        archive.writestr(
            _zip_member(
                f"JS Agent.app/{second}", file_type=stat.S_IFREG, mode=0o644
            ),
            b"second",
        )

    with pytest.raises(RuntimeError, match="collision"):
        build_driver._zip_app_entries(zip_path, "JS Agent.app")


def _fake_closed_build_runner(
    calls: list[dict[str, Any]],
    *,
    fail_at: int | None,
) -> Callable[..., tuple[int, str, str]]:
    def runner(
        cmd: list[str],
        *,
        cwd: Path,
        env: dict[str, str] | None = None,
        timeout: int = 600,
    ) -> tuple[int, str, str]:
        call_index = len(calls)
        calls.append({"cmd": cmd, "cwd": cwd, "env": dict(env or {}), "timeout": timeout})
        if call_index == fail_at:
            return 77, "", f"fixture failure {call_index}"
        if "install" in cmd:
            tauri = cwd / "node_modules/.bin/tauri"
            tauri.parent.mkdir(parents=True, exist_ok=True)
            tauri.write_text("tauri-fixture\n", encoding="utf-8")
            tauri.chmod(0o700)
        elif "PyInstaller" in cmd:
            dist = Path(cmd[cmd.index("--distpath") + 1])
            name = cmd[cmd.index("--name") + 1]
            dist.mkdir(parents=True, exist_ok=True)
            (dist / name).write_bytes(b"sidecar-binary")
        elif len(cmd) > 1 and cmd[1] == "build":
            assert env is not None
            target = (
                Path(env["CARGO_TARGET_DIR"])
                / "aarch64-apple-darwin/release/bundle/macos/JS Agent.app"
            )
            main = target / "Contents/MacOS/js-agent-desktop"
            sidecar = target / "Contents/MacOS/js-agent-host"
            main.parent.mkdir(parents=True, exist_ok=True)
            main.write_bytes(b"rust-main")
            sidecar.write_bytes(b"sidecar-binary")
            _write_info_plist(target / "Contents/Info.plist", build_number="0")
        elif cmd[1:4] == ["-c", "-k", "--keepParent"]:
            _write_zip_from_app(Path(cmd[-2]), Path(cmd[-1]))
        return 0, "", ""

    return runner


@pytest.mark.parametrize("fail_at", [0, 1, 2, 3, 4, 5, 6])
def test_each_build_command_failure_has_no_retry_and_retains_invalid_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_at: int,
) -> None:
    repo_root = tmp_path / "repo"
    _write_release_inputs(repo_root)
    output = tmp_path / f"run-{fail_at}"
    sibling = tmp_path / "user-sibling.txt"
    sibling.write_bytes(b"preserve")
    inputs = _offline_build_inputs(tmp_path / f"inputs-{fail_at}")
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(build_driver, "verify_python_build_requirements", lambda *_a, **_k: None)

    with pytest.raises(RuntimeError, match=f"fixture failure {fail_at}"):
        build_driver.build_desktop(
            output_dir=output,
            build_number=BUILD_NUMBER,
            repo_root=repo_root,
            runner=_fake_closed_build_runner(calls, fail_at=fail_at),
            offline_inputs=inputs,
        )

    assert len(calls) == fail_at + 1
    assert output.is_dir()
    assert (output / ".js-agent-build-invalid-manual-cleanup").is_file()
    assert not (output / "manifest.json").exists()
    assert sibling.read_bytes() == b"preserve"
    for call in calls:
        assert "--online" not in call["cmd"]
        assert call["env"].get("HTTP_PROXY") is None
        assert call["env"].get("HTTPS_PROXY") is None


def test_fake_successful_build_binds_controlled_tools_caches_and_owner_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path / "repo"
    _write_release_inputs(repo_root)
    output = tmp_path / "successful-run"
    inputs = _offline_build_inputs(tmp_path / "inputs")
    calls: list[dict[str, Any]] = []
    ambient_poison = {
        "NODE_OPTIONS": "--require=/tmp/inject.js",
        "RUSTC_WRAPPER": "/tmp/wrapper",
        "RUSTFLAGS": "--cfg injected",
        "PYTHONPATH": "/tmp/python-inject",
        "PYTHONHOME": "/tmp/python-home",
        "PYINSTALLER_CONFIG_DIR": "/tmp/pyinstaller-inject",
        "PIP_INDEX_URL": "https://invalid.example/simple",
        "PIP_EXTRA_INDEX_URL": "https://invalid.example/extra",
        "PIP_CONFIG_FILE": "/tmp/pip.conf",
        "CARGO_HOME": "/tmp/ambient-cargo",
        "HOME": "/tmp/ambient-home",
        "HTTP_PROXY": "http://invalid.example",
        "HTTPS_PROXY": "http://invalid.example",
    }
    for key, value in ambient_poison.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(build_driver, "verify_python_build_requirements", lambda *_a, **_k: None)

    manifest_path = build_driver.build_desktop(
        output_dir=output,
        build_number=BUILD_NUMBER,
        repo_root=repo_root,
        runner=_fake_closed_build_runner(calls, fail_at=None),
        offline_inputs=inputs,
    )

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["build_number"] == BUILD_NUMBER
    assert payload["product_version"] == "0.1.0"
    info = plistlib.loads(
        (output / "artifacts/JS Agent.app/Contents/Info.plist").read_bytes()
    )
    assert info["CFBundleVersion"] == BUILD_NUMBER
    assert info["CFBundleShortVersionString"] == "0.1.0"
    environment = payload["build_environment"]
    assert environment["cargo_home"]["path"] == str(inputs.cargo_home.resolve())
    assert environment["pnpm_store"]["path"] == str(inputs.pnpm_store.resolve())
    assert environment["cargo"]["path"] == str(inputs.cargo_executable.resolve())
    assert environment["pnpm"]["path"] == str(inputs.pnpm_executable.resolve())
    assert environment["node"]["path"] == str(inputs.node_executable.resolve())
    assert environment["ditto"]["path"] == str(inputs.ditto_executable.resolve())
    assert environment["run_owner_marker_sha256"] == hashlib.sha256(
        (output / ".js-agent-build-owner").read_bytes()
    ).hexdigest()
    assert build_driver.verify_manifest(manifest_path, repo_root=repo_root) == []
    assert len(calls) == 7
    assert calls[4]["cmd"][:5] == [
        "/usr/bin/codesign",
        "-s",
        "-",
        "--force",
        "--deep",
    ]
    assert calls[5]["cmd"][:4] == [
        "/usr/bin/codesign",
        "--verify",
        "--deep",
        "--strict",
    ]
    for call in calls:
        for key, value in ambient_poison.items():
            assert call["env"].get(key) != value


def test_failed_final_verification_retains_only_an_invalid_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path / "repo"
    _write_release_inputs(repo_root)
    output = tmp_path / "failed-verification-run"
    inputs = _offline_build_inputs(tmp_path / "inputs")
    real_verify = build_driver.verify_manifest
    monkeypatch.setattr(
        build_driver,
        "verify_python_build_requirements",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        build_driver,
        "verify_manifest",
        lambda *_a, **_k: ["forced final verification failure"],
    )

    with pytest.raises(RuntimeError, match="forced final verification failure"):
        build_driver.build_desktop(
            output_dir=output,
            build_number=BUILD_NUMBER,
            repo_root=repo_root,
            runner=_fake_closed_build_runner([], fail_at=None),
            offline_inputs=inputs,
        )

    manifest = output / "manifest.json"
    assert manifest.is_file()
    assert (output / ".js-agent-build-invalid-manual-cleanup").is_file()
    assert any("invalid" in error for error in real_verify(manifest, repo_root=repo_root))

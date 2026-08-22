"""Gate wrapper for desktop_build: builds the .app and verifies manifest.

Outputs a release_markers result line so the gate receipt runner can parse it.
Tool paths are read from environment variables so the gate spec argv stays stable.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

from js.echo.ledger.release_gates import format_release_result_line


def _success_bindings(manifest_path: Path, manifest: dict[str, object]) -> dict[str, str]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("desktop manifest artifacts are missing")
    rust_main = artifacts.get("rust_main")
    app_tree = artifacts.get("app_tree")
    if not isinstance(rust_main, dict) or not isinstance(app_tree, dict):
        raise ValueError("desktop manifest app bindings are missing")
    app_sha = rust_main.get("sha256")
    tree_sha = app_tree.get("sha256")
    if not isinstance(app_sha, str) or not isinstance(tree_sha, str):
        raise ValueError("desktop manifest app binding digests are invalid")
    return {
        "desktop_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "app_tree_sha256": tree_sha,
        "app_sha256": app_sha,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Desktop build gate")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    pnpm = Path(os.environ.get("JS_AGENT_PNPM_EXECUTABLE", ""))
    cargo = Path(os.environ.get("JS_AGENT_CARGO_EXECUTABLE", ""))
    node = Path(os.environ.get("JS_AGENT_NODE_EXECUTABLE", ""))
    ditto = Path(os.environ.get("JS_AGENT_DITTO_EXECUTABLE", "/usr/bin/ditto"))
    cargo_home = Path(os.environ.get("JS_AGENT_CARGO_HOME", ""))
    pnpm_store = Path(os.environ.get("JS_AGENT_PNPM_STORE", ""))
    build_number_value = os.environ.get("JS_AGENT_BUILD_NUMBER")

    from desktop.build_driver import (
        OfflineBuildInputs,
        build_desktop,
        validate_build_number,
        verify_manifest,
    )

    try:
        build_number = validate_build_number(build_number_value)
    except RuntimeError as exc:
        print(f"[FAIL] desktop_build: {exc}", file=sys.stderr)
        print(format_release_result_line(gate="desktop_build", ok=False))
        return 1

    missing = [
        name
        for name, val in [
            ("pnpm", pnpm),
            ("cargo", cargo),
            ("node", node),
            ("cargo_home", cargo_home),
            ("pnpm_store", pnpm_store),
        ]
        if not val.is_file() and not val.is_dir()
    ]
    if missing:
        print(f"[FAIL] desktop_build: missing tool paths: {missing}", file=sys.stderr)
        print(format_release_result_line(gate="desktop_build", ok=False))
        return 1

    inputs = OfflineBuildInputs(
        pnpm_executable=pnpm,
        cargo_executable=cargo,
        node_executable=node,
        ditto_executable=ditto,
        cargo_home=cargo_home,
        pnpm_store=pnpm_store,
    )

    output_dir = args.output_dir or (args.evidence_dir / "desktop-build")

    # If the .app already exists, verify it instead of rebuilding.
    app_path = output_dir / "artifacts/JS Agent.app"
    manifest_path = output_dir / "manifest.json"
    if app_path.is_dir() and manifest_path.is_file():
        errors = verify_manifest(manifest_path, repo_root=Path(".").resolve())
        if errors:
            print(f"[FAIL] desktop_build: manifest verification failed: {errors}", file=sys.stderr)
            print(format_release_result_line(gate="desktop_build", ok=False))
            return 1
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("build_number") != build_number:
            print(
                "[FAIL] desktop_build: existing manifest build number does not "
                "match JS_AGENT_BUILD_NUMBER",
                file=sys.stderr,
            )
            print(format_release_result_line(gate="desktop_build", ok=False))
            return 1
        source_digest = manifest.get("source_digest", "")
        print(f"[OK] desktop_build manifest={manifest_path} digest={source_digest[:16]}")
        print(
            format_release_result_line(
                gate="desktop_build",
                ok=True,
                bindings=_success_bindings(manifest_path, manifest),
            )
        )
        return 0

    try:
        manifest_path = build_desktop(
            output_dir=output_dir,
            build_number=build_number,
            offline_inputs=inputs,
        )
    except RuntimeError as exc:
        print(f"[FAIL] desktop_build: {exc}", file=sys.stderr)
        print(format_release_result_line(gate="desktop_build", ok=False))
        return 1

    manifest = json.loads(manifest_path.read_text())
    errors = verify_manifest(manifest_path, repo_root=Path(".").resolve())
    if errors:
        print(f"[FAIL] desktop_build: manifest verification failed: {errors}", file=sys.stderr)
        print(format_release_result_line(gate="desktop_build", ok=False))
        return 1

    source_digest = manifest.get("source_digest", "")
    print(f"[OK] desktop_build manifest={manifest_path} digest={source_digest[:16]}")
    print(
        format_release_result_line(
            gate="desktop_build",
            ok=True,
            bindings=_success_bindings(manifest_path, manifest),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

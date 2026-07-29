#!/usr/bin/env python3
"""Generate local release evidence for Echo 2.0.

The generated files are local engineering artifacts. They do not replace
external FTO, clean-room, security-audit, or red-team approvals.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SECURITY_DIR = ROOT / "docs" / "security"
LOCKFILE = ROOT / "uv.lock"


@dataclass(frozen=True)
class PackageEvidence:
    name: str
    version: str
    source: str
    license_text: str
    classifiers: tuple[str, ...]
    hashes: tuple[str, ...]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Echo 2.0 release evidence.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not update evidence artifacts; run gates in disposable temporary state.",
    )
    args = parser.parse_args()

    SECURITY_DIR.mkdir(parents=True, exist_ok=True)
    packages = read_lock_packages()
    current_time = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if args.check:
        now = _existing_generated_at(SECURITY_DIR / "SBOM.spdx.json")
        if now is None:
            print("release evidence is stale: docs/security/SBOM.spdx.json", file=sys.stderr)
            return 1
    else:
        now = current_time
    base_generated = generate_static_artifacts(packages, now)
    if not args.check:
        for path, content in base_generated.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    generated = generate_all(packages, now)
    if args.check:
        stale = [
            str(path.relative_to(ROOT))
            for path, content in generated.items()
            if not path.exists() or path.read_text(encoding="utf-8") != content
        ]
        if stale:
            print("release evidence is stale:", ", ".join(stale), file=sys.stderr)
            return 1
        return 0

    for path, content in generated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print("generated release evidence:")
    for path in generated:
        print(f"- {path.relative_to(ROOT)}")
    return 0


def _existing_generated_at(sbom_path: Path) -> str | None:
    """Return the timestamp embedded in an existing SBOM for deterministic checks."""
    try:
        payload = json.loads(sbom_path.read_text(encoding="utf-8"))
        created = payload["creationInfo"]["created"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(created, str) or not created.strip():
        return None
    return created


def generate_static_artifacts(packages: list[PackageEvidence], now: str) -> dict[Path, str]:
    return {
        SECURITY_DIR / "SBOM.spdx.json": json.dumps(
            build_spdx(packages, now),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        SECURITY_DIR / "LICENSE_SCAN.md": render_license_scan(packages, now),
    }


def generate_all(packages: list[PackageEvidence], now: str) -> dict[Path, str]:
    commands = collect_command_evidence()
    return {
        **generate_static_artifacts(packages, now),
        SECURITY_DIR / "FTO_PRECHECK.md": render_fto_precheck(packages, now, commands),
        SECURITY_DIR / "CLEAN_ROOM_PACKET.md": render_clean_room_packet(now, commands),
        SECURITY_DIR / "LOCAL_SECURITY_AUDIT.md": render_local_security_audit(now, commands),
        SECURITY_DIR / "LOCAL_REDTEAM_SIMULATION.md": render_local_redteam(now, commands),
    }


def read_lock_packages() -> list[PackageEvidence]:
    raw = tomllib.loads(LOCKFILE.read_text(encoding="utf-8"))
    raw_packages = raw.get("package")
    _validate_lock_package_set(raw_packages)
    assert isinstance(raw_packages, list)
    packages: list[PackageEvidence] = []
    for pkg in raw_packages:
        name = str(pkg["name"])
        version = str(pkg.get("version", "0"))
        source = _source_name(pkg.get("source", {}))
        license_text, classifiers = _license_metadata(name, version)
        hashes = tuple(_artifact_hashes(pkg))
        packages.append(
            PackageEvidence(
                name=name,
                version=version,
                source=source,
                license_text=license_text,
                classifiers=classifiers,
                hashes=hashes,
            )
        )
    return sorted(packages, key=lambda p: (p.name.lower(), p.version))


def _validate_lock_package_set(raw_packages: object) -> None:
    if not isinstance(raw_packages, list) or not raw_packages:
        raise ValueError("uv.lock contains no packages")

    package_names: set[str] = set()
    dependency_names: set[str] = set()
    for package in raw_packages:
        if not isinstance(package, dict):
            raise ValueError("uv.lock contains an invalid package entry")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("uv.lock contains a package without a name")
        if not isinstance(version, str) or not version.strip():
            raise ValueError(f"uv.lock package {name!r} has no version")
        normalized_name = _normalize_package_name(name)
        if normalized_name in package_names:
            raise ValueError(f"uv.lock contains duplicate package {name!r}")
        package_names.add(normalized_name)

        dependencies = package.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise ValueError(f"uv.lock package {name!r} has invalid dependencies")
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                raise ValueError(f"uv.lock package {name!r} has an invalid dependency entry")
            dependency_name = dependency.get("name")
            if not isinstance(dependency_name, str) or not dependency_name.strip():
                raise ValueError(f"uv.lock package {name!r} has a dependency without a name")
            dependency_names.add(_normalize_package_name(dependency_name))

    missing_dependencies = sorted(dependency_names - package_names)
    if missing_dependencies:
        raise ValueError(
            "uv.lock package set is incomplete; missing dependency entries: "
            + ", ".join(missing_dependencies)
        )


def _normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _source_name(source: object) -> str:
    if not isinstance(source, dict):
        return "NOASSERTION"
    if registry := source.get("registry"):
        return str(registry)
    if editable := source.get("editable"):
        return f"editable:{editable}"
    if git := source.get("git"):
        return f"git:{git}"
    return "NOASSERTION"


def _license_metadata(name: str, locked_version: str) -> tuple[str, tuple[str, ...]]:
    try:
        dist = metadata.distribution(name)
    except metadata.PackageNotFoundError:
        return "NOASSERTION", ()
    if str(dist.version) != locked_version:
        return "NOASSERTION", ()
    meta = dist.metadata
    classifiers = tuple(
        classifier
        for classifier in meta.get_all("Classifier", [])
        if classifier.startswith("License ::")
    )
    expression = (meta.get("License-Expression") or "").strip()
    declared = (meta.get("License") or "").strip()
    if expression:
        license_text = expression
    elif classifiers:
        license_text = "; ".join(classifiers)
    elif declared and "\n" not in declared and len(declared) <= 120:
        license_text = declared
    elif declared:
        first_line = next((line.strip() for line in declared.splitlines() if line.strip()), "")
        license_text = first_line[:120] if first_line else "Custom/See package metadata"
    else:
        license_text = "NOASSERTION"
    return license_text or "NOASSERTION", classifiers


def _artifact_hashes(pkg: dict[str, Any]) -> list[str]:
    hashes: list[str] = []
    sdist = pkg.get("sdist")
    if isinstance(sdist, dict) and isinstance(sdist.get("hash"), str):
        hashes.append(sdist["hash"])
    wheels = pkg.get("wheels")
    if isinstance(wheels, list):
        for wheel in wheels:
            if isinstance(wheel, dict) and isinstance(wheel.get("hash"), str):
                hashes.append(wheel["hash"])
    return sorted(set(hashes))


def build_spdx(packages: list[PackageEvidence], created_at: str) -> dict[str, Any]:
    document_name = "js-agent-echo-2.0-local-sbom"
    package_nodes = [
        {
            "SPDXID": f"SPDXRef-Package-{_spdx_id(pkg.name)}-{_spdx_id(pkg.version)}",
            "name": pkg.name,
            "versionInfo": pkg.version,
            "downloadLocation": pkg.source,
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": _spdx_license_value(pkg.license_text),
            "licenseComments": f"Raw package metadata: {pkg.license_text}",
            "copyrightText": "NOASSERTION",
            "checksums": _spdx_checksums(pkg.hashes),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/{pkg.name}@{pkg.version}",
                }
            ],
        }
        for pkg in packages
    ]
    root_spdxid = "SPDXRef-Package-js-agent"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": document_name,
        "documentNamespace": (
            "https://example.invalid/js-agent/sbom/"
            + hashlib.sha256(f"{document_name}:{created_at}".encode()).hexdigest()
        ),
        "creationInfo": {
            "created": created_at,
            "creators": ["Tool: scripts/generate_release_evidence.py"],
            "comment": (
                "Local lockfile-derived SBOM. This artifact is not an external "
                "legal or license-review approval."
            ),
        },
        "packages": [
            {
                "SPDXID": root_spdxid,
                "name": "js-agent",
                "versionInfo": "0.1.5",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": "NOASSERTION",
            },
            *package_nodes,
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": root_spdxid,
            },
            *[
                {
                    "spdxElementId": root_spdxid,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": package["SPDXID"],
                }
                for package in package_nodes
            ],
        ],
    }


def _spdx_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]", "-", value)


def _spdx_license_value(value: str) -> str:
    stripped = value.strip()
    if not stripped or stripped == "NOASSERTION":
        return "NOASSERTION"
    classifier_map = {
        "License :: OSI Approved :: MIT License": "MIT",
        "License :: OSI Approved :: Apache Software License": "Apache-2.0",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": (
            "LGPL-3.0-only"
        ),
        "License :: OSI Approved :: ISC License (ISCL)": "ISC",
        "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    }
    if mapped := classifier_map.get(stripped):
        return mapped
    classifier_values = {
        classifier_map[part]
        for part in stripped.split("; ")
        if part in classifier_map
    }
    if len(classifier_values) == 1 and all(
        part in classifier_map for part in stripped.split("; ")
    ):
        return classifier_values.pop()
    if re.fullmatch(r"[A-Za-z0-9-.+]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9-.+]+)*", stripped):
        return stripped
    return "NOASSERTION"


def _spdx_checksums(hashes: tuple[str, ...]) -> list[dict[str, str]]:
    checksums: list[dict[str, str]] = []
    for digest in hashes:
        if digest.startswith("sha256:"):
            checksums.append({"algorithm": "SHA256", "checksumValue": digest.split(":", 1)[1]})
    return checksums[:8]


def render_license_scan(packages: list[PackageEvidence], created_at: str) -> str:
    strong_markers = ("AGPL", "GPL")
    weak_markers = ("LGPL", "MPL", "EPL", "CDDL")
    restrictive_markers = ("SSPL", "BUSL")
    rows = []
    strong = []
    weak = []
    restrictive = []
    noassertion = []
    for pkg in packages:
        text = pkg.license_text
        if text == "NOASSERTION":
            noassertion.append(pkg.name)
        if any(_license_marker(text, marker) for marker in strong_markers):
            strong.append(f"{pkg.name} ({text})")
        elif any(_license_marker(text, marker) for marker in weak_markers):
            weak.append(f"{pkg.name} ({text})")
        elif any(_license_marker(text, marker) for marker in restrictive_markers):
            restrictive.append(f"{pkg.name} ({text})")
        rows.append(f"| `{pkg.name}` | `{pkg.version}` | {text} |")
    strong_text = "None detected." if not strong else "; ".join(strong)
    weak_text = "None detected." if not weak else "; ".join(weak)
    restrictive_text = "None detected." if not restrictive else "; ".join(restrictive)
    noassert_text = ", ".join(f"`{name}`" for name in noassertion) or "None"
    return "\n".join(
        [
            "# License Scan",
            "",
            "Status: COMPLETE_LOCAL_SCAN_EXTERNAL_REVIEW_REQUIRED",
            f"Generated: {created_at}",
            f"Source: `{LOCKFILE.relative_to(ROOT)}` plus installed package metadata when available.",
            "",
            "This local scan does not replace legal or dependency-license review.",
            "",
            "## Summary",
            "",
            f"- Packages scanned: {len(packages)}",
            f"- Strong copyleft markers: {strong_text}",
            f"- Weak/file-level reciprocal markers: {weak_text}",
            f"- Restrictive source-available markers: {restrictive_text}",
            f"- Unknown license metadata: {noassert_text}",
            "",
            "## Package Table",
            "",
            "| Package | Version | License metadata |",
            "| --- | --- | --- |",
            *rows,
            "",
        ]
    )


def _license_marker(text: str, marker: str) -> bool:
    return re.search(rf"(?<![A-Z]){re.escape(marker)}(?:[^A-Z]|$)", text.upper()) is not None


def render_fto_precheck(
    packages: list[PackageEvidence],
    created_at: str,
    commands: dict[str, str],
) -> str:
    return "\n".join(
        [
            "# FTO Precheck Packet",
            "",
            "Status: COMPLETE_LOCAL_PRECHECK_EXTERNAL_FTO_REQUIRED",
            f"Generated: {created_at}",
            "",
            "This packet is engineering input for outside counsel or an external FTO reviewer. It is not legal advice and is not an FTO approval.",
            "",
            "## Materials Prepared",
            "",
            "- `ORIGIN_LEDGER.md` records Echo 2.0 engineering-origin boundaries and non-claims.",
            "- `THIRD_PARTY_NOTICES.md` records newly added runtime dependency posture.",
            "- `docs/echo/ECHO_SELF_DEVELOPED_BOUNDARY.md` defines the guarded engineering-originality boundary.",
            "- `docs/security/ECHO_2_CLEAN_ROOM.md` records project-specific API avoidance rules.",
            "- `docs/security/SBOM.spdx.json` records lockfile-derived package inventory.",
            "- `docs/security/LICENSE_SCAN.md` records local dependency license metadata.",
            "",
            "## Local Gate Evidence",
            "",
            _command_block(commands.get("readiness", "")),
            "",
            "## Dependency Scope",
            "",
            f"- Lockfile packages inventoried: {len(packages)}",
            "- Source package: `js-agent` declared license is MIT in `pyproject.toml`.",
            "",
            "## Required External Review",
            "",
            "Outside review must decide copyright provenance, patent/FTO, trademark/name risk, dependency-license acceptability, and publication wording before stable GitHub release.",
            "",
        ]
    )


def render_clean_room_packet(created_at: str, commands: dict[str, str]) -> str:
    return "\n".join(
        [
            "# Clean-Room Reviewer Packet",
            "",
            "Status: COMPLETE_LOCAL_PACKET_EXTERNAL_REVIEW_REQUIRED",
            f"Generated: {created_at}",
            "",
            "This packet prepares the independent clean-room review. It is not reviewer sign-off.",
            "",
            "## Scope For Reviewer",
            "",
            "- `js/echo/`",
            "- `js/agent/`, `js/models/`, `js/tools/`, and `js/web/` adapters",
            "- `js_work/` product isolation",
            "- `tests/echo/` and `tests/work/`",
            "- `scripts/echo_ledger_smoke.py`",
            "- `scripts/echo_smoke.py`",
            "- `scripts/echo_architecture_benchmark.py`",
            "- `ORIGIN_LEDGER.md`",
            "- `docs/security/ECHO_2_CLEAN_ROOM.md`",
            "",
            "## Local Automated Boundary Check",
            "",
            _command_block(commands.get("ip_boundary", "")),
            "",
            "## Reviewer Decision Needed",
            "",
            "The external reviewer must independently confirm that no copied source code, prompt templates, class hierarchies, API signatures, example flows, golden traces, or benchmark data were introduced.",
            "",
        ]
    )


def render_local_security_audit(created_at: str, commands: dict[str, str]) -> str:
    return "\n".join(
        [
            "# Local Security Audit Packet",
            "",
            "Status: COMPLETE_LOCAL_AUDIT_EXTERNAL_AUDIT_REQUIRED",
            f"Generated: {created_at}",
            "",
            "This is a local engineering audit packet for Echo 2.0. It does not replace an external security audit.",
            "",
            "## Local Controls Covered",
            "",
            "- Echo model boundary authorization through `ScopeGate`.",
            "- Tool execution `CapabilityLease` issue/verify/consume path.",
            "- Owner/session-scoped upload list, preview, delete, and chat attachment resolution.",
            "- WebSocket and HTTP owner/session locks.",
            "- Vision upload pre-read size and policy checks.",
            "- Frame/journal MAC verification, corrupt-tail recovery, compaction, and health counters.",
            "- Echo IP boundary and release readiness gates.",
            "",
            "## Evidence",
            "",
            "### Security Matrix",
            "",
            _command_block(commands.get("security_matrix", "")),
            "",
            "### Core Regression",
            "",
            _command_block(commands.get("core_tests", "")),
            "",
            "### Static Quality",
            "",
            _command_block(commands.get("quality", "")),
            "",
            "## External Audit Needed",
            "",
            "An external auditor must still assess threat coverage, code paths, deployment assumptions, dependency advisories, and residual risk.",
            "",
        ]
    )


def render_local_redteam(created_at: str, commands: dict[str, str]) -> str:
    return "\n".join(
        [
            "# Local Red-Team Simulation Packet",
            "",
            "Status: COMPLETE_LOCAL_SIMULATION_REAL_REDTEAM_REQUIRED",
            f"Generated: {created_at}",
            "",
            "This packet records local adversarial simulation evidence. It is not a real independent red-team report.",
            "",
            "## Attack Families Simulated Locally",
            "",
            "- Prompt injection and secret exfiltration before model call.",
            "- Attachment owner/session bypass.",
            "- Tool lease missing, tampered, cross-run, and args-mismatch paths.",
            "- WebSocket terminal ordering and same-session concurrency.",
            "- Journal corrupt tail, replay, claim/receipt/merge, and compaction behavior.",
            "- Sandbox real-process backend probe.",
            "- Echo self-developed/IP boundary drift.",
            "",
            "## Evidence",
            "",
            "### Echo Ledger Smoke",
            "",
            _command_block(commands.get("echo_ledger_smoke", "")),
            "",
            "### Release Smoke",
            "",
            _command_block(commands.get("release_smoke", "")),
            "",
            "### Benchmark And Safety Matrix",
            "",
            "See `docs/security/ECHO_SLO_BENCHMARK.json` for latest benchmark artifact and 25-case security matrix result.",
            "",
            "## Real Red-Team Needed",
            "",
            "A real red team must still attack a deployed or deployment-like environment with independent operators and retest closure.",
            "",
        ]
    )


def collect_command_evidence() -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="js-agent-echo-evidence-") as temporary_state:
        commands = {
            "ip_boundary": [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    "from js.echo.ledger.release_gates import verify_echo_ip_boundary; "
                    "r=verify_echo_ip_boundary(Path('.')); "
                    "print(f'ip_ok={r.ok} findings={len(r.findings)}')"
                ),
            ],
            "readiness": [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    "from js.echo.ledger.release_gates import verify_release_readiness; "
                    "r=verify_release_readiness(Path('.')); "
                    "print(f'internal_ready={r.internal_ready} stable_ready={r.stable_ready}'); "
                    "print('passed=' + ','.join(r.passed)); "
                    "print('external_blockers=' + ','.join(r.external_blockers))"
                ),
            ],
            "security_matrix": [
                sys.executable,
                "-c",
                (
                    "from js.echo.ledger.security_matrix import run_security_matrix; "
                    "r=run_security_matrix(); "
                    "print(f'ok={r.ok} passed={r.passed} total={r.total} failed={r.failed}')"
                ),
            ],
            "core_tests": [
                sys.executable,
                "-m",
                "pytest",
                "tests/echo/ledger/test_release_gates.py",
                "tests/echo/ledger/test_security_matrix.py",
                "tests/echo/ledger/test_web_status.py",
                "-q",
            ],
            "quality": [
                str(ROOT / ".venv" / "bin" / "ruff"),
                "check",
                "js/echo",
                "js/agent",
                "js/models",
                "js/tools",
                "js/web",
                "js_work",
                "tests/echo",
                "tests/work",
                "scripts/echo_ledger_smoke.py",
            ],
            "echo_ledger_smoke": [
                sys.executable,
                "scripts/echo_ledger_smoke.py",
                "--turns",
                "5",
                "--state-dir",
                temporary_state,
            ],
            "release_smoke": [sys.executable, "scripts/release_smoke.py", "--all"],
        }
        output: dict[str, str] = {}
        for name, command in commands.items():
            output[name] = _run_capture(command, evidence_name=name)
        return output


def _run_capture(command: list[str], *, evidence_name: str = "") -> str:
    env_python = str(ROOT / ".venv" / "bin" / "python")
    if command[0] == sys.executable:
        command = [env_python, *command[1:]]
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=240,
        check=False,
    )
    command_for_display = list(command)
    if evidence_name == "echo_ledger_smoke" and "--state-dir" in command_for_display:
        state_index = command_for_display.index("--state-dir") + 1
        command_for_display[state_index] = "<temporary-state-dir>"
    cmd_text = " ".join(command_for_display)
    body = _trim_output(_normalize_command_output(evidence_name, result.stdout.strip()))
    return f"$ {cmd_text}\nexit={result.returncode}\n{body}"


def _normalize_command_output(evidence_name: str, output: str) -> str:
    """Remove nondeterministic noise while preserving release-gate outcomes."""
    if evidence_name == "release_smoke":
        kept: list[str] = []
        for line in output.splitlines():
            stripped = line.strip()
            if (
                stripped.startswith("[检查]")
                or stripped.startswith("[OK]")
                or stripped.startswith("[失败]")
                or stripped == "发布烟测通过。"
            ):
                kept.append(stripped)
        return "\n".join(kept)

    if evidence_name == "echo_ledger_smoke":
        output = re.sub(
            r"journal=\S+/echo/ledger/chat\.jsonl",
            "journal=<temporary-state-dir>/echo/ledger/chat.jsonl",
            output,
        )

    normalized = re.sub(r"\bin \d+(?:\.\d+)?s\b", "in <elapsed>s", output)
    normalized = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
        "<uuid>",
        normalized,
    )
    return normalized


def _trim_output(output: str, *, max_lines: int = 90) -> str:
    lines = output.splitlines()
    if len(lines) <= max_lines:
        return output
    head = lines[:25]
    tail = lines[-55:]
    omitted = len(lines) - len(head) - len(tail)
    return "\n".join([*head, f"... <{omitted} lines omitted> ...", *tail])


def _command_block(text: str) -> str:
    return "```text\n" + text.strip() + "\n```"


if __name__ == "__main__":
    raise SystemExit(main())

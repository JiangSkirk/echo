from __future__ import annotations

import shlex
import tomllib
from pathlib import Path, PurePosixPath

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def _docker_instructions() -> list[tuple[str, str]]:
    instructions: list[tuple[str, str]] = []
    pending = ""

    for raw_line in (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        pending = f"{pending} {line}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue

        instruction, _, arguments = pending.partition(" ")
        instructions.append((instruction.upper(), arguments))
        pending = ""

    assert not pending, "Dockerfile ends with an incomplete instruction"
    return instructions


def _copy_sources(arguments: str) -> set[PurePosixPath]:
    tokens = shlex.split(arguments)
    while tokens and tokens[0].startswith("--"):
        tokens.pop(0)
    assert len(tokens) >= 2, f"invalid COPY instruction: {arguments}"
    return {PurePosixPath(source.removeprefix("./")) for source in tokens[:-1]}


def _is_copied(package: str, sources: set[PurePosixPath]) -> bool:
    package_path = PurePosixPath(package)
    return any(
        source == PurePosixPath(".") or package_path.is_relative_to(source) for source in sources
    )


def test_docker_copies_declared_runtime_packages_before_install() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    packages = set(project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"])
    scripts = project["project"]["scripts"]
    instructions = _docker_instructions()

    assert {"js", "js_work"} <= packages

    install_index = next(
        index
        for index, (instruction, arguments) in enumerate(instructions)
        if instruction == "RUN" and ("pip install" in arguments or "uv sync" in arguments)
    )
    copied_sources = {
        source
        for instruction, arguments in instructions[:install_index]
        if instruction == "COPY" and "--from=" not in arguments
        for source in _copy_sources(arguments)
    }
    missing_packages = sorted(
        package for package in packages if not _is_copied(package, copied_sources)
    )
    assert not missing_packages, (
        "Docker image installs the project before copying declared runtime packages: "
        f"{missing_packages}"
    )

    # The wheel build force-includes resources/tokenizer; the Dockerfile must
    # COPY it before the install or the image build fails outright.
    force_includes = set(
        project["tool"]["hatch"]["build"]["targets"]["wheel"].get("force-include", {})
    )
    missing_includes = sorted(
        source for source in force_includes if not _is_copied(source, copied_sources)
    )
    assert not missing_includes, (
        f"Docker image installs the project before copying force-included paths: {missing_includes}"
    )

    entry_module = scripts["js-work"].partition(":")[0]
    entry_package = entry_module.partition(".")[0]
    entry_path = REPO_ROOT.joinpath(*entry_module.split(".")).with_suffix(".py")
    assert entry_package in packages
    assert _is_copied(entry_package, copied_sources)
    assert entry_path.is_file(), f"js-work entry module is missing: {entry_path}"


def test_compose_persists_production_work_home() -> None:
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yaml").read_text(encoding="utf-8"))
    volumes = compose["services"]["js-agent"]["volumes"]
    mounts = [str(volume).rsplit(":", 1)[-1] for volume in volumes]
    assert "/home/appuser/.js-work" in mounts

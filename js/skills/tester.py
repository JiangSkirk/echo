"""Skill test generation and execution framework.

Automatically generates pytest-compatible test stubs for code skills,
and provides execution harnesses for prompt / workflow skills.
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from js.echo.os_sandbox import SandboxExecutor
from js.skills.spec import SkillSpec, SkillType, parse_skill_manifest
from js.utils.log import get_logger

logger = get_logger("js.skills.tester")


@dataclass
class TestResult:
    """Result of a single test case."""

    name: str
    passed: bool
    output: str = ""
    error: str = ""
    duration_ms: float = 0.0


@dataclass
class TestReport:
    """Complete test report for a skill."""

    skill_id: str
    results: list[TestResult] = field(default_factory=list)
    generated_tests: list[Path] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "passed": self.passed,
            "summary": {"pass": self.pass_count, "fail": self.fail_count},
            "tests": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "output": r.output,
                    "error": r.error,
                    "duration_ms": r.duration_ms,
                }
                for r in self.results
            ],
        }

    def print_report(self) -> None:
        """Print a human-readable report."""
        status = "✅ PASSED" if self.passed else "❌ FAILED"
        print(f"\n{'=' * 50}")
        print(f"Test Report: {self.skill_id}")
        print(f"Status: {status}")
        print(f"Pass: {self.pass_count} | Fail: {self.fail_count}")
        print(f"{'=' * 50}")
        for r in self.results:
            icon = "✅" if r.passed else "❌"
            print(f"  {icon} {r.name} ({r.duration_ms:.0f}ms)")
            if r.error:
                print(f"     Error: {r.error[:200]}")
        print()


# ---------------------------------------------------------------------------
# Test generation
# ---------------------------------------------------------------------------


def generate_tests(skill_dir: Path, output_dir: Path | None = None) -> list[Path]:
    """Generate test stubs for a skill.

    Returns:
        List of generated test file paths.
    """
    manifest = skill_dir / "SKILL.md"
    if not manifest.exists():
        raise FileNotFoundError(f"SKILL.md not found in {skill_dir}")

    spec = parse_skill_manifest(manifest)
    generated: list[Path] = []

    if spec.type == SkillType.CODE:
        generated.append(_generate_code_tests(spec, skill_dir, output_dir))
    elif spec.type == SkillType.PROMPT:
        generated.append(_generate_prompt_tests(spec, skill_dir, output_dir))
    elif spec.type == SkillType.WORKFLOW:
        generated.append(_generate_workflow_tests(spec, skill_dir, output_dir))
    elif spec.type == SkillType.META:
        generated.append(_generate_meta_tests(spec, skill_dir, output_dir))

    return generated


def _generate_code_tests(spec: SkillSpec, skill_dir: Path, output_dir: Path | None) -> Path:
    """Generate pytest stubs for a code skill."""
    out = output_dir or skill_dir
    test_file = out / f"test_{spec.id.replace('-', '_')}.py"

    params = (spec.metadata or {}).get("parameters") or []

    # Build test cases from parameters (indented 8 spaces for method body)
    test_cases = ""
    for p in params:
        pname = p["name"]
        ptype = p.get("type", "string")
        if ptype == "boolean":
            test_cases += f"\n        # Test --{pname} flag\n"
            test_cases += f"        result = run_skill(['--{pname}'], workspace=tmp_path)\n"
            test_cases += "        assert result is not None\n"
        elif ptype == "integer":
            test_cases += f"\n        # Test --{pname} with integer\n"
            test_cases += f"        result = run_skill(['--{pname}', '42'], workspace=tmp_path)\n"
            test_cases += "        assert result is not None\n"
        else:
            test_cases += f"\n        # Test --{pname} with string\n"
            test_cases += f"        result = run_skill(['--{pname}', 'test_value'], workspace=tmp_path)\n"
            test_cases += "        assert result is not None\n"

    if not test_cases:
        test_cases = "        # TODO: Add test cases for your skill\n        result = run_skill([], workspace=tmp_path)\n        assert result is not None\n"

    content = f'''"""Auto-generated tests for {spec.id}.

Run with: pytest {test_file.name} -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).parent


def run_skill(args: list[str], workspace: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Helper to run the skill entry point."""
    env = os.environ.copy()
    env["JS_SKILL_ARGS"] = json.dumps({{a.lstrip("-").replace("-", "_"): a for a in args}})
    env["JS_SKILL_WORKSPACE"] = str(workspace or SKILL_DIR)

    cmd = [sys.executable, str(SKILL_DIR / "{spec.entry}")] + args
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(SKILL_DIR),
        timeout=30,
    )


class Test{spec.id.replace("-", "_").title()}:
    """Tests for {spec.name}."""

    def test_entry_file_exists(self) -> None:
        assert (SKILL_DIR / "{spec.entry}").exists()

    def test_skill_md_exists(self) -> None:
        assert (SKILL_DIR / "SKILL.md").exists()

    def test_basic_execution(self, tmp_path: Path) -> None:
        """Smoke test: skill runs without crashing."""
{test_cases}

    def test_help_flag(self) -> None:
        """Test that --help works."""
        result = run_skill(["--help"])
        assert result.returncode == 0, f"Help failed: {{result.stderr}}"
        assert "usage:" in result.stdout.lower()
'''

    test_file.write_text(content, encoding="utf-8")
    logger.info(f"Generated code tests: {test_file}")
    return test_file


def _generate_prompt_tests(spec: SkillSpec, skill_dir: Path, output_dir: Path | None) -> Path:
    """Generate evaluation framework for a prompt skill."""
    out = output_dir or skill_dir
    test_file = out / f"test_{spec.id.replace('-', '_')}_eval.py"

    content = f'''"""Auto-generated evaluation for prompt skill: {spec.id}.

Run with: pytest {test_file.name} -v

These tests check that the prompt skill:
1. Has required sections
2. Contains no obvious template errors
3. Has valid bounded frontmatter fields
"""

from __future__ import annotations

from pathlib import Path
import re

SKILL_DIR = Path(__file__).parent
MANIFEST = SKILL_DIR / "SKILL.md"
MANIFEST_TEXT = MANIFEST.read_text(encoding="utf-8")


def frontmatter_field(name: str) -> str:
    match = re.search(r"^" + re.escape(name) + r":\\s*(.+)$", MANIFEST_TEXT, re.MULTILINE)
    assert match is not None
    return match.group(1).strip()


class Test{spec.id.replace("-", "_").title()}:
    def test_manifest_loads(self) -> None:
        assert frontmatter_field("id") == {spec.id!r}
        assert frontmatter_field("name") == {spec.name!r}

    def test_has_instructions(self) -> None:
        body = MANIFEST_TEXT.split("---", 2)[-1]
        assert len(body.strip()) > 50

    def test_no_broken_placeholders(self) -> None:
        """Check for unmatched template variables like {{{{var}}}}."""
        body = MANIFEST_TEXT.split("---", 2)[-1]
        broken = re.findall(r"{{{{[^{{}}]+}}}}", body)
        # Allow known good patterns if needed
        assert not broken, f"Possible broken placeholders: {{broken}}"

    def test_has_example_or_usage(self) -> None:
        """Prompt skills should include example usage."""
        content_lower = MANIFEST_TEXT.split("---", 2)[-1].lower()
        has_example = any(k in content_lower for k in ["example", "usage", "when the user"])
        assert has_example, "Prompt should include example usage guidance"
'''

    test_file.write_text(content, encoding="utf-8")
    logger.info(f"Generated prompt tests: {test_file}")
    return test_file


def _generate_workflow_tests(spec: SkillSpec, skill_dir: Path, output_dir: Path | None) -> Path:
    """Generate tests for a workflow skill."""
    out = output_dir or skill_dir
    test_file = out / f"test_{spec.id.replace('-', '_')}_workflow.py"

    steps = []
    if spec.metadata and "workflow" in spec.metadata:
        steps = spec.metadata["workflow"].get("steps", [])

    step_tests = ""
    for i, step in enumerate(steps[:5], 1):
        stype = step.get("type", "prompt")
        step_tests += f"\n    def test_step_{i}_type(self) -> None:\n"
        step_tests += f"        assert {'type: ' + str(stype)!r} in MANIFEST_TEXT\n"

    if not step_tests:
        step_tests = "    def test_has_at_least_one_step(self) -> None:\n        assert 'steps:' in MANIFEST_TEXT\n"

    content = f'''"""Auto-generated tests for workflow skill: {spec.id}.

Run with: pytest {test_file.name} -v
"""

from __future__ import annotations

from pathlib import Path

SKILL_DIR = Path(__file__).parent
MANIFEST = SKILL_DIR / "SKILL.md"
MANIFEST_TEXT = MANIFEST.read_text(encoding="utf-8")


class Test{spec.id.replace("-", "_").title()}:
    def test_manifest_loads(self) -> None:
        assert {'id: ' + spec.id!r} in MANIFEST_TEXT
        assert "type: workflow" in MANIFEST_TEXT

    def test_has_workflow_definition(self) -> None:
        assert "workflow:" in MANIFEST_TEXT
        assert "steps:" in MANIFEST_TEXT
{step_tests}
'''

    test_file.write_text(content, encoding="utf-8")
    logger.info(f"Generated workflow tests: {test_file}")
    return test_file


def _generate_meta_tests(spec: SkillSpec, skill_dir: Path, output_dir: Path | None) -> Path:
    """Generate tests for a meta skill."""
    out = output_dir or skill_dir
    test_file = out / f"test_{spec.id.replace('-', '_')}_meta.py"

    deps = spec.dependencies or []
    dep_tests = ""
    for dep in deps[:5]:
        dep_tests += f"        assert {dep!r} in MANIFEST_TEXT\n"

    if not dep_tests:
        dep_tests = "        assert False, 'No dependencies declared — meta skills should compose other skills'\n"

    content = f'''"""Auto-generated tests for meta skill: {spec.id}.

Run with: pytest {test_file.name} -v
"""

from __future__ import annotations

from pathlib import Path

SKILL_DIR = Path(__file__).parent
MANIFEST = SKILL_DIR / "SKILL.md"
MANIFEST_TEXT = MANIFEST.read_text(encoding="utf-8")


class Test{spec.id.replace("-", "_").title()}:
    def test_manifest_loads(self) -> None:
        assert {'id: ' + spec.id!r} in MANIFEST_TEXT
        assert "type: meta" in MANIFEST_TEXT

    def test_has_dependencies(self) -> None:
{dep_tests}

    def test_dependency_ids_valid(self) -> None:
        """Dependency IDs should be kebab-case."""
        import re
        for dep in {deps!r}:
            assert re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", dep), f"Invalid dep ID: {{dep}}"
'''

    test_file.write_text(content, encoding="utf-8")
    logger.info(f"Generated meta tests: {test_file}")
    return test_file


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------


async def run_skill_tests(
    skill_dir: Path,
    *,
    sandbox: SandboxExecutor | None = None,
) -> TestReport:
    """Run all tests for a skill directory.

    For code skills: runs pytest.
    For prompt/workflow/meta skills: runs static validation tests.
    """
    manifest = skill_dir / "SKILL.md"
    if not manifest.exists():
        return TestReport(skill_id=skill_dir.name, results=[
            TestResult(name="manifest_exists", passed=False, error="SKILL.md not found"),
        ])

    spec = parse_skill_manifest(manifest)
    report = TestReport(skill_id=spec.id)

    # Ensure tests exist
    test_files = list(skill_dir.glob("test_*.py"))
    if not test_files:
        # Auto-generate tests
        try:
            generated = generate_tests(skill_dir)
            test_files = generated
        except Exception as exc:
            logger.warning("Skill test generation failed: %s", type(exc).__name__)
            report.results.append(TestResult(
                name="test_generation",
                passed=False,
                error="Failed to generate skill tests safely",
            ))
            return report

    # Run pytest on generated tests. Skill tests are untrusted code and have
    # no direct-host fallback.
    if test_files:
        import time
        start = time.perf_counter()
        resolved_skill_dir = skill_dir.resolve()
        test_sandbox = sandbox or SandboxExecutor(
            resolved_skill_dir,
            timeout=60.0,
            max_output_bytes=50_000,
            max_memory_mb=512,
            strict_isolation=True,
            trusted_executables=[Path(sys.executable)],
        )
        sandbox_workspace = getattr(test_sandbox, "workspace", None)
        try:
            workspace_matches = (
                isinstance(sandbox_workspace, Path)
                and sandbox_workspace.resolve() == resolved_skill_dir
            )
        except OSError:
            workspace_matches = False
        if (
            not workspace_matches
            or not bool(getattr(test_sandbox, "strict_isolation", False))
            or not test_sandbox.network_isolation_available()
            or not test_sandbox.filesystem_isolation_available()
        ):
            report.results.append(
                TestResult(
                    name="pytest_suite",
                    passed=False,
                    error="Skill tests require a strict OS sandbox",
                )
            )
            return report
        try:
            result = await asyncio.wait_for(
                test_sandbox.execute(
                    [
                        sys.executable,
                        "-m",
                        "pytest",
                        "-q",
                        "--tb=short",
                        "-o",
                        "log_file=",
                        *[str(f) for f in test_files],
                    ],
                    cwd=str(resolved_skill_dir),
                    timeout=60.0,
                    network_allowed=False,
                    fs_restricted=True,
                    read_only_paths=[Path(sys.prefix).resolve()],
                ),
                timeout=65.0,
            )
            duration = (time.perf_counter() - start) * 1000

            output = _sanitize_test_text(str(result.stdout), resolved_skill_dir)
            errors = _sanitize_test_text(str(result.stderr), resolved_skill_dir)

            # Parse pytest output roughly
            passed = result.returncode == 0
            report.results.append(TestResult(
                name="pytest_suite",
                passed=passed,
                output=output,
                error=errors if not passed else "",
                duration_ms=duration,
            ))
        except TimeoutError:
            report.results.append(TestResult(
                name="pytest_suite", passed=False,
                error="Test suite timed out after 60s", duration_ms=60000,
            ))
        except Exception as exc:
            logger.warning("Skill test sandbox failed: %s", type(exc).__name__)
            report.results.append(TestResult(
                name="pytest_suite",
                passed=False,
                error="Skill test sandbox failed safely",
            ))

    return report


def _sanitize_test_text(value: str, skill_dir: Path) -> str:
    """Bound test diagnostics and remove host-specific private roots."""
    replacements = {
        str(skill_dir): "<skill>",
        str(Path.home().resolve()): "<home>",
        str(Path(sys.prefix).resolve()): "<runtime>",
    }
    for private_root, replacement in replacements.items():
        value = value.replace(private_root, replacement)
    return value[:50_000]

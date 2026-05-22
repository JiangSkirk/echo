"""Skill validation engine — check manifest, structure, execution, and security.

Provides a unified `ValidationReport` that aggregates errors, warnings,
and suggestions so skill authors can fix issues before publishing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from js.skills.security import scan_skill
from js.skills.spec import SkillType, parse_skill_manifest
from js.utils.log import get_logger

logger = get_logger("js.skills.validator")


@dataclass
class ValidationIssue:
    """A single validation finding."""

    severity: str  # error, warning, suggestion
    code: str      # machine-readable category
    message: str   # human-readable description
    file: str | None = None
    line: int | None = None


@dataclass
class ValidationReport:
    """Complete validation result for a skill."""

    skill_id: str
    passed: bool = False
    issues: list[ValidationIssue] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def suggestions(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "suggestion"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "passed": self.passed,
            "summary": {
                "errors": len(self.errors),
                "warnings": len(self.warnings),
                "suggestions": len(self.suggestions),
            },
            "issues": [
                {
                    "severity": i.severity,
                    "code": i.code,
                    "message": i.message,
                    "file": i.file,
                    "line": i.line,
                }
                for i in self.issues
            ],
        }

    def print_report(self) -> None:
        """Print a human-readable report to console."""

        color = {"error": "\033[91m", "warning": "\033[93m", "suggestion": "\033[94m", "reset": "\033[0m"}
        status = f"{'✅ PASSED' if self.passed else '❌ FAILED'}"
        print(f"\n{'=' * 50}")
        print(f"Validation Report: {self.skill_id}")
        print(f"Status: {status}")
        print(f"Errors: {len(self.errors)} | Warnings: {len(self.warnings)} | Suggestions: {len(self.suggestions)}")
        print(f"{'=' * 50}")

        for issue in self.issues:
            c = color.get(issue.severity, "")
            r = color["reset"]
            loc = f" ({issue.file}:{issue.line})" if issue.file and issue.line else f" ({issue.file})" if issue.file else ""
            print(f"  {c}[{issue.severity.upper()}]{r} {issue.code}{loc}")
            print(f"    → {issue.message}")

        print()


# ---------------------------------------------------------------------------
# Validation rules
# ---------------------------------------------------------------------------


def validate_skill(path: Path) -> ValidationReport:
    """Run the full validation suite on a skill directory.

    Args:
        path: Path to the skill directory (must contain SKILL.md)

    Returns:
        ValidationReport with all findings.
    """
    import time

    start = time.perf_counter()
    manifest_path = path / "SKILL.md"
    skill_id = path.name
    report = ValidationReport(skill_id=skill_id)

    # 1. Manifest exists
    if not manifest_path.exists():
        report.issues.append(ValidationIssue(
            severity="error", code="missing_manifest",
            message="SKILL.md not found in skill directory", file=str(path),
        ))
        report.duration_ms = (time.perf_counter() - start) * 1000
        return report

    # 2. Manifest is valid YAML / YAML frontmatter
    frontmatter: dict[str, Any] = {}
    body = ""
    try:
        text = manifest_path.read_text(encoding="utf-8")
        match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.DOTALL)
        if match:
            frontmatter = yaml.safe_load(match.group(1)) or {}
            body = match.group(2).strip()
        else:
            frontmatter = yaml.safe_load(text) or {}
            body = ""
    except yaml.YAMLError as e:
        report.issues.append(ValidationIssue(
            severity="error", code="invalid_yaml",
            message=f"SKILL.md YAML parsing failed: {e}", file="SKILL.md",
        ))
        report.duration_ms = (time.perf_counter() - start) * 1000
        return report

    # 3. Required fields
    required_fields = ["id", "name", "description", "type"]
    for field_name in required_fields:
        if not frontmatter.get(field_name):
            report.issues.append(ValidationIssue(
                severity="error", code="missing_field",
                message=f"Required field '{field_name}' is missing or empty", file="SKILL.md",
            ))

    # 4. ID validation
    raw_id = frontmatter.get("id", "")
    if raw_id:
        if not re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", str(raw_id)):
            report.issues.append(ValidationIssue(
                severity="warning", code="invalid_id_format",
                message=f"Skill ID '{raw_id}' should be kebab-case for consistency", file="SKILL.md",
            ))
        if str(raw_id) != skill_id:
            report.issues.append(ValidationIssue(
                severity="warning", code="id_mismatch",
                message=f"SKILL.md id='{raw_id}' but directory name is '{skill_id}'", file="SKILL.md",
            ))

    # 5. Type validation
    raw_type = frontmatter.get("type", "").lower()
    valid_types = {"code", "prompt", "workflow", "meta"}
    if raw_type not in valid_types:
        report.issues.append(ValidationIssue(
            severity="error", code="invalid_type",
            message=f"Unknown skill type: '{raw_type}'. Must be one of: {valid_types}", file="SKILL.md",
        ))

    # 6. Version validation (semantic versioning-ish)
    version = frontmatter.get("version", "")
    if version and not re.match(r"^\d+\.\d+\.\d+", str(version)):
        report.issues.append(ValidationIssue(
            severity="suggestion", code="non_semantic_version",
            message=f"Version '{version}' does not follow semantic versioning (X.Y.Z)", file="SKILL.md",
        ))

    # 7. Type-specific structure checks
    skill_type = SkillType(raw_type) if raw_type in valid_types else None
    if skill_type == SkillType.CODE:
        entry = frontmatter.get("entry", "main.py")
        entry_path = path / entry
        if not entry_path.exists():
            report.issues.append(ValidationIssue(
                severity="error", code="missing_entry",
                message=f"Entry file '{entry}' not found", file=str(entry_path),
            ))
        else:
            # Check if entry is executable (Python/Shell only)
            if not any(entry.endswith(ext) for ext in (".py", ".sh", ".bash")):
                report.issues.append(ValidationIssue(
                    severity="warning", code="unsupported_entry",
                    message=f"Entry '{entry}' is not .py/.sh/.bash — execution may fail", file=entry,
                ))
            # Check shebang for shell scripts
            if entry.endswith(".sh") or entry.endswith(".bash"):
                content = entry_path.read_text(errors="ignore")
                if not content.startswith("#!/"):
                    report.issues.append(ValidationIssue(
                        severity="warning", code="missing_shebang",
                        message="Shell script missing shebang line", file=entry, line=1,
                    ))

    elif skill_type == SkillType.WORKFLOW:
        exec_config = frontmatter.get("execution", {})
        workflow_meta = frontmatter.get("workflow", {})
        if not workflow_meta and not exec_config.get("workflow"):
            report.issues.append(ValidationIssue(
                severity="warning", code="missing_workflow",
                message="Workflow skill has no 'workflow' section in metadata", file="SKILL.md",
            ))

    elif skill_type == SkillType.META:
        deps = frontmatter.get("skill_dependencies", [])
        if not deps:
            report.issues.append(ValidationIssue(
                severity="warning", code="missing_dependencies",
                message="Meta skill has no 'skill_dependencies'", file="SKILL.md",
            ))

    elif skill_type == SkillType.PROMPT:
        if not body:
            report.issues.append(ValidationIssue(
                severity="warning", code="empty_body",
                message="Prompt skill has no body content after frontmatter", file="SKILL.md",
            ))
        if len(body) < 50:
            report.issues.append(ValidationIssue(
                severity="suggestion", code="short_body",
                message="Prompt body is very short (< 50 chars). Consider adding more detail.", file="SKILL.md",
            ))

    # 8. Prerequisite check
    prereq_data = frontmatter.get("prerequisites", {})
    if isinstance(prereq_data, dict):
        for cmd in prereq_data.get("commands", []):
            if not shutil_which(cmd):
                report.issues.append(ValidationIssue(
                    severity="warning", code="missing_prerequisite",
                    message=f"Required command '{cmd}' not found on this system", file="SKILL.md",
                ))

    # 9. Security scan
    try:
        spec = parse_skill_manifest(manifest_path)
        scan_result = scan_skill(spec)
        for flag in scan_result.risk_flags:
            report.issues.append(ValidationIssue(
                severity="warning", code=f"security_{flag}",
                message=f"Security scan flagged: {flag}", file="SKILL.md",
            ))
    except Exception as e:
        logger.debug(f"Security scan failed during validation: {e}")

    # 10. Content quality suggestions
    description = str(frontmatter.get("description", ""))
    if len(description) < 20:
        report.issues.append(ValidationIssue(
            severity="suggestion", code="short_description",
            message="Description is very short. A good description helps users discover your skill.",
            file="SKILL.md",
        ))

    tags = frontmatter.get("tags", [])
    if not tags:
        report.issues.append(ValidationIssue(
            severity="suggestion", code="no_tags",
            message="No tags provided. Tags improve searchability.", file="SKILL.md",
        ))

    # Finalize
    report.passed = len(report.errors) == 0
    report.duration_ms = (time.perf_counter() - start) * 1000
    return report


def validate_quick(path: Path) -> bool:
    """Fast validation — returns True/False only."""
    report = validate_skill(path)
    return report.passed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def shutil_which(cmd: str) -> str | None:
    """Wrapper around shutil.which that handles None safely."""
    import shutil
    return shutil.which(cmd)

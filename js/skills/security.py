"""Skill security scanner with trust levels and risk detection.

Inspired by OpenClaw's ClawAegis skill security model.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from js.skills.spec import SkillSpec, TrustLevel
from js.utils.log import get_logger

logger = get_logger("js.skills.security")

# Patterns that raise risk flags
RISK_PATTERNS = {
    "network_exfil": re.compile(
        r"(curl\s+.*\|\s*sh|wget\s+.*\|\s*sh|nc\s+-e|/dev/tcp|socket\.connect)",
        re.I,
    ),
    "credential_access": re.compile(
        r"(os\.environ\[.*(KEY|TOKEN|SECRET|PWD|PASS)|\.env|id_rsa|aws_credentials)",
        re.I,
    ),
    "code_execution": re.compile(
        r"(eval\s*\(|exec\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True|os\.system)",
        re.I,
    ),
    "file_deletion": re.compile(
        r"(shutil\.rmtree\s*\(/|rm\s+-rf\s+/|os\.remove\s*\(/(?!.*tmp))",
        re.I,
    ),
    "obfuscation": re.compile(
        r"(base64\.b64decode\s*\(|__import__\s*\(|getattr\s*\(.*__builtins)",
        re.I,
    ),
    "sensitive_path_access": re.compile(
        r"(~/.ssh|~/.aws|~/.gnupg|~/.kube|~/.docker|~/.hermes/\.env|"
        r"\$HOME/\.ssh|\$HOME/\.aws|\$HOME/\.gnupg|"
        r"id_rsa|\.pgpass|\.netrc|credentials\.json|\.npmrc|\.pypirc)",
        re.I,
    ),
}

TRUSTED_AUTHORS = {"JS Team", "hermes-agent", "openclaw"}
TRUSTED_LICENSES = {"MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0"}


@dataclass
class ScanResult:
    """Result of a skill security scan."""

    skill_id: str
    content_hash: str
    risk_flags: list[str] = field(default_factory=list)
    trust_level: TrustLevel = TrustLevel.COMMUNITY
    scan_time: float = 0.0


def scan_skill(spec: SkillSpec) -> ScanResult:
    """Scan a skill for security risks and determine trust level.

    Fail-open: if scan itself crashes, return community-level result.
    """
    start = time.time()
    risk_flags: list[str] = []

    try:
        # Scan all files in skill directory
        if spec.path:
            files_to_scan = list(spec.path.rglob("*.py"))
            files_to_scan.extend(spec.path.rglob("*.sh"))
            files_to_scan.extend(spec.path.rglob("*.js"))
            # Also scan SKILL.md for suspicious patterns
            skill_md = spec.path / "SKILL.md"
            if skill_md.exists():
                files_to_scan.append(skill_md)

            for file_path in files_to_scan:
                try:
                    content = file_path.read_text(errors="ignore")
                    for flag_name, pattern in RISK_PATTERNS.items():
                        if pattern.search(content) and flag_name not in risk_flags:
                            risk_flags.append(flag_name)
                except Exception:
                    continue

        # Determine trust level based on heuristics
        trust = _assess_trust(spec, risk_flags)

    except Exception as e:
        logger.warning(f"Skill scan failed for {spec.id}: {e}")
        trust = TrustLevel.COMMUNITY

    return ScanResult(
        skill_id=spec.id,
        content_hash=spec.content_hash,
        risk_flags=risk_flags,
        trust_level=trust,
        scan_time=time.time() - start,
    )


def _assess_trust(spec: SkillSpec, risk_flags: list[str]) -> TrustLevel:
    """Assess trust level based on multiple signals."""
    # Builtin skills are always trusted
    if spec.trust_level == TrustLevel.BUILTIN:
        return TrustLevel.BUILTIN

    # High risk = quarantine
    if len(risk_flags) >= 3:
        return TrustLevel.QUARANTINE

    # Medium risk = community
    if len(risk_flags) >= 1:
        return TrustLevel.COMMUNITY

    # Trusted author + trusted license = trusted
    if spec.author in TRUSTED_AUTHORS and spec.license in TRUSTED_LICENSES:
        return TrustLevel.TRUSTED

    # No risks + from known source = trusted
    if not risk_flags and spec.trust_level == TrustLevel.TRUSTED:
        return TrustLevel.TRUSTED

    return TrustLevel.COMMUNITY


def verify_integrity(spec: SkillSpec) -> bool:
    """Verify skill hasn't been tampered with since scan."""
    if not spec.content_hash:
        return True  # No hash to verify
    current_hash = spec.compute_hash()
    return current_hash == spec.content_hash


def runtime_security_check(spec: SkillSpec) -> tuple[bool, list[str]]:
    """Fast runtime security check before executing a skill.

    Returns (ok, warnings) where ok=True means execution should proceed.
    This is a lightweight check designed to run on every execute() call.
    """
    warnings: list[str] = []

    # Integrity check
    if not verify_integrity(spec):
        warnings.append("Skill content has changed since last scan — rescan recommended")

    # Hermes-specific: check if skill originates from quarantine
    if spec.id.startswith("hermes:") and spec.path:
        quarantine_marker = spec.path / ".quarantine"
        path_str = str(spec.path)
        if (
            quarantine_marker.exists()
            or ".hub/quarantine" in path_str
            or path_str.endswith("/quarantine")
            or "/quarantine/" in path_str
        ):
            warnings.append("Skill originates from quarantine directory")
            return False, warnings

    # Sensitive path access check in scripts
    if spec.path and spec.type.value == "code":
        entry = spec.path / spec.entry
        if entry.exists():
            try:
                content = entry.read_text(errors="ignore")
                sensitive_pattern = RISK_PATTERNS.get("sensitive_path_access")
                if sensitive_pattern and sensitive_pattern.search(content):
                    warnings.append("Script references sensitive paths (SSH keys, credentials, etc.)")
            except Exception:
                pass

    return len(warnings) == 0 or spec.trust_level != TrustLevel.QUARANTINE, warnings

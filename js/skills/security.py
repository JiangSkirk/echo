"""Skill security scanner with trust levels and risk detection.
# noqa: N806 (intentional UPPER_CASE for path constant)

Inspired by OpenClaw's ClawAegis skill security model.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

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
        r"(os\.environ\[.*(KEY|TOKEN|SECRET|PWD|PASS)|"
        r"os\.environ\.get\s*\(\s*['\"][^'\"]*(?:KEY|TOKEN|SECRET|PWD|PASS)|"
        r"os\.getenv\s*\(\s*['\"][^'\"]*(?:KEY|TOKEN|SECRET|PWD|PASS)|"
        r"\.env|id_rsa|aws_credentials)",
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
        r"(base64\.b64decode\s*\(|b85decode\s*\(|fromhex\s*\(|__import__\s*\(|"
        r"importlib\.import_module\s*\(|getattr\s*\(.*__builtins)",
        re.I,
    ),
    "sensitive_path_access": re.compile(
        r"(~/.ssh|~/.aws|~/.gnupg|~/.kube|~/.docker|~/.hermes/\.env|"
        r"\$HOME/\.ssh|\$HOME/\.aws|\$HOME/\.gnupg|"
        r"id_rsa|\.pgpass|\.netrc|credentials\.json|\.npmrc|\.pypirc)",
        re.I,
    ),
}


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

    Fail-closed: if the scan itself crashes, the skill is quarantined.
    """
    start = time.time()
    risk_flags: list[str] = []

    try:
        # Scan all files in skill directory
        if spec.path:
            files_to_scan = list(spec.path.rglob("*.py"))
            files_to_scan.extend(spec.path.rglob("*.sh"))
            files_to_scan.extend(spec.path.rglob("*.bash"))
            files_to_scan.extend(spec.path.rglob("*.js"))
            files_to_scan.extend(spec.path.rglob("*.zsh"))
            files_to_scan.extend(spec.path.rglob("*.ksh"))
            files_to_scan.extend(spec.path.rglob("*.ps1"))
            # Always scan the declared entry, even when its suffix is outside
            # the glob set (a CODE entry like run.zsh was previously invisible).
            if spec.entry:
                entry_path = spec.path / spec.entry
                if entry_path.is_file() and entry_path not in files_to_scan:
                    files_to_scan.append(entry_path)
            # Also scan SKILL.md for suspicious patterns
            skill_md = spec.path / "SKILL.md"
            if skill_md.exists():
                files_to_scan.append(skill_md)

            for file_path in files_to_scan:
                if file_path.is_symlink():
                    continue
                try:
                    content = file_path.read_text(errors="ignore")
                    for flag_name, pattern in RISK_PATTERNS.items():
                        if pattern.search(content) and flag_name not in risk_flags:
                            risk_flags.append(flag_name)
                except Exception:
                    logger.warning(f"Failed to scan {file_path}", exc_info=True)
                    continue

        # Determine trust level based on heuristics
        trust = _assess_trust(spec, risk_flags)

    except Exception:
        logger.warning(
            "Skill scan failed for %s — failing closed to QUARANTINE",
            spec.id,
            exc_info=True,
        )
        trust = TrustLevel.QUARANTINE

    return ScanResult(
        skill_id=spec.id,
        content_hash=spec.content_hash,
        risk_flags=risk_flags,
        trust_level=trust,
        scan_time=time.time() - start,
    )


def _assess_trust(spec: SkillSpec, risk_flags: list[str]) -> TrustLevel:
    """Assess trust level based on multiple signals."""
    # Only honor BUILTIN trust for skills actually residing in the builtin directory.
    # Self-declared `trust_level: builtin` in a SKILL.md YAML frontmatter must not
    # bypass security scanning — the only legitimate source of BUILTIN trust is the
    # physical location of the skill under js/skills/builtin/.
    if spec.trust_level == TrustLevel.BUILTIN:
        builtin_dir = (Path(__file__).parent / "builtin").resolve()
        is_genuine_builtin = spec.path is not None and str(spec.path.resolve()).startswith(
            str(builtin_dir) + os.sep
        )
        if is_genuine_builtin:
            return TrustLevel.BUILTIN
        # Self-declared from outside — fall through to normal risk assessment
        logger.warning(
            "Skill '%s' self-declared trust_level=builtin but is not in %s — treating as untrusted",
            spec.id,
            builtin_dir,
        )

    # ── Ed25519 signature verification ──
    # A valid cryptographic signature from a built-in or trusted public key
    # overrides risk flags and grants TRUSTED trust level.
    if spec.signature and spec.public_key:
        try:
            from js.security.signer import is_builtin_public_key, verify_skill_manifest

            manifest_path = spec.path / "SKILL.md" if spec.path else None
            if manifest_path and manifest_path.exists():
                if verify_skill_manifest(manifest_path, spec.signature, spec.public_key):
                    if is_builtin_public_key(spec.public_key):
                        return TrustLevel.BUILTIN
                    from js.skills.key_registry import (
                        REGISTRY_NAME,
                        is_trusted_public_key,
                    )

                    candidates: list[Path] = []
                    env_state = os.environ.get("JS_STATE_DIR")
                    if env_state:
                        candidates.append(Path(env_state))
                    if spec.path is not None:
                        for parent in (spec.path, *spec.path.resolve().parents):
                            if (parent / REGISTRY_NAME).is_file():
                                candidates.append(parent)
                    candidates.append(Path.home() / ".js" / "state")
                    trusted = any(
                        is_trusted_public_key(candidate, spec.public_key)
                        for candidate in candidates
                    )
                    if trusted:
                        return TrustLevel.TRUSTED
                    logger.warning(
                        "Skill '%s' has a valid self-signature outside the "
                        "trusted key registry — downgrading to COMMUNITY",
                        spec.id,
                    )
                    return TrustLevel.COMMUNITY
                else:
                    logger.warning(
                        "Skill '%s' has invalid Ed25519 signature — downgrading to COMMUNITY",
                        spec.id,
                    )
                    return TrustLevel.COMMUNITY
        except Exception:
            logger.debug("Signature verification failed for '%s'", spec.id, exc_info=True)

    # High risk = quarantine
    if len(risk_flags) >= 3:
        return TrustLevel.QUARANTINE

    # Medium risk = community
    if len(risk_flags) >= 1:
        return TrustLevel.COMMUNITY

    # No heuristic path may grant TRUSTED: self-declared YAML fields
    # (`author`, `license`, `trust_level`) are forgeable by definition.
    # TRUSTED is only reachable via a valid Ed25519 signature (above) or
    # explicit human promotion through the promotion flow.  A clean scan
    # therefore caps out at COMMUNITY.
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
                    warnings.append(
                        "Script references sensitive paths (SSH keys, credentials, etc.)"
                    )
                # High-confidence execution vectors (curl|sh, reverse shells)
                # block at runtime too — install-time scanning may predate an
                # entry rewrite, and .bash/.sh entries deserve the same screen.
                exfil_pattern = RISK_PATTERNS.get("network_exfil")
                if exfil_pattern and exfil_pattern.search(content):
                    warnings.append(
                        "Script contains a network exfiltration/exec pattern "
                        "(curl|sh, nc -e, /dev/tcp, socket.connect)"
                    )
            except Exception:
                logger.warning(f"Failed to read entry {entry}", exc_info=True)

    # Block execution for any trust level when integrity or sensitive-path
    # warnings are present — not just for QUARANTINE.
    return len(warnings) == 0, warnings

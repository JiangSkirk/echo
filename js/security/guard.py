"""Behavioral guardrails: command filtering, path protection, loop detection."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from js.config import SecurityConfig


class SecurityDecisionType(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class SecurityDecision:
    decision: SecurityDecisionType
    reason: str = ""
    details: dict[str, Any] | None = None


class BehaviorGuard:
    """Multi-layer behavioral guard."""

    ENCODING_PATTERNS = {
        "base64": re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
        "hex": re.compile(r"(?:[0-9a-fA-F]{2}){20,}"),
        "url_encoded": re.compile(r"(?:%[0-9a-fA-F]{2}){10,}"),
    }

    HIGH_RISK_COMMANDS = [
        r"rm\s+-rf\s+/",
        r"dd\s+if=/dev/zero",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\};\s*:",
        r"mkfs\.",
        r">\s*/dev/sd[a-z]",
        r"curl\s+.*\|\s*sh",
        r"wget\s+.*\|\s*sh",
        r"curl\s+.*\|\s*bash",
        r"eval\s*\$",
        r"chmod\s+-R\s+777\s+/",
    ]

    def __init__(self, config: SecurityConfig, workspace: Path) -> None:
        self.config = config
        self.workspace = workspace.resolve()
        self._command_patterns = [re.compile(p) for p in self.HIGH_RISK_COMMANDS]
        self._protected_pattern = [re.compile(p) for p in config.protected_commands]
        self._loop_counters: dict[str, int] = {}
        self._script_artifacts: set[str] = set()

    def check_command(self, command: str, cwd: str = ".") -> SecurityDecision:
        """Check if a shell command is safe to execute."""
        if self.config.defense_mode.value == "off":
            return SecurityDecision(SecurityDecisionType.ALLOW)

        # Check high-risk patterns on raw command
        for pattern in self._command_patterns:
            if pattern.search(command):
                return SecurityDecision(
                    SecurityDecisionType.BLOCK,
                    f"High-risk command pattern detected: {pattern.pattern}",
                )

        for pattern in self._protected_pattern:
            if pattern.search(command):
                return SecurityDecision(
                    SecurityDecisionType.BLOCK,
                    f"Protected command pattern detected: {pattern.pattern}",
                )

        # Check for encoded payloads
        if self.config.encoding_guard:
            enc_decision = self._check_encoding(command)
            if enc_decision.decision == SecurityDecisionType.BLOCK:
                return enc_decision

        # Decode and re-check: attackers may encode dangerous commands
        decoded = self._decode_command(command)
        if decoded != command:
            for pattern in self._command_patterns:
                if pattern.search(decoded):
                    return SecurityDecision(
                        SecurityDecisionType.BLOCK,
                        f"High-risk command pattern detected in decoded payload: {pattern.pattern}",
                    )
            for pattern in self._protected_pattern:
                if pattern.search(decoded):
                    return SecurityDecision(
                        SecurityDecisionType.BLOCK,
                        f"Protected command pattern detected in decoded payload: {pattern.pattern}",
                    )

        return SecurityDecision(SecurityDecisionType.ALLOW)

    def check_path_operation(
        self,
        path: str,
        operation: str,  # read, write, delete, list
    ) -> SecurityDecision:
        """Check if a path operation is allowed."""
        if self.config.defense_mode.value == "off":
            return SecurityDecision(SecurityDecisionType.ALLOW)

        try:
            resolved = Path(path).expanduser().resolve()
        except OSError as e:
            return SecurityDecision(
                SecurityDecisionType.BLOCK,
                f"Invalid path: {e}",
            )

        # Allow operations within workspace unconditionally
        try:
            resolved.relative_to(self.workspace)
            # Inside workspace - additional checks for delete only
            if operation == "delete" and not self.config.allow_workspace_delete:
                return SecurityDecision(
                    SecurityDecisionType.BLOCK,
                    f"Delete inside workspace blocked by policy: {resolved}",
                )
            return SecurityDecision(SecurityDecisionType.ALLOW)
        except ValueError:
            pass  # Outside workspace, continue checks

        # Check protected paths (only for operations outside workspace)
        for protected in self.config.protected_paths:
            try:
                protected_path = Path(protected).resolve()
            except OSError:
                continue
            try:
                resolved.relative_to(protected_path)
                # It's inside a protected path
                if operation in ("write", "delete"):
                    return SecurityDecision(
                        SecurityDecisionType.BLOCK,
                        f"{operation} operation blocked on protected path: {protected_path}",
                    )
            except ValueError:
                pass

        # Check workspace delete
        if operation == "delete" and not self.config.allow_workspace_delete:
            return SecurityDecision(
                SecurityDecisionType.BLOCK,
                f"Delete outside workspace blocked: {resolved}",
            )

        return SecurityDecision(SecurityDecisionType.ALLOW)

    def check_loop(self, run_id: str, tool_name: str, args_key: str) -> SecurityDecision:
        """Check if we're stuck in a tool loop."""
        if self.config.defense_mode.value == "off":
            return SecurityDecision(SecurityDecisionType.ALLOW)

        key = f"{run_id}:{tool_name}:{args_key}"
        count = self._loop_counters.get(key, 0) + 1
        self._loop_counters[key] = count
        # Prune old counters to prevent unbounded growth
        if len(self._loop_counters) > 10_000:
            self._loop_counters.clear()

        if count > self.config.max_loop_iterations:
            return SecurityDecision(
                SecurityDecisionType.BLOCK,
                f"Loop detected: {tool_name} called {count} times with same arguments",
            )
        elif count > self.config.max_loop_iterations // 2:
            return SecurityDecision(
                SecurityDecisionType.WARN,
                f"Potential loop: {tool_name} called {count} times",
            )

        return SecurityDecision(SecurityDecisionType.ALLOW)

    def check_tool_result(self, result: str | None) -> SecurityDecision:
        """Scan tool results for prompt injection or exfiltration attempts."""
        if self.config.defense_mode.value == "off" or not self.config.tool_result_scan:
            return SecurityDecision(SecurityDecisionType.ALLOW)

        if result is None:
            return SecurityDecision(SecurityDecisionType.ALLOW)

        injection_markers = [
            "ignore previous instructions",
            "disregard all prior",
            "new instructions:",
            "system prompt:",
            "you are now",
            "DAN mode",
            "developer mode",
        ]
        result_lower = result.lower()
        for marker in injection_markers:
            if marker in result_lower:
                return SecurityDecision(
                    SecurityDecisionType.WARN,
                    f"Potential prompt injection detected: '{marker}'",
                )

        return SecurityDecision(SecurityDecisionType.ALLOW)

    def register_script_artifact(self, path: str) -> None:
        """Track a newly written script for provenance checking."""
        if self.config.script_provenance:
            self._script_artifacts.add(str(Path(path).resolve()))
            # Prune old artifacts to prevent unbounded growth
            if len(self._script_artifacts) > 10_000:
                self._script_artifacts.clear()

    def check_script_execution(self, path: str) -> SecurityDecision:
        """Check if a script execution is allowed based on provenance."""
        if self.config.defense_mode.value == "off" or not self.config.script_provenance:
            return SecurityDecision(SecurityDecisionType.ALLOW)

        resolved = str(Path(path).resolve())
        if resolved in self._script_artifacts:
            return SecurityDecision(
                SecurityDecisionType.WARN,
                f"Script was written by agent, reviewing before execution: {path}",
            )

        return SecurityDecision(SecurityDecisionType.ALLOW)

    def _check_encoding(self, text: str) -> SecurityDecision:
        """Check for encoded/obfuscated payloads."""
        # Base64 check - try to decode suspicious segments
        for match in self.ENCODING_PATTERNS["base64"].finditer(text):
            segment = match.group(0)
            if len(segment) < 20:
                continue
            try:
                decoded = base64.b64decode(segment, validate=True).decode("utf-8", errors="ignore")
                # Check if decoded contains risky commands
                risk_keywords = ["rm", "curl", "wget", "eval", "exec", "bash", "sh"]
                if any(kw in decoded.lower() for kw in risk_keywords):
                    return SecurityDecision(
                        SecurityDecisionType.BLOCK,
                        "Encoded payload containing commands detected",
                        {"encoding": "base64", "preview": decoded[:100]},
                    )
            except (binascii.Error, ValueError):
                continue

        return SecurityDecision(SecurityDecisionType.ALLOW)

    def _decode_command(self, command: str) -> str:
        """Attempt to decode base64 / hex / url-encoded segments in a command."""
        decoded = command
        # Base64
        for match in self.ENCODING_PATTERNS["base64"].finditer(command):
            segment = match.group(0)
            if len(segment) < 20:
                continue
            try:
                decoded += " " + base64.b64decode(segment, validate=True).decode("utf-8", errors="ignore")
            except (binascii.Error, ValueError):
                continue
        # Hex
        for match in self.ENCODING_PATTERNS["hex"].finditer(command):
            segment = match.group(0)
            try:
                decoded += " " + bytes.fromhex(segment).decode("utf-8", errors="ignore")
            except (ValueError, UnicodeDecodeError):
                continue
        # URL-encoded
        from urllib.parse import unquote
        decoded += " " + unquote(command)
        return decoded

    def reset_loop_counters(self, run_id: str) -> None:
        """Clear loop counters for a run."""
        keys_to_remove = [k for k in self._loop_counters if k.startswith(f"{run_id}:")]
        for k in keys_to_remove:
            del self._loop_counters[k]

"""Behavioral guardrails: command filtering, path protection, loop detection."""

from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from js.config import DefenseMode, SecurityConfig
from js.utils.log import get_logger

logger = get_logger("js.security.guard")


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
    """Multi-layer behavioral guard.

    Inspired by Hermes Agent's defense-in-depth security model:
    - Hardline blocklist: irreversible operations blocked even in yolo/off mode
    - Loop detection: prevents stuck retry loops
    - Repeated failure guard: stops same-tool failure spirals
    - Encoding detection: decodes and re-scans obfuscated payloads
    """

    ENCODING_PATTERNS = {
        "base64": re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
        "hex": re.compile(r"(?:[0-9a-fA-F]{2}){8,}"),
        "url_encoded": re.compile(r"(?:%[0-9a-fA-F]{2}){10,}"),
    }

    # High-risk patterns — blocked when defense_mode != "off"
    HIGH_RISK_COMMANDS = [
        r"rm\s+-rf\s+/",
        r"dd\s+if=/dev/zero",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\};\s*:",
        r"mkfs\.",
        r"\d*>>?\s*/dev/sd[a-z]\d*",
        r"\d*>>?\s*/dev/nvme\d+n\d+",
        r"\d*>>?\s*/dev/mmcblk\d+",
        r"\d*>>?\s*/dev/vd[a-z]\d*",
        r"curl\s+.*\|\s*sh",
        r"wget\s+.*\|\s*sh",
        r"curl\s+.*\|\s*bash",
        r"eval\s*\$",
        r"chmod\s+-R\s+777\s+/",
    ]

    # Hardline blocklist — irreversible operations NEVER allowed, even in yolo mode.
    # These protect against catastrophic data loss regardless of user configuration.
    HARDLINE_PATTERNS = [
        r"rm\s+-rf\s+/+\s*($|\s|;|\*)",
        r"rm\s+-rf\s+/+\s*\.",
        r"rm\s+(-r\s+|-f\s+)*\/\s*($|\s|;)",
        r"dd\s+if=[^\s]*\s+of=/dev/sd[a-z]\d*",
        r"dd\s+if=/dev/zero\s+of=/dev/sd[a-z]\d*",
        r"mkfs\.[a-z0-9]+\s+/dev/sd[a-z]\d*",
        r"mkfs\.[a-z0-9]+\s+/dev/hd[a-z]\d*",
        r"mkfs\.[a-z0-9]+\s+/dev/nvme\d+n\d+",
        r"mkfs\.[a-z0-9]+\s+/dev/mmcblk\d+",
        r"mkfs\.[a-z0-9]+\s+/dev/vd[a-z]\d*",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\};\s*:",
        r"shutdown\s+-h\s+now",
        r"halt\s+-p",
        r"reboot\s+-f",
        r"init\s+0",
        r"poweroff\s+-f",
        r"chmod\s+-R\s+777\s+/+\s*($|\s|;|\*)",
        r"chmod\s+-R\s+000\s+/+\s*($|\s|;|\*)",
    ]

    def __init__(self, config: SecurityConfig, workspace: Path) -> None:
        self.config = config
        self.workspace = workspace.resolve()
        self._command_patterns = [re.compile(p) for p in self.HIGH_RISK_COMMANDS]
        self._hardline_patterns = [re.compile(p) for p in self.HARDLINE_PATTERNS]
        self._protected_pattern = [re.compile(p) for p in config.protected_commands]
        from cachetools import LRUCache

        self._loop_counters: LRUCache[str, int] = LRUCache(maxsize=1000)
        self._tool_name_counters: LRUCache[str, int] = LRUCache(maxsize=1000)
        self._failure_counters: LRUCache[str, int] = LRUCache(maxsize=1000)
        self._script_artifacts: LRUCache[str, bool] = LRUCache(maxsize=1000)

    @staticmethod
    def _normalize_command(command: str) -> str:
        """Normalize command by collapsing whitespace to catch space-obfuscated payloads."""
        # Collapse all whitespace sequences to single spaces
        normalized = re.sub(r"\s+", " ", command).strip()
        # Remove spaces around hyphens that look like flags: "- r" -> "-r"
        normalized = re.sub(r"-\s+(\w)", r"-\1", normalized)
        # Remove spaces between single-letter chunks: "r m" -> "rm", "d d" -> "dd"
        # Repeat until stable to handle chained splits like "r m - r f"
        prev = None
        while prev != normalized:
            prev = normalized
            normalized = re.sub(r"\b(\w)\s+(\w)\b", r"\1\2", normalized)
        return normalized

    @staticmethod
    def _normalize_unicode(text: str) -> str:
        """Normalize Unicode to NFKC form to defeat homoglyph attacks.

        Attackers may use visually identical characters from different
        scripts (e.g. Cyrillic 'а' U+0430 vs Latin 'a' U+0061) to
        bypass string-based filters.
        """
        return unicodedata.normalize("NFKC", text)

    def _check_hardline(self, command: str) -> SecurityDecision | None:
        """Check hardline blocklist — irreversible ops blocked even in off/yolo mode."""
        candidates = [command, self._normalize_command(command)]
        for candidate in candidates:
            for pattern in self._hardline_patterns:
                if pattern.search(candidate):
                    return SecurityDecision(
                        SecurityDecisionType.BLOCK,
                        f"Hardline block: irreversible operation detected: {pattern.pattern}",
                    )
        return None

    def check_command(self, command: str, _cwd: str = ".") -> SecurityDecision:
        """Check if a shell command is safe to execute."""
        # Normalize Unicode to defeat homoglyph bypasses
        normalized_cmd = self._normalize_unicode(command)

        # Hardline check FIRST — always runs regardless of defense_mode
        hardline = self._check_hardline(normalized_cmd)
        if hardline:
            return hardline

        # Subshell / command-substitution stays denied even when defense is off:
        # allowlisted wrappers still run via sh -c, so $(...) must not slip through.
        try:
            from js.security.parser import has_subshell
            from js.security.parser import parse as parse_command

            ast = parse_command(normalized_cmd)
            if ast is not None and has_subshell(ast):
                return SecurityDecision(
                    SecurityDecisionType.BLOCK,
                    "Security rule 'subshell': Command substitution (subshell) "
                    "detected — may hide malicious payloads",
                )
        except Exception:
            return SecurityDecision(
                SecurityDecisionType.BLOCK,
                "Security rule 'subshell': command parser failed — fail-closed",
            )

        if self.config.defense_mode == DefenseMode.OFF:
            return SecurityDecision(SecurityDecisionType.ALLOW)

        # ── Structured parser check (primary) ──
        # Grammar-aware analysis is run FIRST.  If the parser understands the
        # command AND a rule blocks it, we return immediately.  Otherwise we
        # still fall through to the encoding/regex checks for defense-in-depth.
        _parser_blocked = False
        _parser_blocked_reason = ""
        try:
            from js.security.parser import parse as parse_command
            from js.security.rules import evaluate as evaluate_rules

            ast = parse_command(normalized_cmd)
            if ast is not None:
                verdict = evaluate_rules(ast)
                if verdict.blocked:
                    return SecurityDecision(
                        SecurityDecisionType.BLOCK,
                        f"Security rule '{verdict.rule_name}': {verdict.reason}",
                    )
                _parser_understood = True
            else:
                _parser_understood = False
        except Exception:
            logger.debug("Parser-based command check failed", exc_info=True)
            _parser_understood = False

        # ── Regex patterns (fallback when parser cannot understand command) ──
        if not _parser_understood:
            for pattern in self._command_patterns:
                if pattern.search(normalized_cmd):
                    return SecurityDecision(
                        SecurityDecisionType.BLOCK,
                        f"High-risk command pattern detected: {pattern.pattern}",
                    )

            for pattern in self._protected_pattern:
                if pattern.search(normalized_cmd):
                    return SecurityDecision(
                        SecurityDecisionType.BLOCK,
                        f"Protected command pattern detected: {pattern.pattern}",
                    )

        # ── Encoding checks (always run — defense-in-depth) ──
        # Check for encoded payloads
        if self.config.encoding_guard:
            enc_decision = self._check_encoding(normalized_cmd)
            if enc_decision.decision == SecurityDecisionType.BLOCK:
                return enc_decision

        # Decode and re-check: attackers may encode dangerous commands
        decoded = self._decode_command(normalized_cmd)
        if decoded != normalized_cmd:
            # Re-check hardline on decoded content
            hardline_decoded = self._check_hardline(decoded)
            if hardline_decoded:
                return hardline_decoded
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
        # Normalize Unicode to defeat homoglyph bypasses in path names
        path = self._normalize_unicode(path)

        if self.config.defense_mode == DefenseMode.OFF:
            return SecurityDecision(SecurityDecisionType.ALLOW)

        # Security: reject paths with embedded null bytes early
        if "\x00" in path:
            return SecurityDecision(
                SecurityDecisionType.BLOCK,
                "Path contains null bytes",
            )

        try:
            raw_path = Path(path).expanduser()
            # resolve() follows symlinks — this is intentional so that a
            # symlink pointing to /etc gets resolved to /etc and blocked.
            resolved = raw_path.resolve()
        except (OSError, ValueError) as e:
            return SecurityDecision(
                SecurityDecisionType.BLOCK,
                f"Invalid path: {e}",
            )

        # Warn if the original (unresolved) path is a symlink — not a block,
        # because resolve() above already follows it to the real target, but
        # symlink usage is worth logging for audit purposes.
        try:
            if raw_path.is_symlink():
                logger.info(
                    "Path operation on symlink: %s -> %s (op=%s)",
                    raw_path,
                    resolved,
                    operation,
                )
        except OSError:
            pass

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
                pass  # Normal control flow — path is not under this protected root

        # Check workspace delete
        if operation == "delete" and not self.config.allow_workspace_delete:
            return SecurityDecision(
                SecurityDecisionType.BLOCK,
                f"Delete outside workspace blocked: {resolved}",
            )

        return SecurityDecision(SecurityDecisionType.ALLOW)

    def check_loop(self, run_id: str, tool_name: str, args_key: str) -> SecurityDecision:
        """Check if we're stuck in a tool loop.

        Two layers:
        1. Exact-args loop: same tool with identical args repeated.
        2. Tool-name loop: same tool called repeatedly with *different* args
           (catches weak FC models that spam the same tool name).
        """
        if self.config.defense_mode == DefenseMode.OFF:
            return SecurityDecision(SecurityDecisionType.ALLOW)

        # Layer 1: exact args loop
        key = f"{run_id}:{tool_name}:{args_key}"
        count = self._loop_counters.get(key, 0) + 1
        self._loop_counters[key] = count

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

        # Layer 2: same tool name regardless of args (catches navigational loops, etc.)
        name_key = f"{run_id}:{tool_name}"
        name_count = self._tool_name_counters.get(name_key, 0) + 1
        self._tool_name_counters[name_key] = name_count
        _name_loop_threshold = self.config.tool_name_loop_threshold
        if name_count > _name_loop_threshold:
            return SecurityDecision(
                SecurityDecisionType.BLOCK,
                f"Loop detected: {tool_name} called {name_count} times total. "
                "Stop repeating the same tool and proceed to answer.",
            )

        return SecurityDecision(SecurityDecisionType.ALLOW)

    def check_tool_result(self, result: str | None) -> SecurityDecision:
        """Scan tool results for prompt injection or exfiltration attempts."""
        if self.config.defense_mode == DefenseMode.OFF or not self.config.tool_result_scan:
            return SecurityDecision(SecurityDecisionType.ALLOW)

        if result is None:
            return SecurityDecision(SecurityDecisionType.ALLOW)

        # High-confidence injection phrases — blocked outright so poisoned
        # memory/tool output never reaches the system prompt.
        block_markers = [
            "ignore previous instructions",
            "disregard all prior",
            "new instructions:",
            "system prompt:",
            "you are now",
            "dan mode",
            "developer mode",
            # Chinese injection markers
            "忽略之前的指令",
            "忽略所有先前的",
            "新的指令",
            "系统提示词",
            "你现在是",
            "开发者模式",
        ]
        # Code-shaped markers — warn only, to avoid false positives on
        # legitimate code output.
        warn_markers = [
            # Encoding-based bypass patterns
            "base64decode",
            "b64decode",
            "__import__",
            "getattr(__builtins__",
            "exec(",
            "eval(",
        ]
        # NFKC-normalize to defeat homoglyph/Unicode injection attacks
        result = self._normalize_unicode(result)
        result_lower = result.lower()
        for marker in block_markers:
            if marker in result_lower:
                return SecurityDecision(
                    SecurityDecisionType.BLOCK,
                    f"Prompt injection detected: '{marker}'",
                )
        for marker in warn_markers:
            if marker in result_lower:
                return SecurityDecision(
                    SecurityDecisionType.WARN,
                    f"Potential prompt injection detected: '{marker}'",
                )

        return SecurityDecision(SecurityDecisionType.ALLOW)

    def register_script_artifact(self, path: str) -> None:
        """Track a newly written script for provenance checking."""
        if self.config.script_provenance:
            self._script_artifacts[str(Path(path).resolve())] = True
            # Prune old artifacts to prevent unbounded growth
            if len(self._script_artifacts) > 10_000:
                self._script_artifacts.clear()

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
                decoded += " " + base64.b64decode(segment, validate=True).decode(
                    "utf-8", errors="ignore"
                )
            except (binascii.Error, ValueError):
                continue
        # Hex
        for match in self.ENCODING_PATTERNS["hex"].finditer(command):
            segment = match.group(0)
            try:
                decoded += " " + bytes.fromhex(segment).decode("utf-8", errors="ignore")
            except (ValueError, UnicodeDecodeError):
                continue
        # URL-encoded — only append decoded segments, not the entire command
        for match in self.ENCODING_PATTERNS["url_encoded"].finditer(command):
            segment = match.group(0)
            decoded += " " + unquote(segment)
        return decoded

    def check_repeated_failure(
        self,
        run_id: str,
        tool_name: str,
        success: bool,
        tool_args: dict[str, Any] | None = None,
    ) -> SecurityDecision:
        """Check if the same tool is failing repeatedly in a run.

        Hermes-style tool guardrail: if a tool fails N consecutive times
        *with the same arguments*, block further calls to prevent failure
        spirals.  Granularity is per-(tool, args_hash) so that retrying
        the same tool with different parameters is not penalised.
        """
        if self.config.defense_mode == DefenseMode.OFF:
            return SecurityDecision(SecurityDecisionType.ALLOW)

        # Build a stable hash of the arguments for fine-grained tracking
        args_hash = ""
        if tool_args:
            try:
                import hashlib

                args_hash = hashlib.sha256(
                    json.dumps(tool_args, sort_keys=True, ensure_ascii=False).encode("utf-8")
                ).hexdigest()[:16]
            except Exception:
                args_hash = ""

        key = f"{run_id}:{tool_name}:{args_hash}" if args_hash else f"{run_id}:{tool_name}"
        if success:
            # Reset on success
            self._failure_counters.pop(key, None)
            return SecurityDecision(SecurityDecisionType.ALLOW)

        count = self._failure_counters.get(key, 0) + 1
        self._failure_counters[key] = count
        # Prune old counters
        if len(self._failure_counters) > 10_000:
            self._failure_counters.clear()

        threshold = max(3, self.config.max_loop_iterations // 2)
        detail = f" (args hash: {args_hash})" if args_hash else ""
        if count >= threshold:
            return SecurityDecision(
                SecurityDecisionType.BLOCK,
                f"Repeated failure guard: {tool_name} failed {count} consecutive times in this run{detail}",
            )
        elif count >= 2:
            return SecurityDecision(
                SecurityDecisionType.WARN,
                f"{tool_name} has failed {count} times — may be stuck{detail}",
            )

        return SecurityDecision(SecurityDecisionType.ALLOW)

    def reset_loop_counters(self, run_id: str) -> None:
        """Clear loop and failure counters for a run."""
        keys_to_remove = [k for k in self._loop_counters if k.startswith(f"{run_id}:")]
        for k in keys_to_remove:
            del self._loop_counters[k]
        n_keys = [k for k in self._tool_name_counters if k.startswith(f"{run_id}:")]
        for k in n_keys:
            del self._tool_name_counters[k]
        f_keys = [k for k in self._failure_counters if k.startswith(f"{run_id}:")]
        for k in f_keys:
            del self._failure_counters[k]

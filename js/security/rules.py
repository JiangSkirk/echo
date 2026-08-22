"""Security rules engine for shell command AST inspection.
# noqa: SIM102 (intentional layered security checks)

Operates on the AST produced by ``js.security.parser`` and applies
structured, grammar-aware rules instead of fragile regex patterns.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

# Deferred import to avoid circular dependency
# from js.security.parser import (ChainedCommands, CommandNode, PipeNode,
#                                 extract_command_names, extract_all_args,
#                                 extract_redirect_targets, has_subshell)


@dataclass
class RuleVerdict:
    """Result of evaluating a rule against a command AST."""

    blocked: bool
    reason: str = ""
    rule_name: str = ""


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    """A single security rule.

    ``check(ast)`` should return a ``RuleVerdict`` (or ``None`` if the
    rule does not apply to the given command).
    """

    name: str
    description: str
    check: Any  # Callable[[ChainedCommands], RuleVerdict | None]


# ---------------------------------------------------------------------------
# Dangerous command names (basename matching, case-insensitive)
# ---------------------------------------------------------------------------

_DANGEROUS_COMMANDS: frozenset[str] = frozenset({
    "rm", "dd", "mkfs", "mkswap", "swapon",
    "shutdown", "halt", "reboot", "poweroff", "init",
    "chmod", "chown", "chattr",
    "fdisk", "parted", "pvcreate", "vgcreate", "lvcreate",
    "iptables", "ip6tables", "nft",
    "systemctl", "service",
    # Execution-capable wrappers / reverse-shell building blocks: each can
    # run arbitrary commands or create the fifo a reverse shell needs.
    "mkfifo", "xargs", "parallel", "env", "script", "socat",
})

# Source commands whose output piped to a shell interpreter is dangerous
_NETWORK_SOURCES: frozenset[str] = frozenset({
    "curl", "wget", "nc", "netcat", "ncat", "telnet", "ftp",
})

# Interpreters that turn piped bytes into executed code
_SHELL_INTERPRETERS: frozenset[str] = frozenset({
    "sh", "bash", "dash", "zsh", "ksh", "ash", "fish",
    "python", "python3", "perl", "ruby", "node",
})

# netcat-family flags that spawn a program (``nc -e /bin/sh``, bundled
# ``-le``, ncat ``--exec`` / ``--sh-exec``)
_NC_FAMILY: frozenset[str] = frozenset({"nc", "netcat", "ncat"})
_NC_EXEC_LONG_FLAGS = ("--exec", "--sh-exec")


# ---------------------------------------------------------------------------
# Built-in rule implementations
# ---------------------------------------------------------------------------


def _check_dangerous_command(ast: Any) -> RuleVerdict | None:
    """Block commands whose basename is on the hardline blocklist."""
    from js.security.parser import extract_command_names

    names = extract_command_names(ast)
    for name in names:
        if name.lower() in _DANGEROUS_COMMANDS:
            return RuleVerdict(
                blocked=True,
                reason=f"Dangerous command: {name}",
                rule_name="dangerous_command",
            )
    return None


def _check_nc_exec(ast: Any) -> RuleVerdict | None:
    """Block netcat-family command execution flags (``nc -e``, ncat ``--exec``)."""
    from js.security.parser import _basename, extract_all_args

    for args in extract_all_args(ast):
        if not args:
            continue
        if _basename(args[0]).lower() not in _NC_FAMILY:
            continue
        for token in args[1:]:
            for flag in _NC_EXEC_LONG_FLAGS:
                if token == flag or token.startswith(flag + "="):
                    return RuleVerdict(
                        blocked=True,
                        reason=f"netcat exec flag denied (command execution vector): {token}",
                        rule_name="nc_exec",
                    )
            if token.startswith("-") and not token.startswith("--") and "e" in token[1:]:
                return RuleVerdict(
                    blocked=True,
                    reason=f"nc -e style exec flag denied (command execution vector): {token}",
                    rule_name="nc_exec",
                )
    return None


def _check_network_pipe_to_shell(ast: Any) -> RuleVerdict | None:
    """Block patterns like ``curl ... | sh`` or ``wget ... | python3``."""
    from js.security.parser import _basename

    for item in ast.commands:
        from js.security.parser import PipeNode

        if not isinstance(item, PipeNode):
            continue

        # Check if any source stage is a network command
        has_network_source = False
        shell_target = None
        shell_stage_index = -1

        for i, stage in enumerate(item.stages):
            cmd_name = _basename(stage.command).lower()
            if cmd_name in _NETWORK_SOURCES:
                has_network_source = True
            if cmd_name in _SHELL_INTERPRETERS and shell_stage_index < 0:
                shell_stage_index = i
                shell_target = cmd_name

        if has_network_source and shell_target is not None:
            return RuleVerdict(
                blocked=True,
                reason=f"Network command piped to shell interpreter ({shell_target})",
                rule_name="network_pipe_to_shell",
            )

    return None


def _check_subshell(ast: Any) -> RuleVerdict | None:
    """Flag command substitution / subshell as potentially dangerous."""
    from js.security.parser import has_subshell

    if has_subshell(ast):
        return RuleVerdict(
            blocked=True,
            reason="Command substitution (subshell) detected — may hide malicious payloads",
            rule_name="subshell",
        )
    return None


def _check_redirect_to_device(ast: Any) -> RuleVerdict | None:
    """Block redirections to raw block devices."""
    from js.security.parser import extract_redirect_targets

    targets = extract_redirect_targets(ast)
    _device_prefixes = (
        "/dev/sd", "/dev/hd", "/dev/nvme", "/dev/mmcblk",
        "/dev/vd", "/dev/xvd", "/dev/md",
        "/dev/disk", "/dev/rdisk",  # macOS block/raw disks
    )
    for target in targets:
        resolved = os.path.normpath(target)
        if any(resolved.startswith(p) for p in _device_prefixes):
            return RuleVerdict(
                blocked=True,
                reason=f"Redirection to block device: {target}",
                rule_name="redirect_to_device",
            )
    return None


def _check_redirect_to_git_metadata(ast: Any) -> RuleVerdict | None:
    """Block shell redirection into the workspace ``.git`` tree.

    R3-2: a sandboxed ``echo ... > .git/hooks/post-checkout`` plants a hook
    that executes OUTSIDE the sandbox on the host's next git invocation.
    The file tools already refuse .git writes; this closes the shell path.
    The comparison is case-folded because the default macOS/Windows
    filesystems resolve ``.GIT`` onto ``.git``.
    """
    from js.security.parser import extract_redirect_targets

    for target in extract_redirect_targets(ast):
        parts = os.path.normpath(target).split(os.sep)
        if any(part.casefold() == ".git" for part in parts):
            return RuleVerdict(
                blocked=True,
                reason=f"Redirection into .git metadata denied (hook/config planting vector): {target}",
                rule_name="redirect_to_git_metadata",
            )
    return None


def _check_eval(ast: Any) -> RuleVerdict | None:
    """Block ``eval`` in command position."""
    from js.security.parser import _basename

    for item in ast.commands:
        from js.security.parser import CommandNode, PipeNode

        if isinstance(item, PipeNode):
            cmds = [s.command for s in item.stages]
        elif isinstance(item, CommandNode):
            cmds = [item.command]
        else:
            cmds = []

        for cmd in cmds:
            if _basename(cmd).lower() == "eval":
                return RuleVerdict(
                    blocked=True,
                    reason="eval command — arbitrary code execution risk",
                    rule_name="eval",
                )
    return None


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

_RULES: list[Rule] = [
    Rule("dangerous_command", "Block hardline-dangerous commands", _check_dangerous_command),
    Rule("nc_exec", "Block netcat-family exec flags (nc -e, ncat --exec)", _check_nc_exec),
    Rule(
        "network_pipe_to_shell",
        "Block network commands piped to a shell/interpreter",
        _check_network_pipe_to_shell,
    ),
    Rule("subshell", "Detect command substitution", _check_subshell),
    Rule("redirect_to_device", "Block redirection to block devices", _check_redirect_to_device),
    Rule(
        "redirect_to_git_metadata",
        "Block redirection into .git metadata (host-side hook execution)",
        _check_redirect_to_git_metadata,
    ),
    Rule("eval", "Block eval command", _check_eval),
]


def evaluate(ast: Any) -> RuleVerdict:
    """Evaluate all rules against a command AST.

    Returns the first blocking verdict, or an allow verdict if no rule
    blocks the command.
    """
    for rule in _RULES:
        try:
            verdict = rule.check(ast)
            if verdict is not None and verdict.blocked:
                return verdict  # type: ignore[no-any-return]
        except Exception:
            # Parser failure should not crash the guard — fall through
            continue

    return RuleVerdict(blocked=False, rule_name="*")

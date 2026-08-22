"""Sandboxed shell execution tool."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from js.config import ToolLimits
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.security.runtime_tcb import token_is_runtime_tcb_write
from js.security.sandbox import SandboxExecutor
from js.tools.registry import ToolParam, ToolResult, ToolSpec

# ---------------------------------------------------------------------------
# Argument-level deny rules (F-09)
#
# Being on the executable allowlist is not enough: several retained commands
# carry documented argument-level execution/file-access bypasses.  Each rule
# below receives the full argv (including argv[0]) and returns a denial reason
# or None.  Rules are fail-closed: an unparseable or ambiguous shape is denied.
# ---------------------------------------------------------------------------

_FIND_DENIED_FLAGS = frozenset(
    {
        "-exec",
        "-execdir",
        "-ok",
        "-okdir",
        "-delete",
        "-fprintf",
    }
)

_AWK_DENIED_PROGRAM_PATTERNS = (
    (re.compile(r"\bsystem\s*\("), "awk system() call"),
    (re.compile(r"\bgetline\b"), "awk getline file/pipe read"),
    (re.compile(r"(?:print|printf)[^'\";]*(?:>>|>|<[^=]|\|\s*\")"), "awk output redirection/pipe"),
)

# Subcommands are allowlisted, not denylisted: blacklist parsing missed the
# real subcommand whenever a value-taking option (``git -C dir config ...``)
# was consumed as the "first non-dash token", and dangerous subcommands
# (rebase/bisect/filter-branch/send-email/...) outnumber the safe ones.
_GIT_ALLOWED_SUBCOMMANDS = frozenset(
    {
        "status",
        "log",
        "diff",
        "show",
        "grep",
        "add",
        "commit",
        "branch",
        "checkout",
        "switch",
        "restore",
        "mv",
        "rm",
        "tag",
        "rev-parse",
        "ls-files",
        "ls-tree",
        "blame",
        "describe",
        "stash",
        "shortlog",
        "rev-list",
        "cat-file",
    }
)
# Long options whose value is a separate argv token (``--x=y`` never consumes
# the next token).  Their values must not be mistaken for the subcommand.
_GIT_VALUE_LONG_OPTIONS = frozenset({"--git-dir", "--work-tree", "--namespace"})
_GIT_DENIED_LONG_FLAGS = (
    "--config-env",
    "--exec-path",
    # Revision-walk family writes a caller-chosen file; combined with
    # ``--pretty=format:`` this plants workspace ``.git`` metadata that
    # Linux bwrap cannot regex-deny at wrap time (TECH_DEBT #6 / H1).
    "--output",
    # ``git grep -O`` / ``--open-files-in-pager`` runs the configured pager.
    "--open-files-in-pager",
    # External diff drivers execute repo-configured commands.
    "--ext-diff",
)
_GIT_DENIED_SUBSTRINGS = ("ext::", "upload-pack")

# sed `e` (execute) / `w` (write file) commands, allowing address prefixes
# like `1e id`, `$w out`, `/re/e cmd` and command separators.
_SED_DENIED_COMMAND_RE = re.compile(r"(?:^|[;{}\s0-9,$/])[ew](?:[;}\s]|$)")

_TAR_DENIED_LONG_FLAGS = (
    "--directory",
    "--to-command",
    "--checkpoint-action",
    "--use-compress-program",
    "--rsh-command",
    "--absolute-names",
)
# Short tar option letters that change directory, keep absolute names, or run
# external commands (C/P take effect per-member; bundled forms like -xfC).
# I/F are GNU tar's per-member compress-program and volume-script hooks.
# x is extract: archive members can plant a nested ``.git`` that does not
# exist when the OS sandbox profile is snapshotted.
_TAR_DENIED_SHORT_LETTERS = frozenset("CPIF")
_TAR_EXTRACT_LONG_FLAGS = frozenset({"--extract", "--get"})
# Short tar options that consume the following argv token as a value.
_TAR_VALUE_SHORT_LETTERS = frozenset("fCb")
# mkdir/touch/mv/tar path args must never name a ``.git`` component: that is
# the host-executing git config/hook plant (red-team finding 1 residual).
_GIT_METADATA_WRITE_COMMANDS = frozenset({"mkdir", "touch", "mv", "tar"})
# git subcommands that write workspace paths (as opposed to reading a repo).
_GIT_PATH_WRITE_SUBCOMMANDS = frozenset(
    {
        "add",
        "commit",
        "mv",
        "rm",
        "checkout",
        "restore",
        "stash",
        "switch",
        "tag",
    }
)

_JQ_DENIED_FLAGS = frozenset(
    {
        "--arg-file",
        "--slurpfile",
        "--rawfile",
        "-f",
        "--from-file",
    }
)

# rg flags that spawn external commands (F-09 family): --pre runs a command
# per file, --pre-path replaces the preprocessor binary, --hostname-bin runs
# a command to determine the reported hostname.
_RG_DENIED_LONG_FLAGS = (
    "--pre",
    "--pre-path",
    "--hostname-bin",
)


def _find_arg_error(args: list[str]) -> str | None:
    for token in args[1:]:
        if token in _FIND_DENIED_FLAGS or token.startswith("-fprint"):
            return f"find argument denied (execution/file-write vector): {token}"
    return None


def _awk_arg_error(args: list[str]) -> str | None:
    idx = 1
    while idx < len(args):
        token = args[idx]
        if token in ("-f", "--file") or token.startswith("--file="):
            return f"awk program file denied (unscanned code): {token}"
        # Options with separate values (-F, -v) carry no program text.
        if token in ("-F", "-v"):
            idx += 2
            continue
        if token.startswith("-"):
            idx += 1
            continue
        for pattern, reason in _AWK_DENIED_PROGRAM_PATTERNS:
            if pattern.search(token):
                return f"awk program denied ({reason})"
        idx += 1
    return None


def _token_has_git_metadata_component(token: str) -> bool:
    """True when any path component is ``.git`` (case-insensitive).

    Lexical only: the allowlist sees the unexpanded token, and ``resolve()``
    would miss a ``.git`` directory that does not exist yet (the plant case).
    """
    if not token or token in {".", "-"}:
        return False
    normalized = os.path.normpath(token.replace("\\", "/"))
    return any(part.casefold() == ".git" for part in normalized.split("/"))


def _git_metadata_write_arg_error(name: str, args: list[str]) -> str | None:
    """Reject write-command path args that name a ``.git`` component.

    Also reject ``$`` expansions: the AST drops ``has_var``, so a token like
    ``nested/$x`` would otherwise pass the lexical ``.git`` check and expand
    at runtime.
    """
    if name not in _GIT_METADATA_WRITE_COMMANDS:
        return None
    for token in args[1:]:
        if token == "--" or token.startswith("-"):
            continue
        if "$" in token:
            return f"{name} path denied (non-static expansion): {token}"
        if _token_has_git_metadata_component(token):
            return f"{name} path denied (workspace .git metadata write vector): {token}"
    return None


def _runtime_tcb_write_arg_error(name: str, args: list[str], *, workspace: Path) -> str | None:
    """Reject write-command path args that name an installed runtime TCB path.

    ``$`` expansions are denied the same way as git metadata writes: the AST
    drops ``has_var``, so a token like ``js/$x`` must not pass lexical TCB.
    """
    if name not in _GIT_METADATA_WRITE_COMMANDS:
        return None
    for token in args[1:]:
        if token == "--" or token.startswith("-"):
            continue
        if "$" in token:
            return f"{name} path denied (non-static expansion): {token}"
        if token_is_runtime_tcb_write(token, workspace=workspace):
            return f"{name} path denied (runtime TCB write vector): {token}"
    return None


def _git_arg_error(args: list[str]) -> str | None:
    subcommand: str | None = None
    skip_next = False  # value of a separate-form option (-C/--git-dir/...)
    write_positionals: list[str] = []
    for token in args[1:]:
        if token.startswith("-c"):
            return f"git inline config denied (alias/pager RCE vector): {token}"
        if token == "-O" or token.startswith("-O="):
            return f"git flag denied (pager execution vector): {token}"
        for flag in _GIT_DENIED_LONG_FLAGS:
            if token == flag or token.startswith(flag + "="):
                return f"git flag denied (write/exec vector): {token}"
        for needle in _GIT_DENIED_SUBSTRINGS:
            if needle in token:
                return f"git argument denied ({needle} execution vector): {token}"
        if skip_next:
            skip_next = False
            continue
        if subcommand is not None:
            if not token.startswith("-"):
                write_positionals.append(token)
            continue
        if token == "-C":
            skip_next = True
        elif token.startswith("--"):
            name = token.split("=", 1)[0]
            if name in _GIT_VALUE_LONG_OPTIONS and "=" not in token:
                skip_next = True
        elif not token.startswith("-"):
            subcommand = token
    if subcommand is not None and subcommand not in _GIT_ALLOWED_SUBCOMMANDS:
        return f"git subcommand denied (not in allowlist): {subcommand}"
    if subcommand in _GIT_PATH_WRITE_SUBCOMMANDS:
        for token in write_positionals:
            if "$" in token:
                return f"git {subcommand} path denied (non-static expansion): {token}"
            if _token_has_git_metadata_component(token):
                return (
                    f"git {subcommand} path denied (workspace .git metadata write vector): {token}"
                )
    return None


def _sed_arg_error(args: list[str]) -> str | None:
    for token in args[1:]:
        if token == "--in-place" or token.startswith("--in-place="):
            return f"sed in-place edit denied (file overwrite vector): {token}"
        if token.startswith("-i") and not token.startswith("--"):
            return f"sed in-place edit denied (file overwrite vector): {token}"
        # A program file is never scanned by the pattern check below.
        if token in ("-f", "--file") or token.startswith("--file="):
            return f"sed script file denied (unscanned code): {token}"
    for token in args[1:]:
        script: str
        if token.startswith("--expression="):
            script = token.split("=", 1)[1]
        elif token.startswith("-e") and not token.startswith("--") and len(token) > 2:
            script = token[2:]
        elif token.startswith("-"):
            # Bare ``-e``'s separate script word is a non-dash token and is
            # scanned on its own iteration.
            continue
        else:
            script = token
        if _SED_DENIED_COMMAND_RE.search(script):
            return "sed script denied (e/w command execution/write vector)"
    return None


def _tar_arg_error(args: list[str]) -> str | None:
    idx = 1
    seen_cluster = False
    while idx < len(args):
        token = args[idx]
        letters: str | None = None
        if token.startswith("--"):
            name = token.split("=", 1)[0]
            if name in _TAR_DENIED_LONG_FLAGS:
                return f"tar flag denied (directory-escape/exec vector): {token}"
            if name in _TAR_EXTRACT_LONG_FLAGS:
                return "tar extract denied (archive member .git plant vector)"
            if name in ("--file",) and "=" not in token:
                idx += 1  # skip the archive value
        elif token.startswith("-") and len(token) > 1:
            letters = token[1:]
        elif not seen_cluster and token.isalpha():
            # Old-style ``tar xf archive``: the first all-letter token is the
            # operation cluster, not a member path.
            letters = token
        else:
            # Archive member: reject traversal, absolute paths, and .git plants.
            if token.startswith("/"):
                return f"tar member denied (absolute path): {token}"
            if ".." in token.split("/"):
                return f"tar member denied (path traversal): {token}"
            if _token_has_git_metadata_component(token):
                return f"tar member denied (workspace .git metadata write vector): {token}"
            idx += 1
            continue
        if letters is not None:
            seen_cluster = True
            if "x" in letters:
                return "tar extract denied (archive member .git plant vector)"
            denied = _TAR_DENIED_SHORT_LETTERS.intersection(letters)
            if denied:
                return (
                    f"tar flag denied (directory-escape/absolute-path vector): -{sorted(denied)[0]}"
                )
            value_letters = [c for c in letters if c in _TAR_VALUE_SHORT_LETTERS]
            if value_letters and letters.endswith(value_letters[-1]):
                idx += 1  # skip the option value (e.g. archive after -czf)
        idx += 1
    return None


def _mv_arg_error(args: list[str], *, cwd: Path, workspace: Path) -> str | None:
    positional = [t for t in args[1:] if not t.startswith("-")]
    if len(positional) < 2:
        return None
    # Sources must live in the workspace too: mv unlinks the source, so an
    # outside path would mean an arbitrary read + delete (OS-level fs
    # isolation still applies, but deny here for defense in depth).
    # ``~`` is rejected outright: the allowlist layer sees the unexpanded
    # token while the executing shell expands it to the home directory.
    for source in positional[:-1]:
        if source.startswith("~"):
            return f"mv source denied (home-relative path): {source}"
        src = Path(source)
        src_candidate = src if src.is_absolute() else cwd / src
        try:
            src_candidate.resolve(strict=False).relative_to(workspace)
        except (OSError, RuntimeError):
            return "mv source denied (unresolvable path)"
        except ValueError:
            return f"mv source denied (outside workspace): {source}"
    target = Path(positional[-1])
    if positional[-1].startswith("~"):
        return f"mv target denied (home-relative path): {positional[-1]}"
    candidate = target if target.is_absolute() else cwd / target
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return "mv target denied (unresolvable path)"
    try:
        resolved.relative_to(workspace)
    except ValueError:
        return f"mv target denied (outside workspace): {positional[-1]}"
    # Fail-closed: never let mv silently overwrite an existing non-directory.
    if resolved.exists() and not resolved.is_dir():
        return f"mv target denied (would overwrite existing file): {positional[-1]}"
    return None


def _jq_arg_error(args: list[str]) -> str | None:
    for token in args[1:]:
        if token in _JQ_DENIED_FLAGS:
            return f"jq flag denied (arbitrary file read vector): {token}"
        for flag in _JQ_DENIED_FLAGS:
            if flag.startswith("--") and token.startswith(flag + "="):
                return f"jq flag denied (arbitrary file read vector): {token}"
    return None


def _rg_arg_error(args: list[str]) -> str | None:
    flags_done = False
    for token in args[1:]:
        if flags_done:
            continue
        # Everything after a bare `--` is a search pattern, never a flag, so
        # `rg -- "--pre"` (searching the literal text) stays allowed.
        if token == "--":
            flags_done = True
            continue
        for flag in _RG_DENIED_LONG_FLAGS:
            if token == flag or token.startswith(flag + "="):
                return f"rg flag denied (command execution vector): {token}"
    return None


_STATIC_ARG_RULES = {
    "find": _find_arg_error,
    "awk": _awk_arg_error,
    "git": _git_arg_error,
    "sed": _sed_arg_error,
    "tar": _tar_arg_error,
    "jq": _jq_arg_error,
    "rg": _rg_arg_error,
}


class ShellTool:
    """Secure shell command execution."""

    def __init__(self, workspace: Path, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.workspace = workspace.resolve()
        self.limits = limits
        self.guard = guard
        self.executor = SandboxExecutor(
            workspace=workspace,
            timeout=limits.shell_timeout,
            max_output_bytes=limits.shell_max_output_bytes,
            strict_isolation=True,
        )

    def get_spec(self) -> ToolSpec:
        return ToolSpec(
            name="shell",
            description="Execute a shell command. Use with caution. Commands run in workspace.",
            parameters=[
                ToolParam("command", "string", "Shell command to execute"),
                ToolParam(
                    "cwd", "string", "Working directory (relative to workspace)", required=False
                ),
                ToolParam("timeout", "integer", "Override timeout in seconds", required=False),
            ],
            dangerous=True,
        )

    async def execute(self, command: str, cwd: str = ".", timeout: int = 0) -> ToolResult:
        resolved_cwd, cwd_error = self.executor.resolve_cwd(cwd)
        if cwd_error is not None or resolved_cwd is None:
            return ToolResult(success=False, error=cwd_error or "Sandbox cwd denied")

        allowlist_error = self._command_allowlist_error(command, cwd=resolved_cwd)
        if allowlist_error is not None:
            return ToolResult(success=False, error=allowlist_error)

        # Security check
        decision = self.guard.check_command(command, cwd)
        if decision.decision == SecurityDecisionType.BLOCK:
            return ToolResult(success=False, error=f"Security: {decision.reason}")
        elif decision.decision == SecurityDecisionType.WARN:
            # Still allow but mark
            pass

        path_decision = self.guard.check_path_operation(str(resolved_cwd), "read")
        if path_decision.decision == SecurityDecisionType.BLOCK:
            return ToolResult(success=False, error=path_decision.reason)

        result = await self.executor.execute(
            command,
            cwd=str(resolved_cwd),
            # Callers may shorten the timeout but never extend it past the
            # configured limit (an unbounded timeout lets a few long-lived
            # processes exhaust the concurrency slots — red team finding 8).
            timeout=min(timeout or self.limits.shell_timeout, self.limits.shell_timeout),
            network_allowed=False,
            fs_restricted=True,
        )

        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]\n{result.stderr}"

        if result.killed:
            output += "\n[Process was terminated (timeout or resource limit)]"

        return ToolResult(
            success=result.returncode == 0 and not result.killed,
            output=output,
            error=result.stderr if result.returncode != 0 else "",
            metadata={
                "returncode": result.returncode,
                "duration_ms": result.duration_ms,
                "killed": result.killed,
            },
        )

    def _command_allowlist_error(self, command: str, cwd: Path | None = None) -> str | None:
        """Require approved bare names plus per-command argument safety.

        Fail-closed on every layer: unparseable command, unlisted executable,
        or a dangerous argument pattern all deny before any process spawns.
        Commands with static argument rules additionally reject unquoted
        glob characters (``*``/``?``/``[``) — a runtime glob expansion could
        otherwise smuggle option-injection files (e.g. ``tar cf x.tar *``)
        past the literal argv inspection below.
        """

        try:
            from js.security.parser import CommandNode, PipeNode, parse

            parsed = parse(command)
            if parsed is None:
                return "Shell command allowlist denied an unparseable command"
            nodes: list[CommandNode] = []
            for item in parsed.commands:
                if isinstance(item, PipeNode):
                    nodes.extend(item.stages)
                elif isinstance(item, CommandNode):
                    nodes.append(item)
        except Exception:
            return "Shell command allowlist denied an unparseable command"
        if not nodes:
            return "Shell command allowlist denied an empty command"
        allowed = set(self.limits.shell_command_allowlist)
        effective_cwd = (cwd or self.workspace).resolve()
        for node in nodes:
            args = node.args
            if not args:
                return "Shell command allowlist denied an empty command"
            raw_name = args[0]
            if "/" in raw_name or "\\" in raw_name or raw_name not in allowed:
                return f"Shell command allowlist denied executable: {raw_name}"
            if raw_name == "git" and not self.executor._git_sandbox_env_overrides():
                return (
                    "Shell command allowlist denied: git requires sandbox "
                    "config overrides (git >= 2.31)"
                )
            git_write_error = _git_metadata_write_arg_error(raw_name, args)
            if git_write_error is not None:
                return f"Shell command allowlist denied: {git_write_error}"
            tcb_write_error = _runtime_tcb_write_arg_error(raw_name, args, workspace=self.workspace)
            if tcb_write_error is not None:
                return f"Shell command allowlist denied: {tcb_write_error}"
            if raw_name == "mv":
                mv_error = _mv_arg_error(args, cwd=effective_cwd, workspace=self.workspace)
                if mv_error is not None:
                    return f"Shell command allowlist denied: {mv_error}"
                continue
            rule = _STATIC_ARG_RULES.get(raw_name)
            if rule is not None:
                if any(node.arg_globs[1:]):
                    return (
                        "Shell command allowlist denied: unquoted glob character "
                        f"in {raw_name} arguments (option-injection vector)"
                    )
                arg_error = rule(args)
                if arg_error is not None:
                    return f"Shell command allowlist denied: {arg_error}"
        return None

    def register(self, registry: Any) -> None:
        registry.register(self.get_spec(), self.execute)

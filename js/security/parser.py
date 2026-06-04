"""Lightweight POSIX sh command parser for security analysis.

Parses shell commands into a structural AST that the rule engine in
``rules.py`` can inspect.  This replaces regex-based pattern matching
with grammar-aware analysis that is robust against whitespace tricks,
quoting, variable expansions, and command chaining.

The parser is intentionally NOT a full sh implementation — it only
extracts the structural elements relevant to security decisions:
command names, arguments, redirections, pipes, subshells, and
command separators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# AST node types
# ---------------------------------------------------------------------------


@dataclass
class RedirectNode:
    """A redirection like ``> /dev/null`` or ``2>&1``."""

    fd: str = ""          # e.g. "", "2", "&" (for >&)
    direction: str = ">"  # ">", ">>", "<", "<<", ">&", "<&"
    target: str = ""      # file path or fd number


@dataclass
class CommandNode:
    """A single command with arguments and redirections."""

    command: str                               # executable name (basename or full path)
    args: list[str] = field(default_factory=list)  # all arguments including the command
    redirects: list[RedirectNode] = field(default_factory=list)


@dataclass
class PipeNode:
    """A pipeline of commands connected by ``|``."""

    stages: list[CommandNode] = field(default_factory=list)


@dataclass
class SubshellNode:
    """A subshell expression: ``$(...)`` or backtick form."""

    body: str
    backtick: bool = False


@dataclass
class ChainedCommands:
    """A list of commands separated by ``;``, ``&&``, or ``||``."""

    commands: list[CommandNode | PipeNode] = field(default_factory=list)
    separators: list[str] = field(default_factory=list)  # ";", "&&", "||"


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

# Regex patterns for tokenising a shell command line
_TOKEN_PATTERNS: list[tuple[str, str]] = [
    # Subshells and command substitution
    ("SUBSHELL_DOLLAR", r"\$\((?:\\.|[^()]|\((?:\\.|[^()])*\))*\)"),
    ("SUBSHELL_BACKTICK", r"`[^`]*`"),
    # Variable expansions
    ("VAR_BRACE", r"\$\{[^}]+\}"),
    ("VAR_SIMPLE", r"\$[a-zA-Z_][a-zA-Z0-9_]*"),
    # Redirections
    ("REDIR_APPEND", r"\d*>>"),      # N>>
    ("REDIR_MERGE_OUT", r"\d*>&\d+"),  # N>&M  (must be before REDIR_OUT)
    ("REDIR_MERGE_IN", r"\d*<&\d+"),   # N<&M
    ("REDIR_HEREDOC", r"\d*<<"),     # N<<
    ("REDIR_OUT", r"\d*>"),          # N>
    ("REDIR_IN", r"\d*<"),           # N<
    # Control operators
    ("AND_IF", r"&&"),
    ("OR_IF", r"\|\|"),
    ("PIPE", r"\|"),
    ("SEMI", r";"),
    # Quoted strings
    ("DOUBLE_QUOTED", r'"(?:\\.|[^"\\])*"'),
    ("SINGLE_QUOTED", r"'(?:\\.|[^'\\])*'"),
    # Unquoted tokens
    ("TOKEN", r"[^\s;|&><$`\"'\\]+"),
    # Whitespace (discarded)
    ("WS", r"\s+"),
]


def _compile_token_re() -> re.Pattern[str]:
    """Build a combined tokenisation regex."""
    parts = [f"(?P<{name}>{pattern})" for name, pattern in _TOKEN_PATTERNS]
    return re.compile("|".join(parts))


_TOKEN_RE = _compile_token_re()


def tokenize(command: str) -> list[tuple[str, str]]:
    """Tokenize a shell command line.

    Returns a list of ``(token_type, token_value)`` tuples.
    Whitespace tokens are filtered out.
    """
    tokens: list[tuple[str, str]] = []
    for m in _TOKEN_RE.finditer(command):
        kind = m.lastgroup
        value = m.group()
        if kind == "WS":
            continue
        assert kind is not None
        tokens.append((kind, value))
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _is_chained(tokens: list[tuple[str, str]], pos: int) -> bool:
    """Check if tokens[pos] is a command separator (AND_IF, OR_IF, SEMI)."""
    if pos >= len(tokens):
        return False
    return tokens[pos][0] in ("AND_IF", "OR_IF", "SEMI")


def _is_pipe(tokens: list[tuple[str, str]], pos: int) -> bool:
    """Check if tokens[pos] is a pipe operator."""
    if pos >= len(tokens):
        return False
    return tokens[pos][0] == "PIPE"


def _collect_redirects(
    tokens: list[tuple[str, str]], pos: int,
) -> tuple[list[RedirectNode], int]:
    """Collect consecutive redirection tokens and their targets starting at pos.

    Returns (redirects, new_pos).
    """
    redirects: list[RedirectNode] = []
    while pos < len(tokens):
        kind, value = tokens[pos]
        if not kind.startswith("REDIR_"):
            break

        # Extract fd from the redirection token
        fd = ""
        if kind == "REDIR_OUT":
            fd = value[:-1]  # strip trailing >
            direction = ">"
        elif kind == "REDIR_APPEND":
            fd = value[:-2]  # strip trailing >>
            direction = ">>"
        elif kind == "REDIR_IN":
            fd = value[:-1]
            direction = "<"
        elif kind == "REDIR_HEREDOC":
            fd = value[:-2]
            direction = "<<"
        elif kind == "REDIR_MERGE_OUT":
            fd = value[:-2]  # strip trailing >&
            direction = ">&"
        elif kind == "REDIR_MERGE_IN":
            fd = value[:-2]
            direction = "<&"
        else:
            fd = ""
            direction = ">"

        pos += 1
        # Target: the next token (unless it's another redirect or control op)
        target = ""
        if pos < len(tokens) and tokens[pos][0] not in (
            "REDIR_OUT", "REDIR_APPEND", "REDIR_IN", "REDIR_HEREDOC",
            "REDIR_MERGE_OUT", "REDIR_MERGE_IN",
            "PIPE", "AND_IF", "OR_IF", "SEMI", "SUBSHELL_DOLLAR",
            "SUBSHELL_BACKTICK", "VAR_BRACE", "VAR_SIMPLE",
        ):
            target = tokens[pos][1]
            pos += 1

        redirects.append(RedirectNode(fd=fd, direction=direction, target=target))

    return redirects, pos


def _collect_arg_tokens(
    tokens: list[tuple[str, str]], pos: int,
) -> tuple[list[str], list[RedirectNode], int]:
    """Collect argument tokens and redirections for one command.

    Stops at PIPE, AND_IF, OR_IF, SEMI, or end of tokens.
    Redirections can appear anywhere among arguments in shell syntax.

    Returns (args, redirects, new_pos).
    """
    args: list[str] = []
    redirects: list[RedirectNode] = []

    while pos < len(tokens):
        kind, value = tokens[pos]

        # Stop at control operators
        if kind in ("PIPE", "AND_IF", "OR_IF", "SEMI"):
            break

        # Redirections
        if kind.startswith("REDIR_"):
            redirs, pos = _collect_redirects(tokens, pos)
            redirects.extend(redirs)
            continue

        # Collect the value
        if kind in ("DOUBLE_QUOTED",):
            # Strip surrounding quotes but keep inner content
            args.append(value[1:-1])
        elif kind in ("SINGLE_QUOTED",):
            args.append(value[1:-1])
        elif kind in ("SUBSHELL_DOLLAR", "SUBSHELL_BACKTICK", "VAR_BRACE", "VAR_SIMPLE"):
            # Record variable/expansion tokens as-is
            args.append(value)
        else:
            args.append(value)

        pos += 1

    return args, redirects, pos


def parse(command: str) -> ChainedCommands | None:
    """Parse a shell command line into a ``ChainedCommands`` AST.

    Returns ``None`` if parsing fails (empty input or fatal syntax error).
    """
    tokens = tokenize(command)
    if not tokens:
        return None

    result = ChainedCommands()
    pos = 0

    while pos < len(tokens):
        # Collect args and redirections for this command
        args, redirects, pos = _collect_arg_tokens(tokens, pos)

        if not args:
            # Only separators/redirects — skip to next separator
            if pos < len(tokens) and tokens[pos][0] in ("AND_IF", "OR_IF", "SEMI"):
                result.separators.append(tokens[pos][1])
                pos += 1
            elif pos < len(tokens) and tokens[pos][0] == "PIPE":
                pos += 1
            continue

        cmd = CommandNode(
            command=args[0],
            args=args,
            redirects=redirects,
        )

        # Check for pipe chain
        if pos < len(tokens) and tokens[pos][0] == "PIPE":
            pipe = PipeNode(stages=[cmd])
            pos += 1  # skip PIPE
            # Collect subsequent pipe stages
            while pos < len(tokens):
                pipe_args, pipe_redirs, pos = _collect_arg_tokens(tokens, pos)
                if not pipe_args:
                    break
                pipe.stages.append(CommandNode(
                    command=pipe_args[0],
                    args=pipe_args,
                    redirects=pipe_redirs,
                ))
                if pos < len(tokens) and tokens[pos][0] == "PIPE":
                    pos += 1
                else:
                    break
            result.commands.append(pipe)
        else:
            result.commands.append(cmd)

        # Record separator if present
        if pos < len(tokens) and tokens[pos][0] in ("AND_IF", "OR_IF", "SEMI"):
            result.separators.append(tokens[pos][1])
            pos += 1

    return result


# ---------------------------------------------------------------------------
# Convenience: extract all command names and key structural elements
# ---------------------------------------------------------------------------


def extract_command_names(ast: ChainedCommands) -> list[str]:
    """Return the basename of every command in the AST."""
    names: list[str] = []
    for item in ast.commands:
        if isinstance(item, PipeNode):
            for stage in item.stages:
                names.append(_basename(stage.command))
        elif isinstance(item, CommandNode):
            names.append(_basename(item.command))
    return names


def extract_all_args(ast: ChainedCommands) -> list[list[str]]:
    """Return all argument lists from every command in the AST."""
    result: list[list[str]] = []
    for item in ast.commands:
        if isinstance(item, PipeNode):
            for stage in item.stages:
                result.append(stage.args)
        elif isinstance(item, CommandNode):
            result.append(item.args)
    return result


def extract_redirect_targets(ast: ChainedCommands) -> list[str]:
    """Return all redirection target paths."""
    targets: list[str] = []
    for item in ast.commands:
        if isinstance(item, PipeNode):
            for stage in item.stages:
                for r in stage.redirects:
                    targets.append(r.target)
        elif isinstance(item, CommandNode):
            for r in item.redirects:
                targets.append(r.target)
    return [t for t in targets if t]


def has_subshell(ast: ChainedCommands) -> bool:
    """Check whether the command line contains any subshell expression."""
    raw = str(ast)
    return "$(" in raw or "`" in raw


def _basename(path: str) -> str:
    """Return the basename of a command path."""
    return path.rsplit("/", 1)[-1]

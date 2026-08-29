"""Lightweight POSIX sh command parser for security analysis.

Parses shell commands into a structural AST that the rule engine in
``rules.py`` can inspect.  This replaces regex-based pattern matching
with grammar-aware analysis that is robust against whitespace tricks,
quoting, variable expansions, and command chaining.

The parser is intentionally NOT a full sh implementation — it only
extracts the structural elements relevant to security decisions:
command names, arguments, redirections, pipes, subshells, and
command separators.

Security invariants (fail-closed — a violation makes ``parse`` return
``None``, and every caller treats ``None`` as "deny"):

- Full consumption: every input character must belong to a token.  Nothing
  is silently skipped — a bare ``&`` is a command separator, never dropped.
- Single line: line continuations ``\\<newline>`` are removed up front
  (exactly like sh, so ``$\\<newline>(`` is seen as ``$(``); any remaining
  ``\\n``/``\\r`` is a command separator this parser cannot model, so the
  command is rejected.
- Word joining: escape sequences (``\\x``), quote fragments, and adjacent
  unquoted fragments join into ONE argument exactly like sh does, so
  ``-\\c`` / ``-"c"`` are seen as ``-c``.
- Redirection targets must be statically determinable words — a variable
  expansion or glob in target position is rejected.
- Anything else that cannot be modelled statically (bare parentheses,
  ANSI-C ``$'...'`` / locale ``$"..."`` quoting, unterminated quotes or
  expansions) is rejected.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# AST node types
# ---------------------------------------------------------------------------


@dataclass
class RedirectNode:
    """A redirection like ``> /dev/null`` or ``2>&1``."""

    fd: str = ""  # e.g. "", "2" (for 2>)
    direction: str = ">"  # ">", ">>", "<", "<<", ">&", "<&", "&>", "&>>"
    target: str = ""  # file path, fd number (merges), or "-" (fd close)


@dataclass
class CommandNode:
    """A single command with arguments and redirections."""

    command: str  # executable name (basename or full path)
    args: list[str] = field(default_factory=list)  # all arguments including the command
    redirects: list[RedirectNode] = field(default_factory=list)
    # Parallel to ``args``: True when the argument contains an UNQUOTED glob
    # character (``*``, ``?``, ``[``) that sh would expand at runtime.
    arg_globs: list[bool] = field(default_factory=list)
    # Parallel to ``args``: True when the argument contains a ``$`` expansion
    # (``$name`` / ``${...}`` / special parameter) that sh would expand at
    # runtime.  Write-path allowlist checks use this instead of a lexical
    # ``"$" in token`` scan.  ``$(...)`` is a subshell, not a var.
    arg_vars: list[bool] = field(default_factory=list)


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
    """A list of commands separated by ``;``, ``&&``, ``||``, or ``&``."""

    commands: list[CommandNode | PipeNode] = field(default_factory=list)
    separators: list[str] = field(default_factory=list)  # ";", "&&", "||", "&"


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

# Characters that, when unquoted and unescaped, sh would expand into
# (possibly many) words at runtime.
_GLOB_CHARS = frozenset("*?[")

# POSIX special parameters: ``$?``, ``$$``, ``$!``, ``$#``, ``$*``, ``$@``,
# ``$-`` (``$0``–``$9`` are covered by the digit check).
_SPECIAL_PARAMS = frozenset("?$!#*@-")


@dataclass
class _Word:
    """A scanned word: joined text plus security-relevant properties."""

    text: str = ""
    unquoted_glob: bool = False
    has_var: bool = False  # $name / ${...} / $ special parameter, verbatim


@dataclass
class _Sep:
    """A control operator: ``;``, ``&&``, ``||``, ``&`` (background), ``|``."""

    value: str


@dataclass
class _Redir:
    """A redirection operator; ``node.target`` is filled by the parser when
    ``needs_target`` is True (file redirects) and preset for fd merges."""

    node: RedirectNode
    needs_target: bool


_Token = _Word | _Sep | _Redir


def _skip_quoted(command: str, i: int, quote: str, *, escape: bool) -> int | None:
    """Return the position after the closing ``quote`` for the one at ``i``.

    Only the extent matters here (used for backtick bodies and quoted
    strings inside ``$(...)`` spans), not the content.
    """
    n = len(command)
    i += 1
    while i < n:
        ch = command[i]
        if escape and ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return None


def _consume_parens(command: str, i: int) -> int | None:
    """Return the position after the ``)`` matching the ``(`` at ``i``.

    Handles nesting, ``\\x`` escapes, and quoted bodies inside the span.
    Returns ``None`` when unterminated (fail-closed).
    """
    n = len(command)
    depth = 0
    while i < n:
        ch = command[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth -= 1
            i += 1
            if depth == 0:
                return i
            continue
        if ch in "'\"":
            end = _skip_quoted(command, i, ch, escape=(ch == '"'))
            if end is None:
                return None
            i = end
            continue
        if ch == "`":
            end = _skip_quoted(command, i, "`", escape=True)
            if end is None:
                return None
            i = end
            continue
        i += 1
    return None


def _consume_brace(command: str, i: int) -> int | None:
    """Return the position after the ``}`` matching the ``{`` at ``i``."""
    n = len(command)
    depth = 0
    while i < n:
        ch = command[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _scan_dollar(command: str, i: int, *, in_dquote: bool) -> tuple[str, bool, int] | None:
    """Scan a ``$`` expansion at ``i``; returns (verbatim text, has_var, pos).

    Expansions are kept verbatim so downstream checks can see them.
    ANSI-C (``$'...'``) and locale (``$"..."``) quoting decode escapes we do
    not model — outside double quotes they are rejected.  A ``$`` that
    introduces no expansion is a literal character.
    """
    n = len(command)
    nxt = command[i + 1] if i + 1 < n else ""
    if nxt == "(":
        end = _consume_parens(command, i + 1)
        if end is None:
            return None
        return command[i:end], False, end
    if nxt == "{":
        end = _consume_brace(command, i + 1)
        if end is None:
            return None
        return command[i:end], True, end
    if nxt in "'\"":
        if in_dquote:
            return "$", False, i + 1  # literal inside double quotes
        return None  # ANSI-C / locale quoting — not statically modelable
    if nxt.isalpha() or nxt == "_":
        j = i + 1
        while j < n and (command[j].isalnum() or command[j] == "_"):
            j += 1
        return command[i:j], True, j
    if nxt.isdigit() or nxt in _SPECIAL_PARAMS:
        return command[i : i + 2], True, i + 2
    return "$", False, i + 1


def _scan_dquoted(command: str, i: int) -> tuple[str, bool, int] | None:
    """Scan a double-quoted fragment starting at the opening quote.

    Only ``\\$``, ``\\```, ``\\"``, and ``\\\\`` are escapes inside double
    quotes; any other backslash is literal.  ``$``/backtick expansions are
    kept verbatim.  Returns (text, has_var, new pos) or ``None``.
    """
    n = len(command)
    i += 1  # opening quote
    parts: list[str] = []
    has_var = False
    while i < n:
        ch = command[i]
        if ch == '"':
            return "".join(parts), has_var, i + 1
        if ch == "\\":
            nxt = command[i + 1] if i + 1 < n else ""
            if nxt in ("$", "`", '"', "\\"):
                parts.append(nxt)
                i += 2
            else:
                parts.append("\\")
                i += 1
            continue
        if ch == "`":
            end = _skip_quoted(command, i, "`", escape=True)
            if end is None:
                return None
            parts.append(command[i:end])
            i = end
            continue
        if ch == "$":
            dollar = _scan_dollar(command, i, in_dquote=True)
            if dollar is None:
                return None
            text, is_var, i = dollar
            parts.append(text)
            has_var = has_var or is_var
            continue
        parts.append(ch)
        i += 1
    return None  # unterminated double quote


def _scan_word(command: str, i: int) -> tuple[_Word, int] | None:
    """Scan one word starting at ``i``, joining fragments like sh does.

    Adjacent quoted/unquoted fragments form ONE argument, with ``\\x``
    escapes resolved (``-\\c`` → ``-c``).  Returns ``None`` for anything
    that cannot be modelled safely.
    """
    n = len(command)
    word = _Word()
    while i < n:
        ch = command[i]
        if ch in " \t;|&":
            break
        if ch in "<>":
            if command.startswith("(", i + 1):
                # Process substitution <(...) / >(...) — kept verbatim.
                end = _consume_parens(command, i + 1)
                if end is None:
                    return None
                word.text += command[i:end]
                i = end
                continue
            break
        if ch == "\\":
            if i + 1 >= n:
                return None  # trailing backslash
            word.text += command[i + 1]
            i += 2
            continue
        if ch == "'":
            end = command.find("'", i + 1)
            if end == -1:
                return None  # unterminated single quote
            word.text += command[i + 1 : end]
            i = end + 1
            continue
        if ch == '"':
            scanned = _scan_dquoted(command, i)
            if scanned is None:
                return None
            text, has_var, i = scanned
            word.text += text
            word.has_var = word.has_var or has_var
            continue
        if ch == "`":
            end = _skip_quoted(command, i, "`", escape=True)
            if end is None:
                return None
            word.text += command[i:end]
            i = end
            continue
        if ch == "$":
            dollar = _scan_dollar(command, i, in_dquote=False)
            if dollar is None:
                return None
            text, is_var, i = dollar
            word.text += text
            word.has_var = word.has_var or is_var
            continue
        if ch in "()":
            # Bare parentheses are subshell/group syntax we do not model.
            return None
        if ch in _GLOB_CHARS:
            word.unquoted_glob = True
        word.text += ch
        i += 1
    return word, i


def _scan_redirect(command: str, i: int, fd: str) -> tuple[_Redir, int] | None:
    """Scan one redirection operator starting at ``i`` (``<`` or ``>``).

    Fd merges (``2>&1``, ``<&0``) and closes (``>&-``) carry their target
    inline; file redirects (``>``, ``>>``, ``<<``, ``&>``, ``&>>``) need the
    following word as target.  ``<&`` followed by anything but an fd or
    ``-`` is not valid sh — rejected.
    """
    n = len(command)
    target = ""
    needs_target = True
    if command.startswith(">&", i) or command.startswith("<&", i):
        direction = command[i : i + 2]
        i += 2
        start = i
        while i < n and command[i].isdigit():
            i += 1
        if i > start:
            target = command[start:i]  # fd merge: 2>&1
            needs_target = False
        elif i < n and command[i] == "-":
            target = "-"  # fd close: 2>&-
            i += 1
            needs_target = False
        elif direction == ">&":
            # bash ``>&word`` == ``&>word``: both streams to a file.
            direction = "&>"
        else:
            return None
    elif command.startswith(">>", i):
        direction = ">>"
        i += 2
    elif command.startswith("<<", i):
        direction = "<<"
        i += 2
        if i < n and command[i] == "-":  # <<- strips leading tabs
            i += 1
    else:
        direction = command[i]
        i += 1
    node = RedirectNode(fd=fd, direction=direction, target=target)
    return _Redir(node, needs_target), i


def _scan(command: str) -> list[_Token] | None:
    """Lex a command line into word/operator tokens, or ``None``.

    Fail-closed: any character sequence this lexer cannot model exactly the
    way sh would makes the whole command unparseable.
    """
    # Line continuations are removed before any other lexing, exactly like
    # sh: ``$\<newline>(`` becomes ``$(``.  Any remaining line break is a
    # command separator this single-line parser cannot model — reject it.
    command = command.replace("\\\r\n", "").replace("\\\n", "").replace("\\\r", "")
    if "\n" in command or "\r" in command:
        return None

    tokens: list[_Token] = []
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if ch in " \t":
            i += 1
            continue
        if ch == ";":
            tokens.append(_Sep(";"))
            i += 1
            continue
        if ch == "|":
            if command.startswith("||", i):
                tokens.append(_Sep("||"))
                i += 2
            else:
                tokens.append(_Sep("|"))
                i += 1
            continue
        if ch == "&":
            if command.startswith("&&", i):
                tokens.append(_Sep("&&"))
                i += 2
            elif command.startswith("&>>", i):
                tokens.append(_Redir(RedirectNode(direction="&>>"), True))
                i += 3
            elif command.startswith("&>", i):
                tokens.append(_Redir(RedirectNode(direction="&>"), True))
                i += 2
            else:
                tokens.append(_Sep("&"))
                i += 1
            continue

        # A run of digits immediately followed by < or > (but not the
        # process-substitution forms <( / >() is an fd prefix: ``2>err``.
        j = i
        while j < n and command[j].isdigit():
            j += 1
        fd = ""
        if j > i and j < n and command[j] in "<>" and not command.startswith("(", j + 1):
            fd = command[i:j]
            i = j

        if i < n and command[i] in "<>" and not command.startswith("(", i + 1):
            scanned_redir = _scan_redirect(command, i, fd)
            if scanned_redir is None:
                return None
            redir_token, i = scanned_redir
            tokens.append(redir_token)
            continue

        scanned_word = _scan_word(command, i)
        if scanned_word is None:
            return None
        word_token, i = scanned_word
        tokens.append(word_token)

    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _is_pipe_token(token: _Token) -> bool:
    """Check if token is the pipe operator."""
    return isinstance(token, _Sep) and token.value == "|"


def _collect_segment(
    tokens: list[_Token], pos: int
) -> tuple[list[str], list[bool], list[bool], list[RedirectNode], int] | None:
    """Collect words and redirections for one command, starting at ``pos``.

    Stops at a control operator or end of input.  Returns ``None`` when a
    redirection is missing its target word or the target is not statically
    determinable (variable expansion, glob).
    """
    args: list[str] = []
    arg_globs: list[bool] = []
    arg_vars: list[bool] = []
    redirects: list[RedirectNode] = []
    while pos < len(tokens):
        token = tokens[pos]
        if isinstance(token, _Sep):
            break
        if isinstance(token, _Redir):
            pos += 1
            node = token.node
            if token.needs_target:
                if pos >= len(tokens):
                    return None  # missing target — a syntax error in sh
                target_token = tokens[pos]
                if not isinstance(target_token, _Word):
                    return None
                if target_token.has_var or target_token.unquoted_glob:
                    # Target not statically determinable — fail closed.
                    return None
                node.target = target_token.text
                pos += 1
            redirects.append(node)
            continue
        args.append(token.text)
        arg_globs.append(token.unquoted_glob)
        arg_vars.append(token.has_var)
        pos += 1
    return args, arg_globs, arg_vars, redirects, pos


def parse(command: str) -> ChainedCommands | None:
    """Parse a shell command line into a ``ChainedCommands`` AST.

    Returns ``None`` when the command is empty or cannot be modelled
    exactly (fail-closed: callers treat ``None`` as "deny").
    """
    tokens = _scan(command)
    if not tokens:
        return None

    result = ChainedCommands()
    pos = 0

    while pos < len(tokens):
        # Collect args and redirections for this command
        segment = _collect_segment(tokens, pos)
        if segment is None:
            return None
        args, arg_globs, arg_vars, redirects, pos = segment

        if not args:
            if redirects:
                # A redirection without a command has no AST home — and no
                # legitimate use in this harness.  Fail closed.
                return None
            # Only a separator — record it and move on.
            token = tokens[pos]
            if isinstance(token, _Sep):
                if token.value != "|":
                    result.separators.append(token.value)
                pos += 1
            continue

        cmd = CommandNode(
            command=args[0],
            args=args,
            redirects=redirects,
            arg_globs=arg_globs,
            arg_vars=arg_vars,
        )

        # Check for pipe chain
        if pos < len(tokens) and _is_pipe_token(tokens[pos]):
            pipe = PipeNode(stages=[cmd])
            pos += 1  # skip PIPE
            # Collect subsequent pipe stages
            while pos < len(tokens):
                stage = _collect_segment(tokens, pos)
                if stage is None:
                    return None
                stage_args, stage_globs, stage_vars, stage_redirs, pos = stage
                if not stage_args:
                    if stage_redirs:
                        return None
                    break
                pipe.stages.append(
                    CommandNode(
                        command=stage_args[0],
                        args=stage_args,
                        redirects=stage_redirs,
                        arg_globs=stage_globs,
                        arg_vars=stage_vars,
                    )
                )
                if pos < len(tokens) and _is_pipe_token(tokens[pos]):
                    pos += 1
                else:
                    break
            result.commands.append(pipe)
        else:
            result.commands.append(cmd)

        # Record separator if present (";", "&&", "||", "&")
        if pos < len(tokens):
            token = tokens[pos]
            if isinstance(token, _Sep):
                if token.value != "|":
                    result.separators.append(token.value)
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
    """Check whether the command line contains any subshell expression.

    Structured traversal of args and redirect targets — never a repr scan.
    Detects command substitution (``$(...)`` / backticks, which the lexer
    preserves verbatim, including inside quoted strings for a conservative
    fail-safe) and process substitution (``<(...)`` / ``>(...)``, which bash
    executes even when ``sh`` is bash in POSIX mode).
    """

    def _token_is_subshell(token: str) -> bool:
        return "$(" in token or "`" in token or "<(" in token or ">(" in token

    for item in ast.commands:
        nodes = item.stages if isinstance(item, PipeNode) else [item]
        for node in nodes:
            if any(_token_is_subshell(arg) for arg in node.args):
                return True
            if any(_token_is_subshell(r.target) for r in node.redirects):
                return True
    return False


def _basename(path: str) -> str:
    """Return the basename of a command path."""
    return path.rsplit("/", 1)[-1]

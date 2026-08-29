"""F-09 regression tests: shell allowlist bypass families.

Every test reproduces a CONFIRMED attack string against the shell tool's
command allowlist gate.  After the fix each attack must be rejected before
any process is spawned (fail-closed, no sandbox-exec required).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.security.parser import CommandNode, extract_command_names, has_subshell, parse
from js.security.sandbox import SandboxResult
from js.tools.shell import ShellTool


@pytest.fixture
def shell_tool(tmp_path: Path) -> ShellTool:
    limits = ToolLimits()
    guard = BehaviorGuard(SecurityConfig(), tmp_path)
    return ShellTool(tmp_path, limits, guard)


def _denied(tool: ShellTool, command: str) -> bool:
    return tool._command_allowlist_error(command, tool.workspace) is not None


class TestRemovedFromDefaultAllowlist:
    """The most dangerous, least-used commands are gone from the defaults."""

    def test_find_removed_from_default_allowlist(self) -> None:
        assert "find" not in ToolLimits().shell_command_allowlist

    def test_awk_removed_from_default_allowlist(self) -> None:
        assert "awk" not in ToolLimits().shell_command_allowlist

    def test_find_exec_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "find . -name '*.py' -exec id \\;")

    def test_find_delete_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "find . -name '*.tmp' -delete")

    def test_awk_system_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "awk 'BEGIN{system(\"id\")}'")

    def test_awk_getline_pipe_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "awk 'BEGIN{\"id\"|getline x; print x}'")


class TestGitArgumentRules:
    def test_git_dash_c_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git -c core.pager=id log")

    def test_git_config_env_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git --config-env=core.pager=ID log")

    def test_git_config_subcommand_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git config alias.x '!id'")

    def test_git_alias_subcommand_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git alias")

    def test_git_ext_scheme_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git clone ext::sh -c id% .")

    def test_git_upload_pack_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git clone --upload-pack=id https://x/y")

    def test_git_status_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "git status")

    def test_git_log_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "git log --oneline -5")

    def test_git_output_flag_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git log --output=out.txt")
        assert _denied(shell_tool, "git show --output=out.txt HEAD")
        assert _denied(shell_tool, "git log --output out.txt")
        assert _denied(shell_tool, "git format-patch --output-directory /tmp HEAD")
        assert _denied(shell_tool, "git format-patch --output-directory=/tmp HEAD")

    def test_git_pager_and_extdiff_flags_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git grep -O foo")
        assert _denied(shell_tool, "git grep --open-files-in-pager foo")
        assert _denied(shell_tool, "git diff --ext-diff")

    def test_git_dash_c_upper_value_consumed(self, shell_tool: ShellTool) -> None:
        # The -C path value must not be mistaken for the subcommand.
        assert not _denied(shell_tool, "git -C subdir status")

    def test_git_dash_c_upper_config_denied(self, shell_tool: ShellTool) -> None:
        # CONFIRMED-EXEC: ``nested`` used to shadow the real config subcommand.
        assert _denied(shell_tool, "git -C nested config user.email x")

    def test_git_dash_c_upper_rebase_exec_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git -C nested rebase --exec 'id' HEAD~1")

    def test_git_value_long_options_consumed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "git --git-dir subdir/.git status")
        assert not _denied(shell_tool, "git --git-dir=subdir/.git status")
        assert not _denied(shell_tool, "git --work-tree wt diff")
        assert not _denied(shell_tool, "git --namespace ns log")

    def test_git_value_long_options_config_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git --git-dir nested/.git config core.x y")
        assert _denied(shell_tool, "git --git-dir=nested/.git config core.x y")
        assert _denied(shell_tool, "git --work-tree wt config core.x y")
        assert _denied(shell_tool, "git --namespace ns config core.x y")

    def test_git_non_allowlisted_subcommands_denied(self, shell_tool: ShellTool) -> None:
        for command in (
            "git init nested",
            "git rebase -i HEAD~1",
            "git bisect start",
            "git filter-branch --force",
            "git mergetool",
            "git send-email",
            "git am patch",
            "git apply patch",
            "git instaweb",
            "git daemon",
            "git worktree add x",
            "git submodule update",
            "git clone https://example.com/x.git",
            "git fetch origin",
            "git pull",
            "git push origin main",
            "git remote add origin https://example.com/x.git",
            "git merge feature",
            "git reset --hard HEAD~1",
            "git cherry-pick abc123",
            "git revert abc123",
            "git gc",
            "git clean -fd",
        ):
            assert _denied(shell_tool, command), command

    def test_git_allowlisted_subcommands_allowed(self, shell_tool: ShellTool) -> None:
        for command in (
            "git diff --stat",
            "git show HEAD",
            "git grep pattern",
            "git add file.txt",
            "git commit -m msg",
            "git branch -a",
            "git checkout -b feature",
            "git switch main",
            "git restore file.txt",
            "git mv old.txt new.txt",
            "git rm cached.txt",
            "git tag v1.0",
            "git rev-parse HEAD",
            "git ls-files",
            "git ls-tree HEAD",
            "git blame file.txt",
            "git describe --tags",
            "git stash list",
            "git shortlog -sn",
            "git rev-list --count HEAD",
            "git cat-file -p HEAD",
        ):
            assert not _denied(shell_tool, command), command


class TestSedArgumentRules:
    def test_sed_in_place_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "sed -i '' 's/a/b/' file.txt")

    def test_sed_in_place_suffix_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "sed -i.bak 's/a/b/' file.txt")

    def test_sed_execute_command_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "sed '1e id' file.txt")

    def test_sed_substitute_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "sed -n 's/a/b/p' file.txt")

    def test_sed_script_file_denied(self, shell_tool: ShellTool) -> None:
        # -f/--file load a program file that is never pattern-scanned.
        assert _denied(shell_tool, "sed -f script.sed file.txt")
        assert _denied(shell_tool, "sed --file script.sed file.txt")
        assert _denied(shell_tool, "sed --file=script.sed file.txt")

    def test_sed_attached_expression_execute_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "sed -e'1e id' file.txt")

    def test_sed_long_expression_write_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "sed --expression='1w out.txt' file.txt")

    def test_sed_attached_expression_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "sed -e's/a/b/' file.txt")
        assert not _denied(shell_tool, "sed --expression='s/a/b/' file.txt")

    def test_sed_separate_expression_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "sed -e 's/a/b/' file.txt")


class TestTarArgumentRules:
    def test_tar_change_dir_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "tar -C / -xf archive.tar")

    def test_tar_absolute_member_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "tar -cf out.tar /etc/passwd")

    def test_tar_dotdot_member_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "tar -cf out.tar ../../secret")

    def test_tar_checkpoint_action_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "tar -cf out.tar --checkpoint-action=exec=id .")

    def test_tar_compress_program_letter_denied(self, shell_tool: ShellTool) -> None:
        # GNU tar -I runs an external compression program.
        assert _denied(shell_tool, "tar -I id -cf out.tar src")

    def test_tar_info_script_letter_denied(self, shell_tool: ShellTool) -> None:
        # GNU tar -F runs a script at each volume switch.
        assert _denied(shell_tool, "tar -F id -cf out.tar src")

    def test_tar_workspace_archive_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "tar -cf out.tar src")
        assert not _denied(shell_tool, "tar cf out.tar src")
        assert not _denied(shell_tool, "tar tf archive.tar")

    def test_tar_extract_denied(self, shell_tool: ShellTool) -> None:
        # Extract can plant a nested .git that does not exist when the OS
        # sandbox profile is snapshotted (finding 1 residual).
        for command in (
            "tar -xf archive.tar",
            "tar xf archive.tar",
            "tar --extract -f archive.tar",
            "tar --get -f archive.tar",
        ):
            assert _denied(shell_tool, command), command


class TestMvArgumentRules:
    def test_mv_overwrite_existing_denied(self, shell_tool: ShellTool, tmp_path: Path) -> None:
        (tmp_path / "victim.txt").write_text("keep", encoding="utf-8")
        (tmp_path / "new.txt").write_text("new", encoding="utf-8")
        assert _denied(shell_tool, "mv new.txt victim.txt")

    def test_mv_to_fresh_target_allowed(self, shell_tool: ShellTool, tmp_path: Path) -> None:
        (tmp_path / "new.txt").write_text("new", encoding="utf-8")
        assert not _denied(shell_tool, "mv new.txt renamed.txt")

    def test_mv_into_directory_allowed(self, shell_tool: ShellTool, tmp_path: Path) -> None:
        (tmp_path / "new.txt").write_text("new", encoding="utf-8")
        (tmp_path / "dest").mkdir()
        assert not _denied(shell_tool, "mv new.txt dest")


class TestJqArgumentRules:
    def test_jq_arg_file_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "jq --arg-file x secrets.txt -n '$x'")

    def test_jq_slurpfile_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "jq --slurpfile x data.txt -n '$x'")

    def test_jq_rawfile_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "jq --rawfile x data.txt -n '$x'")

    def test_jq_from_file_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "jq -f program.jq data.json")

    def test_jq_filter_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "jq '.name' data.json")


class TestRgArgumentRules:
    def test_rg_pre_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "rg --pre id pattern .")

    def test_rg_pre_equals_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "rg --pre=id pattern .")

    def test_rg_pre_path_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "rg --pre-path /bin/sh pattern .")

    def test_rg_pre_path_equals_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "rg --pre-path=/bin/sh pattern .")

    def test_rg_hostname_bin_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "rg --hostname-bin id pattern .")

    def test_rg_plain_search_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "rg -l foo .")

    def test_rg_literal_dangerous_text_after_ddash_allowed(self, shell_tool: ShellTool) -> None:
        # `--` ends flag parsing; searching the literal text "--pre" is safe.
        assert not _denied(shell_tool, 'rg -- "--pre"')


class TestParserSeparators:
    """Parser hardening: every confirmed lexer/parser bypass must be rejected.

    The old regex tokenizer silently dropped unmatched characters (bare
    ``&``, line breaks, backslashes) and split words at quote boundaries,
    so real sh executed far more than the parser saw.  Each test below
    reproduces one confirmed payload and asserts the fail-closed outcome.
    """

    def test_background_separator_exposes_second_command(self, shell_tool: ShellTool) -> None:
        # Real sh runs ``perl evil.pl`` in the background; the parser must
        # see both commands (previously the bare ``&`` was dropped).
        ast = parse("touch x & perl evil.pl")
        assert ast is not None
        assert extract_command_names(ast) == ["touch", "perl"]
        assert "&" in ast.separators
        assert _denied(shell_tool, "touch x & perl evil.pl")

    def test_newline_is_unparseable(self, shell_tool: ShellTool) -> None:
        # sh treats \n as a command separator — this parser is single-line.
        assert parse("touch x\nperl evil.pl") is None
        assert _denied(shell_tool, "touch x\nperl evil.pl")

    def test_carriage_return_is_unparseable(self, shell_tool: ShellTool) -> None:
        assert parse("touch x\rperl evil.pl") is None
        assert _denied(shell_tool, "touch x\rperl evil.pl")

    def test_line_continuation_subshell_detected(self, shell_tool: ShellTool) -> None:
        # sh removes the line continuation first, joining "$\" + "(" into "$(…".
        payload = "echo $\\\n(sh -c 'id')"
        ast = parse(payload)
        assert ast is not None
        assert has_subshell(ast)
        decision = shell_tool.guard.check_command(payload)
        assert decision.decision == SecurityDecisionType.BLOCK
        assert "subshell" in decision.reason.lower()

    def test_escaped_git_flag_rejoined(self, shell_tool: ShellTool) -> None:
        # sh joins "-\" + "c" into the single word "-c".
        assert _denied(shell_tool, "git -\\c core.pager=id log")

    def test_quoted_git_flag_rejoined(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, 'git -"c" core.pager=id log')

    def test_mixed_quote_git_flag_rejoined(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "git -''c core.pager=id log")

    def test_escaped_sed_flag_rejoined(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "sed -\\i s/a/b/ f")

    def test_escaped_rg_flag_rejoined(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "rg --pr\\e id .")

    def test_redirect_target_brace_var_unparseable(self, shell_tool: ShellTool) -> None:
        # ${X:-/dev/sda1} can resolve to a raw device — not statically known.
        assert parse("echo hi > ${X:-/dev/sda1}") is None
        assert _denied(shell_tool, "echo hi > ${X:-/dev/sda1}")

    def test_redirect_target_simple_var_unparseable(self, shell_tool: ShellTool) -> None:
        assert parse("echo hi > $HOME/x") is None
        assert _denied(shell_tool, "echo hi > $HOME/x")

    def test_ansi_c_quote_unparseable(self, shell_tool: ShellTool) -> None:
        # $'\x69\x64' decodes to "id" — escape decoding is not modelled.
        assert parse("echo $'\\x69\\x64'") is None
        assert _denied(shell_tool, "echo $'\\x69\\x64'")

    def test_tar_unquoted_glob_denied(self, shell_tool: ShellTool) -> None:
        # Runtime expansion of * can smuggle flag-named files past argv rules.
        assert _denied(shell_tool, "tar cf x.tar *")

    def test_unquoted_glob_denied_for_static_rule_commands(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "tar cf x.tar ?")
        assert _denied(shell_tool, "rg foo [a] .")
        assert _denied(shell_tool, "git log *")
        assert _denied(shell_tool, "sed 's/a/b/' *")

    def test_quoted_glob_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "rg 'foo*bar' .")
        assert not _denied(shell_tool, "git log -- '*.py'")

    def test_bare_parens_unparseable(self) -> None:
        # Subshell/group syntax is not modelled; the fork bomb still hits the
        # guard's hardline regex layer.
        assert parse(":(){ :|:& };:") is None

    def test_unterminated_constructs_unparseable(self) -> None:
        assert parse("echo 'unterminated") is None
        assert parse('echo "unterminated') is None
        assert parse("echo $(id") is None
        assert parse("echo `id") is None
        assert parse("echo hi >") is None

    def test_redirect_merge_forms_preserved(self) -> None:
        # Fd merges/closes keep converging on redirect nodes, never on a bare
        # "&" separator.
        ast = parse("cmd 2>&1")
        assert ast is not None
        node = ast.commands[0]
        assert isinstance(node, CommandNode)
        assert node.redirects[0].direction == ">&"
        assert node.redirects[0].target == "1"
        for command in ("cmd >&2", "cmd 2>&-", "cmd &> out.txt", "cmd &>> out.txt"):
            merged = parse(command)
            assert merged is not None, command
            assert merged.separators == [], command

    def test_benign_commands_unaffected(self, shell_tool: ShellTool) -> None:
        for command in (
            "echo hello",
            "ls -la",
            "git status",
            "rg pattern .",
            "ls 2>&1",
            "grep foo < bar.txt 2>&1",
            "git log --oneline -5",
            "echo $HOME",
            "echo '$HOME'",
            "echo hi > out.txt",
        ):
            assert parse(command) is not None, command
            assert not _denied(shell_tool, command), command

    def test_parser_exposes_arg_vars_on_expansions(self) -> None:
        """``has_var`` is on the AST so write-path allowlist can reject it."""
        for command in ("echo $HOME", 'echo "$HOME"', "echo ${HOME}", "mkdir nested/$x"):
            ast = parse(command)
            assert ast is not None, command
            node = ast.commands[0]
            assert isinstance(node, CommandNode)
            assert any(node.arg_vars), command
        literal = parse("echo '$HOME'")
        assert literal is not None
        lit_node = literal.commands[0]
        assert isinstance(lit_node, CommandNode)
        assert not any(lit_node.arg_vars)

    def test_read_command_variable_expansion_still_allowed(self, shell_tool: ShellTool) -> None:
        for command in ("echo $HOME", 'echo "$HOME"', "echo ${HOME}", "ls $PWD"):
            assert not _denied(shell_tool, command), command
        assert not _denied(shell_tool, "echo '$HOME'")


class TestBypassRejectedEndToEnd:
    """The shell tool rejects the attack before any process spawns."""

    @pytest.mark.asyncio
    async def test_find_exec_rejected_before_spawn(self, shell_tool: ShellTool) -> None:
        result = await shell_tool.execute("find . -exec id \\;")
        assert not result.success
        assert result.error

    @pytest.mark.asyncio
    async def test_git_dash_c_rejected_before_spawn(self, shell_tool: ShellTool) -> None:
        result = await shell_tool.execute("git -c core.pager=id log")
        assert not result.success
        assert result.error
        assert "denied" in result.error.lower()


class TestGitMetadataShellWriteDenied:
    """R3-2: the shell tool must never plant .git hooks/config — they execute
    OUTSIDE the sandbox on the host's next git invocation.  Defense in depth:
    the rules layer rejects the redirect and the OS sandbox denies the write."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "command",
        [
            "echo 'id' > .git/hooks/post-checkout",
            "echo 'x' >> .git/hooks/pre-commit",
            "printf 'x' > .git/config",
            "echo 'id' > .GIT/hooks/pwn",
            "echo 'id' > sub/../.git/config",
        ],
    )
    async def test_redirect_into_git_tree_blocked(
        self, shell_tool: ShellTool, tmp_path: Path, command: str
    ) -> None:
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        result = await shell_tool.execute(command)
        assert not result.success, command
        assert not (tmp_path / ".git" / "hooks" / "post-checkout").exists()
        assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()
        assert not (tmp_path / ".git" / "config").exists()

    @pytest.mark.asyncio
    async def test_benign_workspace_redirect_still_works(self, shell_tool: ShellTool) -> None:
        result = await shell_tool.execute("echo ok > normal.txt")
        assert result.success

    def test_write_commands_into_git_component_denied(self, shell_tool: ShellTool) -> None:
        for command in (
            "mkdir nested/.git",
            "mkdir -p nested/.git/hooks",
            "mkdir .GIT",
            "touch nested/.git",
            "touch nested/.git/config",
            "mv payload.txt nested/.git/config",
            "mkdir -p nested/.git && mv payload.txt nested/.git/config",
            "git mv payload.txt nested/.git/config",
            "git add nested/.git/config",
        ):
            assert _denied(shell_tool, command), command

    def test_benign_mkdir_touch_mv_git_still_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "mkdir nested")
        assert not _denied(shell_tool, "mkdir -p nested/sub")
        assert not _denied(shell_tool, "mkdir .github")
        assert not _denied(shell_tool, "touch file.txt")
        assert not _denied(shell_tool, "touch .gitignore")
        assert not _denied(shell_tool, "mv old.txt new.txt")
        assert not _denied(shell_tool, "git mv old.txt new.txt")
        assert not _denied(shell_tool, "git add file.txt")
        assert not _denied(shell_tool, "git --git-dir nested/.git status")

    def test_write_command_dollar_expansion_denied(self, shell_tool: ShellTool) -> None:
        # Write-path ``arg_vars`` fail closed; read-only expansions stay allowed.
        for command in (
            "mkdir nested/$x",
            "mkdir nested/${x}",
            "touch nested/$x/config",
            "mv payload.txt nested/$x/config",
            "git add nested/$x",
        ):
            assert _denied(shell_tool, command), command
        assert not _denied(shell_tool, "echo $HOME")
        assert not _denied(shell_tool, "mkdir nested")

    @pytest.mark.asyncio
    async def test_mkdir_then_mv_into_new_nested_git_blocked(
        self, shell_tool: ShellTool, tmp_path: Path
    ) -> None:
        (tmp_path / "payload.txt").write_text("plant\n", encoding="utf-8")
        result = await shell_tool.execute(
            "mkdir -p nested/.git && mv payload.txt nested/.git/config"
        )
        assert not result.success
        assert not (tmp_path / "nested" / ".git").exists()
        assert (tmp_path / "payload.txt").read_text(encoding="utf-8") == "plant\n"


class TestTimeoutClamp:
    """Finding 8: a caller-supplied timeout may only shorten, never extend."""

    @staticmethod
    def _capture_executor(shell_tool: ShellTool, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        captured: dict[str, Any] = {}

        async def fake_execute(command: Any, **kwargs: Any) -> SandboxResult:
            captured.update(kwargs)
            return SandboxResult(returncode=0, stdout="ok", stderr="", duration_ms=1.0)

        monkeypatch.setattr(shell_tool.executor, "execute", fake_execute)
        return captured

    @pytest.mark.asyncio
    async def test_oversized_timeout_clamped_to_limit(
        self, shell_tool: ShellTool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._capture_executor(shell_tool, monkeypatch)
        result = await shell_tool.execute("echo hi", timeout=10**8)
        assert result.success
        assert captured["timeout"] == shell_tool.limits.shell_timeout

    @pytest.mark.asyncio
    async def test_shorter_timeout_still_honored(
        self, shell_tool: ShellTool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._capture_executor(shell_tool, monkeypatch)
        result = await shell_tool.execute("echo hi", timeout=5)
        assert result.success
        assert captured["timeout"] == 5

    @pytest.mark.asyncio
    async def test_default_timeout_uses_limit(
        self, shell_tool: ShellTool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._capture_executor(shell_tool, monkeypatch)
        result = await shell_tool.execute("echo hi")
        assert result.success
        assert captured["timeout"] == shell_tool.limits.shell_timeout

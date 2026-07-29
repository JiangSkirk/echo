"""F-09 regression tests: shell allowlist bypass families.

Every test reproduces a CONFIRMED attack string against the shell tool's
command allowlist gate.  After the fix each attack must be rejected before
any process is spawned (fail-closed, no sandbox-exec required).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
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


class TestSedArgumentRules:
    def test_sed_in_place_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "sed -i '' 's/a/b/' file.txt")

    def test_sed_in_place_suffix_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "sed -i.bak 's/a/b/' file.txt")

    def test_sed_execute_command_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "sed '1e id' file.txt")

    def test_sed_substitute_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "sed -n 's/a/b/p' file.txt")


class TestTarArgumentRules:
    def test_tar_change_dir_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "tar -C / -xf archive.tar")

    def test_tar_absolute_member_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "tar -cf out.tar /etc/passwd")

    def test_tar_dotdot_member_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "tar -cf out.tar ../../secret")

    def test_tar_checkpoint_action_denied(self, shell_tool: ShellTool) -> None:
        assert _denied(shell_tool, "tar -cf out.tar --checkpoint-action=exec=id .")

    def test_tar_workspace_archive_allowed(self, shell_tool: ShellTool) -> None:
        assert not _denied(shell_tool, "tar -cf out.tar src")


class TestMvArgumentRules:
    def test_mv_overwrite_existing_denied(
        self, shell_tool: ShellTool, tmp_path: Path
    ) -> None:
        (tmp_path / "victim.txt").write_text("keep", encoding="utf-8")
        (tmp_path / "new.txt").write_text("new", encoding="utf-8")
        assert _denied(shell_tool, "mv new.txt victim.txt")

    def test_mv_to_fresh_target_allowed(
        self, shell_tool: ShellTool, tmp_path: Path
    ) -> None:
        (tmp_path / "new.txt").write_text("new", encoding="utf-8")
        assert not _denied(shell_tool, "mv new.txt renamed.txt")

    def test_mv_into_directory_allowed(
        self, shell_tool: ShellTool, tmp_path: Path
    ) -> None:
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

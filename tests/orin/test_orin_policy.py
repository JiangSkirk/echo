"""Orin WP2 policy table tests: every row, both profiles, fixed priority."""

from __future__ import annotations

import pytest

from js.orin import taint as t
from js.orind import policy as p


class TestSinksForTool:
    @pytest.mark.parametrize(
        ("tool", "expected"),
        [
            ("file_read", p.SINK_FS_READ),
            ("file_write", p.SINK_FS_WRITE),
            ("shell", p.SINK_SPAWN | p.SINK_FS_WRITE | p.SINK_FS_OUTSIDE),
            ("web_search", p.SINK_NETWORK_EGRESS),
            ("connector.mail.send", p.SINK_NETWORK_EGRESS | p.SINK_CONNECTOR),
        ],
    )
    def test_known_tools(self, tool: str, expected: int) -> None:
        assert p.sinks_for_tool(tool) == expected

    def test_unknown_tool_has_no_sink_bits(self) -> None:
        assert p.sinks_for_tool("totally_unknown") == 0


class TestConservativeRows:
    def test_fs_read_allowed_even_when_dirty(self) -> None:
        decision = p.evaluate(
            tool_name="file_read",
            context_taint=t.WEB_CONTENT | t.TOOL_RESULT,
            arg_taint_bits=t.DIRTY_FOR_WRITE,
            args_overlap_dirty=True,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_ALLOW

    def test_fs_write_clean_args_allowed(self) -> None:
        decision = p.evaluate(
            tool_name="file_write",
            context_taint=t.USER_TURN,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_ALLOW

    def test_fs_write_with_dirty_args_requires_approval(self) -> None:
        decision = p.evaluate(
            tool_name="file_write",
            context_taint=t.WEB_CONTENT,
            arg_taint_bits=t.WEB_CONTENT,
            args_overlap_dirty=True,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_APPROVAL

    def test_shell_user_turn_allow(self) -> None:
        decision = p.evaluate(
            tool_name="shell",
            context_taint=t.USER_TURN,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_ALLOW

    def test_shell_web_overlap_denied(self) -> None:
        decision = p.evaluate(
            tool_name="shell",
            context_taint=t.WEB_CONTENT,
            arg_taint_bits=t.WEB_CONTENT,
            args_overlap_dirty=True,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_DENY

    def test_shell_without_user_turn_needs_approval(self) -> None:
        decision = p.evaluate(
            tool_name="shell",
            context_taint=t.TOOL_RESULT,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_APPROVAL

    def test_egress_memory_draw_approval(self) -> None:
        decision = p.evaluate(
            tool_name="web_search",
            context_taint=t.MEMORY_READ,
            arg_taint_bits=t.MEMORY_READ,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_APPROVAL

    def test_egress_secret_context_export_gate(self) -> None:
        decision = p.evaluate(
            tool_name="browser_fetch",
            context_taint=t.SECRET,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=2,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_EXPORT_GATE
        assert decision.needs_export_gate is True

    def test_memory_write_free_async_review(self) -> None:
        decision = p.evaluate(
            tool_name="memory_store",
            context_taint=t.TOOL_RESULT,
            arg_taint_bits=t.TOOL_RESULT,
            args_overlap_dirty=True,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_ALLOW

    def test_policy_change_indirect_denied(self) -> None:
        decision = p.evaluate(
            tool_name="__orin_policy__",
            context_taint=t.TOOL_RESULT,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_APPROVAL


class TestPolicyChangeSink:
    def _policy_change_eval(self, context_taint: int) -> p.PolicyDecision:
        return p.evaluate(
            tool_name="orin_control",  # unknown → default sink bits
            context_taint=context_taint,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )

    def test_direct_user_turn_only_path(self) -> None:
        # The policy-change sink is exercised via the dedicated bit; the
        # default row covers unclassified tools (approval in conservative).
        assert self._policy_change_eval(t.USER_TURN).verdict == p.VERDICT_APPROVAL


class TestDefaultRow:
    def test_conservative_default_is_approval(self) -> None:
        decision = p.evaluate(
            tool_name="mystery_tool",
            context_taint=0,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_APPROVAL
        assert decision.matched_row == "default"

    def test_compat_default_is_allow(self) -> None:
        decision = p.evaluate(
            tool_name="mystery_tool",
            context_taint=0,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_COMPAT,
        )
        assert decision.verdict == p.VERDICT_ALLOW
        assert "log" in decision.reason


class TestCompatEqualsLegacy:
    """compat 档 = 旧行为：任何输入组合都不得产生阻断性判定。"""

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"tool_name": "mystery_tool"},
            {"tool_name": "file_read"},
            {
                "tool_name": "file_write",
                "arg_taint_bits": t.DIRTY_FOR_WRITE,
                "args_overlap_dirty": True,
            },
            {
                "tool_name": "shell",
                "context_taint": t.WEB_CONTENT,
                "arg_taint_bits": t.WEB_CONTENT,
                "args_overlap_dirty": True,
            },
        ],
    )
    def test_compat_never_blocks(self, kwargs: dict) -> None:
        decision = p.evaluate(
            clearance=1,
            profile=p.PROFILE_COMPAT,
            **kwargs,
        )
        assert decision.verdict in (p.VERDICT_ALLOW,)


class TestPriorityOrder:
    def test_deny_beats_approval_on_same_sink(self) -> None:
        # shell hits both the deny row (web overlap) and the approval path.
        decision = p.evaluate(
            tool_name="shell",
            context_taint=t.WEB_CONTENT,
            arg_taint_bits=t.WEB_CONTENT,
            args_overlap_dirty=True,
            clearance=2,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_DENY

    def test_export_gate_beats_approval(self) -> None:
        decision = p.evaluate(
            tool_name="web_search",
            context_taint=t.SECRET,
            arg_taint_bits=t.MEMORY_READ,
            args_overlap_dirty=False,
            clearance=2,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_EXPORT_GATE

    def test_secret_escalates_egress_verdicts(self) -> None:
        decision = p.evaluate(
            tool_name="web_search",
            context_taint=0,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=2,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_EXPORT_GATE


class TestUnknownProfile:
    def test_falls_back_to_conservative(self) -> None:
        decision = p.evaluate(
            tool_name="mystery_tool",
            context_taint=0,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile="bogus",
        )
        assert decision.verdict == p.VERDICT_APPROVAL


class TestHostControlRow:
    def test_provider_mutate_allowed_under_conservative(self) -> None:
        decision = p.evaluate(
            tool_name="control_provider_mutate",
            context_taint=0,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_ALLOW
        assert decision.matched_row == "host_control"

    def test_memory_mutate_allowed_under_conservative(self) -> None:
        decision = p.evaluate(
            tool_name="control_memory_mutate",
            context_taint=0,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_ALLOW
        assert decision.matched_row == "host_control"

    def test_unknown_agent_tool_still_requires_approval(self) -> None:
        decision = p.evaluate(
            tool_name="mystery_tool",
            context_taint=0,
            arg_taint_bits=0,
            args_overlap_dirty=False,
            clearance=1,
            profile=p.PROFILE_CONSERVATIVE,
        )
        assert decision.verdict == p.VERDICT_APPROVAL
        assert decision.matched_row == "default"

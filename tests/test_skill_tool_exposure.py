"""Regression: v0.1.4-alpha PR-1.5 — quarantine/draft skills must NOT be
exposed in the model-callable tool registry.

Five guards:

1. Auto-created (quarantine + draft) skill is registered into SkillManager
   in-memory, but is NOT registered as a tool the model can call.
2. trust_skill() promoting OUT OF quarantine registers the tool.
3. trust_skill() demoting BACK INTO quarantine unregisters the tool.
4. A community-trust skill IS exposed (positive path — no regression).
5. PR-1 + PR-4 builtin / Hermes auto-promote protection still holds
   (delegated check, not duplicated here).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from js.skills.manager import SkillManager
from js.skills.spec import SkillSpec, SkillType, TrustLevel


class _FakeToolRegistry:
    """Captures register / unregister calls; mirrors the registry's surface."""

    def __init__(self) -> None:
        self.registered: dict[str, Any] = {}

    def register(self, tool_spec: Any, handler: Any) -> None:
        self.registered[tool_spec.name] = (tool_spec, handler)

    def unregister(self, tool_name: str) -> None:
        self.registered.pop(tool_name, None)


def _make_spec(skill_id: str, trust: TrustLevel, path: Path | None = None) -> SkillSpec:
    return SkillSpec(
        id=skill_id,
        name=skill_id,
        description="test",
        type=SkillType.PROMPT,
        trust_level=trust,
        path=path,
    )


def _make_manager(tmp_path: Path) -> tuple[SkillManager, _FakeToolRegistry]:
    state_dir = tmp_path / "state"
    workspace = tmp_path / "ws"
    state_dir.mkdir()
    workspace.mkdir()
    mgr = SkillManager(state_dir=state_dir, workspace=workspace)
    fake = _FakeToolRegistry()
    mgr.register_as_tools(fake)  # binds registry; loops over current _skills
    return mgr, fake


# ---------------------------------------------------------------------------
# 1. Auto-created draft / quarantine skill must NOT enter the tool registry.
# ---------------------------------------------------------------------------


def test_quarantine_skill_not_registered_via_register_auto_skill(tmp_path: Path) -> None:
    mgr, fake = _make_manager(tmp_path)
    spec = _make_spec("auto_abc123", TrustLevel.QUARANTINE)
    mgr.register_auto_skill(spec)
    # in-memory yes, tool no
    assert mgr.get_skill("auto_abc123") is spec
    assert all("auto_abc123" not in name for name in fake.registered)


def test_quarantine_skill_not_registered_via_register_as_tools_loop(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    workspace = tmp_path / "ws"
    state_dir.mkdir()
    workspace.mkdir()
    mgr = SkillManager(state_dir=state_dir, workspace=workspace)
    # Pre-seed a QUARANTINE spec BEFORE the registry is attached.
    spec = _make_spec("auto_draft01", TrustLevel.QUARANTINE)
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]
    fake = _FakeToolRegistry()
    mgr.register_as_tools(fake)
    assert all("auto_draft01" not in name for name in fake.registered)


def test_should_expose_as_tool_helper(tmp_path: Path) -> None:
    mgr, _ = _make_manager(tmp_path)
    assert mgr._should_expose_as_tool(_make_spec("a", TrustLevel.QUARANTINE)) is False
    assert mgr._should_expose_as_tool(_make_spec("b", TrustLevel.COMMUNITY)) is True
    assert mgr._should_expose_as_tool(_make_spec("c", TrustLevel.TRUSTED)) is True
    assert mgr._should_expose_as_tool(_make_spec("d", TrustLevel.BUILTIN)) is True


# ---------------------------------------------------------------------------
# 2. trust_skill() upgrade out of quarantine → register.
# ---------------------------------------------------------------------------


def test_trust_skill_promote_registers_tool(tmp_path: Path) -> None:
    mgr, fake = _make_manager(tmp_path)
    spec = _make_spec("auto_promote", TrustLevel.QUARANTINE)
    mgr.register_auto_skill(spec)
    # Not exposed yet.
    tool_name = mgr._skill_id_to_tool_name("auto_promote")
    assert tool_name not in fake.registered

    ok = mgr.trust_skill("auto_promote", TrustLevel.COMMUNITY)
    assert ok is True
    assert spec.trust_level == TrustLevel.COMMUNITY
    assert tool_name in fake.registered


def test_trust_skill_promote_to_trusted_registers_tool(tmp_path: Path) -> None:
    mgr, fake = _make_manager(tmp_path)
    spec = _make_spec("auto_trusted", TrustLevel.QUARANTINE)
    mgr.register_auto_skill(spec)
    tool_name = mgr._skill_id_to_tool_name("auto_trusted")
    mgr.trust_skill("auto_trusted", TrustLevel.TRUSTED)
    assert tool_name in fake.registered


# ---------------------------------------------------------------------------
# 3. trust_skill() demote back to quarantine → unregister.
# ---------------------------------------------------------------------------


def test_trust_skill_demote_unregisters_tool(tmp_path: Path) -> None:
    mgr, fake = _make_manager(tmp_path)
    spec = _make_spec("manual_skill", TrustLevel.COMMUNITY)
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]
    mgr._register_skill_as_tool(spec)
    tool_name = mgr._skill_id_to_tool_name("manual_skill")
    assert tool_name in fake.registered

    mgr.trust_skill("manual_skill", TrustLevel.QUARANTINE)
    assert tool_name not in fake.registered


def test_trust_skill_lateral_move_no_double_register(tmp_path: Path) -> None:
    """COMMUNITY -> TRUSTED stays exposed; should not double-register or break."""
    mgr, fake = _make_manager(tmp_path)
    spec = _make_spec("lateral", TrustLevel.COMMUNITY)
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]
    mgr._register_skill_as_tool(spec)
    tool_name = mgr._skill_id_to_tool_name("lateral")
    assert tool_name in fake.registered

    mgr.trust_skill("lateral", TrustLevel.TRUSTED)
    assert tool_name in fake.registered
    assert spec.trust_level == TrustLevel.TRUSTED


def test_trust_skill_unknown_returns_false(tmp_path: Path) -> None:
    mgr, _ = _make_manager(tmp_path)
    assert mgr.trust_skill("does-not-exist", TrustLevel.COMMUNITY) is False


# ---------------------------------------------------------------------------
# 4. Positive path: community skill IS exposed (catches accidental over-block).
# ---------------------------------------------------------------------------


def test_community_skill_exposed_via_register_auto_skill(tmp_path: Path) -> None:
    mgr, fake = _make_manager(tmp_path)
    spec = _make_spec("community_skill", TrustLevel.COMMUNITY)
    mgr.register_auto_skill(spec)
    tool_name = mgr._skill_id_to_tool_name("community_skill")
    assert tool_name in fake.registered


def test_builtin_skill_exposed(tmp_path: Path) -> None:
    mgr, fake = _make_manager(tmp_path)
    spec = _make_spec("builtin_skill", TrustLevel.BUILTIN)
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]
    mgr._register_skill_as_tool(spec)
    assert mgr._skill_id_to_tool_name("builtin_skill") in fake.registered


# ---------------------------------------------------------------------------
# 5. PR-1 / PR-4 protection logic still passes (smoke import + helper call).
# ---------------------------------------------------------------------------


def test_pr1_pr4_auto_promote_protection_still_present() -> None:
    from js.skills.evolver import _is_protected_for_promote

    assert _is_protected_for_promote("hermes:demo", None) is True


@pytest.mark.asyncio
async def test_auto_created_quarantine_skill_still_refused_by_execute(tmp_path: Path) -> None:
    """End-to-end: auto-create + register + try to invoke -> refused.

    Anchors that PR-1 (execute() rejects QUARANTINE) and PR-1.5 (tool
    registry skips QUARANTINE) compose correctly: the skill cannot be
    invoked, period — neither as a tool nor directly via execute().
    """
    mgr, fake = _make_manager(tmp_path)
    spec = _make_spec("auto_e2e", TrustLevel.QUARANTINE)
    mgr.register_auto_skill(spec)
    # Not in the tool registry.
    assert mgr._skill_id_to_tool_name("auto_e2e") not in fake.registered
    # And execute() also refuses.
    result = await mgr.execute("auto_e2e", args={})
    assert result["success"] is False
    assert "quarantine" in result.get("error", "").lower()

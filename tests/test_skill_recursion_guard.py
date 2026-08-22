"""Regression tests for the workflow/meta skill recursion guard.

A self-referencing meta skill used to recurse through SkillManager.execute
(acting as the sub-skill resolver) until RecursionError, with exponentially
growing output. The executor now threads a depth counter and an ancestor set
through the resolver chain and fails closed on cycles or excessive nesting.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from js.skills.executor import MAX_SUBSKILL_DEPTH, execute_skill
from js.skills.manager import SkillManager
from js.skills.spec import SkillSpec, SkillType, TrustLevel


def _meta_spec(skill_id: str, sub_skill_id: str) -> SkillSpec:
    return SkillSpec(
        id=skill_id,
        name=skill_id,
        type=SkillType.META,
        trust_level=TrustLevel.BUILTIN,
        metadata={"workflow": {"steps": [{"type": "skill", "skill_id": sub_skill_id}]}},
    )


def _workflow_spec(skill_id: str, sub_skill_id: str) -> SkillSpec:
    return SkillSpec(
        id=skill_id,
        name=skill_id,
        type=SkillType.WORKFLOW,
        trust_level=TrustLevel.BUILTIN,
        metadata={"workflow": {"steps": [{"type": "skill", "skill_id": sub_skill_id}]}},
    )


class TestExecutorRecursionGuard:
    async def test_meta_self_reference_blocked_before_resolver_call(
        self, tmp_path: Path
    ) -> None:
        calls: list[str] = []

        async def resolver(skill_id: str, args: dict, **_kwargs: Any) -> dict:
            calls.append(skill_id)
            return {"success": True}

        result = await execute_skill(
            _meta_spec("loop", "loop"), {}, tmp_path, skill_resolver=resolver
        )
        assert result["success"] is False
        assert calls == []  # fail closed: the resolver is never invoked
        steps = json.loads(result["output"])
        assert steps[0]["status"] == "error"
        assert "Recursive skill reference" in steps[0]["error"]

    async def test_workflow_self_reference_blocked(self, tmp_path: Path) -> None:
        async def resolver(skill_id: str, args: dict, **_kwargs: Any) -> dict:
            return {"success": True}

        result = await execute_skill(
            _workflow_spec("wf", "wf"), {}, tmp_path, skill_resolver=resolver
        )
        assert result["success"] is False
        assert result["steps_failed"] == 1
        steps = json.loads(result["output"])
        assert "Recursive skill reference" in steps[0]["error"]

    async def test_mutual_cycle_blocked(self, tmp_path: Path) -> None:
        specs = {"a": _meta_spec("a", "b"), "b": _meta_spec("b", "a")}

        async def resolver(
            skill_id: str,
            args: dict,
            _depth: int = 0,
            _ancestors: tuple[str, ...] = (),
        ) -> dict:
            return await execute_skill(
                specs[skill_id],
                args,
                tmp_path,
                skill_resolver=resolver,
                _depth=_depth,
                _ancestors=_ancestors,
            )

        result = await execute_skill(specs["a"], {}, tmp_path, skill_resolver=resolver)
        assert result["success"] is False
        assert "Recursive skill reference" in result["output"]

    async def test_depth_limit_blocks_deep_acyclic_chain(self, tmp_path: Path) -> None:
        # a0 -> a1 -> ... -> a30: no cycles, but deeper than MAX_SUBSKILL_DEPTH.
        specs = {f"a{i}": _meta_spec(f"a{i}", f"a{i + 1}") for i in range(30)}
        specs["a30"] = SkillSpec(
            id="a30",
            name="a30",
            type=SkillType.PROMPT,
            trust_level=TrustLevel.BUILTIN,
            full_content="leaf",
        )
        calls: list[str] = []

        async def resolver(
            skill_id: str,
            args: dict,
            _depth: int = 0,
            _ancestors: tuple[str, ...] = (),
        ) -> dict:
            calls.append(skill_id)
            return await execute_skill(
                specs[skill_id],
                args,
                tmp_path,
                skill_resolver=resolver,
                _depth=_depth,
                _ancestors=_ancestors,
            )

        result = await execute_skill(specs["a0"], {}, tmp_path, skill_resolver=resolver)
        assert result["success"] is False
        # Bounded: exactly MAX_SUBSKILL_DEPTH nested resolutions, no runaway.
        assert len(calls) == MAX_SUBSKILL_DEPTH
        assert "depth" in result["output"]

    async def test_legacy_two_arg_resolver_still_supported(self, tmp_path: Path) -> None:
        calls: list[str] = []

        async def resolver(skill_id: str, args: dict) -> dict:
            calls.append(skill_id)
            return {"success": True, "output": "ok"}

        result = await execute_skill(
            _meta_spec("top", "child"), {}, tmp_path, skill_resolver=resolver
        )
        assert result["success"] is True
        assert calls == ["child"]


class TestManagerRecursionGuard:
    """The same guard holds when SkillManager.execute is the resolver."""

    def _manager(self, tmp_path: Path) -> SkillManager:
        return SkillManager(tmp_path / "state", tmp_path / "workspace")

    async def test_self_referencing_meta_fails_closed(self, tmp_path: Path) -> None:
        manager = self._manager(tmp_path)
        manager._skills["loop"] = _meta_spec("loop", "loop")
        result = await manager.execute("loop", {})
        assert result["success"] is False
        assert "Recursive skill reference" in json.dumps(result)

    async def test_mutual_cycle_fails_closed(self, tmp_path: Path) -> None:
        manager = self._manager(tmp_path)
        manager._skills["ma"] = _meta_spec("ma", "mb")
        manager._skills["mb"] = _meta_spec("mb", "ma")
        result = await manager.execute("ma", {})
        assert result["success"] is False
        assert "Recursive skill reference" in json.dumps(result)

    async def test_deep_chain_hits_depth_limit(self, tmp_path: Path) -> None:
        manager = self._manager(tmp_path)
        for i in range(20):
            manager._skills[f"d{i}"] = _meta_spec(f"d{i}", f"d{i + 1}")
        result = await manager.execute("d0", {})
        assert result["success"] is False
        assert "depth" in json.dumps(result)

    async def test_entry_guard_rejects_injected_context(self, tmp_path: Path) -> None:
        manager = self._manager(tmp_path)
        manager._skills["x"] = _meta_spec("x", "x")

        result = await manager.execute("x", {}, _ancestors=("x",))
        assert result["success"] is False
        assert "Recursive skill reference" in result["error"]

        result = await manager.execute("x", {}, _depth=MAX_SUBSKILL_DEPTH + 1)
        assert result["success"] is False
        assert "depth" in result["error"]

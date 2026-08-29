"""Turn a scenario template into a bots room + goal run. Not a second runtime."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from js.bots.models import GoalContract
from js.bots.service import BotService, bot_store_for
from js.scenarios.schemas import Scenario, ScenarioRole


def soul_for_role(scenario: Scenario, role: ScenarioRole) -> str:
    parts = [role.description.strip(), scenario.system_prompt_addon.strip()]
    text = "\n\n".join(part for part in parts if part)
    return (text or scenario.description or scenario.name)[:8000]


def goal_contract_for(scenario: Scenario) -> GoalContract:
    return GoalContract(
        objective=scenario.description or scenario.name,
        success_criteria=tuple(scenario.example_prompts[:3]),
        constraints=tuple(f"role:{role.role}" for role in scenario.roles),
    )


def instantiate_scenario(
    scenario: Scenario,
    *,
    owner_key_hash: str,
    state_dir: Path,
) -> dict[str, Any]:
    """Create active bots, one room, and one clarify-phase goal for the owner."""

    if not owner_key_hash.strip():
        raise ValueError("owner is required")
    service = BotService(bot_store_for(state_dir))
    bot_ids: list[str] = []
    for role in scenario.roles:
        draft = service.create_draft(
            role.name[:64] or scenario.name[:64], owner_key_hash=owner_key_hash
        )
        service.store.update_soul(
            draft.id,
            soul_text=soul_for_role(scenario, role),
            owner_key_hash=owner_key_hash,
            activate=True,
        )
        bot_ids.append(draft.id)
    if not bot_ids:
        draft = service.create_draft(scenario.name[:64], owner_key_hash=owner_key_hash)
        service.store.update_soul(
            draft.id,
            soul_text=(scenario.system_prompt_addon or scenario.description or scenario.name)[
                :8000
            ],
            owner_key_hash=owner_key_hash,
            activate=True,
        )
        bot_ids.append(draft.id)
    room = service.store.create_room(
        title=scenario.name[:128],
        member_bot_ids=bot_ids,
        owner_key_hash=owner_key_hash,
    )
    goal = service.store.create_goal_run(
        room.id,
        owner_key_hash=owner_key_hash,
        questions=list(scenario.example_prompts[:5]),
        contract=goal_contract_for(scenario),
    )
    return {
        "bot_ids": bot_ids,
        "room_id": room.id,
        "goal_id": goal.id,
        "goal": goal.to_public_dict(),
        "room": room.to_public_dict(),
    }

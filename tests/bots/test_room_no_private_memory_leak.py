"""Room transcript never carries another bot's private memory session."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.agent import JSAgent
from js.agent.state import AgentState
from js.bots.persona import BotTurnBinding, bind_bot_turn, strip_volatile_tail
from js.bots.rooms import wrap_room_transcript
from js.bots.service import BotService
from js.bots.store import BotStore, private_memory_session
from js.config import JSSettings
from js.echo.turn_context import (
    RuntimeContext,
    reset_runtime_context,
    set_runtime_context,
)
from js.echo.turn_loop import EchoTurnLoop
from js.models.providers import ChatMessage


def test_room_transcript_excludes_foreign_private_memory(tmp_path: Path) -> None:
    store = BotStore(tmp_path / "state")
    owner = "owner-a"
    left = store.create_bot(
        display_name="调查bot", owner_key_hash=owner, status="active", soul_text="我是调查bot"
    )
    right = store.create_bot(
        display_name="研究员", owner_key_hash=owner, status="active", soul_text="我是研究员"
    )
    room = store.create_room(
        title="组",
        member_bot_ids=[left.id, right.id],
        owner_key_hash=owner,
    )
    store.append_message(
        room.id,
        speaker_kind="bot",
        speaker_id=left.id,
        content="公开结论",
        taint=0,
        owner_key_hash=owner,
    )
    wrapped = wrap_room_transcript(store.list_messages(room.id, owner_key_hash=owner))
    assert "公开结论" in wrapped
    assert private_memory_session(left.id) not in wrapped
    assert private_memory_session(right.id) not in wrapped
    assert left.memory_session != right.memory_session
    assert left.memory_session.startswith("bot:")
    assert "private" in left.memory_session


def test_service_does_not_read_peer_private_session(tmp_path: Path) -> None:
    store = BotStore(tmp_path / "state")
    service = BotService(store)
    owner = "owner-a"
    left = store.create_bot(
        display_name="调查bot", owner_key_hash=owner, status="active", soul_text="soul-a"
    )
    right = store.create_bot(
        display_name="研究员", owner_key_hash=owner, status="active", soul_text="soul-b"
    )
    assert service.store.get_bot(left.id, owner_key_hash=owner)
    assert left.memory_session != right.memory_session
    assert left.memory_session not in right.memory_session


def test_volatile_tail_is_stripped_from_room_history() -> None:
    leaked = (
        "当前请求：查X\n\n## Volatile Context\n"
        "run_id=abc\n"
        '<memory trust="untrusted">\nprivate-of-a\n</memory>'
    )
    assert strip_volatile_tail(leaked) == "当前请求：查X"
    assert "private-of-a" not in strip_volatile_tail(leaked)


_PRIVATE_A = "PRIVATE_FACT_ALPHA_SHOULD_NEVER_REACH_BOT_B"


def _agent(tmp_path: Path) -> JSAgent:
    return JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=1,
            echo_engine="on",
        )
    )


def _bots_context(agent: JSAgent, session_id: str, run_id: str) -> RuntimeContext:
    return RuntimeContext(
        product_id="js-agent",
        channel="bots",
        owner_key_hash="owner-a",
        session_id=session_id,
        run_id=run_id,
        role="local-user",
        profile="default",
        capabilities=(),
        workspace=agent.settings.workspace,
        state_dir=agent.settings.state_dir,
        fs_roots=(agent.settings.workspace,),
        surface="bots",
    )


def _binding(bot_id: str, memory_session: str) -> BotTurnBinding:
    return BotTurnBinding(
        bot_id=bot_id,
        soul_text=f"soul-{bot_id}",
        persona_appendix="",
        memory_session=memory_session,
        prefix_id=bot_id,
    )


@pytest.mark.asyncio
async def test_finalize_strips_volatile_before_room_persist(tmp_path: Path) -> None:
    agent = _agent(tmp_path)
    store = BotStore(tmp_path / "bots")
    owner = "owner-a"
    left = store.create_bot(
        display_name="调查bot", owner_key_hash=owner, status="active", soul_text="soul-a"
    )
    right = store.create_bot(
        display_name="研究员", owner_key_hash=owner, status="active", soul_text="soul-b"
    )
    room = store.create_room(
        title="组",
        member_bot_ids=[left.id, right.id],
        owner_key_hash=owner,
    )
    session_id = room.transcript_session
    user_with_volatile = (
        f"当前请求：查X\n\n## Volatile Context\nrun_id=run-a\n"
        f'<memory trust="untrusted">\n{_PRIVATE_A}\n</memory>'
    )
    state = AgentState(session_id=session_id, run_id="run-a")
    state.status = "completed"
    state.messages = [
        ChatMessage(role="system", content="SOUL"),
        ChatMessage(role="user", content=user_with_volatile),
        ChatMessage(role="assistant", content="公开结论"),
    ]
    context = _bots_context(agent, session_id, "run-a")
    token = set_runtime_context(context)
    try:
        with bind_bot_turn(_binding(left.id, left.memory_session)):
            await agent._finalize_run(state, session_id, "run-a", "当前请求：查X", 0)
    finally:
        reset_runtime_context(token)

    stored = agent.memory.get_session_messages(session_id, owner)
    blob = "\n".join(str(item.get("content") or "") for item in stored)
    assert "公开结论" in blob
    assert "当前请求：查X" in blob
    assert _PRIVATE_A not in blob
    assert "## Volatile Context" not in blob


@pytest.mark.asyncio
async def test_second_bot_echo_history_excludes_first_bot_private_memory(
    tmp_path: Path,
) -> None:
    agent = _agent(tmp_path)
    store = BotStore(tmp_path / "bots")
    owner = "owner-a"
    left = store.create_bot(
        display_name="调查bot", owner_key_hash=owner, status="active", soul_text="soul-a"
    )
    right = store.create_bot(
        display_name="研究员", owner_key_hash=owner, status="active", soul_text="soul-b"
    )
    room = store.create_room(
        title="组",
        member_bot_ids=[left.id, right.id],
        owner_key_hash=owner,
    )
    session_id = room.transcript_session
    agent.memory.store_messages(
        left.memory_session,
        [{"role": "user", "content": _PRIVATE_A}, {"role": "assistant", "content": "noted"}],
        owner,
    )
    agent.memory.store_messages(
        session_id,
        [
            {
                "role": "user",
                "content": (
                    f"当前请求：查X\n\n## Volatile Context\n"
                    f'<memory trust="untrusted">\n{_PRIVATE_A}\n</memory>'
                ),
            },
            {"role": "assistant", "content": "公开结论"},
        ],
        owner,
    )

    loop = EchoTurnLoop(
        agent,
        "请交叉验证",
        session_id,
        None,
        None,
        None,
        None,
        None,
    )
    context = _bots_context(agent, session_id, "run-b")
    token = set_runtime_context(context)
    try:
        with bind_bot_turn(_binding(right.id, right.memory_session)):
            await loop._setup()
    finally:
        reset_runtime_context(token)

    ua = [
        msg
        for msg in loop.state.messages
        if msg.role in ("user", "assistant") and isinstance(msg.content, str)
    ]
    historical = "\n".join(str(msg.content) for msg in ua[: loop.history_ua_count])
    current = "\n".join(str(msg.content) for msg in ua[loop.history_ua_count :])
    assert "公开结论" in historical
    assert "当前请求：查X" in historical
    assert "## Volatile Context" not in historical
    assert _PRIVATE_A not in historical
    assert _PRIVATE_A not in current

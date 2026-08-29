from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from js.echo.attachment_gate import delete_owned_upload_by_name
from js.integrations.telegram_bot import (
    _MAX_TELEGRAM_SESSIONS,
    TelegramBotIntegration,
)
from js.models.providers import ChatMessage
from js.tools.registry import ToolResult


def test_telegram_session_map_is_bounded_and_lru() -> None:
    integration = object.__new__(TelegramBotIntegration)
    integration._session_map = OrderedDict()

    for chat_id in range(_MAX_TELEGRAM_SESSIONS + 3):
        integration._set_session(chat_id, f"session-{chat_id}")

    assert len(integration._session_map) == _MAX_TELEGRAM_SESSIONS
    assert integration._get_session(0) is None
    assert integration._get_session(_MAX_TELEGRAM_SESSIONS + 2) == (
        f"session-{_MAX_TELEGRAM_SESSIONS + 2}"
    )


@pytest.mark.asyncio
async def test_telegram_text_error_does_not_echo_private_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    integration = object.__new__(TelegramBotIntegration)
    integration._session_map = OrderedDict()
    integration.allowed_chat_ids = frozenset({123})
    integration.agent = MagicMock()
    private_detail = "/Users/private/Documents/customer.xlsx secret-token"
    message = SimpleNamespace(
        text="hello",
        chat=SimpleNamespace(send_action=AsyncMock()),
        reply_text=AsyncMock(),
    )
    update = SimpleNamespace(
        effective_chat=SimpleNamespace(id=123),
        message=message,
    )
    monkeypatch.setattr(
        "js.gateway.channels.telegram.run_echo_turn",
        AsyncMock(side_effect=RuntimeError(private_detail)),
    )

    await integration._on_text(update, None)

    message.reply_text.assert_awaited_once_with("❌ Error processing message.")
    assert private_detail not in str(message.reply_text.await_args)


@pytest.mark.asyncio
async def test_telegram_document_uses_secure_streamed_owner_session_upload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    integration = object.__new__(TelegramBotIntegration)
    integration._session_map = OrderedDict()
    integration.allowed_chat_ids = frozenset({123})
    integration.settings = SimpleNamespace(
        workspace=tmp_path / "workspace",
        product_id="js-agent",
    )
    agent = MagicMock()
    integration.agent = agent
    commits: dict[str, tuple[str, str, object]] = {}
    payloads: dict[str, tuple[str, dict[str, str]]] = {}
    results: dict[str, tuple[str, str, dict[str, object]]] = {}

    def stage_commit(owner: str, session_id: str, writer: object) -> str:
        commits["commit-ref"] = (owner, session_id, writer)
        return "commit-ref"

    def stage_payload(
        owner: str,
        payload: dict[str, str],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        assert product_id == "js-agent"
        assert session_id == payload["session_id"]
        payloads["delete-ref"] = (owner, dict(payload))
        return "delete-ref"

    async def execute_effect(effect: object, _runtime: object) -> tuple[object, ToolResult]:
        arguments = __import__("json").loads(effect.arguments_json)  # type: ignore[attr-defined]
        if arguments["action"] == "commit":
            owner, upload_session_id, writer = commits.pop(arguments["payload_ref"])
            target = writer.commit()  # type: ignore[attr-defined]
            result_ref = "result-ref"
            results[result_ref] = (
                owner,
                upload_session_id,
                {
                    "saved_as": target.name,
                    "path": target.relative_to(integration.settings.workspace).as_posix(),
                    "size": writer.bytes_written,  # type: ignore[attr-defined]
                },
            )
            result = ToolResult(
                success=True,
                output="Upload commit completed",
                metadata={"result_ref": result_ref},
            )
        else:
            owner, payload = payloads.pop(arguments["payload_ref"])
            assert delete_owned_upload_by_name(
                integration.settings.workspace,
                owner,
                payload["filename"],
                payload["session_id"],
            )
            result = ToolResult(success=True, output="Upload deletion completed")
        return ChatMessage(role="tool", content=result.output), result

    def take_result(
        reference: str,
        owner: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, object] | None:
        assert product_id == "js-agent"
        entry = results.pop(reference, None)
        return entry[2] if entry is not None and entry[:2] == (owner, session_id) else None

    agent.stage_upload_commit = MagicMock(side_effect=stage_commit)
    agent.discard_upload_commit = MagicMock()
    agent.stage_upload_mutation_payload = MagicMock(side_effect=stage_payload)
    agent.discard_upload_mutation_payload = MagicMock()
    agent.take_upload_mutation_result = MagicMock(side_effect=take_result)
    runtime_context = MagicMock()
    runtime_context.product_id = "js-agent"
    runtime_context.session_id = "telegram-session"
    agent.echo_runtime.build_context.return_value = runtime_context
    agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=execute_effect)

    async def download_to_memory(*, out: object) -> None:
        out.write(b"telegram-bytes")  # type: ignore[attr-defined]

    file_obj = SimpleNamespace(
        download_to_memory=AsyncMock(side_effect=download_to_memory),
        download_to_drive=AsyncMock(),
    )
    document = SimpleNamespace(
        file_name="..\\unsafe\nname.txt",
        file_size=len(b"telegram-bytes"),
        get_file=AsyncMock(return_value=file_obj),
    )
    message = SimpleNamespace(
        document=document,
        reply_text=AsyncMock(),
    )
    update = SimpleNamespace(
        effective_chat=SimpleNamespace(id=123),
        message=message,
    )
    state = SimpleNamespace(
        session_id="telegram-session",
        messages=[SimpleNamespace(role="assistant", content="processed")],
    )
    run_turn = AsyncMock(return_value=state)
    monkeypatch.setattr("js.gateway.channels.telegram.run_echo_turn", run_turn)

    await integration._on_document(update, None)

    file_obj.download_to_memory.assert_awaited_once()
    file_obj.download_to_drive.assert_not_awaited()
    kwargs = run_turn.await_args.kwargs
    assert kwargs["session_id"].startswith("telegram-")
    assert kwargs["attachments"][0].startswith("uploads/")
    assert "\\" not in kwargs["attachments"][0]
    assert not (integration.settings.workspace / kwargs["attachments"][0]).exists()
    effects = [call.args[0] for call in agent.echo_runtime.execute_tool_effect.await_args_list]
    assert [effect.tool_name for effect in effects] == [
        "control_upload_mutate",
        "control_upload_mutate",
    ]
    assert [__import__("json").loads(effect.arguments_json)["action"] for effect in effects] == [
        "commit",
        "delete",
    ]
    assert all("unsafe" not in effect.arguments_json for effect in effects)
    assert all("telegram-bytes" not in effect.arguments_json for effect in effects)

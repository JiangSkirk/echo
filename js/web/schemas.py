"""Strict request bodies for Host REST and WebSocket frames."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChatRequest(_StrictModel):
    message: StrictStr = ""
    session_id: StrictStr | None = None
    model: StrictStr | None = None
    attachments: list[StrictStr] = Field(default_factory=list)


class ChatWsFrame(_StrictModel):
    type: Literal["message", "stream", "ping", "cancel"] = "message"
    content: StrictStr = ""
    session_id: StrictStr | None = None
    request_id: StrictStr | None = None
    turn_id: StrictStr | None = None
    run_id: StrictStr | None = None
    model: StrictStr | None = None
    attachments: Any = Field(default_factory=list)
    enable_tools: StrictBool = True


class CronJobWriteRequest(_StrictModel):
    name: StrictStr | None = None
    description: StrictStr | None = None
    cron_expr: StrictStr | None = None
    schedule_summary: StrictStr | None = None
    task_type: StrictStr | None = None
    template_id: StrictStr | None = None
    natural_language: StrictStr | None = None
    payload: dict[str, Any] | None = None
    enabled: StrictBool | None = None
    max_retries: StrictInt | None = None
    notify_on_success: StrictBool | None = None
    notify_on_failure: StrictBool | None = None


class CronParseRequest(_StrictModel):
    text: StrictStr = ""


class FleetCollaborateRequest(_StrictModel):
    task: StrictStr
    subtasks: list[StrictStr] | None = None
    session_id: StrictStr | None = None
    role_mapping: dict[str, StrictStr] | None = None
    mode: StrictStr = "auto"


class FleetContinueRequest(_StrictModel):
    follow_up: StrictStr = Field(min_length=1, max_length=20_000)


class ManualReviewResolveRequest(_StrictModel):
    action: Literal["cancel", "override", "resolved"]
    reason: StrictStr = Field(min_length=1, max_length=1000)


class DesktopWizardActionRequest(_StrictModel):
    action_type: StrictStr


class SetupTestModelRequest(_StrictModel):
    model_id: StrictStr


class MemoryFilePutRequest(_StrictModel):
    content: StrictStr = ""


class MemorySemanticCreateRequest(_StrictModel):
    key: StrictStr
    value: StrictStr
    category: StrictStr = "fact"
    source: StrictStr = "user"
    memory_path: StrictStr | None = None
    entity_type: StrictStr | None = None
    entity_name: StrictStr | None = None
    parent_id: StrictInt | None = None
    relation_type: StrictStr | None = None
    evidence: StrictStr = ""


class MemorySemanticUpdateRequest(_StrictModel):
    value: StrictStr
    category: StrictStr | None = None
    memory_path: StrictStr | None = None
    entity_type: StrictStr | None = None
    entity_name: StrictStr | None = None
    parent_id: StrictInt | None = None
    relation_type: StrictStr | None = None


class MemoryProposalApproveRequest(_StrictModel):
    value: StrictStr | None = None
    memory_path: StrictStr | None = None
    category: StrictStr | None = None


class MemoryBlockRequest(_StrictModel):
    src: StrictStr
    dst: StrictStr


class MemoryCompressionProposalRequest(_StrictModel):
    source_refs: list[StrictStr]
    proposed_summary: StrictStr


class PluginInstallRequest(_StrictModel):
    source: StrictStr | None = None
    name: StrictStr | None = None
    url: StrictStr | None = None

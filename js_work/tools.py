"""Tool profiles for JS Agent Work."""

from __future__ import annotations

from enum import StrEnum

from js.tools.registry import ToolRegistry


class WorkToolProfile(StrEnum):
    """Visible tool sets for Work agents."""

    EXECUTE = "execute"
    SAFE = "safe"
    OFFICE = "office"


_COMMON_READ_TOOLS = {
    "web_search",
    "browser_fetch",
    "file_read",
    "file_view",
    "file_list",
    "file_search",
    "code_search",
}

_FILE_WRITE_TOOLS = {
    "file_write",
    "file_edit",
}

_OFFICE_TOOLS = {
    "accessory_order_run",
    "csv_read",
    "csv_write",
    "excel_read",
    "excel_write",
    "excel_merge",
    "excel_create",
    "excel_template_analyze",
    "excel_extract_table",
    "excel_precise_edit",
    "excel_render_from_template",
    "excel_validate_output",
    "pdf_generate",
    "pdf_extract",
    "packing_details_run",
    "work_routine_preview",
    "work_routine_run",
    "word_create",
    "word_read",
    "word_replace",
}

# Web-only, model-hidden provider controls remain registered so Work's own
# configuration can enter Echo.  They never appear in model tool schemas.
_WORK_CONTROL_TOOLS = {
    "control_fleet_configure",
    "control_fleet_continue",
    "control_fleet_session_delete",
    "control_model_switch",
    "control_setup_state",
    "control_session_mutate",
    "control_task_mutate",
    "control_memory_mutate",
    "control_upload_mutate",
    "control_cron_mutate",
    "control_work_routine_draft",
    "control_work_routine_approve",
    "control_provider_discover",
    "control_provider_mutate",
}

_PROFILE_ALLOWED_TOOLS: dict[WorkToolProfile, set[str]] = {
    WorkToolProfile.EXECUTE: _COMMON_READ_TOOLS
    | _FILE_WRITE_TOOLS
    | {"shell", "python", "fleet_collaborate"}
    | _WORK_CONTROL_TOOLS,
    WorkToolProfile.SAFE: _COMMON_READ_TOOLS | _WORK_CONTROL_TOOLS,
    WorkToolProfile.OFFICE: _COMMON_READ_TOOLS
    | _FILE_WRITE_TOOLS
    | _OFFICE_TOOLS
    | _WORK_CONTROL_TOOLS,
}


def allowed_tools_for_profile(profile: WorkToolProfile) -> set[str]:
    """Return the exact model-visible tool names for a Work profile."""
    return set(_PROFILE_ALLOWED_TOOLS[profile])


def apply_tool_profile(registry: ToolRegistry, profile: WorkToolProfile) -> None:
    """Remove tools that are not visible for the selected Work profile."""
    allowed = allowed_tools_for_profile(profile)
    for tool in list(registry.list_tools()):
        if tool.name not in allowed:
            registry.unregister(tool.name)

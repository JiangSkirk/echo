"""Control-plane tool name constants."""

from __future__ import annotations

DESKTOP_WIZARD_ACTION_TOOL = "desktop_wizard_action"
DESKTOP_WIZARD_ACTIONS = frozenset({"install", "open_accessibility", "open_screen_recording"})
CONTROL_SKILL_INSTALL_TOOL = "control_skill_install"
CONTROL_CLAWHUB_DISCOVER_TOOL = "control_clawhub_discover"
CONTROL_CLAWHUB_INSTALL_TOOL = "control_clawhub_install"
CONTROL_PROVIDER_DISCOVER_TOOL = "control_provider_discover"
CONTROL_PROVIDER_MUTATE_TOOL = "control_provider_mutate"
CONTROL_FLEET_CONFIGURE_TOOL = "control_fleet_configure"
CONTROL_FLEET_CONTINUE_TOOL = "control_fleet_continue"
CONTROL_FLEET_SESSION_DELETE_TOOL = "control_fleet_session_delete"
CONTROL_MODEL_SWITCH_TOOL = "control_model_switch"
CONTROL_SETUP_STATE_TOOL = "control_setup_state"
CONTROL_DESKTOP_STATE_TOOL = "control_desktop_state"
CONTROL_SESSION_MUTATE_TOOL = "control_session_mutate"
CONTROL_TASK_MUTATE_TOOL = "control_task_mutate"
CONTROL_MEMORY_MUTATE_TOOL = "control_memory_mutate"
CONTROL_SKILL_MUTATE_TOOL = "control_skill_mutate"
CONTROL_EVOLUTION_ACTION_TOOL = "control_evolution_action"
CONTROL_UPLOAD_MUTATE_TOOL = "control_upload_mutate"
CONTROL_CRON_MUTATE_TOOL = "control_cron_mutate"
CONTROL_GATEWAY_PUSH_TOOL = "control_gateway_push"
CONTROL_PLANE_TOOL_NAMES = frozenset(
    {
        CONTROL_SKILL_INSTALL_TOOL,
        CONTROL_CLAWHUB_DISCOVER_TOOL,
        CONTROL_CLAWHUB_INSTALL_TOOL,
        CONTROL_PROVIDER_DISCOVER_TOOL,
        CONTROL_PROVIDER_MUTATE_TOOL,
        CONTROL_FLEET_CONFIGURE_TOOL,
        CONTROL_FLEET_CONTINUE_TOOL,
        CONTROL_FLEET_SESSION_DELETE_TOOL,
        CONTROL_MODEL_SWITCH_TOOL,
        CONTROL_SETUP_STATE_TOOL,
        CONTROL_DESKTOP_STATE_TOOL,
        CONTROL_SESSION_MUTATE_TOOL,
        CONTROL_TASK_MUTATE_TOOL,
        CONTROL_MEMORY_MUTATE_TOOL,
        CONTROL_SKILL_MUTATE_TOOL,
        CONTROL_EVOLUTION_ACTION_TOOL,
        CONTROL_UPLOAD_MUTATE_TOOL,
        CONTROL_CRON_MUTATE_TOOL,
        CONTROL_GATEWAY_PUSH_TOOL,
    }
)

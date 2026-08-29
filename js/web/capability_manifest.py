"""Product capability / navigation manifest (M5).

Single authority for which UI tabs and backend feature surfaces a product
exposes. Work hides Personal-only surfaces; Personal keeps the full surface.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from js.config import AgentFeatureConfig, JSSettings

NAV_TAB_IDS: tuple[str, ...] = (
    "chat",
    "bots",
    "memory",
    "files",
    "models",
    "agents",
    "scenarios",
    "evolution",
    "skills",
    "search",
    "dashboard",
    "tasks",
    "friends",
    "audit",
    "approvals",
    "stats",
    "status",
    "cron",
)

# Tabs that require matching feature gates. Missing/False → hidden + API denied.
_FEATURE_GATED_TABS: dict[str, str] = {
    "skills": "skills_enabled",
    "evolution": "evolution_enabled",
    "friends": "friends_enabled",
}


def _features_of(settings: JSSettings) -> AgentFeatureConfig:
    features = getattr(settings, "features", None)
    if isinstance(features, AgentFeatureConfig):
        return features
    return AgentFeatureConfig()


def build_capability_manifest(settings: JSSettings) -> dict[str, Any]:
    """Return the authoritative capability manifest for *settings*."""
    product_id = str(getattr(settings, "product_id", "js-agent") or "js-agent")
    features = _features_of(settings)
    feature_map = {
        "plugins_enabled": bool(features.plugins_enabled),
        "skills_enabled": bool(features.skills_enabled),
        "skill_tools_enabled": bool(features.skill_tools_enabled),
        "hermes_skills_enabled": bool(features.hermes_skills_enabled),
        "evolution_enabled": bool(features.evolution_enabled),
        "pipeline_enabled": bool(features.pipeline_enabled),
        "daemon_enabled": bool(features.daemon_enabled),
        "desktop_control_enabled": bool(getattr(settings, "desktop_control_enabled", False)),
        "friends_enabled": bool(getattr(settings, "friends_enabled", False)),
    }
    tabs: dict[str, dict[str, Any]] = {}
    for tab_id in NAV_TAB_IDS:
        gate = _FEATURE_GATED_TABS.get(tab_id)
        enabled = True if gate is None else bool(feature_map.get(gate, False))
        # Work also hides multi-agent / scenario / cron / search personal extras
        # that conflict with the professional office profile.
        if product_id == "js-work" and tab_id in {
            "agents",
            "bots",
            "scenarios",
            "search",
            "cron",
            "tasks",
            "friends",
        }:
            enabled = False
        tabs[tab_id] = {
            "id": tab_id,
            "enabled": enabled,
            "reason": None if enabled else (f"feature:{gate}" if gate else f"product:{product_id}"),
        }
    enabled_tabs = tuple(tab_id for tab_id, meta in tabs.items() if meta["enabled"])
    return {
        "schema_version": "js-agent-capability-manifest-v1",
        "product_id": product_id,
        "features": feature_map,
        "tabs": tabs,
        "enabled_tabs": list(enabled_tabs),
        "api": {
            "skills_mutations": feature_map["skills_enabled"],
            "evolution_actions": feature_map["evolution_enabled"],
            "desktop_control": feature_map["desktop_control_enabled"],
            "hermes_skills": feature_map["hermes_skills_enabled"],
            "friends_actions": feature_map["friends_enabled"],
        },
    }


def assert_tab_allowed(manifest: Mapping[str, Any], tab_id: str) -> bool:
    tabs = manifest.get("tabs")
    if not isinstance(tabs, dict):
        return False
    meta = tabs.get(tab_id)
    return isinstance(meta, dict) and meta.get("enabled") is True

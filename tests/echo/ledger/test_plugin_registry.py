from __future__ import annotations

import pytest

from js.echo.ledger.plugins import PluginManifest, PluginRegistry


def test_plugin_registry_tracks_conformance_and_lifecycle() -> None:
    registry = PluginRegistry()
    manifest = PluginManifest(
        plugin_id="echo-tool",
        version="1.0.0",
        license="MIT",
        permissions=("tool:echo",),
        mode="stable",
    )

    registered = registry.register(manifest)
    conformance = registry.check_conformance("echo-tool")
    drained = registry.drain("echo-tool", reason="upgrade")
    revoked = registry.revoke("echo-tool", reason="vulnerable")

    assert registered.state == "active"
    assert conformance.ok
    assert drained.state == "drained"
    assert revoked.state == "revoked"


def test_plugin_registry_quarantines_unknown_license() -> None:
    registry = PluginRegistry(allowed_licenses=("MIT",))
    manifest = PluginManifest(
        plugin_id="unknown-license",
        version="1.0.0",
        license="Mystery-License",
        permissions=("tool:echo",),
        mode="stable",
    )

    record = registry.register(manifest)

    assert record.state == "quarantined"
    assert record.reason == "license_not_allowed"


def test_stable_manifest_still_rejects_dev_bypass() -> None:
    with pytest.raises(ValueError, match="dev bypass"):
        PluginManifest(
            plugin_id="bad",
            version="1.0.0",
            license="MIT",
            permissions=("tool:echo",),
            mode="stable",
            dev_bypasses=("disable_manifest_validation",),
        )

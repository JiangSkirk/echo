"""R4 security connector framework tests."""

from __future__ import annotations

import pytest

from js.connectors.base import ConnectorRegistry, FakeConnector
from js.connectors.manager import ConnectorManager
from js.echo.mode_contract import ConnectorManifestV1, ConnectorManifestValidationError


class TestConnectorManifest:
    """ConnectorManifestV1 from R1 is the authority for connector capabilities."""

    def test_read_only_manifest_rejects_write_scopes(self) -> None:
        with pytest.raises(ConnectorManifestValidationError):
            ConnectorManifestV1(
                connector_type="test",
                capabilities=("read",),
                read_scopes=("data",),
                write_scopes=("write",),
                approval_policy="read_only",
            )

    def test_never_policy_rejects_write_scopes(self) -> None:
        with pytest.raises(ConnectorManifestValidationError):
            ConnectorManifestV1(
                connector_type="test",
                capabilities=("read",),
                read_scopes=("data",),
                write_scopes=("write",),
                approval_policy="never",
            )

    def test_always_policy_allows_write_scopes(self) -> None:
        m = ConnectorManifestV1(
            connector_type="test",
            capabilities=("read", "write"),
            read_scopes=("data",),
            write_scopes=("write",),
            approval_policy="always",
        )
        assert m.write_scopes == ("write",)

    def test_manifest_round_trip(self) -> None:
        m = ConnectorManifestV1(
            connector_type="gmail",
            capabilities=("read",),
            read_scopes=("inbox",),
            write_scopes=(),
            approval_policy="read_only",
        )
        d = m.to_dict()
        m2 = ConnectorManifestV1.from_dict(d)
        assert m2.connector_type == m.connector_type
        assert m2.read_scopes == m.read_scopes


class TestFakeConnector:
    """Fake connector returns deterministic data without network or credentials."""

    @pytest.mark.asyncio
    async def test_fake_connector_direct_read_requires_runtime_authority(self) -> None:
        connector = FakeConnector()
        result = await connector.read("test")
        assert result.success is False
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_fake_connector_write_rejected(self) -> None:
        connector = FakeConnector()
        result = await connector.write("test")
        assert result.success is False
        assert result.error == "connector_runtime_authority_required"

    def test_fake_manifest_is_read_only(self) -> None:
        connector = FakeConnector()
        assert connector.manifest.approval_policy == "read_only"
        assert connector.manifest.write_scopes == ()


class TestConnectorRegistry:
    """Registry manages connector manifests and instances."""

    def test_register_manifest(self) -> None:
        registry = ConnectorRegistry()
        m = ConnectorManifestV1(
            connector_type="test-conn",
            capabilities=("read",),
            read_scopes=("data",),
            approval_policy="read_only",
        )
        registry.register_manifest(m)
        assert registry.has_connector("test-conn")
        assert registry.get_manifest("test-conn") is not None

    def test_duplicate_manifest_rejected(self) -> None:
        registry = ConnectorRegistry()
        m = ConnectorManifestV1(
            connector_type="dup",
            capabilities=("read",),
            read_scopes=("data",),
            approval_policy="read_only",
        )
        registry.register_manifest(m)
        with pytest.raises(ValueError):
            registry.register_manifest(m)

    def test_register_instance(self) -> None:
        registry = ConnectorRegistry()
        fake = FakeConnector()
        registry.register_instance(fake)
        assert registry.get_instance("fake") is fake

    def test_list_manifests(self) -> None:
        registry = ConnectorRegistry()
        m1 = ConnectorManifestV1(
            connector_type="a",
            capabilities=("read",),
            read_scopes=("x",),
            approval_policy="read_only",
        )
        m2 = ConnectorManifestV1(
            connector_type="b",
            capabilities=("read",),
            read_scopes=("y",),
            approval_policy="read_only",
        )
        registry.register_manifest(m1)
        registry.register_manifest(m2)
        types = {m.connector_type for m in registry.list_manifests()}
        assert types == {"a", "b"}


class TestConnectorManager:
    """Manager provides authorized dispatch and Echo integration."""

    def test_manager_production_defaults_empty(self) -> None:
        mgr = ConnectorManager(production=True)
        assert not mgr.is_available("fake")
        assert mgr.list_available() == []

    def test_manager_test_factory_has_fake(self) -> None:
        from js.connectors.manager import build_test_connector_manager

        mgr = build_test_connector_manager()
        assert mgr.is_available("fake")
        available = mgr.list_available()
        types = {c["connector_type"] for c in available}
        assert "fake" in types

    @pytest.mark.asyncio
    async def test_direct_execute_read_fake_requires_runtime_authority(self) -> None:
        mgr = ConnectorManager(production=False)
        result = await mgr.execute_read("fake", "test")
        assert result.success is False
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_execute_read_unknown_connector(self) -> None:
        mgr = ConnectorManager(production=False)
        result = await mgr.execute_read("nonexistent", "test")
        assert result.success is False
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_execute_write_on_read_only(self) -> None:
        mgr = ConnectorManager(production=False)
        result = await mgr.execute_write("fake", "test")
        assert result.success is False

    @pytest.mark.asyncio
    async def test_execute_read_rejects_scope_outside_manifest(self) -> None:
        mgr = ConnectorManager(production=False)
        result = await mgr.execute_read("fake", "unauthorized_scope")
        assert result.success is False
        assert result.error == "connector_runtime_authority_required"

    def test_default_test_manager_is_also_sealed(self) -> None:
        mgr = ConnectorManager(production=False)
        m = ConnectorManifestV1(
            connector_type="custom",
            capabilities=("read",),
            read_scopes=("data",),
            approval_policy="read_only",
        )
        with pytest.raises(PermissionError, match="sealed"):
            mgr.register_manifest(m)
        assert not mgr.is_available("custom")

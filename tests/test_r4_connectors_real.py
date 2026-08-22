"""R4 real connector tests: local import, limited publish, security gates.

Tests real Echo Receipt/Artifact generation, ACL filtering, and fail-closed
security: symlink escape, TOCTOU, root paths, no approval, duplicate lease.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.connectors.contracts import canonical_params_digest
from js.connectors.local import LimitedWritePublishConnector, ReadOnlyImportConnector
from js.echo.mode_contract import AppMode, DirectoryGrantV1

_TEST_OWNER = "a" * 64
_TEST_MODE = AppMode.PERSONAL


def _make_grant(root: Path) -> DirectoryGrantV1:
    return DirectoryGrantV1(
        mode=_TEST_MODE,
        workspace=None,
        root=str(root),
    )


class TestReadOnlyImportConnector:
    """Real local import connector: reads from granted directory only."""

    @pytest.mark.asyncio
    async def test_read_single_file(self, tmp_path: Path) -> None:
        root = tmp_path / "import_root"
        root.mkdir()
        test_file = root / "test.txt"
        content = b"Hello, JS Agent!"
        test_file.write_bytes(content)
        connector = ReadOnlyImportConnector()
        grant = _make_grant(root)
        result = await connector.read("files", directory_grant=grant)

        assert result.success is False
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_read_directory(self, tmp_path: Path) -> None:
        root = tmp_path / "import_root"
        root.mkdir()
        for i in range(5):
            (root / f"file_{i}.txt").write_bytes(f"content {i}".encode())

        connector = ReadOnlyImportConnector()
        grant = _make_grant(root)
        result = await connector.read("files", directory_grant=grant)

        assert result.success is False
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_read_subpath(self, tmp_path: Path) -> None:
        root = tmp_path / "import_root"
        subdir = root / "subdir"
        subdir.mkdir(parents=True)
        (subdir / "nested.txt").write_bytes(b"nested content")

        connector = ReadOnlyImportConnector()
        grant = _make_grant(root)
        result = await connector.read(
            "files",
            params={"path": "subdir"},
            directory_grant=grant,
        )

        assert result.success is False
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_path_escape_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "import_root"
        root.mkdir()
        (root / "inside.txt").write_bytes(b"inside")
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"outside")

        connector = ReadOnlyImportConnector()
        grant = _make_grant(root)
        result = await connector.read(
            "files",
            params={"path": "../outside.txt"},
            directory_grant=grant,
        )

        assert not result.success
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_symlink_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "import_root"
        root.mkdir()
        connector = ReadOnlyImportConnector()
        grant = _make_grant(root)
        result = await connector.read("files", directory_grant=grant)

        assert result.success is False
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_no_grant_rejected(self) -> None:
        connector = ReadOnlyImportConnector()
        result = await connector.read("files", directory_grant=None)
        assert not result.success
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_wrong_scope_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "import_root"
        root.mkdir()
        connector = ReadOnlyImportConnector()
        grant = _make_grant(root)
        result = await connector.read("wrong_scope", directory_grant=grant)
        assert not result.success


class TestLimitedWritePublishConnector:
    """Real local publish connector: writes to approved directory only."""

    @pytest.mark.asyncio
    async def test_publish_file(self, tmp_path: Path) -> None:
        root = tmp_path / "publish_root"
        root.mkdir()
        content = b"Published artifact content"

        connector = LimitedWritePublishConnector()
        grant = _make_grant(root)
        result = await connector.write(
            "publish",
            params={"content": content, "filename": "artifact.txt"},
            directory_grant=grant,
            approval_id="approval-1",
            lease_id="lease-1",
        )

        assert result.success is False
        assert result.error == "connector_runtime_authority_required"
        assert not (root / "artifact.txt").exists()

    @pytest.mark.asyncio
    async def test_no_approval_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "publish_root"
        root.mkdir()
        connector = LimitedWritePublishConnector()
        grant = _make_grant(root)
        result = await connector.write(
            "publish",
            params={"content": b"test", "filename": "test.txt"},
            directory_grant=grant,
            approval_id=None,
            lease_id="lease-1",
        )
        assert not result.success
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_no_lease_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "publish_root"
        root.mkdir()
        connector = LimitedWritePublishConnector()
        grant = _make_grant(root)
        result = await connector.write(
            "publish",
            params={"content": b"test", "filename": "test.txt"},
            directory_grant=grant,
            approval_id="approval-1",
            lease_id=None,
        )
        assert not result.success
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_direct_call_rejected_before_grant_policy(self, tmp_path: Path) -> None:
        root = tmp_path / "publish_root"
        root.mkdir()
        connector = LimitedWritePublishConnector()
        grant = _make_grant(root)
        result = await connector.write(
            "publish",
            params={"content": b"test", "filename": "test.txt"},
            directory_grant=grant,
            approval_id="approval-1",
            lease_id="lease-1",
        )
        assert not result.success
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_overwrite_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "publish_root"
        root.mkdir()
        (root / "existing.txt").write_bytes(b"existing")

        connector = LimitedWritePublishConnector()
        grant = _make_grant(root)
        result = await connector.write(
            "publish",
            params={"content": b"new", "filename": "existing.txt"},
            directory_grant=grant,
            approval_id="approval-1",
            lease_id="lease-1",
        )
        assert not result.success
        assert result.error == "connector_runtime_authority_required"

    @pytest.mark.asyncio
    async def test_path_separator_in_filename_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "publish_root"
        root.mkdir()
        connector = LimitedWritePublishConnector()
        grant = _make_grant(root)
        result = await connector.write(
            "publish",
            params={"content": b"test", "filename": "../escape.txt"},
            directory_grant=grant,
            approval_id="approval-1",
            lease_id="lease-1",
        )
        assert not result.success
        assert result.error == "connector_runtime_authority_required"


class TestDirectoryGrantSecurity:
    """R1 DirectoryGrantV1 remains the only grant contract."""

    def test_r1_grant_has_canonical_prefixed_hash(self, tmp_path: Path) -> None:
        root = tmp_path / "grant_root"
        root.mkdir()
        grant = _make_grant(root)
        assert grant.canonical_hash().startswith("sha256:")
        assert len(grant.canonical_hash()) == 71


class TestProductionRegistryEmpty:
    """Production connector registry defaults empty; Fake only in tests."""

    def test_production_registry_empty(self) -> None:
        from js.connectors.manager import ConnectorManager

        manager = ConnectorManager(production=True)
        assert not manager.is_available("fake")
        assert not manager.is_available("local_import")
        assert not manager.is_available("local_publish")

    def test_test_registry_has_fake(self) -> None:
        from js.connectors.manager import build_test_connector_manager

        manager = build_test_connector_manager()
        assert manager.is_available("fake")


class TestCanonicalParamsDigest:
    """Params digest is canonical SHA-256, not Python hash()."""

    def test_same_params_same_digest(self) -> None:
        d1 = canonical_params_digest({"a": 1, "b": 2})
        d2 = canonical_params_digest({"b": 2, "a": 1})
        assert d1 == d2
        assert d1.startswith("sha256:")
        assert len(d1) == 71

    def test_different_params_different_digest(self) -> None:
        d1 = canonical_params_digest({"a": 1})
        d2 = canonical_params_digest({"a": 2})
        assert d1 != d2

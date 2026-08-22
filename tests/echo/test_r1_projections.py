"""R1-D and R1-E: AttentionItem, ArtifactRef, ConnectorManifest, ConnectionRef tests."""
from __future__ import annotations

import dataclasses
import importlib
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def contract() -> Any:
    return importlib.import_module("js.echo.mode_contract")


DIGEST = "sha256:" + "a" * 64


# -- AttentionItem --

def test_attention_item_symbols() -> None:
    mod = contract()
    assert mod.ATTENTION_ITEM_SCHEMA_VERSION == 1
    assert mod.ATTENTION_ITEM_HASH_DOMAIN == b"js-agent:attention-item:v1\0"
    assert issubclass(mod.AttentionItemValidationError, mod.ModeContractError)
    assert dataclasses.is_dataclass(mod.AttentionItemV1)


def test_attention_item_construction() -> None:
    mod = contract()
    item = mod.AttentionItemV1(
        kind="approval", mode=mod.AppMode.WORK, owner="owner-a",
        session="session-a", run="run-a", workspace="ws-a",
        effect_digest=DIGEST, args_digest=DIGEST,
        eligible_approver="approver-a", ttl_seconds=300,
    )
    assert item.kind == "approval"
    assert item.schema_version == 1
    assert item.ttl_seconds == 300


def test_memory_proposal_is_a_valid_attention_kind() -> None:
    mod = contract()
    item = mod.AttentionItemV1(
        kind="memory_proposal", mode=mod.AppMode.PERSONAL, owner="owner-a",
        session="session-a", run="memory-proposal:1", workspace=None,
        effect_digest=DIGEST, args_digest=DIGEST,
        eligible_approver="owner-a", ttl_seconds=86400,
    )

    assert mod.AttentionItemV1.from_dict(item.to_dict()) == item


def test_attention_item_rejects_unknown_kind() -> None:
    mod = contract()
    with pytest.raises(mod.AttentionItemValidationError):
        mod.AttentionItemV1(
            kind="evil", mode=mod.AppMode.WORK, owner="owner-a",
            session="session-a", run="run-a", workspace="ws-a",
            effect_digest=DIGEST, args_digest=DIGEST,
            eligible_approver="approver-a", ttl_seconds=300,
        )


def test_attention_item_rejects_bad_digest() -> None:
    mod = contract()
    with pytest.raises(mod.AttentionItemValidationError):
        mod.AttentionItemV1(
            kind="approval", mode=mod.AppMode.WORK, owner="owner-a",
            session="session-a", run="run-a", workspace="ws-a",
            effect_digest="not-a-digest", args_digest=DIGEST,
            eligible_approver="approver-a", ttl_seconds=300,
        )


def test_attention_item_hash() -> None:
    mod = contract()
    item = mod.AttentionItemV1(
        kind="approval", mode=mod.AppMode.WORK, owner="owner-a",
        session="session-a", run="run-a", workspace="ws-a",
        effect_digest=DIGEST, args_digest=DIGEST,
        eligible_approver="approver-a", ttl_seconds=300,
    )
    h = item.canonical_hash()
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", h)


def test_attention_item_personal_no_workspace() -> None:
    mod = contract()
    item = mod.AttentionItemV1(
        kind="question", mode=mod.AppMode.PERSONAL, owner="owner-a",
        session="session-a", run="run-a", workspace=None,
        effect_digest=DIGEST, args_digest=DIGEST,
        eligible_approver="approver-a", ttl_seconds=300,
    )
    assert item.workspace is None


def test_attention_item_subclass_rejected() -> None:
    mod = contract()
    with pytest.raises(TypeError):
        class Evil(mod.AttentionItemV1):
            pass


# -- ArtifactRef --

def test_artifact_ref_symbols() -> None:
    mod = contract()
    assert mod.ARTIFACT_REF_SCHEMA_VERSION == 1
    assert issubclass(mod.ArtifactRefValidationError, mod.ModeContractError)
    assert dataclasses.is_dataclass(mod.ArtifactRefV1)


def test_artifact_ref_construction() -> None:
    mod = contract()
    ref = mod.ArtifactRefV1(
        mode=mod.AppMode.WORK, owner="owner-a", session="session-a",
        workspace="ws-a", kind="document", uri="echo://artifact/abc",
        digest=DIGEST, acl="workspace", created_by_run="run-a",
    )
    assert ref.kind == "document"
    assert ref.acl == "workspace"
    assert ref.schema_version == 1


def test_artifact_ref_rejects_bad_kind() -> None:
    mod = contract()
    with pytest.raises(mod.ArtifactRefValidationError):
        mod.ArtifactRefV1(
            mode=mod.AppMode.WORK, owner="owner-a", session="session-a",
            workspace="ws-a", kind="evil", uri="echo://x",
            digest=DIGEST, acl="private", created_by_run="run-a",
        )


def test_artifact_ref_hash() -> None:
    mod = contract()
    ref = mod.ArtifactRefV1(
        mode=mod.AppMode.PERSONAL, owner="owner-a", session="session-a",
        workspace=None, kind="report", uri="echo://artifact/xyz",
        digest=DIGEST, acl="owner", created_by_run="run-a",
    )
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", ref.canonical_hash())


def test_artifact_ref_subclass_rejected() -> None:
    mod = contract()
    with pytest.raises(TypeError):
        class Evil(mod.ArtifactRefV1):
            pass


# -- ConnectorManifest --

def test_connector_manifest_symbols() -> None:
    mod = contract()
    assert mod.CONNECTOR_MANIFEST_SCHEMA_VERSION == 1
    assert issubclass(mod.ConnectorManifestValidationError, mod.ModeContractError)
    assert dataclasses.is_dataclass(mod.ConnectorManifestV1)


def test_connector_manifest_construction() -> None:
    mod = contract()
    m = mod.ConnectorManifestV1(
        connector_type="gmail",
        capabilities=("read", "send"),
        read_scopes=("inbox",),
        write_scopes=(),
        approval_policy="always",
    )
    assert m.connector_type == "gmail"
    assert m.capabilities == ("read", "send")
    assert m.approval_policy == "always"
    assert m.schema_version == 1


def test_connector_manifest_rejects_bad_policy() -> None:
    mod = contract()
    with pytest.raises(mod.ConnectorManifestValidationError):
        mod.ConnectorManifestV1(
            connector_type="gmail", approval_policy="evil",
        )


def test_connector_manifest_hash() -> None:
    mod = contract()
    m = mod.ConnectorManifestV1(connector_type="slack", capabilities=("read",))
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", m.canonical_hash())


def test_connector_manifest_subclass_rejected() -> None:
    mod = contract()
    with pytest.raises(TypeError):
        class Evil(mod.ConnectorManifestV1):
            pass


# -- ConnectionRef --

def test_connection_ref_symbols() -> None:
    mod = contract()
    assert mod.CONNECTION_REF_SCHEMA_VERSION == 1
    assert issubclass(mod.ConnectionRefValidationError, mod.ModeContractError)
    assert dataclasses.is_dataclass(mod.ConnectionRefV1)


def test_connection_ref_construction() -> None:
    mod = contract()
    ref = mod.ConnectionRefV1(
        mode=mod.AppMode.WORK, owner="owner-a", workspace="ws-a",
        connector_type="gmail", connection_id="conn-1",
        authorized_by="user-a",
    )
    assert ref.connector_type == "gmail"
    assert ref.connection_id == "conn-1"
    assert ref.schema_version == 1


def test_connection_ref_personal_no_workspace() -> None:
    mod = contract()
    ref = mod.ConnectionRefV1(
        mode=mod.AppMode.PERSONAL, owner="owner-a", workspace=None,
        connector_type="calendar", connection_id="conn-2",
        authorized_by="user-a",
    )
    assert ref.workspace is None


def test_connection_ref_hash() -> None:
    mod = contract()
    ref = mod.ConnectionRefV1(
        mode=mod.AppMode.WORK, owner="owner-a", workspace="ws-a",
        connector_type="drive", connection_id="conn-3",
        authorized_by="user-a",
    )
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", ref.canonical_hash())


def test_connection_ref_subclass_rejected() -> None:
    mod = contract()
    with pytest.raises(TypeError):
        class Evil(mod.ConnectionRefV1):
            pass


# ============================================================
# R1-F09: from_dict for all 4 types
# ============================================================

def test_attention_item_from_dict_round_trip() -> None:
    mod = contract()
    item = mod.AttentionItemV1(
        kind="approval", mode=mod.AppMode.WORK, owner="owner-a",
        session="session-a", run="run-a", workspace="ws-a",
        effect_digest=DIGEST, args_digest=DIGEST,
        eligible_approver="approver-a", ttl_seconds=300,
    )
    d = item.to_dict()
    restored = mod.AttentionItemV1.from_dict(d)
    assert restored == item


def test_attention_item_from_dict_rejects_unknown_field() -> None:
    mod = contract()
    item = mod.AttentionItemV1(
        kind="approval", mode=mod.AppMode.WORK, owner="owner-a",
        session="session-a", run="run-a", workspace="ws-a",
        effect_digest=DIGEST, args_digest=DIGEST,
        eligible_approver="approver-a", ttl_seconds=300,
    )
    d = item.to_dict()
    d["evil"] = "data"
    with pytest.raises(mod.AttentionItemValidationError):
        mod.AttentionItemV1.from_dict(d)


def test_attention_item_from_dict_rejects_missing_field() -> None:
    mod = contract()
    item = mod.AttentionItemV1(
        kind="approval", mode=mod.AppMode.WORK, owner="owner-a",
        session="session-a", run="run-a", workspace="ws-a",
        effect_digest=DIGEST, args_digest=DIGEST,
        eligible_approver="approver-a", ttl_seconds=300,
    )
    d = item.to_dict()
    del d["ttl_seconds"]
    with pytest.raises(mod.AttentionItemValidationError):
        mod.AttentionItemV1.from_dict(d)


def test_attention_item_from_dict_rejects_bool_schema_version() -> None:
    mod = contract()
    item = mod.AttentionItemV1(
        kind="approval", mode=mod.AppMode.WORK, owner="owner-a",
        session="session-a", run="run-a", workspace="ws-a",
        effect_digest=DIGEST, args_digest=DIGEST,
        eligible_approver="approver-a", ttl_seconds=300,
    )
    d = item.to_dict()
    d["schema_version"] = True
    with pytest.raises(mod.AttentionItemValidationError):
        mod.AttentionItemV1.from_dict(d)


def test_artifact_ref_from_dict_round_trip() -> None:
    mod = contract()
    ref = mod.ArtifactRefV1(
        mode=mod.AppMode.WORK, owner="owner-a", session="session-a",
        workspace="ws-a", kind="document", uri="echo://artifact/abc",
        digest=DIGEST, acl="workspace", created_by_run="run-a",
    )
    d = ref.to_dict()
    restored = mod.ArtifactRefV1.from_dict(d)
    assert restored == ref


def test_artifact_ref_from_dict_rejects_unknown_field() -> None:
    mod = contract()
    ref = mod.ArtifactRefV1(
        mode=mod.AppMode.WORK, owner="owner-a", session="session-a",
        workspace="ws-a", kind="document", uri="echo://artifact/abc",
        digest=DIGEST, acl="workspace", created_by_run="run-a",
    )
    d = ref.to_dict()
    d["evil"] = "data"
    with pytest.raises(mod.ArtifactRefValidationError):
        mod.ArtifactRefV1.from_dict(d)


def test_connector_manifest_from_dict_round_trip() -> None:
    mod = contract()
    m_obj = mod.ConnectorManifestV1(
        connector_type="gmail",
        capabilities=("read", "send"),
        read_scopes=("inbox",),
        write_scopes=(),
        approval_policy="always",
    )
    d = m_obj.to_dict()
    restored = mod.ConnectorManifestV1.from_dict(d)
    assert restored == m_obj


def test_connector_manifest_from_dict_rejects_unknown_field() -> None:
    mod = contract()
    m_obj = mod.ConnectorManifestV1(
        connector_type="gmail", capabilities=("read",),
    )
    d = m_obj.to_dict()
    d["evil"] = "data"
    with pytest.raises(mod.ConnectorManifestValidationError):
        mod.ConnectorManifestV1.from_dict(d)


def test_connection_ref_from_dict_round_trip() -> None:
    mod = contract()
    ref = mod.ConnectionRefV1(
        mode=mod.AppMode.WORK, owner="owner-a", workspace="ws-a",
        connector_type="gmail", connection_id="conn-1",
        authorized_by="user-a",
    )
    d = ref.to_dict()
    restored = mod.ConnectionRefV1.from_dict(d)
    assert restored == ref


def test_connection_ref_from_dict_rejects_unknown_field() -> None:
    mod = contract()
    ref = mod.ConnectionRefV1(
        mode=mod.AppMode.WORK, owner="owner-a", workspace="ws-a",
        connector_type="gmail", connection_id="conn-1",
        authorized_by="user-a",
    )
    d = ref.to_dict()
    d["evil"] = "data"
    with pytest.raises(mod.ConnectionRefValidationError):
        mod.ConnectionRefV1.from_dict(d)


# ============================================================
# R1-F10: ArtifactRef created_by_run binding
# ============================================================

def test_artifact_ref_requires_created_by_run() -> None:
    """ArtifactRef must require non-empty created_by_run field."""
    mod = contract()
    with pytest.raises(mod.ArtifactRefValidationError):
        mod.ArtifactRefV1(
            mode=mod.AppMode.WORK, owner="owner-a", session="session-a",
            workspace="ws-a", kind="document", uri="echo://artifact/abc",
            digest=DIGEST, acl="workspace", created_by_run="",
        )


def test_artifact_ref_created_by_run_enters_hash() -> None:
    """created_by_run must enter canonical hash."""
    mod = contract()
    ref1 = mod.ArtifactRefV1(
        mode=mod.AppMode.WORK, owner="owner-a", session="session-a",
        workspace="ws-a", kind="document", uri="echo://artifact/abc",
        digest=DIGEST, acl="workspace", created_by_run="run-a",
    )
    ref2 = mod.ArtifactRefV1(
        mode=mod.AppMode.WORK, owner="owner-a", session="session-a",
        workspace="ws-a", kind="document", uri="echo://artifact/abc",
        digest=DIGEST, acl="workspace", created_by_run="run-b",
    )
    assert ref1.canonical_hash() != ref2.canonical_hash()


def test_artifact_ref_rejects_path_traversal_uri() -> None:
    """URI must not accept path traversal characters."""
    mod = contract()
    with pytest.raises(mod.ArtifactRefValidationError):
        mod.ArtifactRefV1(
            mode=mod.AppMode.WORK, owner="owner-a", session="session-a",
            workspace="ws-a", kind="document", uri="../../../etc/passwd",
            digest=DIGEST, acl="workspace", created_by_run="run-a",
        )


def test_artifact_ref_rejects_absolute_path_uri() -> None:
    """URI must not accept absolute file paths."""
    mod = contract()
    with pytest.raises(mod.ArtifactRefValidationError):
        mod.ArtifactRefV1(
            mode=mod.AppMode.WORK, owner="owner-a", session="session-a",
            workspace="ws-a", kind="document", uri="/etc/passwd",
            digest=DIGEST, acl="workspace", created_by_run="run-a",
        )


def test_artifact_ref_rejects_control_chars_in_uri() -> None:
    """URI must not accept control characters."""
    mod = contract()
    with pytest.raises(mod.ArtifactRefValidationError):
        mod.ArtifactRefV1(
            mode=mod.AppMode.WORK, owner="owner-a", session="session-a",
            workspace="ws-a", kind="document", uri="echo://art\0ifact/abc",
            digest=DIGEST, acl="workspace", created_by_run="run-a",
        )


# ============================================================
# R1-F11: AttentionItem/Connector/Connection boundary hardening
# ============================================================

def test_attention_item_rejects_bool_ttl() -> None:
    """ttl_seconds must reject bool."""
    mod = contract()
    with pytest.raises(mod.AttentionItemValidationError):
        mod.AttentionItemV1(
            kind="approval", mode=mod.AppMode.WORK, owner="owner-a",
            session="session-a", run="run-a", workspace="ws-a",
            effect_digest=DIGEST, args_digest=DIGEST,
            eligible_approver="approver-a", ttl_seconds=True,
        )


def test_attention_item_rejects_excessive_ttl() -> None:
    """ttl_seconds must have an upper bound."""
    mod = contract()
    with pytest.raises(mod.AttentionItemValidationError):
        mod.AttentionItemV1(
            kind="approval", mode=mod.AppMode.WORK, owner="owner-a",
            session="session-a", run="run-a", workspace="ws-a",
            effect_digest=DIGEST, args_digest=DIGEST,
            eligible_approver="approver-a", ttl_seconds=999_999_999,
        )


def test_attention_item_eligible_approver_uses_identity_grammar() -> None:
    """eligible_approver must use strict identity grammar, not just non-empty."""
    mod = contract()
    with pytest.raises(mod.AttentionItemValidationError):
        mod.AttentionItemV1(
            kind="approval", mode=mod.AppMode.WORK, owner="owner-a",
            session="session-a", run="run-a", workspace="ws-a",
            effect_digest=DIGEST, args_digest=DIGEST,
            eligible_approver="has space", ttl_seconds=300,
        )


def test_connector_manifest_read_only_rejects_write_scopes() -> None:
    """read_only policy must reject non-empty write_scopes."""
    mod = contract()
    with pytest.raises(mod.ConnectorManifestValidationError):
        mod.ConnectorManifestV1(
            connector_type="gmail",
            capabilities=("read",),
            read_scopes=("inbox",),
            write_scopes=("send",),
            approval_policy="read_only",
        )


def test_connector_manifest_never_rejects_write_scopes() -> None:
    """never policy must reject non-empty write_scopes."""
    mod = contract()
    with pytest.raises(mod.ConnectorManifestValidationError):
        mod.ConnectorManifestV1(
            connector_type="gmail",
            capabilities=("read",),
            read_scopes=("inbox",),
            write_scopes=("send",),
            approval_policy="never",
        )


def test_connection_ref_connection_id_uses_identity_grammar() -> None:
    """connection_id must use opaque identity grammar, not just non-empty."""
    mod = contract()
    with pytest.raises(mod.ConnectionRefValidationError):
        mod.ConnectionRefV1(
            mode=mod.AppMode.WORK, owner="owner-a", workspace="ws-a",
            connector_type="gmail", connection_id="has space",
            authorized_by="user-a",
        )


def test_connection_ref_authorized_by_uses_identity_grammar() -> None:
    """authorized_by must use identity grammar."""
    mod = contract()
    with pytest.raises(mod.ConnectionRefValidationError):
        mod.ConnectionRefV1(
            mode=mod.AppMode.WORK, owner="owner-a", workspace="ws-a",
            connector_type="gmail", connection_id="conn-1",
            authorized_by="has space",
        )

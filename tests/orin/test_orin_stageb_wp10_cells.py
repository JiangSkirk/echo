"""WP10 Cell-side reconciliation contracts.

The commit membrane may retry an *observation*, never an irreversible
effect.  These tests therefore pin the existing ``reconcile`` /
``reconcile_ack`` wire vocabulary to read-only Connector and File Cell
probes.  Cell handlers use membrane states internally, while ``CellBase``
maps them onto the frozen wire vocabulary: ``COMMITTED -> committed``,
``PREPARED -> absent`` and ``UNKNOWN_COMMIT -> unknown``.  Only the daemon
may then apply the corresponding membrane transition.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from js.orin.draft import CellPackage, CommitPermit, EffectDraft, StateWitness
from js.orin.handles import OriginHandle
from js.orin.protocol import ProtocolError, make_envelope, parse_frame
from js.orind.cells.base import CellBase
from js.orind.cells.file import FileCell
from js.orind.cells.services import ConnectorCell, SecretStore
from js.orind.kernel import canonical_effect_hash_of


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _hash(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


class _MemoryWriter:
    def __init__(self) -> None:
        self.frames: list[bytes] = []

    def write(self, payload: bytes) -> None:
        self.frames.append(payload)

    async def drain(self) -> None:
        return None

    def is_closing(self) -> bool:
        return False

    def last_frame(self) -> dict[str, Any]:
        payload = self.frames[-1]
        size = int.from_bytes(payload[:4], "big")
        assert size == len(payload) - 4
        return parse_frame(payload[4:])


def _bind_writer(cell: CellBase) -> _MemoryWriter:
    writer = _MemoryWriter()
    cell._writer = writer  # type: ignore[assignment]  # noqa: SLF001
    cell._session_key = b"r" * 32  # noqa: SLF001
    cell._session_nonce = "a" * 64  # noqa: SLF001
    return writer


def _run_reconcile_frame(
    cell: CellBase,
    *,
    effect_id: str,
    probe: dict[str, Any],
) -> dict[str, Any]:
    writer = _bind_writer(cell)
    envelope = make_envelope(
        "reconcile",
        seq=7,
        nonce="a" * 64,
        session_key=b"r" * 32,
        effect_id=effect_id,
        probe=probe,
    )
    asyncio.run(cell._on_reconcile(envelope))  # noqa: SLF001
    return writer.last_frame()


def _reconcile_direct(
    cell: CellBase,
    *,
    effect_id: str,
    probe: dict[str, Any],
) -> dict[str, Any]:
    handler = cell._reconcile_handler  # noqa: SLF001
    assert handler is not None
    result = handler(effect_id, probe)
    assert not asyncio.iscoroutine(result), "the built-in Cell probes are synchronous"
    assert isinstance(result, dict)
    return result


class TestCellBaseReconcileProtocol:
    @pytest.mark.parametrize(
        "sensitive_key",
        [
            "secret",
            "Authorization",
            "access-token",
            "accessToken",
            "refresh_token",
            "client-secret",
            "credential_blob",
            "passwordValue",
            "X-API-Key",
            "package_payload",
            "commitPermit",
            "body_draft",
        ],
    )
    def test_strict_result_rejects_nested_authority_and_credential_shaped_keys(
        self,
        sensitive_key: str,
    ) -> None:
        with pytest.raises(ProtocolError):
            CellBase._bounded_strict_result(  # noqa: SLF001
                {"status": "COMMITTED", "metadata": [{sensitive_key: "must-not-leak"}]}
            )

    def test_strict_cell_dispatches_optional_reconcile_handler_and_only_returns_state(
        self,
    ) -> None:
        secret_content = "do-not-reflect-package-content"
        owner_root = "/private/do-not-reflect-owner-root"
        seen: list[tuple[str, dict[str, Any]]] = []

        def reconcile(effect_id: str, probe: dict[str, Any]) -> dict[str, Any]:
            seen.append((effect_id, probe))
            # A Cell handler is not a second wire schema.  Even if an adapter
            # adds diagnostic fields, CellBase must project the ack to state.
            return {
                "state": "COMMITTED",
                "package": {"content": secret_content},
                "root": owner_root,
            }

        cell = CellBase(
            cap="cell.test",
            socket_path=Path("/unused/cells.sock"),
            state_dir=Path("/unused/state"),
            handler=lambda _permit, _package: {"status": "COMMITTED"},
            preflight_handler=lambda _package: None,
            reconcile_handler=reconcile,
            strict_effect_protocol=True,
        )
        probe = {"idempotency_key": "idem:one", "canonical_effect_hash": _hash("one")}

        ack = _run_reconcile_frame(cell, effect_id="effect:one", probe=probe)

        assert seen == [("effect:one", probe)]
        assert ack["type"] == "reconcile_ack"
        assert ack["ok"] is True
        assert ack["state"] == "committed"
        assert set(ack) == {"v", "type", "seq", "nonce", "mac", "ok", "state"}
        rendered = json.dumps(ack, sort_keys=True)
        assert secret_content not in rendered
        assert owner_root not in rendered
        assert "package" not in rendered

    @pytest.mark.parametrize(
        ("internal_state", "wire_state"),
        [("PREPARED", "absent"), ("UNKNOWN_COMMIT", "unknown")],
    )
    def test_internal_membrane_state_maps_to_frozen_wire_state(
        self,
        internal_state: str,
        wire_state: str,
    ) -> None:
        cell = CellBase(
            cap="cell.test",
            socket_path=Path("/unused/cells.sock"),
            state_dir=Path("/unused/state"),
            handler=lambda _permit, _package: {"status": "COMMITTED"},
            reconcile_handler=lambda _effect_id, _probe: {"state": internal_state},
            strict_effect_protocol=True,
        )

        ack = _run_reconcile_frame(
            cell,
            effect_id=f"effect:{wire_state}",
            probe={"idempotency_key": f"idem:{wire_state}"},
        )

        assert ack["ok"] is True
        assert ack["state"] == wire_state

    def test_strict_cell_without_reconcile_handler_fails_closed_without_probe_echo(
        self,
    ) -> None:
        cell = CellBase(
            cap="cell.test",
            socket_path=Path("/unused/cells.sock"),
            state_dir=Path("/unused/state"),
            handler=lambda _permit, _package: {"status": "COMMITTED"},
            strict_effect_protocol=True,
        )
        secret = "probe-secret-that-must-not-return"

        ack = _run_reconcile_frame(
            cell,
            effect_id="effect:no-handler",
            probe={"content": secret},
        )

        assert ack["type"] == "reconcile_ack"
        assert ack["ok"] is False
        assert ack["code"] == "bad_message"
        assert secret not in json.dumps(ack, sort_keys=True)

    def test_legacy_build_rejects_reconcile_and_commit_payload_remains_exact(self) -> None:
        seen: list[dict[str, Any]] = []

        def build_handler(payload: dict[str, Any]) -> dict[str, Any]:
            seen.append(payload)
            return {"status": "COMMITTED", "output": "legacy-ok"}

        cell = CellBase(
            cap="cell.build",
            socket_path=Path("/unused/cells.sock"),
            state_dir=Path("/unused/state"),
            handler=build_handler,
            strict_effect_protocol=False,
        )
        payload = {
            "kind": "shell",
            "command": "printf legacy",
            "cwd": ".",
            "tool": "shell",
        }

        reconcile_ack = _run_reconcile_frame(
            cell,
            effect_id="effect:must-not-reach-build",
            probe={"idempotency_key": "idem:ignored"},
        )
        assert reconcile_ack["ok"] is False
        assert seen == []

        writer = _bind_writer(cell)
        asyncio.run(cell._on_commit({"seq": 8, "permit": payload}))  # noqa: SLF001
        commit_ack = writer.last_frame()
        assert commit_ack["ok"] is True
        assert seen == [payload]
        assert seen[0] == payload
        assert "package" not in commit_ack


def _connector(tmp_path: Path) -> ConnectorCell:
    state_dir = tmp_path / "state"
    return ConnectorCell(
        socket_path=tmp_path / "unused.sock",
        state_dir=state_dir,
        mac_key=b"c" * 32,
        secrets=SecretStore(state_dir),
    )


def _recipient(token: str) -> OriginHandle:
    now = _now_ms()
    return OriginHandle(
        handle_id=f"rcpt:{token}",
        kind="RecipientHandle",
        owner_key_hash="sha256:" + "7" * 64,
        tenant="work",
        source_class="USER_AUTHENTICATED",
        integrity="trusted_local_object",
        confidentiality="CONFIDENTIAL",
        object_digest=_hash(token),
        capabilities=("send",),
        issuer="orind:broker",
        created_at_ms=now,
        expires_at_ms=now + 120_000,
    )


def _connector_probe(
    idempotency_key: str,
    payload_hash: str,
    destination_handles: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "idempotency_key": idempotency_key,
        "canonical_effect_hash": payload_hash,
        "destination_handles": list(destination_handles),
    }


class TestConnectorReconcile:
    def test_same_idempotency_key_and_hash_is_committed_and_query_sends_nothing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cell = _connector(tmp_path)
        idem = f"idem:{uuid4().hex}"
        payload_hash = _hash("connector-exact-payload")
        recipient = _recipient("connector-exact")
        appended = cell._append_outbox_once(  # noqa: SLF001
            idempotency_key=idem,
            payload_hash=payload_hash,
            recipients=(recipient,),
            bytes_out=0,
        )
        assert appended["status"] == "COMMITTED"
        before = cell._outbox_path.read_bytes()  # noqa: SLF001

        def forbidden_send(_raw: dict[str, Any]) -> dict[str, Any]:
            pytest.fail("reconcile must not send or append a provider effect")

        monkeypatch.setattr(cell, "_send_exact", forbidden_send)
        monkeypatch.setattr(cell, "_handler", forbidden_send)

        result = _reconcile_direct(
            cell,
            effect_id="effect:connector-committed",
            probe=_connector_probe(idem, payload_hash, (recipient.handle_id,)),
        )

        assert result == {"state": "COMMITTED"}
        assert cell._outbox_path.read_bytes() == before  # noqa: SLF001

    def test_clean_outbox_with_no_matching_record_returns_prepared(
        self,
        tmp_path: Path,
    ) -> None:
        cell = _connector(tmp_path)

        result = _reconcile_direct(
            cell,
            effect_id="effect:connector-prepared",
            probe=_connector_probe(
                f"idem:{uuid4().hex}",
                _hash("not-sent"),
                ("rcpt:not-sent",),
            ),
        )

        assert result == {"state": "PREPARED"}
        assert not cell._outbox_path.exists()  # noqa: SLF001

    @pytest.mark.parametrize("tamper", ["mode", "hardlink"])
    def test_commit_rejects_insecure_outbox_before_append(
        self,
        tmp_path: Path,
        tamper: str,
    ) -> None:
        cell = _connector(tmp_path)
        first = _recipient("secure-first")
        initial = cell._append_outbox_once(  # noqa: SLF001
            idempotency_key="idem:secure-first",
            payload_hash=_hash("secure-first"),
            recipients=(first,),
            bytes_out=0,
        )
        assert initial["status"] == "COMMITTED"
        outbox = cell._outbox_path  # noqa: SLF001
        before = outbox.read_bytes()
        if tamper == "mode":
            outbox.chmod(0o640)
        else:
            os.link(outbox, outbox.with_name("connector_outbox.alias"))

        second = _recipient("must-not-append")
        result = cell._append_outbox_once(  # noqa: SLF001
            idempotency_key="idem:must-not-append",
            payload_hash=_hash("must-not-append"),
            recipients=(second,),
            bytes_out=0,
        )

        assert result["status"] == "FAILED"
        assert outbox.read_bytes() == before
        if tamper == "mode":
            assert outbox.stat().st_mode & 0o777 == 0o640

    def test_reconcile_insecure_outbox_is_unknown_without_repair(
        self,
        tmp_path: Path,
    ) -> None:
        cell = _connector(tmp_path)
        recipient = _recipient("reconcile-insecure")
        idem = "idem:reconcile-insecure"
        payload_hash = _hash("reconcile-insecure")
        appended = cell._append_outbox_once(  # noqa: SLF001
            idempotency_key=idem,
            payload_hash=payload_hash,
            recipients=(recipient,),
            bytes_out=0,
        )
        assert appended["status"] == "COMMITTED"
        outbox = cell._outbox_path  # noqa: SLF001
        before = outbox.read_bytes()
        outbox.chmod(0o640)

        result = _reconcile_direct(
            cell,
            effect_id="effect:reconcile-insecure",
            probe=_connector_probe(idem, payload_hash, (recipient.handle_id,)),
        )

        assert result == {"state": "UNKNOWN_COMMIT"}
        assert outbox.read_bytes() == before
        assert outbox.stat().st_mode & 0o777 == 0o640

    def test_same_idempotency_key_bound_to_different_hash_is_unknown(
        self,
        tmp_path: Path,
    ) -> None:
        cell = _connector(tmp_path)
        idem = f"idem:{uuid4().hex}"
        recipient = _recipient("connector-conflict")
        cell._append_outbox_once(  # noqa: SLF001
            idempotency_key=idem,
            payload_hash=_hash("first-payload"),
            recipients=(recipient,),
            bytes_out=0,
        )

        result = _reconcile_direct(
            cell,
            effect_id="effect:connector-conflict",
            probe=_connector_probe(
                idem,
                _hash("different-payload"),
                (recipient.handle_id,),
            ),
        )

        assert result == {"state": "UNKNOWN_COMMIT"}

    def test_destination_subset_does_not_match_full_outbox_tuple(
        self,
        tmp_path: Path,
    ) -> None:
        cell = _connector(tmp_path)
        idem = f"idem:{uuid4().hex}"
        payload_hash = _hash("same-payload-different-destination")
        first = _recipient("expected-first")
        second = _recipient("expected-second")
        cell._append_outbox_once(  # noqa: SLF001
            idempotency_key=idem,
            payload_hash=payload_hash,
            recipients=(first, second),
            bytes_out=0,
        )

        result = _reconcile_direct(
            cell,
            effect_id="effect:connector-destination-conflict",
            probe=_connector_probe(idem, payload_hash, (first.handle_id,)),
        )

        assert result == {"state": "UNKNOWN_COMMIT"}

    def test_destination_order_is_canonical_but_duplicates_fail_closed(
        self,
        tmp_path: Path,
    ) -> None:
        cell = _connector(tmp_path)
        idem = f"idem:{uuid4().hex}"
        payload_hash = _hash("canonical-destination-order")
        first = _recipient("canonical-first")
        second = _recipient("canonical-second")
        cell._append_outbox_once(  # noqa: SLF001
            idempotency_key=idem,
            payload_hash=payload_hash,
            recipients=(first, second),
            bytes_out=0,
        )

        reordered = _reconcile_direct(
            cell,
            effect_id="effect:connector-destination-order",
            probe=_connector_probe(
                idem,
                payload_hash,
                (second.handle_id, first.handle_id),
            ),
        )
        duplicate = _reconcile_direct(
            cell,
            effect_id="effect:connector-destination-duplicate",
            probe=_connector_probe(
                idem,
                payload_hash,
                (first.handle_id, first.handle_id),
            ),
        )

        assert reordered == {"state": "COMMITTED"}
        assert duplicate == {"state": "UNKNOWN_COMMIT"}

    @pytest.mark.parametrize(
        "corrupt_line",
        [
            "{not-json}\n",
            json.dumps({"idempotency_key": "idem:broken", "payload_hash": 7}) + "\n",
        ],
        ids=("invalid-json", "invalid-record-shape"),
    )
    def test_corrupt_outbox_is_unknown_never_false_prepared(
        self,
        tmp_path: Path,
        corrupt_line: str,
    ) -> None:
        cell = _connector(tmp_path)
        cell._outbox_path.parent.mkdir(parents=True, exist_ok=True)  # noqa: SLF001
        cell._outbox_path.write_text(corrupt_line, encoding="utf-8")  # noqa: SLF001

        result = _reconcile_direct(
            cell,
            effect_id="effect:connector-corrupt",
            probe=_connector_probe(
                "idem:broken",
                _hash("expected"),
                ("rcpt:expected",),
            ),
        )

        assert result == {"state": "UNKNOWN_COMMIT"}


def _directory_handle(mac_key: bytes, owner_root: Path) -> OriginHandle:
    now = _now_ms()
    raw = OriginHandle(
        handle_id=f"dirh:{uuid4().hex}",
        kind="DirectoryHandle",
        owner_key_hash="sha256:" + "7" * 64,
        tenant="work",
        source_class="USER_AUTHENTICATED",
        integrity="trusted_local_object",
        confidentiality="CONFIDENTIAL",
        object_digest=str(owner_root.resolve()),
        capabilities=("read", "stage", "write"),
        issuer="orind:broker",
        created_at_ms=now,
        expires_at_ms=now + 120_000,
    )
    return raw.sealed_by(mac_key, "orind:broker", now)


def _file_fixture(
    tmp_path: Path,
    changes: list[dict[str, str]],
) -> tuple[FileCell, CellPackage, CommitPermit, Path]:
    mac_key = b"f" * 32
    owner_root = tmp_path / "owner"
    owner_root.mkdir(parents=True, exist_ok=True)
    handle = _directory_handle(mac_key, owner_root)
    draft = EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=f"task:{uuid4().hex}",
        effect_type="file.commit",
        arguments={"directory_handle": handle.handle_id, "changes": changes},
        declared_expectation={
            "external_visibility": "private",
            "reversibility": "reversible_until_stage",
        },
    )
    package = CellPackage(
        draft=draft,
        executor_id="cell.file",
        canonical_effect_hash=canonical_effect_hash_of(draft),
        resolved_handles=(handle,),
        clearance=1,
    )
    cell = FileCell(
        socket_path=tmp_path / "unused.sock",
        state_dir=tmp_path / "state",
        mac_key=mac_key,
    )
    witness = cell._preflight_package(package)  # noqa: SLF001
    assert isinstance(witness, StateWitness)
    committed_package = replace(package, state_witness=witness)
    now = _now_ms()
    permit = CommitPermit(
        permit_id=f"permit:{uuid4().hex}",
        intent_id=f"intent:{uuid4().hex}",
        draft_id=draft.draft_id,
        state_witness_id=witness.witness_id,
        executor_id="cell.file",
        canonical_effect_hash=package.canonical_effect_hash,
        idempotency_key=f"idem:{uuid4().hex}",
        sequence=1,
        not_before_ms=now - 1_000,
        expires_at_ms=now + 60_000,
    )
    committed_package.validate_binding(permit, require_witness=True)
    return cell, committed_package, permit, owner_root


def _file_probe(package: CellPackage, permit: CommitPermit) -> dict[str, Any]:
    return {"permit": permit.to_dict(), "package": package.to_dict()}


def test_strict_commit_ack_fails_closed_on_nested_credential_key(tmp_path: Path) -> None:
    cell, package, permit, _owner_root = _file_fixture(
        tmp_path,
        [{"path": "safe.txt", "content": "approved\n"}],
    )
    credential = "credential-value-must-not-return"
    cell._handler = lambda _permit, _package: {  # noqa: SLF001
        "status": "COMMITTED",
        "metadata": {"AccessToken": credential},
    }
    writer = _bind_writer(cell)

    asyncio.run(  # noqa: SLF001
        cell._on_commit(
            {
                "seq": 8,
                "permit": permit.to_dict(),
                "package": package.to_dict(),
            }
        )
    )
    ack = writer.last_frame()

    assert ack["type"] == "commit_ack"
    assert ack["ok"] is False
    assert ack["code"] == "bad_message"
    assert credential not in json.dumps(ack, sort_keys=True)


def test_strict_commit_ack_never_stringifies_non_object_result(tmp_path: Path) -> None:
    cell, package, permit, _owner_root = _file_fixture(
        tmp_path,
        [{"path": "safe.txt", "content": "approved\n"}],
    )
    credential = "non-object-credential-must-not-return"
    cell._handler = lambda _permit, _package: credential  # noqa: SLF001
    writer = _bind_writer(cell)

    asyncio.run(  # noqa: SLF001
        cell._on_commit(
            {
                "seq": 8,
                "permit": permit.to_dict(),
                "package": package.to_dict(),
            }
        )
    )
    ack = writer.last_frame()

    assert ack["ok"] is False
    assert ack["code"] == "bad_message"
    assert credential not in json.dumps(ack, sort_keys=True)


def _file_reconcile(
    cell: FileCell,
    package: CellPackage,
    permit: CommitPermit,
) -> dict[str, Any]:
    return _reconcile_direct(
        cell,
        effect_id=f"effect:{uuid4().hex}",
        probe=_file_probe(package, permit),
    )


def _stage_report(cell: FileCell) -> Path:
    reports = list(cell._stage_root.rglob("report.json"))  # noqa: SLF001
    assert len(reports) == 1
    return reports[0]


def _staged_payload(cell: FileCell, expected: bytes) -> Path:
    matches = [
        path
        for path in cell._stage_root.rglob("*")  # noqa: SLF001
        if path.is_file() and path.read_bytes() == expected
    ]
    assert len(matches) == 1
    return matches[0]


class TestFileReconcile:
    def test_all_targets_at_staged_content_is_committed(self, tmp_path: Path) -> None:
        changes = [
            {"path": "a.txt", "content": "new-a\n"},
            {"path": "nested/b.txt", "content": "new-b\n"},
        ]
        cell, package, permit, owner_root = _file_fixture(tmp_path, changes)
        result = cell._commit_package(permit, package)  # noqa: SLF001
        assert result["status"] == "COMMITTED"

        reconciled = _file_reconcile(cell, package, permit)

        assert reconciled == {"state": "COMMITTED"}
        assert (owner_root / "a.txt").read_text(encoding="utf-8") == "new-a\n"
        assert (owner_root / "nested/b.txt").read_text(encoding="utf-8") == "new-b\n"

    def test_all_targets_at_original_source_returns_prepared(
        self,
        tmp_path: Path,
    ) -> None:
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        target = owner_root / "existing.txt"
        target.write_text("original\n", encoding="utf-8")
        changes = [{"path": "existing.txt", "content": "approved\n"}]
        cell, package, permit, _root = _file_fixture(tmp_path, changes)

        reconciled = _file_reconcile(cell, package, permit)

        assert reconciled == {"state": "PREPARED"}
        assert target.read_text(encoding="utf-8") == "original\n"

    def test_safe_mixed_state_is_prepared_then_commit_skips_done_target(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        first = owner_root / "a.txt"
        second = owner_root / "b.txt"
        first.write_text("old-a\n", encoding="utf-8")
        second.write_text("old-b\n", encoding="utf-8")
        changes = [
            {"path": "a.txt", "content": "new-a\n"},
            {"path": "b.txt", "content": "new-b\n"},
        ]
        cell, package, permit, _root = _file_fixture(tmp_path, changes)

        # Model a crash after the first atomic rename but before the second.
        first.write_text("new-a\n", encoding="utf-8")
        reconciled = _file_reconcile(cell, package, permit)
        assert reconciled == {"state": "PREPARED"}

        real_replace = os.replace
        replaced_targets: list[str] = []

        def record_replace(src: str, dst: str, **kwargs: Any) -> None:
            replaced_targets.append(dst)
            real_replace(src, dst, **kwargs)

        monkeypatch.setattr("js.orind.cells.file.os.replace", record_replace)
        result = cell._commit_package(permit, package)  # noqa: SLF001

        assert result["status"] == "COMMITTED"
        assert replaced_targets == ["b.txt"]
        assert first.read_text(encoding="utf-8") == "new-a\n"
        assert second.read_text(encoding="utf-8") == "new-b\n"

    def test_target_conflict_is_unknown_and_owner_content_is_unchanged(
        self,
        tmp_path: Path,
    ) -> None:
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        target = owner_root / "conflict.txt"
        target.write_text("original\n", encoding="utf-8")
        cell, package, permit, _root = _file_fixture(
            tmp_path,
            [{"path": "conflict.txt", "content": "approved\n"}],
        )
        target.write_text("foreign-writer\n", encoding="utf-8")

        reconciled = _file_reconcile(cell, package, permit)

        assert reconciled == {"state": "UNKNOWN_COMMIT"}
        assert target.read_text(encoding="utf-8") == "foreign-writer\n"

    @pytest.mark.parametrize("tamper", ["report", "staged-bytes"])
    def test_stage_tamper_is_unknown_never_prepared(
        self,
        tmp_path: Path,
        tamper: str,
    ) -> None:
        cell, package, permit, owner_root = _file_fixture(
            tmp_path,
            [{"path": "safe.txt", "content": "approved\n"}],
        )
        if tamper == "report":
            report = _stage_report(cell)
            report.write_bytes(report.read_bytes() + b" ")
        else:
            staged = _staged_payload(cell, b"approved\n")
            staged.write_bytes(b"tampered\n")

        reconciled = _file_reconcile(cell, package, permit)

        assert reconciled == {"state": "UNKNOWN_COMMIT"}
        assert not (owner_root / "safe.txt").exists()

    def test_reconcile_result_and_wire_ack_do_not_leak_package_content_or_root(
        self,
        tmp_path: Path,
    ) -> None:
        secret_content = "private-file-content-never-in-reconcile-ack"
        cell, package, permit, owner_root = _file_fixture(
            tmp_path,
            [{"path": "private.txt", "content": secret_content}],
        )
        probe = _file_probe(package, permit)

        direct = _reconcile_direct(
            cell,
            effect_id="effect:file-safe-projection",
            probe=probe,
        )
        ack = _run_reconcile_frame(
            cell,
            effect_id="effect:file-safe-projection",
            probe=probe,
        )

        assert direct == {"state": "PREPARED"}
        assert ack["ok"] is True
        assert ack["state"] == "absent"
        rendered = json.dumps(ack, sort_keys=True)
        assert secret_content not in rendered
        assert str(owner_root) not in rendered
        assert "package" not in rendered
        assert "permit" not in rendered


def test_file_reconcile_rejects_probe_authority_mismatch_as_unknown(tmp_path: Path) -> None:
    cell, package, permit, _owner_root = _file_fixture(
        tmp_path,
        [{"path": "bound.txt", "content": "approved\n"}],
    )
    wrong_hash = replace(permit, canonical_effect_hash=_hash("wrong"))

    result = _file_reconcile(cell, package, wrong_hash)

    assert result == {"state": "UNKNOWN_COMMIT"}


def test_connector_reconcile_rejects_malformed_probe_as_unknown(tmp_path: Path) -> None:
    cell = _connector(tmp_path)
    malformed = {
        "idempotency_key": "idem:bounded",
        "canonical_effect_hash": _hash("payload"),
        "destination_handles": ["rcpt:bounded"],
        "unexpected": "authority",
    }

    result = _reconcile_direct(
        cell,
        effect_id="effect:connector-bad-probe",
        probe=malformed,
    )

    assert result == {"state": "UNKNOWN_COMMIT"}

"""WP9: File Cell staging, exact preflight and atomic owner-root commit.

These tests deliberately exercise the File Cell through the same strict
``draft -> preflight -> consume(draft_id)`` boundary as the other Stage-B
effect cells.  The unit probes keep filesystem edge cases deterministic;
the integration probes pin the authenticated ``cells.sock`` frame shape.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import time
import unicodedata
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.appshell.principal import AppShellEpochBindingV1
from js.echo import stable_payload_hash
from js.echo.capability import LeaseDenied
from js.echo.turn_context import (
    RuntimeContext,
    reset_runtime_context,
    set_runtime_context,
)
from js.orin.client import OrinLeaseClientAdapter
from js.orin.draft import CellPackage, CommitPermit, EffectDraft, StateWitness
from js.orin.handles import OriginHandle, make_handle_id
from js.orin.intent import Budgets, IntentEnvelope
from js.orin.protocol import ProtocolError, canonical_json
from js.orin.testing import TestOrind
from js.orin.witness import build_intent_from_template
from js.orind.kernel import canonical_effect_hash_of
from js.tools import registry as registry_module
from js.tools.registry import ToolExecutionContext


def _now_ms() -> int:
    return int(time.time() * 1000)


def _pub_of(key: ed25519.Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _adapter(orind: TestOrind) -> OrinLeaseClientAdapter:
    return OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=Path(orind.daemon._state_dir),  # noqa: SLF001 - boundary probe
        stage_b=True,
    )


def _directory_handle(mac_key: bytes, owner_root: Path, *, owner: str) -> OriginHandle:
    now = _now_ms()
    raw = OriginHandle(
        handle_id=f"dirh:{uuid4().hex}",
        kind="DirectoryHandle",
        owner_key_hash=owner,
        tenant="work",
        source_class="USER_AUTHENTICATED",
        integrity="trusted_local_object",
        confidentiality="CONFIDENTIAL",
        object_digest=str(owner_root.resolve()),
        capabilities=("read", "stage", "write"),
        issuer="orind:broker",
        created_at_ms=now,
        expires_at_ms=now + 60_000,
    )
    return raw.sealed_by(mac_key, "orind:broker", now)


def _draft(
    task_id: str,
    handle_id: str,
    changes: list[dict[str, str]],
) -> EffectDraft:
    return EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=task_id,
        effect_type="file.commit",
        arguments={"directory_handle": handle_id, "changes": changes},
        declared_expectation={
            "external_visibility": "private",
            "reversibility": "reversible_until_stage",
        },
    )


def _package(draft: EffectDraft, handle: OriginHandle) -> CellPackage:
    return CellPackage(
        draft=draft,
        executor_id="cell.file",
        canonical_effect_hash=canonical_effect_hash_of(draft),
        resolved_handles=(handle,),
        clearance=1,
    )


def _permit(package: CellPackage, witness: StateWitness) -> CommitPermit:
    now = _now_ms()
    return CommitPermit(
        permit_id=f"permit:{uuid4().hex}",
        intent_id=f"intent:{uuid4().hex}",
        draft_id=package.draft.draft_id,
        state_witness_id=witness.witness_id,
        executor_id="cell.file",
        canonical_effect_hash=package.canonical_effect_hash,
        idempotency_key=f"idem:{uuid4().hex}",
        sequence=1,
        not_before_ms=now - 100,
        expires_at_ms=now + 60_000,
    )


def _file_cell(tmp_path: Path, mac_key: bytes):
    from js.orind.cells.file import FileCell

    return FileCell(
        socket_path=tmp_path / "unused.sock",
        state_dir=tmp_path / "state",
        mac_key=mac_key,
    )


def _stage(cell: Any, package: CellPackage) -> StateWitness:
    witness = cell._preflight_package(package)  # noqa: SLF001 - cell contract probe
    assert isinstance(witness, StateWitness)
    return witness


def _commit(cell: Any, package: CellPackage, witness: StateWitness) -> dict[str, Any]:
    permit = _permit(package, witness)
    committed_package = replace(package, state_witness=witness)
    committed_package.validate_binding(permit, require_witness=True)
    result = cell._commit_package(permit, committed_package)  # noqa: SLF001
    assert isinstance(result, dict)
    return result


def _assert_commit_rejected(
    cell: Any,
    package: CellPackage,
    witness: StateWitness,
) -> None:
    try:
        result = _commit(cell, package, witness)
    except ProtocolError:
        return
    assert result.get("status") == "FAILED"


def _json_objects_below(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in root.rglob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def _preview_path(root: Path, draft_id: str) -> Path:
    matches: list[Path] = []
    for path in root.rglob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if (
            isinstance(value, dict)
            and value.get("draft_id") == draft_id
            and "normalized_diff" in value
        ):
            matches.append(path)
    assert len(matches) == 1, "preflight must persist exactly one canonical stage report"
    return matches[0]


def _staged_file_with_bytes(root: Path, payload: bytes) -> Path:
    matches: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.read_bytes() == payload:
                matches.append(path)
        except OSError:
            continue
    assert len(matches) == 1, "preflight must stage the exact proposed bytes once"
    return matches[0]


def _appshell_directory_handle_id(
    *,
    installation_owner_hash: str,
    product_id: str,
    task_id: str,
    profile: str,
    principal_owner: str,
    principal_session: str,
    principal_epoch: int,
    workspace_root: Path,
) -> str:
    """Independent product-side oracle for ``orin:appshell-dirh:v1``."""

    root_nfc = unicodedata.normalize("NFC", os.fspath(workspace_root.resolve()))
    material = [
        "orin:appshell-dirh:v1",
        installation_owner_hash,
        product_id,
        task_id,
        profile,
        principal_owner,
        principal_session,
        principal_epoch,
        root_nfc,
    ]
    digest = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
    return make_handle_id("DirectoryHandle", f"appshell-{digest}")


class TestFileCellUnit:
    def test_canonical_effect_hash_recurses_through_change_objects(self) -> None:
        task_id = f"task:{uuid4().hex}"
        handle_id = f"dirh:{uuid4().hex}"
        first = _draft(
            task_id,
            handle_id,
            [
                {"path": "b.txt", "content": "b"},
                {"path": "a.txt", "content": "a"},
            ],
        )
        second = _draft(
            task_id,
            handle_id,
            [
                {"content": "b", "path": "b.txt"},
                {"content": "a", "path": "a.txt"},
            ],
        )
        reordered = _draft(
            task_id,
            handle_id,
            [
                {"content": "a", "path": "a.txt"},
                {"content": "b", "path": "b.txt"},
            ],
        )
        first_hash = canonical_effect_hash_of(first)
        assert first_hash == canonical_effect_hash_of(first)
        assert first_hash == canonical_effect_hash_of(second)
        assert first_hash != canonical_effect_hash_of(reordered)
        assert first_hash.startswith("sha256:") and len(first_hash) == 71

    def test_preflight_stages_bytes_and_records_machine_canonical_preview(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mac_key = b"f" * 32
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        (owner_root / "report.txt").write_text("old\n", encoding="utf-8")
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "1" * 64)
        draft = _draft(
            f"task:{uuid4().hex}",
            handle.handle_id,
            [
                {"path": "new.txt", "content": "created\n"},
                {"path": "report.txt", "content": "new\n"},
            ],
        )
        package = _package(draft, handle)
        cell = _file_cell(tmp_path, mac_key)

        # The Cell receives its complete authority package on cells.sock.  It
        # must not reach sideways into Orind's WAL for an execution package.
        def forbidden_connect(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("File Cell must not read Orind SQLite")

        monkeypatch.setattr(sqlite3, "connect", forbidden_connect)
        witness = _stage(cell, package)

        assert (owner_root / "report.txt").read_text(encoding="utf-8") == "old\n"
        assert not (owner_root / "new.txt").exists()
        assert witness.executor_id == "cell.file"
        assert witness.canonical_effect_hash == package.canonical_effect_hash
        assert witness.impact.writes == 2

        staged_payloads = []
        for path in (tmp_path / "state").rglob("*"):
            if not path.is_file():
                continue
            try:
                staged_payloads.append(path.read_bytes())
            except OSError:
                continue
        assert b"created\n" in staged_payloads
        assert b"new\n" in staged_payloads

        previews = [
            item
            for item in _json_objects_below(tmp_path / "state")
            if item.get("draft_id") == draft.draft_id and "normalized_diff" in item
        ]
        assert len(previews) == 1
        preview = previews[0]
        assert preview["files"] == ["new.txt", "report.txt"]
        assert preview["file_count"] == 2
        assert preview["bytes_written"] == len(b"created\n") + len(b"new\n")
        assert preview["overwrites"] == ["report.txt"]
        assert preview["source_hashes"] == {
            "new.txt": None,
            "report.txt": "sha256:" + hashlib.sha256(b"old\n").hexdigest(),
        }
        diff = str(preview["normalized_diff"])
        assert "--- a/report.txt" in diff and "+++ b/report.txt" in diff
        assert "-old" in diff and "+new" in diff

    def test_commit_rechecks_source_hash_then_uses_same_directory_atomic_replace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from js.orind.cells import file as file_cell_module

        mac_key = b"a" * 32
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        target = owner_root / "report.txt"
        target.write_text("old\n", encoding="utf-8")
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "2" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                handle.handle_id,
                [{"path": "report.txt", "content": "approved\n"}],
            ),
            handle,
        )
        cell = _file_cell(tmp_path, mac_key)
        witness = _stage(cell, package)

        real_replace = file_cell_module.os.replace
        replacements: list[tuple[Any, Any, int | None, int | None]] = []

        def recording_replace(source: Any, destination: Any, *args: Any, **kwargs: Any) -> Any:
            replacements.append(
                (
                    source,
                    destination,
                    kwargs.get("src_dir_fd"),
                    kwargs.get("dst_dir_fd"),
                )
            )
            return real_replace(source, destination, *args, **kwargs)

        monkeypatch.setattr(file_cell_module.os, "replace", recording_replace)
        result = _commit(cell, package, witness)
        assert result["status"] == "COMMITTED"
        assert target.read_text(encoding="utf-8") == "approved\n"
        assert replacements
        assert all(
            src_dir_fd is not None and src_dir_fd == dst_dir_fd
            for _source, _destination, src_dir_fd, dst_dir_fd in replacements
        ), "atomic publish must rename descriptor-relative within one verified directory"
        echo_visible = json.dumps(result, sort_keys=True)
        assert str(owner_root) not in echo_visible
        assert "approved" not in echo_visible
        assert "package" not in echo_visible.lower()
        assert "permit" not in echo_visible.lower()

    def test_commit_cas_refuses_source_changed_after_preflight(self, tmp_path: Path) -> None:
        mac_key = b"c" * 32
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        target = owner_root / "report.txt"
        target.write_text("old\n", encoding="utf-8")
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "3" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                handle.handle_id,
                [{"path": "report.txt", "content": "approved\n"}],
            ),
            handle,
        )
        cell = _file_cell(tmp_path, mac_key)
        witness = _stage(cell, package)
        target.write_text("raced\n", encoding="utf-8")

        try:
            result = _commit(cell, package, witness)
        except ProtocolError:
            pass
        else:
            assert result["status"] == "FAILED"
        assert target.read_text(encoding="utf-8") == "raced\n"

    @pytest.mark.parametrize(
        "changes",
        [
            [{"path": "../escape.txt", "content": "x"}],
            [{"path": "/tmp/absolute.txt", "content": "x"}],
            [
                {"path": "\N{LATIN SMALL LETTER E WITH ACUTE}.txt", "content": "a"},
                {"path": "e\N{COMBINING ACUTE ACCENT}.txt", "content": "b"},
            ],
            [
                {"path": "Report.txt", "content": "a"},
                {"path": "report.TXT", "content": "b"},
            ],
        ],
        ids=("parent", "absolute", "nfc-collision", "casefold-collision"),
    )
    def test_preflight_rejects_lexical_and_normalization_escapes(
        self, tmp_path: Path, changes: list[dict[str, str]]
    ) -> None:
        mac_key = b"n" * 32
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "4" * 64)
        package = _package(_draft(f"task:{uuid4().hex}", handle.handle_id, changes), handle)
        with pytest.raises(ProtocolError):
            _stage(_file_cell(tmp_path, mac_key), package)
        assert not (tmp_path / "escape.txt").exists()

    def test_preflight_rejects_symlink_parent_and_hardlinked_target(self, tmp_path: Path) -> None:
        mac_key = b"l" * 32
        owner_root = tmp_path / "owner"
        outside = tmp_path / "outside"
        owner_root.mkdir()
        outside.mkdir()
        (owner_root / "link").symlink_to(outside, target_is_directory=True)
        outside_file = outside / "shared.txt"
        outside_file.write_text("outside\n", encoding="utf-8")
        os.link(outside_file, owner_root / "hard.txt")
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "5" * 64)
        cases = (
            [{"path": "link/pwn.txt", "content": "pwn"}],
            [{"path": "hard.txt", "content": "changed"}],
        )
        for changes in cases:
            package = _package(_draft(f"task:{uuid4().hex}", handle.handle_id, changes), handle)
            with pytest.raises(ProtocolError):
                _stage(_file_cell(tmp_path / uuid4().hex, mac_key), package)
        assert not (outside / "pwn.txt").exists()
        assert outside_file.read_text(encoding="utf-8") == "outside\n"

    def test_file_cell_rejects_forged_directory_handle_mac_before_staging(
        self,
        tmp_path: Path,
    ) -> None:
        mac_key = b"k" * 32
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        valid = _directory_handle(mac_key, owner_root, owner="sha256:" + "7" * 64)
        forged = replace(valid, signature="orin-hmac-sha256:" + "0" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                forged.handle_id,
                [{"path": "forbidden.txt", "content": "must-not-stage"}],
            ),
            forged,
        )

        with pytest.raises(ProtocolError):
            _stage(_file_cell(tmp_path, mac_key), package)
        assert not (owner_root / "forbidden.txt").exists()
        assert b"must-not-stage" not in [
            path.read_bytes() for path in (tmp_path / "state").rglob("*") if path.is_file()
        ]

    @pytest.mark.parametrize(
        ("existing_name", "requested_path"),
        [
            (
                "\N{LATIN SMALL LETTER E WITH ACUTE}",
                "e\N{COMBINING ACUTE ACCENT}/report.txt",
            ),
            ("Reports", "reports/report.txt"),
        ],
        ids=("existing-nfc-alias", "existing-casefold-alias"),
    )
    def test_preflight_rejects_existing_directory_normalization_alias(
        self,
        tmp_path: Path,
        existing_name: str,
        requested_path: str,
    ) -> None:
        mac_key = b"d" * 32
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        (owner_root / existing_name).mkdir()
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "8" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                handle.handle_id,
                [{"path": requested_path, "content": "must-not-stage"}],
            ),
            handle,
        )

        with pytest.raises(ProtocolError):
            _stage(_file_cell(tmp_path, mac_key), package)
        assert not any(
            path.is_file() and path.read_bytes() == b"must-not-stage"
            for path in owner_root.rglob("*")
        )

    @pytest.mark.parametrize("dangling", [False, True], ids=("final-symlink", "dangling"))
    def test_preflight_rejects_final_symlink(
        self,
        tmp_path: Path,
        dangling: bool,
    ) -> None:
        mac_key = b"s" * 32
        owner_root = tmp_path / "owner"
        outside = tmp_path / "outside"
        owner_root.mkdir()
        outside.mkdir()
        outside_target = outside / "target.txt"
        if not dangling:
            outside_target.write_text("outside\n", encoding="utf-8")
        final_link = owner_root / "report.txt"
        final_link.symlink_to(outside_target)
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "9" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                handle.handle_id,
                [{"path": "report.txt", "content": "must-not-follow\n"}],
            ),
            handle,
        )

        with pytest.raises(ProtocolError):
            _stage(_file_cell(tmp_path, mac_key), package)
        assert final_link.is_symlink()
        if not dangling:
            assert outside_target.read_text(encoding="utf-8") == "outside\n"
        else:
            assert not outside_target.exists()

    def test_commit_rejects_target_swapped_to_hardlink_after_preflight(
        self,
        tmp_path: Path,
    ) -> None:
        mac_key = b"h" * 32
        owner_root = tmp_path / "owner"
        outside = tmp_path / "outside"
        owner_root.mkdir()
        outside.mkdir()
        target = owner_root / "report.txt"
        target.write_text("same-source\n", encoding="utf-8")
        outside_target = outside / "shared.txt"
        outside_target.write_text("same-source\n", encoding="utf-8")
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "a" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                handle.handle_id,
                [{"path": "report.txt", "content": "approved\n"}],
            ),
            handle,
        )
        cell = _file_cell(tmp_path, mac_key)
        witness = _stage(cell, package)

        target.unlink()
        os.link(outside_target, target)
        assert target.stat().st_nlink == 2
        _assert_commit_rejected(cell, package, witness)
        assert outside_target.read_text(encoding="utf-8") == "same-source\n"
        assert target.read_text(encoding="utf-8") == "same-source\n"

    def test_commit_rejects_parent_swapped_to_symlink_after_preflight(
        self,
        tmp_path: Path,
    ) -> None:
        mac_key = b"p" * 32
        owner_root = tmp_path / "owner"
        outside = tmp_path / "outside"
        nested = owner_root / "nested"
        nested.mkdir(parents=True)
        outside.mkdir()
        target = nested / "report.txt"
        target.write_text("old\n", encoding="utf-8")
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "a" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                handle.handle_id,
                [{"path": "nested/report.txt", "content": "approved\n"}],
            ),
            handle,
        )
        cell = _file_cell(tmp_path, mac_key)
        witness = _stage(cell, package)

        saved_nested = owner_root / "nested-before-swap"
        nested.rename(saved_nested)
        nested.symlink_to(outside, target_is_directory=True)
        _assert_commit_rejected(cell, package, witness)
        assert not (outside / "report.txt").exists()
        assert (saved_nested / "report.txt").read_text(encoding="utf-8") == "old\n"

    @pytest.mark.parametrize("tamper", ["report", "bytes"], ids=("report", "staged-bytes"))
    def test_commit_rejects_tampered_stage_report_or_staged_bytes(
        self,
        tmp_path: Path,
        tamper: str,
    ) -> None:
        mac_key = b"t" * 32
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        target = owner_root / "report.txt"
        target.write_text("old\n", encoding="utf-8")
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "b" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                handle.handle_id,
                [{"path": "report.txt", "content": "approved\n"}],
            ),
            handle,
        )
        cell = _file_cell(tmp_path, mac_key)
        witness = _stage(cell, package)
        state_root = tmp_path / "state"
        if tamper == "report":
            report_path = _preview_path(state_root, package.draft.draft_id)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["bytes_written"] = int(report["bytes_written"]) + 1
            report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        else:
            staged_path = _staged_file_with_bytes(state_root, b"approved\n")
            staged_path.write_bytes(b"tampered\n")

        _assert_commit_rejected(cell, package, witness)
        assert target.read_text(encoding="utf-8") == "old\n"

    def test_commit_sha256_rejects_same_size_content_with_forged_mtime(
        self,
        tmp_path: Path,
    ) -> None:
        mac_key = b"m" * 32
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        target = owner_root / "report.txt"
        target.write_bytes(b"AAAA\n")
        before = target.stat()
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "c" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                handle.handle_id,
                [{"path": "report.txt", "content": "final\n"}],
            ),
            handle,
        )
        cell = _file_cell(tmp_path, mac_key)
        witness = _stage(cell, package)

        target.write_bytes(b"BBBB\n")
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        after = target.stat()
        assert after.st_size == before.st_size
        assert after.st_mtime_ns == before.st_mtime_ns
        _assert_commit_rejected(cell, package, witness)
        assert target.read_bytes() == b"BBBB\n"

    @pytest.mark.parametrize("tamper", ["witness-id", "target-version", "canonical-hash"])
    def test_commit_rejects_tampered_witness_or_package_hash(
        self,
        tmp_path: Path,
        tamper: str,
    ) -> None:
        mac_key = b"w" * 32
        owner_root = tmp_path / "owner"
        owner_root.mkdir()
        target = owner_root / "report.txt"
        target.write_text("old\n", encoding="utf-8")
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "c" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                handle.handle_id,
                [{"path": "report.txt", "content": "approved\n"}],
            ),
            handle,
        )
        cell = _file_cell(tmp_path, mac_key)
        witness = _stage(cell, package)
        tampered_package = package
        tampered_witness = witness
        if tamper == "witness-id":
            tampered_witness = replace(witness, witness_id=f"state:{uuid4().hex}")
        elif tamper == "target-version":
            tampered_witness = replace(witness, target_version="file-plan:" + "0" * 64)
        else:
            forged_hash = "sha256:" + "0" * 64
            tampered_package = replace(package, canonical_effect_hash=forged_hash)
            tampered_witness = replace(witness, canonical_effect_hash=forged_hash)

        _assert_commit_rejected(cell, tampered_package, tampered_witness)
        assert target.read_text(encoding="utf-8") == "old\n"

    @pytest.mark.parametrize("boundary_name", ["level", "mounted"])
    def test_preflight_rejects_device_change_at_each_directory_layer(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boundary_name: str,
    ) -> None:
        mac_key = b"v" * 32
        owner_root = tmp_path / "owner"
        mounted = owner_root / "level" / "mounted"
        mounted.mkdir(parents=True)
        handle = _directory_handle(mac_key, owner_root, owner="sha256:" + "d" * 64)
        package = _package(
            _draft(
                f"task:{uuid4().hex}",
                handle.handle_id,
                [{"path": "level/mounted/report.txt", "content": "blocked"}],
            ),
            handle,
        )
        cell = _file_cell(tmp_path, mac_key)
        real_fd_device = cell._fd_device  # noqa: SLF001 - mount-boundary seam
        root_device = owner_root.stat().st_dev
        calls = 0
        # _validate_device_layers checks root first, then each opened parent.
        # The second call is ``level``; ``mounted`` is the fourth because the
        # second prefix is reopened from the trusted root.  Counting calls is
        # portable on macOS, where readlink('/dev/fd/<directory-fd>') is EINVAL.
        forged_call = 2 if boundary_name == "level" else 4

        def forged_fd_device(fd: int) -> int:
            nonlocal calls
            calls += 1
            if calls == forged_call:
                return root_device + 1
            return real_fd_device(fd)

        monkeypatch.setattr(cell, "_fd_device", forged_fd_device)
        with pytest.raises(ProtocolError):
            _stage(cell, package)
        assert not (mounted / "report.txt").exists()


@pytest.fixture(scope="module")
def file_orind(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("wp9-file-orind")
    witness = ed25519.Ed25519PrivateKey.generate()
    with TestOrind(
        state_dir=root / "state",
        stage_b=True,
        cell_file=True,
        witness_public_keys=(_pub_of(witness),),
    ) as orind:
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if orind.daemon._cell_by_cap("cell.file") is not None:  # noqa: SLF001
                break
            time.sleep(0.1)
        else:
            pytest.fail("File Cell subprocess did not connect")
        yield orind, witness, root


class TestFileCellIntegration:
    @staticmethod
    def _issue_directory(
        orind: TestOrind,
        owner_root: Path,
        *,
        owner: str,
        tenant: str = "work",
        capabilities: tuple[str, ...] = ("read", "stage", "write"),
    ) -> str:
        issued = orind.daemon._broker.issue(  # noqa: SLF001 - approval-channel stand-in
            kind="DirectoryHandle",
            token=uuid4().hex,
            owner_key_hash=owner,
            tenant=tenant,
            object_digest=str(owner_root.resolve()),
            capabilities=capabilities,
            approved=True,
        )
        assert issued["ok"] is True
        return str(issued["handle"]["handle_id"])

    @staticmethod
    def _register_file_intent(
        orind: TestOrind,
        witness_key: ed25519.Ed25519PrivateKey,
        *,
        owner: str,
        resource_handles: tuple[str, ...],
        profile: str = "work",
    ) -> tuple[OrinLeaseClientAdapter, str]:
        task_id = f"task:{uuid4().hex}"
        now = _now_ms()
        intent = IntentEnvelope(
            intent_id=f"intent:{uuid4().hex}",
            owner_key_hash=owner,
            product_id="js-agent",
            profile=profile,
            task_id=task_id,
            raw_request_hash="sha256:" + "7" * 64,
            allowed_effect_classes=("file.commit",),
            allowed_resource_handles=resource_handles,
            allowed_sink_handles=(),
            budgets=Budgets(max_invocations=20, max_bytes_out=1 << 20),
            approval_policy="preauthorized_exact_template",
            issued_by="appshell:test",
            issued_at_ms=now - 1_000,
            expires_at_ms=now + 60_000,
        ).sign_with(witness_key)
        adapter = _adapter(orind)
        assert adapter.register_intent(intent.to_dict())["ok"] is True
        return adapter, task_id

    def _register_file_authority(
        self,
        orind: TestOrind,
        witness_key: ed25519.Ed25519PrivateKey,
        owner_root: Path,
    ) -> tuple[OrinLeaseClientAdapter, str, str]:
        owner = "sha256:" + "6" * 64
        handle_id = self._issue_directory(orind, owner_root, owner=owner)
        adapter, task_id = self._register_file_intent(
            orind,
            witness_key,
            owner=owner,
            resource_handles=(handle_id,),
        )
        return adapter, task_id, handle_id

    @staticmethod
    def _register_product_file_binding(
        orind: TestOrind,
        witness_key: ed25519.Ed25519PrivateKey,
        owner_root: Path,
        *,
        profile: str,
    ) -> tuple[OrinLeaseClientAdapter, dict[str, Any]]:
        installation_owner = "sha256:" + hashlib.sha256(
            f"installation:{uuid4().hex}".encode()
        ).hexdigest()
        principal_owner = "sha256:" + hashlib.sha256(
            f"appshell:{uuid4().hex}".encode()
        ).hexdigest()
        principal_session = f"appshell:wp9-product-{uuid4().hex}"
        principal_epoch = 37
        product_id = "js-work" if profile == "work" else "js-agent"
        task_id = f"task:{uuid4().hex}"
        handle_id = _appshell_directory_handle_id(
            installation_owner_hash=installation_owner,
            product_id=product_id,
            task_id=task_id,
            profile=profile,
            principal_owner=principal_owner,
            principal_session=principal_session,
            principal_epoch=principal_epoch,
            workspace_root=owner_root,
        )
        intent = build_intent_from_template(
            template=profile,
            task_id=task_id,
            raw_request="commit this exact workspace change",
            owner_key_hash=installation_owner,
            product_id=product_id,
            resource_handles=(handle_id,),
        ).sign_with(witness_key)
        adapter = _adapter(orind)
        ack = adapter.register_file_binding(
            intent.to_dict(),
            appshell_owner=principal_owner,
            appshell_session=principal_session,
            appshell_epoch=principal_epoch,
            workspace_root=owner_root,
        )
        assert ack["ok"] is True
        assert ack["directory_handle_id"] == handle_id
        return adapter, {
            "installation_owner": installation_owner,
            "principal_owner": principal_owner,
            "principal_session": principal_session,
            "principal_epoch": principal_epoch,
            "product_id": product_id,
            "profile": profile,
            "task_id": task_id,
            "handle_id": handle_id,
        }

    @staticmethod
    def _enter_product_file_context(
        owner_root: Path,
        binding: dict[str, Any],
        change: dict[str, str],
    ) -> tuple[Any, Any]:
        runtime_state = owner_root.parent / f"runtime-state-{uuid4().hex}"
        runtime_state.mkdir()
        echo_session = f"echo-child:{uuid4().hex}"
        run_id = f"run:{uuid4().hex}"
        runtime = RuntimeContext(
            product_id=str(binding["product_id"]),
            channel="web",
            owner_key_hash=str(binding["principal_owner"]),
            session_id=echo_session,
            run_id=run_id,
            role="user",
            # This is deliberately not the Orin personal/work profile.  The
            # trusted mode comes from the parent AppShell epoch binding.
            profile="runtime-tool-profile",
            capabilities=("file_write",),
            workspace=owner_root.resolve(),
            state_dir=runtime_state.resolve(),
            fs_roots=(owner_root.resolve(),),
            appshell_epoch_binding=AppShellEpochBindingV1(
                owner=str(binding["principal_owner"]),
                session=str(binding["principal_session"]),
                active_mode=str(binding["profile"]),  # type: ignore[arg-type]
                # The epoch workspace is an opaque product selection, never
                # a filesystem root.  RuntimeContext.workspace is authoritative.
                workspace="workspace:opaque-selection-not-a-path",
                epoch=int(binding["principal_epoch"]),
            ),
        )
        tool = ToolExecutionContext(
            owner_key_hash=str(binding["principal_owner"]),
            run_id=run_id,
            tool_name="file_write",
            args_hash=stable_payload_hash(change),
            fs_roots=(os.fspath(owner_root.resolve()),),
            network_policy="deny",
            max_bytes=1 << 20,
            max_duration_ms=10_000,
            product_id=str(binding["product_id"]),
            session_id=echo_session,
            profile="runtime-tool-profile",
        )
        runtime_token = set_runtime_context(runtime)
        tool_token = registry_module._CURRENT_TOOL_EXECUTION_CONTEXT.set(  # noqa: SLF001
            tool
        )
        return runtime_token, tool_token

    @staticmethod
    def _exit_product_file_context(tokens: tuple[Any, Any]) -> None:
        runtime_token, tool_token = tokens
        registry_module._CURRENT_TOOL_EXECUTION_CONTEXT.reset(tool_token)  # noqa: SLF001
        reset_runtime_context(runtime_token)

    @staticmethod
    def _record_product_file_chain(
        adapter: OrinLeaseClientAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> tuple[list[str], list[dict[str, Any]]]:
        calls: list[str] = []
        drafts: list[dict[str, Any]] = []
        original_submit = adapter.submit_draft
        original_preflight = adapter.preflight_draft
        original_consume = adapter.consume_draft

        def submit(*args: Any, **kwargs: Any) -> dict[str, Any]:
            calls.append("submit")
            raw = args[0] if args else kwargs.get("draft_data")
            assert isinstance(raw, dict)
            drafts.append(raw)
            return original_submit(*args, **kwargs)

        def preflight(*args: Any, **kwargs: Any) -> dict[str, Any]:
            calls.append("preflight")
            return original_preflight(*args, **kwargs)

        def consume(*args: Any, **kwargs: Any) -> dict[str, Any]:
            calls.append("consume")
            return original_consume(*args, **kwargs)

        monkeypatch.setattr(adapter, "submit_draft", submit)
        monkeypatch.setattr(adapter, "preflight_draft", preflight)
        monkeypatch.setattr(adapter, "consume_draft", consume)
        return calls, drafts

    @staticmethod
    def _assert_authority_rejected_before_cell(
        orind: TestOrind,
        adapter: OrinLeaseClientAdapter,
        draft: EffectDraft,
        owner_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cell_calls: list[tuple[str, str]] = []

        async def forbidden_cell_request(
            cap: str,
            message_type: str,
            **_fields: Any,
        ) -> dict[str, Any] | None:
            cell_calls.append((cap, message_type))
            raise AssertionError("invalid resource authority reached cells.sock")

        monkeypatch.setattr(orind.daemon, "_request_cell", forbidden_cell_request)
        try:
            proposed = adapter.submit_draft(draft.to_dict())
            assert proposed["verdict"] == "deny_policy"
            assert proposed["missing"] == []
            with pytest.raises(LeaseDenied):
                adapter.preflight_draft(draft.draft_id)
        finally:
            adapter.close()
        assert cell_calls == []
        assert not (owner_root / "forbidden.txt").exists()

    def test_real_draft_preflight_commit_uses_peer_package_without_export_pass(
        self, file_orind: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        orind, witness_key, root = file_orind
        owner_root = root / f"owner-{uuid4().hex}"
        owner_root.mkdir()
        target = owner_root / "nested" / "report.txt"
        adapter, task_id, handle_id = self._register_file_authority(orind, witness_key, owner_root)
        draft = _draft(
            task_id,
            handle_id,
            [{"path": "nested/report.txt", "content": "from-file-cell\n"}],
        )
        original_request = orind.daemon._request_cell  # noqa: SLF001
        frames: list[tuple[str, str, dict[str, Any]]] = []

        async def recording_request(
            cap: str, message_type: str, **fields: Any
        ) -> dict[str, Any] | None:
            frames.append((cap, message_type, fields))
            return await original_request(cap, message_type, **fields)

        monkeypatch.setattr(orind.daemon, "_request_cell", recording_request)
        intents = orind.daemon._intents  # noqa: SLF001
        assert intents is not None

        def no_export_pass(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("local file.commit must not query or consume ExportPass")

        monkeypatch.setattr(intents, "active_exact_export_passes", no_export_pass)
        monkeypatch.setattr(intents, "claim_personal_export_pass", no_export_pass)
        try:
            proposed = adapter.submit_draft(draft.to_dict())
            assert proposed["verdict"] == "deny_missing_witness"
            preflight = adapter.preflight_draft(draft.draft_id, executor_id="cell.file")
            assert preflight["ok"] is True
            assert not target.exists(), "preflight may stage, never mutate owner root"
            committed = adapter.consume_draft(draft.draft_id)
        finally:
            adapter.close()

        assert committed["status"] == "COMMITTED"
        assert target.read_text(encoding="utf-8") == "from-file-cell\n"
        assert [message for _cap, message, _fields in frames] == ["preflight", "commit"]
        preflight_fields = frames[0][2]
        commit_fields = frames[1][2]
        assert "package" in preflight_fields and "permit" not in preflight_fields
        assert set(commit_fields) >= {"permit", "package"}
        assert "package" not in commit_fields["permit"]
        assert commit_fields["package"]["draft"]["draft_id"] == draft.draft_id

    def test_work_product_binding_runs_strict_file_chain_and_returns_safe_projection(
        self,
        file_orind: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        orind, witness_key, root = file_orind
        owner_root = root / f"product-workspace-{uuid4().hex}"
        owner_root.mkdir()
        target = owner_root / "nested" / "product.txt"
        change = {"path": "nested/product.txt", "content": "product-binding\n"}
        adapter, binding = self._register_product_file_binding(
            orind,
            witness_key,
            owner_root,
            profile="work",
        )
        assert binding["installation_owner"] != binding["principal_owner"]
        calls, drafts = self._record_product_file_chain(adapter, monkeypatch)
        intents = orind.daemon._intents  # noqa: SLF001
        assert intents is not None

        def no_export_pass(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("file.commit must not inspect or consume ExportPass")

        monkeypatch.setattr(intents, "active_exact_export_passes", no_export_pass)
        monkeypatch.setattr(intents, "claim_personal_export_pass", no_export_pass)
        tokens = self._enter_product_file_context(owner_root, binding, change)
        try:
            result = adapter.run_file_change(change)
        finally:
            self._exit_product_file_context(tokens)
            adapter.close()

        assert calls == ["submit", "preflight", "consume"]
        assert len(drafts) == 1
        assert drafts[0]["task_id"] == binding["task_id"]
        assert drafts[0]["effect_type"] == "file.commit"
        assert drafts[0]["arguments"] == {
            "directory_handle": binding["handle_id"],
            "changes": [change],
        }
        assert result["status"] == "COMMITTED"
        assert target.read_text(encoding="utf-8") == "product-binding\n"

        visible = json.dumps(result, ensure_ascii=False, sort_keys=True)
        for secret in (
            "permit",
            "package",
            "license",
            "token",
            "directory_handle",
            "workspace_root",
            "object_digest",
            "content",
            os.fspath(owner_root.resolve()),
            "product-binding",
        ):
            assert secret not in visible

    def test_personal_product_binding_requires_owner_approval_then_commits(
        self,
        file_orind: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        orind, witness_key, root = file_orind
        owner_root = root / f"product-personal-{uuid4().hex}"
        owner_root.mkdir()
        target = owner_root / "private.txt"
        change = {"path": "private.txt", "content": "owner-approved\n"}
        adapter, binding = self._register_product_file_binding(
            orind,
            witness_key,
            owner_root,
            profile="personal",
        )
        calls, drafts = self._record_product_file_chain(adapter, monkeypatch)
        intents = orind.daemon._intents  # noqa: SLF001
        assert intents is not None

        def no_export_pass(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("personal file.commit must not touch ExportPass")

        monkeypatch.setattr(intents, "active_exact_export_passes", no_export_pass)
        monkeypatch.setattr(intents, "claim_personal_export_pass", no_export_pass)
        tokens = self._enter_product_file_context(owner_root, binding, change)
        try:
            with pytest.raises(LeaseDenied) as pending_error:
                adapter.run_file_change(change)
        finally:
            self._exit_product_file_context(tokens)

        assert calls == ["submit", "preflight"]
        assert len(drafts) == 1
        assert drafts[0]["task_id"] == binding["task_id"]
        assert drafts[0]["arguments"] == {
            "directory_handle": binding["handle_id"],
            "changes": [change],
        }
        assert not target.exists()

        previews = adapter.pending_file_approvals(
            appshell_owner=str(binding["principal_owner"]),
            appshell_session=str(binding["principal_session"]),
            appshell_epoch=int(binding["principal_epoch"]),
            active_mode="personal",
            product_id=str(binding["product_id"]),
            workspace_root=owner_root,
        )
        assert len(previews) == 1
        preview = previews[0]
        assert set(preview) == {
            "file_count",
            "bytes",
            "overwrites",
            "diff_hash",
            "witness_id",
        }
        assert preview["file_count"] == 1
        assert preview["bytes"] == len(change["content"].encode("utf-8"))
        assert preview["overwrites"] == []
        assert "draft:" not in str(pending_error.value)
        try:
            committed = adapter.approve_pending_file_change(
                witness_id=str(preview["witness_id"]),
                diff_hash=str(preview["diff_hash"]),
                ttl_ms=60_000,
                private_key=witness_key,
                appshell_owner=str(binding["principal_owner"]),
                appshell_session=str(binding["principal_session"]),
                appshell_epoch=int(binding["principal_epoch"]),
                active_mode="personal",
                product_id=str(binding["product_id"]),
                workspace_root=owner_root,
            )
            assert committed["status"] == "COMMITTED"
            assert target.read_text(encoding="utf-8") == "owner-approved\n"
            with pytest.raises(LeaseDenied):
                adapter.approve_pending_file_change(
                    witness_id=str(preview["witness_id"]),
                    diff_hash=str(preview["diff_hash"]),
                    ttl_ms=60_000,
                    private_key=witness_key,
                    appshell_owner=str(binding["principal_owner"]),
                    appshell_session=str(binding["principal_session"]),
                    appshell_epoch=int(binding["principal_epoch"]),
                    active_mode="personal",
                    product_id=str(binding["product_id"]),
                    workspace_root=owner_root,
                )
        finally:
            adapter.close()

    def test_raw_cell_file_payload_is_rejected(self, file_orind: Any) -> None:
        orind, _witness_key, root = file_orind
        owner_root = root / f"raw-owner-{uuid4().hex}"
        owner_root.mkdir()
        adapter = _adapter(orind)
        try:
            with pytest.raises(LeaseDenied):
                adapter.run_in_cell(
                    "cell.file",
                    {
                        "tool": "file_write",
                        "path": str(owner_root / "bypass.txt"),
                        "content": "bypass",
                    },
                    context_taint=0,
                )
        finally:
            adapter.close()
        assert not (owner_root / "bypass.txt").exists()

    def test_same_owner_directory_not_in_intent_is_hard_rejected_before_cell(
        self,
        file_orind: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        orind, witness_key, root = file_orind
        owner = "sha256:" + "e" * 64
        allowed_root = root / f"allowed-{uuid4().hex}"
        forbidden_root = root / f"unlisted-{uuid4().hex}"
        allowed_root.mkdir()
        forbidden_root.mkdir()
        allowed_id = self._issue_directory(orind, allowed_root, owner=owner)
        unlisted_id = self._issue_directory(orind, forbidden_root, owner=owner)
        adapter, task_id = self._register_file_intent(
            orind,
            witness_key,
            owner=owner,
            resource_handles=(allowed_id,),
        )
        draft = _draft(
            task_id,
            unlisted_id,
            [{"path": "forbidden.txt", "content": "must-not-stage"}],
        )
        self._assert_authority_rejected_before_cell(
            orind,
            adapter,
            draft,
            forbidden_root,
            monkeypatch,
        )

    @pytest.mark.parametrize(
        "capabilities",
        [("read", "write"), ("read", "stage")],
        ids=("missing-stage", "missing-write"),
    )
    def test_directory_missing_stage_or_write_capability_is_hard_rejected_before_cell(
        self,
        file_orind: Any,
        monkeypatch: pytest.MonkeyPatch,
        capabilities: tuple[str, ...],
    ) -> None:
        orind, witness_key, root = file_orind
        owner = "sha256:" + "f" * 64
        owner_root = root / f"weak-cap-{uuid4().hex}"
        owner_root.mkdir()
        handle_id = self._issue_directory(
            orind,
            owner_root,
            owner=owner,
            capabilities=capabilities,
        )
        adapter, task_id = self._register_file_intent(
            orind,
            witness_key,
            owner=owner,
            resource_handles=(handle_id,),
        )
        draft = _draft(
            task_id,
            handle_id,
            [{"path": "forbidden.txt", "content": "must-not-stage"}],
        )
        self._assert_authority_rejected_before_cell(
            orind,
            adapter,
            draft,
            owner_root,
            monkeypatch,
        )

    def test_directory_tenant_profile_mismatch_is_hard_rejected_before_cell(
        self,
        file_orind: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        orind, witness_key, root = file_orind
        owner = "sha256:" + "0" * 64
        owner_root = root / f"wrong-tenant-{uuid4().hex}"
        owner_root.mkdir()
        handle_id = self._issue_directory(
            orind,
            owner_root,
            owner=owner,
            tenant="personal",
        )
        adapter, task_id = self._register_file_intent(
            orind,
            witness_key,
            owner=owner,
            resource_handles=(handle_id,),
            profile="work",
        )
        draft = _draft(
            task_id,
            handle_id,
            [{"path": "forbidden.txt", "content": "must-not-stage"}],
        )
        self._assert_authority_rejected_before_cell(
            orind,
            adapter,
            draft,
            owner_root,
            monkeypatch,
        )

    def test_wp7_build_cell_keeps_legacy_non_strict_protocol(self, tmp_path: Path) -> None:
        from js.orind.cells.build import BuildCell
        from js.orind.cells.file import FileCell

        build = BuildCell(
            socket_path=tmp_path / "unused-build.sock",
            state_dir=tmp_path,
            workspace=tmp_path / "workspace",
        )
        file_cell = FileCell(
            socket_path=tmp_path / "unused-file.sock",
            state_dir=tmp_path,
            mac_key=b"b" * 32,
        )
        assert build._strict_effect_protocol is False  # noqa: SLF001 - WP7 frozen frame
        assert file_cell._strict_effect_protocol is True  # noqa: SLF001

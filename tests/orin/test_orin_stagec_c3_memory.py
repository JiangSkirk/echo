"""WP-C3 Memory Cell harness.  Does not claim Memory has been product-migrated."""

from __future__ import annotations

import os
import stat as stat_module
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.config import OrinConfig
from js.echo.capability import LeaseDenied
from js.orin.client import OrinLeaseClientAdapter
from js.orin.draft import CellPackage, CommitPermit, EffectDraft
from js.orin.intent import Budgets, IntentEnvelope, request_hash_of
from js.orin.protocol import ProtocolError
from js.orin.taint import SECRET
from js.orin.testing import C3TestOrind
from js.orind.cells.memory import MemoryCell
from js.orind.daemon import OrinDaemon
from js.orind.kernel import canonical_effect_hash_of


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _public_key(private_key: ed25519.Ed25519PrivateKey) -> str:
    import base64

    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _cell(tmp_path: Path) -> MemoryCell:
    cell = MemoryCell(
        socket_path=tmp_path / "unused.sock",
        state_dir=tmp_path / "memory-state",
        mac_key=b"m" * 32,
    )
    cell._session_key = b"s" * 32  # noqa: SLF001
    return cell


def _draft(task_id: str, effect_type: str, arguments: dict[str, Any]) -> EffectDraft:
    return EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=task_id,
        effect_type=effect_type,
        arguments=arguments,
        declared_expectation={
            "external_visibility": "private",
            "reversibility": "reversible_until_stage",
        },
    )


def _package(draft: EffectDraft, *, clearance: int = 1) -> CellPackage:
    return CellPackage(
        draft=draft,
        executor_id="cell.memory",
        canonical_effect_hash=canonical_effect_hash_of(draft),
        resolved_handles=(),
        clearance=clearance,
    )


def _scope(
    *,
    owner: str = "sha256:" + "1" * 64,
    profile: str = "work",
    session: str = "session:one",
    task_id: str | None = None,
    key: str = "note",
    **extra: Any,
) -> dict[str, Any]:
    body = {
        "owner_key_hash": owner,
        "profile": profile,
        "session_id": session,
        "key": key,
    }
    if task_id is not None:
        body["task_id"] = task_id
    body.update(extra)
    return body


def _permit(package: CellPackage, witness: Any) -> CommitPermit:
    now = _now_ms()
    return CommitPermit(
        permit_id=f"permit:{uuid4().hex}",
        intent_id=f"intent:{uuid4().hex}",
        draft_id=package.draft.draft_id,
        state_witness_id=witness.witness_id,
        executor_id="cell.memory",
        canonical_effect_hash=package.canonical_effect_hash,
        idempotency_key=f"idem:{uuid4().hex}",
        sequence=1,
        not_before_ms=now - 100,
        expires_at_ms=now + 60_000,
    )


def _write(cell: MemoryCell, task_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    package = _package(_draft(task_id, "memory.write", arguments))
    preflight = cell._preflight_package(package)  # noqa: SLF001
    committed = replace(package, state_witness=preflight.witness)
    return cell._commit_package(_permit(committed, preflight.witness), committed)  # noqa: SLF001


def test_cell_memory_defaults_off_and_is_lazy() -> None:
    default = OrinConfig()
    opted = OrinConfig(cell_memory=True)
    assert default.cell_memory is False
    assert opted.cell_memory is True
    assert opted.enforce is False


def test_memory_cell_cannot_activate_outside_explicit_c3_harness(tmp_path: Path) -> None:
    daemon = OrinDaemon(
        state_dir=tmp_path,
        stage_b=True,
        cell_memory=True,
        cell_identity_enforce=True,
        c1_test_harness=False,
    )
    try:
        assert daemon._cell_memory_enabled is False  # noqa: SLF001
    finally:
        daemon._store.close()  # noqa: SLF001


def test_c3_harness_starts_memory_not_desktop(tmp_path: Path) -> None:
    harness = C3TestOrind(state_dir=tmp_path)
    assert harness._cell_memory is True  # noqa: SLF001
    assert harness._cell_desktop is False  # noqa: SLF001
    assert harness._c1_test_harness is True  # noqa: SLF001


def test_cross_owner_session_profile_reads_are_absent(tmp_path: Path) -> None:
    cell = _cell(tmp_path)
    task_id = f"task:{uuid4().hex}"
    owner = "sha256:" + "1" * 64
    _write(
        cell,
        task_id,
        _scope(owner=owner, session="session:one", key="secret-note", value="alpha", source="user"),
    )

    other_owner = cell._preflight_package(  # noqa: SLF001
        _package(
            _draft(
                task_id,
                "memory.read",
                _scope(owner="sha256:" + "2" * 64, session="session:one", key="secret-note"),
            )
        )
    )
    other_session = cell._preflight_package(  # noqa: SLF001
        _package(
            _draft(
                task_id,
                "memory.read",
                _scope(owner=owner, session="session:two", key="secret-note"),
            )
        )
    )
    other_profile = cell._preflight_package(  # noqa: SLF001
        _package(
            _draft(
                task_id,
                "memory.read",
                _scope(owner=owner, profile="personal", session="session:one", key="secret-note"),
            )
        )
    )
    assert other_owner.projection["status"] == "ABSENT"
    assert other_session.projection["status"] == "ABSENT"
    assert other_profile.projection["status"] == "ABSENT"


def test_secret_cannot_be_washed_or_shown_below_clearance(tmp_path: Path) -> None:
    cell = _cell(tmp_path)
    task_id = f"task:{uuid4().hex}"
    args = _scope(key="vault", value="top-secret", source="user", taint=SECRET, clearance=2)
    _write(cell, task_id, args)

    redacted = cell._preflight_package(  # noqa: SLF001
        _package(_draft(task_id, "memory.read", _scope(key="vault")), clearance=1)
    )
    assert redacted.projection["status"] == "REDACTED"
    assert "top-secret" not in str(redacted.projection)

    mutate = _package(
        _draft(
            task_id,
            "memory.mutate",
            _scope(key="vault", value="summary", source="model", taint=0, clearance=1),
        )
    )
    with pytest.raises(ProtocolError, match="SECRET|clearance|taint"):
        cell._preflight_package(mutate)  # noqa: SLF001


def test_replay_does_not_duplicate_persist(tmp_path: Path) -> None:
    cell = _cell(tmp_path)
    task_id = f"task:{uuid4().hex}"
    draft = _draft(
        task_id,
        "memory.write",
        _scope(key="once", value="first", source="user"),
    )
    package = _package(draft)
    preflight = cell._preflight_package(package)  # noqa: SLF001
    committed = replace(package, state_witness=preflight.witness)
    permit = _permit(committed, preflight.witness)
    first = cell._commit_package(permit, committed)  # noqa: SLF001
    second = cell._commit_package(permit, committed)  # noqa: SLF001
    assert first["status"] == "COMMITTED"
    assert first["duplicate"] is False
    assert second["duplicate"] is True
    assert cell._reconcile_effect(draft.draft_id, {"draft_id": draft.draft_id}) == {
        "state": "COMMITTED"
    }


def test_commit_rechecks_secret_taint_and_skips_unknown_insert(tmp_path: Path) -> None:
    cell = _cell(tmp_path)
    task_id = f"task:{uuid4().hex}"
    draft = _draft(
        task_id,
        "memory.write",
        _scope(key="vault", value="plain", source="user", taint=0, clearance=1),
    )
    package = _package(draft)
    preflight = cell._preflight_package(package)  # noqa: SLF001
    committed = replace(package, state_witness=preflight.witness)
    scope = cell._scope(committed)  # noqa: SLF001
    cell._conn.execute(  # noqa: SLF001
        "INSERT INTO memories("
        "record_id, owner_key_hash, profile, session_id, task_id, key, "
        "value, source, taint, clearance, created_at_ms, updated_at_ms"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "memory:secret",
            scope.owner_key_hash,
            scope.profile,
            scope.session_id,
            scope.task_id,
            scope.key,
            "top-secret",
            "user",
            SECRET,
            2,
            1,
            1,
        ),
    )
    cell._conn.commit()  # noqa: SLF001

    with pytest.raises(ProtocolError, match="overwrite|SECRET|taint"):
        cell._commit_package(_permit(committed, preflight.witness), committed)  # noqa: SLF001
    row = cell._conn.execute(  # noqa: SLF001
        "SELECT state FROM commits WHERE draft_id = ?",
        (draft.draft_id,),
    ).fetchone()
    assert row is None


def test_c3_orind_read_write_and_blocks_ambient_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    task_id = f"task:{uuid4().hex}"
    owner = "sha256:" + "1" * 64
    now = _now_ms()
    intent = IntentEnvelope(
        intent_id=f"intent:{uuid4().hex}",
        owner_key_hash=owner,
        product_id="js-work",
        profile="work",
        task_id=task_id,
        raw_request_hash=request_hash_of("remember this note"),
        allowed_effect_classes=("memory.read", "memory.write", "memory.mutate"),
        allowed_resource_handles=(),
        allowed_sink_handles=(),
        budgets=Budgets(
            max_invocations=20,
            max_bytes_read=1 << 20,
            max_bytes_out=0,
            max_cost_minor_units=0,
        ),
        approval_policy="preauthorized_exact_template",
        issued_by="appshell:owner-witness",
        issued_at_ms=now - 1_000,
        expires_at_ms=now + 60_000,
    ).sign_with(private_key)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("C3 harness must not write js.memory.store")

    monkeypatch.setattr("js.memory.store.MemoryStore.store", forbidden)
    monkeypatch.setattr("js.memory.store.MemoryStore.store_semantic", forbidden)
    monkeypatch.setattr("js.memory.store.MemoryStore.write_memory_file", forbidden)
    monkeypatch.setattr("js.memory.enhanced_store.EnhancedMemoryStore.store_semantic", forbidden)

    with C3TestOrind(
        state_dir=tmp_path / "state",
        witness_public_keys=(_public_key(private_key),),
    ) as orind:
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if orind.daemon._cell_by_cap("cell.memory") is not None:  # noqa: SLF001
                break
            time.sleep(0.05)
        else:
            pytest.fail("authenticated Memory Cell did not become ready")

        adapter = OrinLeaseClientAdapter(
            socket_path=orind.socket_path,
            state_dir=Path(orind.daemon._state_dir),  # noqa: SLF001
            stage_b=True,
        )
        assert adapter.register_intent(intent.to_dict(), session_id="session:c3")["ok"] is True
        written = adapter.write_memory(
            task_id,
            owner_key_hash=owner,
            profile="work",
            session_id="session:c3",
            key="note",
            value="hello",
            source="user",
        )
        assert written["status"] == "COMMITTED"
        read = adapter.read_memory(
            task_id,
            owner_key_hash=owner,
            profile="work",
            session_id="session:c3",
            key="note",
        )
        assert read["status"] == "READ"
        assert read["value"] == "hello"
        assert "signed_receipt" not in written
        assert "permit_id" not in written
        state_dir = Path(orind.daemon._state_dir)  # noqa: SLF001
        assert not (state_dir / "memory-cell.db").exists()
        shared_hits = [
            path for path in state_dir.rglob("memory-cell.db") if "cell-runtime" not in path.parts
        ]
        assert shared_hits == []
        private_dbs = [
            root / "state" / "memory-cell.db"
            for root in orind.daemon._cell_runtime_roots.values()  # noqa: SLF001
        ]
        assert any(path.exists() for path in private_dbs)

        found = next(path for path in private_dbs if path.exists())
        assert stat_module.S_IMODE(found.stat().st_mode) == 0o600
        foreign = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import pathlib, sys;"
                    "root = pathlib.Path(sys.argv[1]);"
                    "hits = [p for p in root.rglob('memory-cell.db')"
                    " if 'cell-runtime' not in p.parts];"
                    "sys.exit(2 if hits else 0)"
                ),
                str(state_dir),
            ],
            check=False,
            capture_output=True,
            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
        )
        assert foreign.returncode == 0, foreign.stderr

        with pytest.raises(LeaseDenied):
            adapter.read_memory(
                task_id,
                owner_key_hash="sha256:" + "9" * 64,
                profile="work",
                session_id="session:c3",
                key="note",
            )
        with pytest.raises(LeaseDenied):
            adapter.write_memory(
                task_id,
                owner_key_hash=owner,
                profile="work",
                session_id="session:other",
                key="note-two",
                value="nope",
                source="user",
            )
        with pytest.raises(LeaseDenied):
            adapter.write_memory(
                task_id,
                owner_key_hash=owner,
                profile="personal",
                session_id="session:c3",
                key="note-three",
                value="nope",
                source="user",
            )
        with pytest.raises(LeaseDenied):
            adapter.write_memory(
                f"task:{uuid4().hex}",
                owner_key_hash=owner,
                profile="work",
                session_id="session:c3",
                key="note-four",
                value="nope",
                source="user",
            )


def test_default_launchers_do_not_wire_memory_cell() -> None:
    root = Path(__file__).resolve().parents[2]
    for path in (
        root / "js" / "appshell" / "launcher.py",
        root / "js" / "web" / "server.py",
        root / "desktop" / "sidecar" / "host.py",
    ):
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        assert "cell_memory" not in text
        assert "C3TestOrind" not in text
        assert "cells.memory" not in text


def test_memory_cell_environment_is_an_exact_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json
    import secrets

    sensitive = {
        "ALL_PROXY",
        "AWS_SECRET_ACCESS_KEY",
        "OPENAI_API_KEY",
        "PYTHONPATH",
        "SSH_AUTH_SOCK",
    }
    for key in sensitive:
        monkeypatch.setenv(key, "must-not-enter-memory-cell")
    daemon = OrinDaemon(
        state_dir=tmp_path / "state",
        stage_b=True,
        cell_memory=True,
        cell_identity_enforce=True,
        c1_test_harness=True,
    )
    ticket = secrets.token_hex(16)
    runtime_root = tmp_path / "memory-private"
    runtime_root.mkdir(mode=0o700)
    try:
        environment = daemon._cell_environment(  # noqa: SLF001
            kind="memory",
            caps=frozenset({"cell.memory"}),
            tickets={"cell.memory": ticket},
            runtime_root=runtime_root,
        )
        assert sensitive.isdisjoint(environment)
        expected = {
            "HOME",
            "LC_ALL",
            "ORIN_CELLS_SOCKET",
            "ORIN_CELL_IDENTITY_ENFORCE",
            "ORIN_CELL_LAUNCH_TICKETS",
            "ORIN_CELL_PRIVATE_STATE",
            "ORIN_ORIND_PID",
            "ORIN_STATE_DIR",
            "PATH",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONIOENCODING",
            "PYTHONUTF8",
            "TMPDIR",
            "ORIN_KEYBOX_TIER",
        }
        assert set(environment) == expected
        assert environment["ORIN_CELL_PRIVATE_STATE"] != environment["ORIN_STATE_DIR"]
        assert Path(environment["ORIN_CELL_PRIVATE_STATE"]).is_dir()
        desktop_root = tmp_path / "desktop-private"
        desktop_root.mkdir(mode=0o700)
        desktop_env = daemon._cell_environment(  # noqa: SLF001
            kind="desktop",
            caps=frozenset({"cell.desktop"}),
            tickets={"cell.desktop": secrets.token_hex(16)},
            runtime_root=desktop_root,
        )
        assert "ORIN_CELL_PRIVATE_STATE" not in desktop_env
        assert json.loads(environment["ORIN_CELL_LAUNCH_TICKETS"]) == {"cell.memory": ticket}
        assert environment["ORIN_CELL_IDENTITY_ENFORCE"] == "1"
        assert environment["ORIN_ORIND_PID"] == str(os.getpid())
        assert environment["ORIN_KEYBOX_TIER"] == daemon.keybox_tier
        assert "PYTHONPATH" not in environment
    finally:
        daemon._store.close()  # noqa: SLF001

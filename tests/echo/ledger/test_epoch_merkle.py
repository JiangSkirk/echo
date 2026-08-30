"""P1-2: HMAC epoch ratchet bound to Merkle inclusion proofs."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

import pytest

from js.echo.ledger.epoch import (
    EpochCloseError,
    close_epoch,
    derive_next_key,
    destroy_key_file,
    load_live_epoch,
    permit_epoch_name,
    recover_pending_key_rotation,
    verify_closed_epochs,
    verify_journal_dual_read,
)
from js.echo.ledger.journal import EchoJournal, FileEchoLedger, verify_file
from js.echo.ledger.merkle import (
    empty_root,
    inclusion_proof,
    leaf_hash,
    merkle_tree_hash,
    verify_inclusion,
)
from js.echo.ledger.service import EchoSafetyService


def test_permit_epoch_name_starts_at_one() -> None:
    assert permit_epoch_name(1) == "permit-epoch-1"
    assert permit_epoch_name(2) == "permit-epoch-2"


def test_rfc6962_empty_and_single_leaf() -> None:
    assert merkle_tree_hash(()) == empty_root()
    assert merkle_tree_hash((b"a",)) == leaf_hash(b"a")


def test_inclusion_proof_round_trips() -> None:
    leaves = tuple(f"leaf-{index}".encode() for index in range(7))
    root = merkle_tree_hash(leaves)
    for index, data in enumerate(leaves):
        proof = inclusion_proof(index, leaves)
        assert verify_inclusion(data, proof, root)
        assert not verify_inclusion(b"tampered", proof, root)


def test_destroy_key_without_anchored_root_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "journal.key"
    path.write_text(secrets.token_bytes(32).hex(), encoding="utf-8")
    with pytest.raises(EpochCloseError, match="not anchored"):
        destroy_key_file(path, merkle_root_anchored=False)
    assert path.is_file()


def _seed_journal(root: Path) -> tuple[bytes, bytes, FileEchoLedger]:
    journal_key = secrets.token_bytes(32)
    permit_key = secrets.token_bytes(32)
    (root / "journal.key").write_text(journal_key.hex(), encoding="utf-8")
    (root / "permit.key").write_text(permit_key.hex(), encoding="utf-8")
    journal = FileEchoLedger(root / "chat.jsonl", mac_key=journal_key, local_tip_seal=True)
    for index in range(5):
        journal.append(
            record_type="decision",
            tenant_id="tenant-a",
            run_id="run-1",
            payload={"index": index, "note": f"row-{index}"},
        )
    return journal_key, permit_key, journal


def test_close_epoch_anchors_merkle_then_destroys_old_key(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    root.mkdir()
    journal_key, permit_key, journal = _seed_journal(root)
    result = close_epoch(
        root,
        records=journal.records,
        journal_key=journal_key,
        permit_key=permit_key,
        journal_key_path=root / "journal.key",
        permit_key_path=root / "permit.key",
        journal_path=root / "chat.jsonl",
    )
    assert result.closed_epoch == 1
    assert result.live_epoch == 2
    assert load_live_epoch(root) == 2
    new_key = bytes.fromhex((root / "journal.key").read_text(encoding="utf-8"))
    assert new_key != journal_key
    assert new_key == derive_next_key(journal_key, closed_epoch=1, purpose="journal")
    live = verify_file(root / "chat.jsonl", mac_key=new_key)
    assert live.ok
    old_live = verify_file(root / "chat.jsonl", mac_key=journal_key)
    assert not old_live.ok
    closed = verify_closed_epochs(root)
    assert closed.ok
    dual = verify_journal_dual_read(
        FileEchoLedger(root / "chat.jsonl", mac_key=new_key).records,
        live_mac_key=new_key,
        root=root,
    )
    assert dual.ok


def test_close_epoch_reloads_disk_instead_of_stale_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    root.mkdir()
    journal_key, permit_key, journal = _seed_journal(root)
    stale = journal.records
    extra = FileEchoLedger(root / "chat.jsonl", mac_key=journal_key, local_tip_seal=True)
    extra.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"index": 5, "note": "appended-after-snapshot"},
    )
    assert len(stale) == 5
    result = close_epoch(
        root,
        records=stale,
        journal_key=journal_key,
        permit_key=permit_key,
        journal_key_path=root / "journal.key",
        permit_key_path=root / "permit.key",
        journal_path=root / "chat.jsonl",
    )
    assert result.leaf_count == 6
    archive = json.loads((root / "epochs" / "epoch-1.json").read_text(encoding="utf-8"))
    notes = [row["payload"]["note"] for row in archive["records"]]
    assert "appended-after-snapshot" in notes


def test_tamper_locates_closed_epoch_seq(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    root.mkdir()
    journal_key, permit_key, journal = _seed_journal(root)
    close_epoch(
        root,
        records=journal.records,
        journal_key=journal_key,
        permit_key=permit_key,
        journal_key_path=root / "journal.key",
        permit_key_path=root / "permit.key",
        journal_path=root / "chat.jsonl",
    )
    archive = root / "epochs" / "epoch-1.json"
    payload = json.loads(archive.read_text(encoding="utf-8"))
    payload["records"][2]["payload"]["note"] = "mutated"
    archive.write_text(json.dumps(payload), encoding="utf-8")
    report = verify_closed_epochs(root)
    assert not report.ok
    assert any("seq:2:record_hash_mismatch" in item for item in report.errors)


def test_leaked_live_key_cannot_forge_closed_epoch(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    root.mkdir()
    journal_key, permit_key, journal = _seed_journal(root)
    close_epoch(
        root,
        records=journal.records,
        journal_key=journal_key,
        permit_key=permit_key,
        journal_key_path=root / "journal.key",
        permit_key_path=root / "permit.key",
        journal_path=root / "chat.jsonl",
    )
    leaked = bytes.fromhex((root / "journal.key").read_text(encoding="utf-8"))
    forged = EchoJournal(mac_key=leaked)
    forged.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"index": 0, "note": "forged-with-live-key"},
    )
    archive = root / "epochs" / "epoch-1.json"
    payload = json.loads(archive.read_text(encoding="utf-8"))
    payload["records"][0] = {
        "seq": 0,
        "record_type": forged.records[0].record_type,
        "tenant_id": forged.records[0].tenant_id,
        "run_id": forged.records[0].run_id,
        "payload": forged.records[0].payload,
        "prev_hash": forged.records[0].prev_hash,
        "record_hash": forged.records[0].record_hash,
        "mac": forged.records[0].mac.hex(),
    }
    archive.write_text(json.dumps(payload), encoding="utf-8")
    report = verify_closed_epochs(root)
    assert not report.ok
    assert any("seq:0:" in item for item in report.errors)


def test_legacy_verify_file_still_reads_unrotated_chain(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    root.mkdir()
    journal_key, _permit_key, journal = _seed_journal(root)
    report = verify_file(root / "chat.jsonl", mac_key=journal_key)
    assert report.ok
    assert journal.record_count == 5
    assert load_live_epoch(root) == 1
    assert verify_closed_epochs(root).ok


def test_service_close_journal_epoch(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    service._default_state.journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"ok": True},
    )
    result = service.close_journal_epoch()
    assert result.closed_epoch == 1
    assert service._default_state.live_epoch == 2
    closed = verify_closed_epochs(tmp_path / "echo" / "ledger")
    assert closed.ok
    assert verify_file(service.journal_path, mac_key=service.journal_key).ok
    logical = service._default_state.journal.verified_logical_records()
    assert any(getattr(record, "record_type", "") == "decision" for record in logical)
    assert any(getattr(record, "record_type", "") == "epoch_open" for record in logical)


def test_health_cache_invalidates_when_closed_epoch_is_tampered(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    service._default_state.journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"ok": True},
    )
    service.close_journal_epoch()
    archive = tmp_path / "echo" / "ledger" / "epochs" / "epoch-1.json"
    payload = json.loads(archive.read_text(encoding="utf-8"))
    payload["records"][0]["payload"]["ok"] = False
    archive.write_text(json.dumps(payload), encoding="utf-8")
    report = service._health_verify_report(service._default_state, max_verify_age_seconds=60)
    assert not report.ok
    assert any("seq:" in item for item in report.errors)


def test_remember_health_runs_merkle_without_verify_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    service._default_state.journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"ok": True},
    )
    service.close_journal_epoch()
    archive = tmp_path / "echo" / "ledger" / "epochs" / "epoch-1.json"
    payload = json.loads(archive.read_text(encoding="utf-8"))
    payload["records"][0]["payload"]["ok"] = False
    archive.write_text(json.dumps(payload), encoding="utf-8")
    verify_calls = 0

    def counting_verify_file(path: Path, *, mac_key: bytes):
        nonlocal verify_calls
        verify_calls += 1
        return verify_file(path, mac_key=mac_key)

    monkeypatch.setattr("js.echo.ledger.service.verify_file", counting_verify_file)
    service._remember_health_verified(service._default_state)
    report = service._health_verify_report(service._default_state, max_verify_age_seconds=60)
    assert verify_calls == 0
    assert not report.ok
    assert any("seq:" in item for item in report.errors)


def test_second_close_inherits_snapshot_tombstones(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    root.mkdir()
    journal_key, permit_key, journal = _seed_journal(root)
    journal.append(
        record_type="epoch_open",
        tenant_id="__system__",
        run_id="epoch-close",
        payload={"effect_tombstones": ["effect-keep"]},
    )
    journal.append(
        record_type="merge",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"effect_id": "effect-new"},
    )
    first = close_epoch(
        root,
        records=journal.records,
        journal_key=journal_key,
        permit_key=permit_key,
        journal_key_path=root / "journal.key",
        permit_key_path=root / "permit.key",
        journal_path=root / "chat.jsonl",
    )
    live_key = bytes.fromhex((root / "journal.key").read_text(encoding="utf-8"))
    permit_next = bytes.fromhex((root / "permit.key").read_text(encoding="utf-8"))
    live = FileEchoLedger(root / "chat.jsonl", mac_key=live_key, local_tip_seal=True)
    opens = [record for record in live.records if record.record_type == "epoch_open"]
    assert opens
    assert "effect-keep" in opens[-1].payload["effect_tombstones"]
    assert "effect-new" in opens[-1].payload["effect_tombstones"]
    second = close_epoch(
        root,
        records=live.records,
        journal_key=live_key,
        permit_key=permit_next,
        journal_key_path=root / "journal.key",
        permit_key_path=root / "permit.key",
        journal_path=root / "chat.jsonl",
    )
    assert first.closed_epoch == 1
    assert second.closed_epoch == 2
    newest = bytes.fromhex((root / "journal.key").read_text(encoding="utf-8"))
    after = FileEchoLedger(root / "chat.jsonl", mac_key=newest, local_tip_seal=True)
    tombstones = [record for record in after.records if record.record_type == "epoch_open"][-1]
    assert "effect-keep" in tombstones.payload["effect_tombstones"]
    assert "effect-new" in tombstones.payload["effect_tombstones"]
    assert verify_closed_epochs(root).ok
    assert after.verified_logical_records()


def test_recover_promotes_next_key_after_journal_rewrite(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    root.mkdir()
    journal_key, permit_key, journal = _seed_journal(root)
    close_epoch(
        root,
        records=journal.records,
        journal_key=journal_key,
        permit_key=permit_key,
        journal_key_path=root / "journal.key",
        permit_key_path=root / "permit.key",
        journal_path=root / "chat.jsonl",
    )
    new_journal = bytes.fromhex((root / "journal.key").read_text(encoding="utf-8"))
    new_permit = bytes.fromhex((root / "permit.key").read_text(encoding="utf-8"))
    (root / "journal.key").write_text(journal_key.hex(), encoding="utf-8")
    (root / "permit.key").write_text(permit_key.hex(), encoding="utf-8")
    (root / "journal.key.next").write_text(new_journal.hex(), encoding="utf-8")
    (root / "permit.key.next").write_text(new_permit.hex(), encoding="utf-8")
    recover_pending_key_rotation(
        root / "chat.jsonl",
        journal_key_path=root / "journal.key",
        permit_key_path=root / "permit.key",
    )
    assert bytes.fromhex((root / "journal.key").read_text(encoding="utf-8")) == new_journal
    assert not (root / "journal.key.next").exists()
    assert FileEchoLedger(root / "chat.jsonl", mac_key=new_journal).record_count >= 5


def test_recover_discards_stale_next_key(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    root.mkdir()
    journal_key, permit_key, journal = _seed_journal(root)
    (root / "journal.key.next").write_text(secrets.token_bytes(32).hex(), encoding="utf-8")
    (root / "permit.key.next").write_text(secrets.token_bytes(32).hex(), encoding="utf-8")
    recover_pending_key_rotation(
        root / "chat.jsonl",
        journal_key_path=root / "journal.key",
        permit_key_path=root / "permit.key",
    )
    assert not (root / "journal.key.next").exists()
    assert verify_file(root / "chat.jsonl", mac_key=journal_key).ok
    assert journal.record_count == 5


def test_service_load_completes_interrupted_epoch_close(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    service._default_state.journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"ok": True},
    )
    service.close_journal_epoch()
    root = tmp_path / "echo" / "ledger"
    new_journal = bytes.fromhex((root / "journal.key").read_text(encoding="utf-8"))
    new_permit = bytes.fromhex((root / "permit.key").read_text(encoding="utf-8"))
    (root / "journal.key.next").write_text(new_journal.hex(), encoding="utf-8")
    (root / "permit.key.next").write_text(new_permit.hex(), encoding="utf-8")
    (root / "journal.key").write_text(secrets.token_bytes(32).hex(), encoding="utf-8")
    (root / "permit.key").write_text(secrets.token_bytes(32).hex(), encoding="utf-8")
    (root / "epoch.json").write_text('{"live_epoch": 1}', encoding="utf-8")
    reloaded = EchoSafetyService(state_dir=tmp_path)
    assert reloaded._default_state.live_epoch == 2
    assert reloaded._default_state.journal_key == new_journal
    assert not (root / "journal.key.next").exists()


def test_load_does_not_advance_epoch_without_epoch_open(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    service._default_state.journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"ok": True},
    )
    root = tmp_path / "echo" / "ledger"
    (root / "merkle_anchors.jsonl").write_text(
        json.dumps(
            {
                "epoch": 1,
                "first_seq": 0,
                "last_seq": 0,
                "merkle_root": "sha256:" + "ab" * 32,
                "leaf_count": 1,
                "prev_anchor_hash": "sha256:" + "0" * 64,
                "archive_name": "epoch-1.json",
                "record_hash": "sha256:" + "cd" * 32,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "epoch.json").write_text('{"live_epoch": 1}', encoding="utf-8")
    reloaded = EchoSafetyService(state_dir=tmp_path)
    assert reloaded._default_state.live_epoch == 1


def test_load_rebuilds_anchor_chain_from_epoch_open(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    service._default_state.journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"ok": True},
    )
    service.close_journal_epoch()
    root = tmp_path / "echo" / "ledger"
    (root / "merkle_anchors.jsonl").unlink()
    (root / "epoch.json").write_text('{"live_epoch": 1}', encoding="utf-8")
    reloaded = EchoSafetyService(state_dir=tmp_path)
    assert reloaded._default_state.live_epoch == 2
    assert verify_closed_epochs(root).ok
